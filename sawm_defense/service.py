"""Shared desktop/CLI service; sensors continue independently of Cloud calls."""
from __future__ import annotations

import html
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from contextlib import contextmanager
from . import __version__

from .config import ConfigManager, default_state_dir, validate_config
from .storage import Store
from .secrets import SecretVault
from .cloud import CloudBridge
from .platforms import Collector, no_symlink
from .antivirus import Antivirus
from .actions import ActionExecutor
from . import autorun
from .policy import authorize
from .downloads import effective_config, downloads_directory, StableFiles
from .security_sensors import Sensor
from .notifications import NotificationCenter
from .orders import OrderQueue


def utc():
    return datetime.now(timezone.utc).isoformat()


class MonitorLock:
    """OS-released lock; a stale PID file never authorizes concurrent monitors."""
    def __init__(self, path):
        self.path, self.file = path, None

    def acquire(self):
        self.file = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                if not self.file.read(1):
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError):
            self.file.close()
            self.file = None
            return False
        return True

    def release(self):
        if self.file:
            self.file.close()
            self.file = None


class AgentService:
    def __init__(self, state_dir=None):
        self.state_dir = Path(state_dir or default_state_dir()).expanduser().resolve()
        self.config = ConfigManager(self.state_dir)
        self.store = Store(self.state_dir)
        self._settings = self.config.load()
        self.vault = self._vault_for(self._settings)
        self.collector = Collector(effective_config(self._settings))
        self.security = Sensor(self._settings, self.state_dir)
        self.notifications = NotificationCenter(self.state_dir)
        self.orders = OrderQueue(self.state_dir)
        self._stable_files = StableFiles()
        self.av = Antivirus()
        self.executor = ActionExecutor(self.state_dir)
        self._lock = threading.RLock()
        self._sampling_lock = threading.Lock()
        self._cloud_lock = threading.Lock()
        self._monitor_lock = MonitorLock(self.state_dir / "monitor.lock")
        self._operation_lock = MonitorLock(self.state_dir / "cloud-operation.lock")
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._threads = []
        self._finishing_stop = None
        self._running = False
        self._snapshot = {}
        self._key_state = {"persisted": False, "backend": "system keyring"}
        self._cloud_state = {"status": "non configuré", "last_error": ""}
        self._journal = self.store.verify_chain()
        self._key = self.vault.get()
        self._reviewed = set()
        # Monotonic time may start near zero on a freshly booted host.
        # Run catch-up work immediately, including expired firewall receipts.
        self._last_maintenance = float("-inf")
        self._last_expiry = float("-inf")
        self._av_health = None
        if self._key:
            self._key_state["persisted"] = True

    def settings(self):
        with self._lock:
            return json.loads(json.dumps(self._settings))

    @contextmanager
    def _state_guard(self):
        guard = MonitorLock(self.state_dir / "settings.lock")
        deadline = time.monotonic() + 10
        while not guard.acquire():
            if time.monotonic() >= deadline:
                raise ValueError("Configuration utilisée par un autre processus ; réessayez.")
            time.sleep(.02)
        try:
            yield
        finally:
            guard.release()

    def _vault_for(self, config):
        destination = "|".join(config[k] for k in ("cloud_base_url", "space_id", "entity_id"))
        return SecretVault(self.state_dir / "key-scopes" / hashlib.sha256(destination.encode()).hexdigest())

    def save_settings(self, patch, api_key=None, persist_key=True):
        with self._lock, self._state_guard():
            old = self.config.load()
            updated = validate_config({**old, **patch})
            switching = any(updated[k] != old.get(k) for k in ("cloud_base_url", "space_id", "entity_id"))
            if switching and self.store.pending(limit=1):
                raise ValueError("La file Cloud doit être livrée avant de changer de destination. Utilisez un autre profil pour un autre compte.")
            if switching or api_key:
                if self._cloud_lock.locked():
                    raise ValueError("Terminez l'opération Cloud avant de changer sa destination ou sa clé.")
                probe = MonitorLock(self.state_dir / "cloud-operation.lock")
                if not probe.acquire():
                    raise ValueError("Terminez l'opération Cloud avant de changer sa destination ou sa clé.")
                probe.release()
            vault = self._vault_for(updated) if switching else self.vault
            new_key, new_info = self._key, self._key_state
            if switching:
                new_key = vault.get()
                new_info = {"persisted": bool(new_key), "backend": "system keyring"}
            if api_key is not None and api_key.strip():
                new_info = vault.set(api_key.strip(), persist=persist_key)
                new_key = api_key.strip()
            # Keys are bound to the destination in the OS keyring. A failed
            # configuration write cannot send a new endpoint an old key.
            self.config.save(updated)
            self.vault, self._key, self._key_state = vault, new_key, new_info
            self._settings = updated
            self.collector.update_config(effective_config(updated))
            self.security.update_config(updated)
        self._event("settings_changed", "info", "Configuration locale mise à jour.",
                    {"fields": sorted(patch), "key_changed": bool(api_key)})
        self._wake.set()
        return {"status": "completed", "settings": self.settings(), "key": self._key_state}

    def status(self):
        with self._lock:
            settings = self.settings()
            snapshot = json.loads(json.dumps(self._snapshot))
            cloud = dict(self._cloud_state)
        external = False
        if not self._running:
            cached = self.state_dir / "last-snapshot.json"
            try:
                if not cached.is_symlink() and cached.stat().st_size < 1048576:
                    stored = json.loads(cached.read_text(encoding="utf-8"))
                    snapshot = stored.get("snapshot", {})
                    age = time.time() - stored.get("saved_at", 0)
                    probe = MonitorLock(self.state_dir / "monitor.lock")
                    external = age < max(20, settings["poll_seconds"] * 3) and not probe.acquire()
                    probe.release()
            except (OSError, ValueError, TypeError):
                pass
        cloud.update(configured=self._configured(), enabled=settings["cloud_enabled"],
                     queued=len(self.store.pending(limit=1000)))
        return {"running": self._running or external, "external_monitor": external, "settings": settings, "snapshot": snapshot,
                "events": self.store.events(limit=200), "actions": self.store.actions(limit=100),
                "calls": self.store.calls(limit=100), "cloud": cloud,
                "journal": self._journal, "antivirus": self.av.capabilities(),
                "security_capabilities": self.security.capabilities(),
                "file_inspection": {"available": True, "mode": "static-no-execution", "antivirus_equivalent": False},
                "downloads": {"enabled": settings["protect_downloads"], "path": str(downloads_directory()),
                              "effective_paths": effective_config(settings)["monitor_paths"]},
                "notifications": self.notifications.list(), "notification_capabilities": self.notifications.capabilities(),
                "orders": self.orders.list(),
                "key": {**self._key_state, "available": bool(self._key)}}

    def _configured(self):
        return bool(self._key and self._settings.get("space_id") and self._settings.get("entity_id"))

    def _event(self, kind, severity, summary, details=None):
        event = self.store.add_event({"kind": kind, "severity": severity,
                                      "summary": summary, "details": details or {}})
        # Shared with save_settings across desktop and daemon processes: a
        # queue cannot acquire an old destination after the destination changed.
        with self._lock, self._state_guard():
            current = self.config.load()
            if current.get("cloud_upload_enabled") and current.get("space_id") and current.get("entity_id"):
                self.store.enqueue(event)
            if (kind in ("file_created", "file_modified", "file_changed") and
                    current.get("automatic_scan_enabled")):
                self.store.enqueue_scan(event)
            if severity in ("warning", "critical"):
                self.store.enqueue_work("notify", event)
                if kind in {"resource_pressure", "antivirus_detection", "file_suspicious", "auth_bruteforce"}:
                    self.store.enqueue_work("review", event)
            if kind == "auth_bruteforce":
                self.store.enqueue_work("respond", event)
        return event

    def tick(self):
        if not self._sampling_lock.acquire(blocking=False):
            return {"status": "busy"}
        try:
            # A GUI can adjust an already-running user service. The service
            # reloads only validated configuration, never Cloud-supplied settings.
            with self._lock, self._state_guard():
                updated = self.config.load()
                if updated != self._settings:
                    identity_changed = any(updated[k] != self._settings[k] for k in ("cloud_base_url", "space_id", "entity_id"))
                    self._settings = updated
                    self.collector.update_config(effective_config(updated))
                    self.security.update_config(updated)
                    if identity_changed:
                        self.vault = self._vault_for(updated)
                        self._key = self.vault.get()
            snapshot, events = self.collector.sample()
            events.extend(self.security.sample())
            with self._lock:
                self._snapshot = snapshot
            fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=self.state_dir)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as out:
                    json.dump({"saved_at": time.time(), "snapshot": snapshot}, out)
                os.replace(temporary, self.state_dir / "last-snapshot.json")
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            saved = []
            for item in events:
                saved.append(self._event(item.get("kind", "observation"), item.get("severity", "info"),
                                         item.get("summary", "Observation"), item.get("details", {})))
            # Scanning runs in a separate worker, never holding up process sampling.
            if saved:
                self._wake.set()
            return {"status": "completed", "snapshot": snapshot, "events": saved}
        finally:
            self._sampling_lock.release()

    def start(self):
        with self._lock:
            if self._running:
                if self._stop.is_set():
                    return {"status": "stopping", "reason": "Fin de l'opération en cours ; réessayez ensuite."}
                return {"status": "completed", "running": True}
            if not self._monitor_lock.acquire():
                return {"status": "denied", "reason": "Une surveillance utilise déjà ce profil (service ou application)."}
            self._stop.clear()
            self._running = True
            self._threads = [threading.Thread(target=method, daemon=True, name=name) for method, name in (
                (self._monitor, "SAWM sensors"), (self._background, "SAWM Cloud"),
                (self._scanning, "SAWM file inspection"), (self._responses, "SAWM local response"),
                (self._missions, "SAWM missions"), (self._notifying, "SAWM notifications"))]
            for thread in self._threads:
                thread.start()
        self._event("monitor_started", "info", "Surveillance locale démarrée.")
        return {"status": "completed", "running": True}

    def _monitor(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:
                with self._lock:
                    self._snapshot.setdefault("coverage", {})["sensor_error"] = type(exc).__name__
                try:
                    self._event("sensor_error", "warning", "Un capteur est indisponible.", {"error_type": type(exc).__name__})
                except Exception:
                    # A full disk may prevent journaling. Preserve a visible
                    # health signal and retry instead of killing the monitor.
                    with self._lock:
                        self._snapshot.setdefault("coverage", {})["journal_write_failed"] = True
            self._stop.wait(self._settings.get("poll_seconds", 5))

    def _background(self):
        while not self._stop.is_set():
            self._wake.wait(timeout=30)
            self._wake.clear()
            if self._stop.is_set():
                break
            current = self.config.load()
            if current["cloud_enabled"] and current["space_id"] and current["entity_id"] and not self._key:
                # A separate GUI may add the first key after the daemon started.
                # Do not let a cached 'unconfigured' state suppress that transition.
                with self._lock:
                    self.vault = self._vault_for(current)
                    self._key = self.vault.get()
            if not current["cloud_enabled"] or not self._configured() or not current["cloud_upload_enabled"]:
                continue
            # Upload and review get independent attempts. A failed judge must
            # never prevent evidence from reaching a healthy ingestion endpoint.
            operations = ["upload", "review"] if not getattr(self, "_review_first", False) else ["review", "upload"]
            self._review_first = not getattr(self, "_review_first", False)
            for operation in operations:
                if self._stop.is_set():
                    break
                try:
                    if operation == "review" and current["autonomous_analysis_enabled"]:
                        candidates = self.store.pending_work("review", limit=1)
                        if candidates:
                            candidate = candidates[0]
                            self.analyze(candidate["id"])
                            self.store.ack_work("review", candidate["id"])
                    elif operation == "upload":
                        batch = self.store.pending(limit=5)
                        if batch:
                            result = self._cloud_call("upload", batch)
                            self.store.ack_pending(result.get("event_ids", []))
                except Exception as exc:
                    with self._lock:
                        self._cloud_state.update(status="indisponible", last_error=type(exc).__name__)

    def _scan_pending(self):
        current = self.config.load()
        if not current["automatic_scan_enabled"]:
            return
        # Inspect a wider window: a partial download must not hold up later files.
        completed = 0
        for event in self.store.pending_scans(limit=100):
            if self._stop.is_set() or completed >= 2:
                break
            path = event.get("details", {}).get("path")
            try:
                if not path:
                    raise ValueError("No target")
                target = self._scan_scope(path)
                if not self._stable_files.ready(target, current["download_scan_settle_seconds"]):
                    continue
                self.scan(target)
            except (ValueError, OSError):
                self._event("scan_skipped", "warning", "Analyse non effectuée : fichier absent ou périmètre modifié.", {"event_id": event["id"]})
            self.store.ack_scans([event["id"]])
            completed += 1

    def _scanning(self):
        while not self._stop.is_set():
            try:
                self._scan_pending()
            except Exception as exc:
                self._worker_error("file_scan", exc)
            self._stop.wait(1)

    def _worker_error(self, worker, exc):
        with self._lock:
            self._snapshot.setdefault("coverage", {})[worker + "_error"] = type(exc).__name__

    def _respond_pending(self):
        for event in self.store.pending_work("respond", limit=20):
            result = self.act("block_ip", event["id"], approved=False)
            if result.get("status") == "busy":
                break
            self.store.ack_work("respond", event["id"])

    def _expire_blocks(self):
        # Receipts survive process death before an action could reach the ledger.
        # Removing our own expired temporary rule is safe to retry after a crash.
        for path in list(self.executor.receipts.glob("*.json"))[:10000]:
            try:
                if not no_symlink(path) or path.stat().st_size > 16384:
                    continue
                receipt = json.loads(path.read_text(encoding="utf-8"))
                if receipt.get("action") != "block_ip" or not receipt.get("expires_at") or receipt["expires_at"] > time.time():
                    continue
                if any(a.get("expired_receipt") == receipt["receipt_id"] and a.get("status") == "completed"
                       for a in self.store.actions(limit=10000)):
                    continue
                intervention = MonitorLock(self.state_dir / "intervention.lock")
                if not intervention.acquire():
                    continue
                try:
                    current = effective_config(self.config.load())
                    result = self.executor.rollback(receipt, current)
                    self.store.record_action({**result, "action": "expire_block", "expired_receipt": receipt["receipt_id"], "approval": "local_policy"})
                finally:
                    intervention.release()
                self._event("temporary_block_expired", "info" if result.get("status") == "completed" else "warning",
                            "Fin du blocage temporaire : " + result.get("status", "error"), {"receipt_id": receipt["receipt_id"]})
            except (OSError, ValueError, KeyError, TypeError):
                continue

    def _responses(self):
        while not self._stop.is_set():
            try:
                self._respond_pending()
                if time.monotonic() - self._last_expiry > 30:
                    self._expire_blocks()
                    self._last_expiry = time.monotonic()
                if time.monotonic() - self._last_maintenance > 3600:
                    self.store.prune(self.config.load()["retention_days"])
                    self._journal = self.store.verify_chain()
                    self._last_maintenance = time.monotonic()
            except Exception as exc:
                self._worker_error("local_response", exc)
            self._stop.wait(1)

    def _notifying(self):
        while not self._stop.is_set():
            try:
                for event in self.store.pending_work("notify", limit=10):
                    self.notifications.publish(event, enabled=self.config.load()["notifications_enabled"])
                    self.store.ack_work("notify", event["id"])
            except Exception as exc:
                self._worker_error("notification", exc)
            self._stop.wait(1)

    def submit_order(self, kind, payload, approved=False, idempotency_key=None):
        order = self.orders.submit(kind, payload, approved=approved, idempotency_key=idempotency_key)
        self._event("order_submitted", "info", "Mission locale enregistrée : " + kind,
                    {"order_id": order["id"], "actor": order["actor"], "approved": order["approved"]})
        return order

    def acknowledge_notification(self, identifier):
        result = self.notifications.acknowledge(identifier)
        self._event("notification_acknowledged", "info", "Notification consultée.", {"notification_id": identifier})
        return result

    def _execute_next_order(self):
        order = self.orders.claim(lease_seconds=900)
        if not order:
            return None
        kind, payload, lease = order["kind"], order["payload"], order["lease_token"]
        try:
            if kind == "scan":
                result = self.scan(payload["path"])
            elif kind == "inventory":
                result = self.inventory()
            elif kind == "analyze":
                result = self.analyze(payload["event_id"])
            elif kind == "act":
                result = self.act(payload["action"], payload["event_id"], approved=order["approved"])
            elif kind == "restore":
                result = self.restore(payload["action_id"], approved=order["approved"])
            elif kind == "report":
                result = {"status": "completed", "path": self.export_report(payload["path"], exclusive=True)}
            else:
                raise ValueError("Ordre inconnu")
            self.orders.complete(order["id"], result, lease_token=lease)
            self._event("order_completed", "info", "Mission traitée : " + kind,
                        {"order_id": order["id"], "result_status": result.get("status", "completed") if isinstance(result, dict) else "completed"})
            return result
        except Exception as exc:
            self.orders.fail(order["id"], type(exc).__name__, lease_token=lease,
                             uncertain=kind in {"act", "restore", "scan", "analyze"})
            self._event("order_failed", "warning", "Mission à examiner : " + kind, {"order_id": order["id"], "error_type": type(exc).__name__})
            return {"status": "error", "error_type": type(exc).__name__}

    def _missions(self):
        while not self._stop.is_set():
            try:
                self._execute_next_order()
            except Exception as exc:
                self._worker_error("mission", exc)
            self._stop.wait(1)

    def _complete_stop(self):
        with self._lock:
            was_running = self._running
            self._running = False
            self._monitor_lock.release()
        if was_running:
            try:
                self._event("monitor_stopped", "info", "Surveillance locale arrêtée.")
            except Exception:
                pass  # A full disk must not prevent releasing the process lock.

    def _finish_stop(self):
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join()
        self._complete_stop()

    def stop(self):
        self._stop.set()
        self._wake.set()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=0.5)
        if any(t.is_alive() for t in self._threads):
            with self._lock:
                if self._finishing_stop is None or not self._finishing_stop.is_alive():
                    self._finishing_stop = threading.Thread(target=self._finish_stop, daemon=True, name="SAWM graceful stop")
                    self._finishing_stop.start()
            return {"status": "stopping", "reason": "Fin de l'opération en cours ; aucun nouveau cycle ne démarre."}
        self._complete_stop()
        return {"status": "completed", "running": False}

    def _cloud_call(self, method, *args):
        if not self._cloud_lock.acquire(blocking=False):
            raise ValueError("Une opération Cloud est déjà en cours.")
        bridge = None
        try:
            with self._lock, self._state_guard():
                if not self._operation_lock.acquire():
                    raise ValueError("Une opération Cloud du service est déjà en cours.")
                settings = self.config.load()
                changed = any(settings[k] != self._settings[k] for k in ("cloud_base_url", "space_id", "entity_id"))
                if changed:
                    self.vault = self._vault_for(settings)
                    self._key = self.vault.get()
                self._settings = settings
                self._key = self.vault.get()
                key = self._key
                if not key or not settings["space_id"] or not settings["entity_id"]:
                    raise ValueError("Renseignez la clé API, l'espace et l'entité Basira.")
                if method != "check" and not settings["cloud_enabled"]:
                    raise ValueError("Activez les échanges Cloud dans les réglages.")
                if method in ("upload", "analyze") and not settings["cloud_upload_enabled"]:
                    raise ValueError("L'envoi des observations Cloud n'est pas autorisé.")
                if method == "chat" and not settings["cloud_upload_enabled"]:
                    args = (args[0], [])
                if not self.store.reserve_cloud(settings["cloud_per_hour"]):
                    raise ValueError("Budget Cloud horaire atteint. La surveillance locale continue.")
            identity = str(self.state_dir) + ":" + settings["cloud_base_url"] + ":" + settings["space_id"] + ":" + settings["entity_id"]
            session_id = "defense-" + hashlib.sha256(identity.encode()).hexdigest()[:32]
            bridge = CloudBridge(settings, key, self.store.record_call, session_id=session_id)
            result = getattr(bridge, method)(*args)
            with self._lock:
                self._cloud_state.update(status="indisponible" if result.get("status") == "error" else "connecté", last_error="" if result.get("status") != "error" else "Événements non confirmés conservés")
            return result
        except Exception as exc:
            with self._lock:
                self._cloud_state.update(status="indisponible", last_error=type(exc).__name__)
            raise
        finally:
            if bridge:
                bridge.close()
            self._operation_lock.release()
            self._cloud_lock.release()

    def check_connection(self):
        return self._cloud_call("check")

    def analyze(self, event_id=None):
        if event_id:
            event = self.store.get_event(event_id)
            if event is None:
                raise ValueError("Observation introuvable.")
            events = [event]
        else:
            events = self.store.events(limit=20)
        if not self._settings["cloud_upload_enabled"]:
            raise ValueError("Autorisez l'envoi des observations au Cloud avant de demander leur analyse.")
        result = self._cloud_call("analyze", events, self.settings()["automatic_actions"])
        self._event("cloud_proposal", "info", "Proposition SAWM reçue ; vérification locale requise.", result)
        if result.get("action") and result["action"] != "observe":
            result["execution"] = self.act(result["action"], result.get("event_id"), approved=False)
        return result

    def chat(self, message):
        message = str(message).strip()
        if not message or len(message) > 8192:
            raise ValueError("Message requis, limité à 8 192 caractères pour ce client.")
        # Chat input is intentional disclosure; event context needs the separate opt-in.
        events = self.store.events(limit=20) if self._settings["cloud_upload_enabled"] else []
        result = self._cloud_call("chat", message, events)
        self._event("chat_completed", "info", "Échange avec SAWM terminé.",
                    {"usage": result.get("usage", {}), "context_events": len(events)})
        return result

    def _scan_scope(self, path):
        candidate = Path(path).expanduser()
        if not no_symlink(candidate.absolute()):
            raise ValueError("Les liens symboliques ne sont pas analysés.")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            raise ValueError("Sélectionnez un fichier ordinaire.")
        current = effective_config(self.config.load())
        roots = [Path(p).expanduser().resolve() for p in current["monitor_paths"]]
        if not any(resolved.is_relative_to(root) for root in roots):
            raise ValueError("Ajoutez d'abord ce dossier au périmètre surveillé.")
        if resolved.stat().st_size > current["max_file_mb"] * 1024 * 1024:
            raise ValueError("Fichier au-delà de la limite d'analyse configurée.")
        return resolved

    def scan(self, path):
        from .file_inspection import inspect_file
        target = self._scan_scope(path)
        inspection = inspect_file(target, max_file_mb=self.config.load()["max_file_mb"])
        av = self.av.scan(target)
        detected = av.get("status") == "detected"
        suspicious = inspection.get("status") == "suspicious"
        status = "detected" if detected else "suspicious" if suspicious else "no_indicator" if av.get("status") == "clean" and inspection.get("status") == "no_indicator" else "incomplete"
        result = {"status": status, "path": str(target), "sha256": av.get("sha256") or inspection.get("sha256"),
                  "antivirus": av, "static_inspection": inspection, "engine": av.get("engine")}
        kind = "antivirus_detection" if detected else "file_suspicious" if suspicious else "file_inspected"
        summary = "Détection antivirus." if detected else "Fichier suspect : indices locaux à examiner." if suspicious else "Inspection locale terminée ; aucun certificat d'innocuité."
        event = self._event(kind, "critical" if detected else "warning" if suspicious else "info", summary,
                            {**result, "scan_status": av.get("status"), "verification_origin": "local_scanner" if detected else "local_static_inspector"})
        result["event_id"] = event["id"]
        health = av.get("status") if av.get("status") in {"unavailable", "error"} else "available"
        with self._lock:
            health_changed = health != self._av_health
            self._av_health = health
        if health_changed and health in {"unavailable", "error"}:
            self._event("antivirus_unavailable", "warning", "Inspection statique effectuée ; protection antivirus complète indisponible.",
                        {"event_id": event["id"], "path": str(target), "antivirus_status": av.get("status")})
        current = self.config.load()
        if detected and "terminate" in current["automatic_actions"]:
            result["process_responses"] = self._respond_detected_processes(event, current)
        if detected and "quarantine" in current["automatic_actions"]:
            result["execution"] = self.act("quarantine", event["id"], approved=False)
        return result

    def _respond_detected_processes(self, event, current):
        from .platforms import psutil
        results = []
        if not psutil or event["details"]["path"] not in current["allowed_process_paths"]:
            return results
        for process in psutil.process_iter(["pid", "exe", "create_time"]):
            try:
                if process.info["exe"] != event["details"]["path"]:
                    continue
                proof = self._event("antivirus_process_detection", "critical", "Exécutable détecté associé à un processus local.",
                    {**event["details"], "pid": process.pid, "exe": process.info["exe"],
                     "create_time": process.info["create_time"], "exe_sha256": event["details"]["sha256"], "scan_event_id": event["id"]})
                results.append(self.act("terminate", proof["id"], approved=False))
                if len(results) >= 10:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return results

    def inventory(self):
        result = self.collector.inventory()
        self._event("inventory_completed", "info", "Inventaire des logiciels demandé.",
                    {"status": result.get("status", "completed")} if isinstance(result, dict) else {})
        return result

    def act(self, action, event_id, approved=False):
        event = self.store.get_event(event_id) if event_id else None
        intervention = MonitorLock(self.state_dir / "intervention.lock")
        if not intervention.acquire():
            return {"status": "busy", "reason": "Une intervention locale est en cours."}
        try:
            with self._lock, self._state_guard():
                current = effective_config(self.config.load())
                permitted, reason = authorize(action, event, current, approved=approved)
                if not permitted:
                    result = {"status": "denied", "reason": reason}
                elif action == "observe":
                    result = {"status": "completed", "reason": reason}
                elif not approved and not self.store.claim_effect(action + ":" + event_id):
                    result = {"status": "denied", "reason": "Intervention déjà engagée pour cette preuve ; examiner le reçu avant toute reprise."}
                else:
                    result = None
            # Mandate checked at dispatch; slow OS calls hold only the intervention
            # lock. Sensors, status and permission updates remain available.
            if result is None:
                result = self.executor.execute(action, event, {**current, "_automatic_response": not approved})
            record = self.store.record_action({**result, "action": action, "event_id": event_id,
                                               "approval": "human" if approved else "local_policy", "policy_reason": reason})
        finally:
            intervention.release()
        self._event("action_result", "warning" if result.get("status") == "completed" and action != "observe" else "info",
                    f"Action {action} : {result.get('status', 'error')}", {"action_id": record["id"], "event_id": event_id,
                                                                             "reason": result.get("reason", reason)})
        return record

    def restore(self, action_id, approved=False):
        if not approved:
            return {"status": "denied", "reason": "Restauration soumise à confirmation."}
        record = next((a for a in self.store.actions(limit=10000) if a["id"] == action_id), None)
        partial_firewall = record and record.get("action") == "block_ip" and record.get("receipt_id") and record.get("status") == "error"
        if record is None or (record.get("status") != "completed" and not partial_firewall):
            return {"status": "denied", "reason": "Action réversible introuvable."}
        intervention = MonitorLock(self.state_dir / "intervention.lock")
        if not intervention.acquire():
            return {"status": "busy", "reason": "Une intervention locale est en cours."}
        try:
            with self._lock, self._state_guard():
                current = effective_config(self.config.load())
            if record.get("action") == "quarantine":
                result = self.executor.restore(record, current)
            elif record.get("action") == "block_ip":
                result = self.executor.rollback(record, current)
            else:
                result = {"status": "denied", "reason": "Cette action ne peut pas être annulée."}
            return self.store.record_action({**result, "action": "restore", "restores": action_id, "approval": "human"})
        finally:
            intervention.release()

    def export_report(self, path, exclusive=False):
        target = Path(path).expanduser()
        if not no_symlink(target.absolute()):
            raise ValueError("Rapport : les liens symboliques sont exclus.")
        report = {"generated_at": utc(), "version": __version__, **self.status()}
        report["journal"] = self.store.verify_chain()
        if target.suffix.lower() == ".json":
            text = json.dumps(report, ensure_ascii=False, indent=2)
        else:
            sections = []
            for label, key in (("Couverture observée", "snapshot"), ("Antivirus", "antivirus"), ("Cloud", "cloud"),
                               ("Observations", "events"), ("Actions et décisions", "actions"), ("Appels Cloud", "calls"),
                               ("Missions", "orders"), ("Notifications", "notifications"), ("Capteurs de sécurité", "security_capabilities"),
                               ("Intégrité du journal local", "journal")):
                sections.append(f"<h2>{label}</h2><pre>{html.escape(json.dumps(report[key], ensure_ascii=False, indent=2))}</pre>")
            text = '<!doctype html><html lang="fr"><meta charset="utf-8"><title>SAWM Defense — Rapport</title><style>body{max-width:1050px;margin:50px auto;padding:0 24px;font:16px system-ui;background:#fafafa;color:#161616}h1{font-size:42px}h2{border-top:1px solid #bbb;padding-top:22px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:20px;border:1px solid #ddd;font-size:12px}</style><h1>SAWM Defense</h1><p>Rapport d’observation et d’intervention · ' + html.escape(report["generated_at"]) + '</p><p>Ce rapport décrit les événements disponibles et les actions enregistrées. Une absence d’alerte ne certifie pas une absence de menace.</p>' + ''.join(sections) + '</html>'
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        flags |= os.O_EXCL if exclusive else os.O_TRUNC
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return str(target.resolve())

    def _command(self):
        return [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m", "sawm_defense"]

    def install_startup(self):
        if self._running and self.stop().get("status") != "completed":
            return {"status": "denied", "reason": "Une opération se termine ; réessayez après son arrêt."}
        result = autorun.install_startup(self._command(), self.state_dir)
        self._event("startup_changed", "info", "Installation de la surveillance au démarrage demandée.", result)
        return result

    def remove_startup(self):
        result = autorun.remove_startup(self.state_dir)
        self._event("startup_changed", "info", "Retrait de la surveillance au démarrage demandé.", result)
        return result

    def close(self):
        self.stop()
        if self._finishing_stop is not None and self._finishing_stop is not threading.current_thread():
            self._finishing_stop.join(timeout=180)
        # Background threads may still finish a bounded scan or request. Do not
        # close their SQLite connection underneath them.
        if not any(t.is_alive() for t in self._threads) and hasattr(self.store, "close"):
            self.store.close()
            self.orders.close()
            self.notifications.close()
