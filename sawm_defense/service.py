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

from .config import ConfigManager, default_state_dir, validate_config
from .storage import Store
from .secrets import SecretVault
from .cloud import CloudBridge
from .platforms import Collector
from .antivirus import Antivirus
from .actions import ActionExecutor
from . import autorun
from .policy import authorize


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
        self.collector = Collector(self._settings)
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
        self._last_maintenance = 0.0
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
            self.collector.update_config(updated)
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
                    "quarantine" in current.get("automatic_actions", [])):
                self.store.enqueue_scan(event)
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
                    self.collector.update_config(updated)
                    if identity_changed:
                        self.vault = self._vault_for(updated)
                        self._key = self.vault.get()
            snapshot, events = self.collector.sample()
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
            self._threads = [threading.Thread(target=self._monitor, daemon=True, name="SAWM sensors"),
                             threading.Thread(target=self._background, daemon=True, name="SAWM Cloud and scans")]
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
            try:
                recent = self.store.events(limit=100)
                queued = self.store.pending_scans(limit=2)
                for event in queued:
                    if self._stop.is_set():
                        break
                    path = event.get("details", {}).get("path")
                    if "quarantine" not in self.config.load().get("automatic_actions", []):
                        break
                    try:
                        if path:
                            self.scan(path)
                    except (ValueError, OSError):
                        self._event("scan_skipped", "warning", "Analyse non effectuée : fichier absent ou périmètre modifié.", {"event_id": event["id"]})
                    self.store.ack_scans([event["id"]])
                if len(queued) == 2 and self.store.pending_scans(limit=1) and "quarantine" in self.config.load().get("automatic_actions", []):
                    self._wake.set()
                if time.monotonic() - self._last_maintenance > 3600:
                    self.store.prune(self._settings["retention_days"])
                    self._journal = self.store.verify_chain()
                    self._last_maintenance = time.monotonic()
                if not self._settings["cloud_enabled"] or not self._configured():
                    continue
                if self._settings["cloud_upload_enabled"]:
                    # Review fresh signals before ingesting the backlog. SAWM sees
                    # current evidence directly; old memory is context, not proof.
                    candidates = [e for e in recent if e["id"] not in self._reviewed
                                  and e["severity"] in ("warning", "critical")
                                  and e["kind"] in ("resource_pressure", "antivirus_detection")]
                    if candidates:
                        candidate = candidates[0]
                        self.analyze(candidate["id"])
                        self._reviewed.add(candidate["id"])
                    batch = self.store.pending(limit=5)
                    if batch:
                        result = self._cloud_call("upload", batch)
                        self.store.ack_pending(result.get("event_ids", []))
            except Exception as exc:
                with self._lock:
                    self._cloud_state.update(status="indisponible", last_error=type(exc).__name__)

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
        if candidate.is_symlink():
            raise ValueError("Les liens symboliques ne sont pas analysés.")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            raise ValueError("Sélectionnez un fichier ordinaire.")
        roots = [Path(p).expanduser().resolve() for p in self._settings["monitor_paths"]]
        if not any(resolved.is_relative_to(root) for root in roots):
            raise ValueError("Ajoutez d'abord ce dossier au périmètre surveillé.")
        if resolved.stat().st_size > self._settings["max_file_mb"] * 1024 * 1024:
            raise ValueError("Fichier au-delà de la limite d'analyse configurée.")
        return resolved

    def scan(self, path):
        target = self._scan_scope(path)
        result = self.av.scan(target)
        detected = result.get("status") == "detected"
        event = self._event("antivirus_detection" if detected else "antivirus_scan",
                            "critical" if detected else "info", "Détection antivirus." if detected else "Analyse antivirus terminée.",
                            {**result, "scan_status": result.get("status"), "verification_origin": "local_scanner"})
        result["event_id"] = event["id"]
        if detected and "quarantine" in self._settings["automatic_actions"]:
            result["execution"] = self.act("quarantine", event["id"], approved=False)
        return result

    def inventory(self):
        result = self.collector.inventory()
        self._event("inventory_completed", "info", "Inventaire des logiciels demandé.",
                    {"status": result.get("status", "completed")} if isinstance(result, dict) else {})
        return result

    def act(self, action, event_id, approved=False):
        event = self.store.get_event(event_id) if event_id else None
        with self._lock, self._state_guard():
            current = self.config.load()
            permitted, reason = authorize(action, event, current, approved=approved)
            if not permitted:
                result = {"status": "denied", "reason": reason}
            elif action == "observe":
                result = {"status": "completed", "reason": reason}
            else:
                result = self.executor.execute(action, event, current)
            record = self.store.record_action({**result, "action": action, "event_id": event_id,
                                               "approval": "human" if approved else "local_policy", "policy_reason": reason})
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
        with self._lock, self._state_guard():
            current = self.config.load()
            if record.get("action") == "quarantine":
                result = self.executor.restore(record, current)
            elif record.get("action") == "block_ip":
                result = self.executor.rollback(record, current)
            else:
                result = {"status": "denied", "reason": "Cette action ne peut pas être annulée."}
            return self.store.record_action({**result, "action": "restore", "restores": action_id, "approval": "human"})

    def export_report(self, path):
        target = Path(path).expanduser()
        report = {"generated_at": utc(), "version": "0.1.0", **self.status()}
        report["journal"] = self.store.verify_chain()
        if target.suffix.lower() == ".json":
            text = json.dumps(report, ensure_ascii=False, indent=2)
        else:
            sections = []
            for label, key in (("Couverture observée", "snapshot"), ("Antivirus", "antivirus"), ("Cloud", "cloud"),
                               ("Observations", "events"), ("Actions et décisions", "actions"), ("Appels Cloud", "calls"),
                               ("Intégrité du journal local", "journal")):
                sections.append(f"<h2>{label}</h2><pre>{html.escape(json.dumps(report[key], ensure_ascii=False, indent=2))}</pre>")
            text = '<!doctype html><html lang="fr"><meta charset="utf-8"><title>SAWM Defense — Rapport</title><style>body{max-width:1050px;margin:50px auto;padding:0 24px;font:16px system-ui;background:#fafafa;color:#161616}h1{font-size:42px}h2{border-top:1px solid #bbb;padding-top:22px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:20px;border:1px solid #ddd;font-size:12px}</style><h1>SAWM Defense</h1><p>Rapport d’observation et d’intervention · ' + html.escape(report["generated_at"]) + '</p><p>Ce rapport décrit les événements disponibles et les actions enregistrées. Une absence d’alerte ne certifie pas une absence de menace.</p>' + ''.join(sections) + '</html>'
        target.write_text(text, encoding="utf-8")
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
