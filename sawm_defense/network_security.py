"""Correlate bounded OS socket observations; never infer malware from an IP alone."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import tempfile
import threading
import time

from .config import private_dir

MAX_BASELINE = 4096
MAX_CONTACTS = 2048


def _stamp(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _load(path, default):
    if path.is_symlink():
        raise ValueError("État du capteur remplacé par un lien.")
    if not path.exists():
        return default
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("version") != 1:
            raise ValueError
        for key, expected in default.items():
            if key not in value or type(value[key]) is not type(expected):
                raise ValueError
        return value
    except (OSError, ValueError, TypeError):
        raise ValueError("État du capteur invalide ; historique non réinitialisé silencieusement.") from None


def _save(path, state):
    if path.is_symlink():
        raise ValueError("État du capteur remplacé par un lien.")
    fd, name = tempfile.mkstemp(prefix=".sensor-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class NetworkSecurity:
    """Snapshot input must come directly from Collector.sample, never Cloud text."""
    def __init__(self, config, state_dir):
        self.config = dict(config)
        self.path = private_dir(Path(state_dir)) / "network-security.json"
        self._lock = threading.RLock()
        self._state = _load(self.path, {"version": 1, "initialized": False, "baseline": {},
                                      "current": [], "contacts": [], "notices": {}})
        self._validate()
        self._status = {"coverage": "not_sampled", "last_sample": None, "new_events": 0}

    def _validate(self):
        state = self._state
        if (len(state["baseline"]) > MAX_BASELINE or len(state["contacts"]) > MAX_CONTACTS
                or len(state["current"]) > 4096 or len(state["notices"]) > 512):
            raise ValueError("État réseau hors limite.")
        if any(not isinstance(k, str) or type(v) not in {int, float} or not math.isfinite(v)
               for name in ("baseline", "notices") for k, v in state[name].items()):
            raise ValueError("État réseau invalide.")
        if any(not isinstance(v, str) for v in state["current"]):
            raise ValueError("Identités réseau invalides.")
        for item in state["contacts"]:
            if (not isinstance(item, dict) or type(item.get("at")) not in {int, float}
                    or not math.isfinite(item["at"]) or not isinstance(item.get("group"), str)
                    or not isinstance(item.get("id"), str) or type(item.get("port")) is not int):
                raise ValueError("Contact réseau invalide.")
            ipaddress.ip_address(item["ip"])

    def update_config(self, config):
        with self._lock:
            self.config = dict(config)

    def capabilities(self):
        return [{"name": "Corrélation réseau locale", "available": self.config.get("network_security_enabled", True),
                 "reason": "Sockets OS échantillonnés ; baseline par exécutable/utilisateur/destination/service. Aucune capture paquet ni inspection TLS."},
                {"name": "Blocage d'une destination interdite", "available": bool(self.config.get("denied_remote_ips")),
                 "reason": "Politique locale explicite, preuve récente, autorisation de cible et pare-feu pris en charge requis ; une anomalie seule reste une alerte."}]

    def status(self):
        with self._lock:
            return {**self._status, "enabled": self.config.get("network_security_enabled", True),
                    "baseline_count": len(self._state["baseline"]), "recent_contacts": len(self._state["contacts"]),
                    "window_seconds": self.config.get("network_window_seconds", 300),
                    "denied_destinations": len(self.config.get("denied_remote_ips", []))}

    def _allow_notice(self, key, now, delay=60):
        if now - self._state["notices"].get(key, -1e30) < delay:
            return False
        self._state["notices"][key] = now
        self._state["notices"] = dict(sorted(self._state["notices"].items(), key=lambda x: x[1])[-512:])
        return True

    def sample(self, snapshot):
        with self._lock:
            return self._sample(snapshot)

    def _sample(self, snapshot):
        if not self.config.get("network_security_enabled", True):
            self._status["coverage"] = "disabled"
            return []
        coverage = snapshot.get("coverage", {})
        if coverage.get("network_source") != "psutil.net_connections" or coverage.get("network_access_denied"):
            self._status["coverage"] = "unavailable_or_unattributed"
            return []
        now = time.time()
        try:
            observed = datetime.fromisoformat(snapshot["sampled_at"].replace("Z", "+00:00"))
            at = observed.timestamp()
            if observed.tzinfo is None or not 0 <= now - at <= 30:
                raise ValueError
        except (KeyError, ValueError, TypeError, AttributeError):
            self._status["coverage"] = "stale_snapshot"
            return []
        window = min(3600, max(30, int(self.config.get("network_window_seconds", 300))))
        state = self._state
        state["contacts"] = [c for c in state["contacts"] if 0 <= now - c["at"] <= window]
        events, current = [], set()
        previous = set(state["current"])
        initialized = state["initialized"]
        denied = {str(ipaddress.ip_address(value)) for value in self.config.get("denied_remote_ips", [])}
        for row in snapshot.get("connections", [])[:400]:
            try:
                ip = str(ipaddress.ip_address(row["remote_ip"]))
                port = row["remote_port"]
                if type(port) is not int or not 1 <= port <= 65535 or not row.get("remote"):
                    continue
                if ipaddress.ip_address(ip).is_multicast or ipaddress.ip_address(ip).is_unspecified:
                    continue
            except (KeyError, ValueError, TypeError):
                continue
            identity = {key: row.get(key) for key in ("pid", "create_time", "exe", "username")}
            # PID reuse cannot share a process sequence. Missing process metadata
            # means correlation is unavailable, not that all unknown sockets match.
            attributed = (type(identity["pid"]) is int and bool(identity["exe"])
                          and bool(identity["username"]) and bool(identity["create_time"]))
            group = _digest(identity) if attributed else None
            protocol = row.get("protocol", "unknown")
            socket_key = _digest([identity, row.get("local"), ip, port, protocol])
            current.add(socket_key)
            baseline_key = _digest([identity["exe"], identity["username"], ip, port, protocol])
            fresh = socket_key not in previous
            evidence_id = _digest([socket_key, snapshot["sampled_at"]])
            detail = {**identity, "remote_ip": ip, "remote_port": port, "local": row.get("local"),
                      "protocol": protocol, "socket_status": row.get("status"), "observed_at": snapshot["sampled_at"],
                      "verification_origin": "local_psutil_socket", "verified_local": True,
                      "process_attributed": attributed, "malware_proven": False, "evidence_ids": [evidence_id]}
            if ip in denied and self._allow_notice("denied:" + ip, now):
                events.append({"kind": "network_policy_violation", "timestamp": _stamp(now), "severity": "critical",
                               "summary": "Communication observée avec une destination interdite par votre politique",
                               "details": {**detail, "policy_rule": "denied_remote_ips", "policy_value": ip,
                                           "policy_violation": True}})
            if initialized and fresh and baseline_key not in state["baseline"] and self._allow_notice("baseline:" + baseline_key, now):
                events.append({"kind": "network_baseline_change", "timestamp": _stamp(now), "severity": "info",
                               "summary": "Nouvelle combinaison processus, utilisateur et service réseau observée",
                               "details": {**detail, "suspicious": False}})
            state["baseline"][baseline_key] = now
            if initialized and fresh and group:
                state["contacts"].append({"at": now, "group": group, "ip": ip, "port": port, "id": evidence_id})
                recent = [c for c in state["contacts"] if c["group"] == group]
                same_host = [c for c in recent if c["ip"] == ip]
                patterns = [("network_port_scan", same_host, len({c["port"] for c in same_host}),
                             int(self.config.get("network_port_scan_threshold", 8)), group + ip,
                             "Contacts répétés sur plusieurs ports : exploration possible à examiner"),
                            ("network_fanout", recent, len({c["ip"] for c in recent}),
                             int(self.config.get("network_fanout_threshold", 12)), group,
                             "Un processus contacte de nombreuses destinations : activité à examiner")]
                for kind, evidence, distinct, threshold, key, summary in patterns:
                    if distinct >= max(3, threshold) and self._allow_notice(kind + key, now, window):
                        events.append({"kind": kind, "timestamp": _stamp(now), "severity": "warning", "summary": summary,
                                       "details": {**detail, "distinct_count": distinct, "window_seconds": window,
                                                   "evidence_ids": [c["id"] for c in evidence][-100:],
                                                   "automatic_block_eligible": False,
                                                   "uncertainty": "Un scan autorisé ou un logiciel légitime peut produire ce motif ; direction d'initiative non établie."}})
        state["current"] = sorted(current | previous if coverage.get("connections_truncated") else current)[-4096:]
        state["baseline"] = dict(sorted(state["baseline"].items(), key=lambda x: x[1])[-MAX_BASELINE:])
        state["contacts"] = state["contacts"][-MAX_CONTACTS:]
        state["initialized"] = True
        # Keep actionable policy violations ahead of informational discovery events.
        events.sort(key=lambda event: {"critical": 0, "warning": 1, "info": 2}[event["severity"]])
        self._status = {"coverage": "partial" if coverage.get("connections_truncated") else "sampled_sockets_only",
                        "last_sample": snapshot["sampled_at"], "new_events": min(64, len(events)),
                        "events_truncated": len(events) > 64}
        _save(self.path, state)
        return events[:64]
