"""Observe selected path permissions and OpenLDAP stats logs, without changing IAM.

Text log provenance is not authenticated, even on root-owned files. LDAP events
are investigative leads only. Raw lines, passwords and attribute values are never
retained; directory names are represented by stable hashes in local evidence.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import re
import stat
import threading
import time

from .config import private_dir
from .network_security import _digest, _load, _save, _stamp
from .platforms import no_symlink

PREFIX = re.compile(r"^(?:[A-Z][a-z]{2} [ 0-9][0-9] [0-9:]{8}|\d{4}-\d{2}-\d{2}T[^\s]+)\s+\S+\s+slapd\[[0-9]+\]:\s+conn=(\d{1,16}) op=(\d{1,16}) (.+)$")
DN = re.compile(r'^(BIND|MOD) dn="([^"\r\n]{0,1024})"(?: method=\d{1,8})?$')
ATTR = re.compile(r"^MOD attr=([A-Za-z0-9;_ -]{1,512})$")
RESULT = re.compile(r"^RESULT tag=(\d{1,4}) err=(\d{1,4})(?: .*)?$")
WATCHED_ATTRIBUTES = frozenset({"olcaccess", "member", "uniquemember", "memberuid", "gidnumber", "uidnumber", "olcrootdn", "olcrootpw", "userpassword"})


class AccessMonitor:
    MAX_PATHS = 128
    MAX_LOGS = 16
    MAX_BYTES = 256 * 1024
    MAX_LINES = 256
    MAX_STATE = 2048

    def __init__(self, config, state_dir):
        self.config = dict(config)
        self.path = private_dir(Path(state_dir)) / "access-monitor.json"
        self._lock = threading.RLock()
        self._state = _load(self.path, {"version": 1, "paths": {}, "logs": {}, "operations": {},
                                      "failures": [], "notices": {}})
        self._validate()
        self._status = {"coverage": "not_sampled", "last_sample": None, "access_changes": 0, "ldap_failures": 0}

    def _validate(self):
        state = self._state
        if any(len(state[k]) > self.MAX_STATE for k in ("paths", "logs", "operations", "failures", "notices")):
            raise ValueError("Historique des accès hors limite.")
        for row in state["paths"].values():
            if not isinstance(row, dict) or not all(type(row.get(k)) is int for k in ("mode", "uid", "gid", "inode", "device")):
                raise ValueError("Métadonnées des accès invalides.")
        for row in state["logs"].values():
            if not isinstance(row, dict) or type(row.get("offset")) is not int or row["offset"] < 0 or not isinstance(row.get("identity"), list):
                raise ValueError("Curseur LDAP invalide.")
        for row in [*state["operations"].values(), *state["failures"]]:
            if not isinstance(row, dict) or type(row.get("at")) not in {int, float} or not math.isfinite(row["at"]):
                raise ValueError("Fenêtre LDAP invalide.")
        if any(type(v) not in {int, float} or not math.isfinite(v) for v in state["notices"].values()):
            raise ValueError("État des alertes invalide.")

    def update_config(self, config):
        with self._lock:
            self.config = dict(config)
            allowed = set(config.get("access_monitor_paths", [])[:self.MAX_PATHS])
            self._state["paths"] = {k: v for k, v in self._state["paths"].items() if k in allowed}
            logs = set(config.get("ldap_log_paths", [])[:self.MAX_LOGS])
            self._state["logs"] = {k: v for k, v in self._state["logs"].items() if k in logs}
            # Removed source evidence must not keep contributing to new alerts.
            self._state["operations"] = {k: v for k, v in self._state["operations"].items() if v.get("source") in logs}
            self._state["failures"] = [v for v in self._state["failures"] if v.get("source") in logs]
            _save(self.path, self._state)

    def capabilities(self):
        return [{"name": "Permissions et propriétaires des chemins sélectionnés", "available": bool(self.config.get("access_monitor_paths")),
                 "reason": "Métadonnées des chemins explicites, sans parcours récursif ni attribution du changement à son auteur. Windows : bits stat limités, DACL non décodées."},
                {"name": "OpenLDAP — authentification et changements d'accès", "available": bool(self.config.get("ldap_log_paths")),
                 "reason": "Journaux stats slapd configurés : BIND/RESULT et MOD d'attributs d'accès. Sources texte non authentifiées, alertes uniquement ; aucune écriture LDAP."}]

    def status(self):
        with self._lock:
            return {**self._status, "paths": len(self.config.get("access_monitor_paths", [])),
                    "log_sources": len(self.config.get("ldap_log_paths", [])),
                    "ldap_window_seconds": self.config.get("ldap_window_seconds", 300),
                    "source_trust": "OpenLDAP text is untrusted; no automatic IAM changes"}

    def _notice(self, key, delay=60):
        now = time.time()
        if now - self._state["notices"].get(key, -1e30) < delay:
            return False
        self._state["notices"][key] = now
        self._state["notices"] = dict(sorted(self._state["notices"].items(), key=lambda v: v[1])[-512:])
        return True

    def _gap(self, source, reason):
        if not self._notice("gap:" + source + reason):
            return []
        return [{"kind": "access_sensor_gap", "timestamp": _stamp(), "severity": "warning",
                 "summary": "Couverture de surveillance des accès à vérifier", "details": {
                     "source": source, "reason": reason, "verified_local": False, "automatic_block_eligible": False}}]

    def _paths(self):
        events = []
        for source in self.config.get("access_monitor_paths", [])[:self.MAX_PATHS]:
            try:
                path = Path(source).expanduser().absolute()
                if not no_symlink(path):
                    raise ValueError
                info = path.lstat()
                value = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                         "inode": info.st_ino, "device": info.st_dev}
                old = self._state["paths"].get(source)
                self._state["paths"][source] = value
                if old and old != value:
                    events.append({"kind": "access_permission_changed", "timestamp": _stamp(), "severity": "warning",
                                   "summary": "Permissions, propriétaire ou identité d'un chemin modifiés",
                                   "details": {"path": str(path), "before": old, "after": value,
                                               "verification_origin": "local_stat", "verified_local": True,
                                               "actor_attributed": False, "automatic_block_eligible": False,
                                               "uncertainty": "Un changement peut être autorisé. Le propriétaire courant n'est pas la preuve de l'auteur."}})
            except (OSError, ValueError):
                events.extend(self._gap(source, "path_unavailable_or_symlink"))
        return events

    def _parse(self, source, line, evidence_id):
        match = PREFIX.fullmatch(line)
        if not match:
            return []
        connection, operation, message = match.groups()
        key = _digest([source, connection, operation])
        now = time.time()
        dn = DN.fullmatch(message)
        if dn:
            kind, value = dn.groups()
            self._state["operations"][key] = {"at": now, "source": source, "operation": kind,
                                              "subject_hash": hashlib.sha256(value.encode()).hexdigest(), "attributes": []}
            return []
        attrs = ATTR.fullmatch(message)
        if attrs:
            item = self._state["operations"].get(key)
            if item and item["operation"] == "MOD":
                item["attributes"] = sorted({v.lower() for v in attrs[1].split()} & WATCHED_ATTRIBUTES)
            return []
        result = RESULT.fullmatch(message)
        if not result:
            return []
        tag, error = map(int, result.groups())
        item = self._state["operations"].pop(key, None)
        if not item:
            return []
        details = {"source": source, "source_kind": "openldap_stats_text", "verification_origin": "untrusted_ldap_text",
                   "verified_local": False, "actor_attributed": False, "automatic_block_eligible": False,
                   "evidence_ids": [evidence_id], "subject_hash": item["subject_hash"], "result_code": error,
                   "time_basis": "local_receipt_time", "observed_at": _stamp(now)}
        if tag == 97 and error == 49 and item["operation"] == "BIND":
            if any(f["id"] == evidence_id for f in self._state["failures"]):
                return []
            self._state["failures"].append({"at": now, "source": source, "subject_hash": item["subject_hash"], "id": evidence_id})
            threshold = max(3, int(self.config.get("ldap_failure_threshold", 5)))
            failures = [f for f in self._state["failures"] if f["source"] == source and f["subject_hash"] == item["subject_hash"]]
            if len(failures) >= threshold and self._notice("ldap:" + source + item["subject_hash"], self.config.get("ldap_window_seconds", 300)):
                return [{"kind": "ldap_auth_burst", "timestamp": _stamp(now), "severity": "warning",
                         "summary": "Échecs d'authentification OpenLDAP répétés : vérifier la source",
                         "details": {**details, "failure_count": len(failures), "window_seconds": self.config.get("ldap_window_seconds", 300),
                                     "evidence_ids": [f["id"] for f in failures][-100:]}}]
        if tag == 103 and item["operation"] == "MOD" and item["attributes"]:
            return [{"kind": "ldap_access_change", "timestamp": _stamp(now), "severity": "warning",
                     "summary": "Le journal OpenLDAP rapporte une modification d'attributs d'accès" if error == 0 else "Le journal OpenLDAP rapporte une tentative de modification refusée",
                     "details": {**details, "attributes": item["attributes"], "operation_result": "reported_success" if error == 0 else "reported_failure",
                                 "uncertainty": "Écriture de journal non authentifiée ; contrôler l'annuaire et le mandat avant toute intervention."}}]
        return []

    def _tail(self, source):
        events = []
        path = Path(source).expanduser().absolute()
        try:
            if not no_symlink(path):
                raise ValueError
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError
                identity = [info.st_dev, info.st_ino]
                cursor = self._state["logs"].get(source)
                def checkpoint(offset):
                    stream.seek(max(0, offset - 64))
                    anchor = hashlib.sha256(stream.read(min(offset, 64))).hexdigest()
                    self._state["logs"][source] = {"offset": offset, "identity": identity, "anchor": anchor}
                if cursor is None:
                    checkpoint(info.st_size)
                    return []
                offset = cursor["offset"]
                stream.seek(max(0, offset - 64))
                anchor = hashlib.sha256(stream.read(min(offset, 64))).hexdigest()
                if identity != cursor["identity"] or info.st_size < offset or anchor != cursor.get("anchor"):
                    offset = 0
                    events.extend(self._gap(source, "log_rotation_or_truncation"))
                    self._state["operations"] = {k: v for k, v in self._state["operations"].items() if v["source"] != source}
                stream.seek(offset)
                data = stream.read(self.MAX_BYTES + 1)
                clipped = len(data) > self.MAX_BYTES
                data = data[:self.MAX_BYTES]
                # Split only real line delimiters. Embedded CR is rejected below
                # instead of pinning the cursor or creating a second log record.
                fragments = data.split(b"\n")
                lines = [part + b"\n" for part in fragments[:-1]]
                if fragments[-1]:
                    lines.append(fragments[-1])
                consumed = 0
                for line in lines[:self.MAX_LINES]:
                    if not line.endswith(b"\n"):
                        if clipped and len(line) > 8192:
                            consumed += len(line)
                            events.extend(self._gap(source, "oversized_line"))
                        break
                    position = offset + consumed
                    consumed += len(line)
                    if len(line) > 8192:
                        events.extend(self._gap(source, "oversized_line"))
                        continue
                    text = line.decode("utf-8", errors="replace").removesuffix("\n").removesuffix("\r")
                    if "\r" in text or "\n" in text:
                        continue
                    evidence_id = hashlib.sha256((source + str(identity) + str(position)).encode() + line).hexdigest()
                    events.extend(self._parse(source, text, evidence_id))
                checkpoint(offset + consumed)
                if clipped or len(lines) > self.MAX_LINES:
                    events.extend(self._gap(source, "bounded_backlog"))
        except (OSError, ValueError, KeyError, TypeError):
            events.extend(self._gap(source, "log_unavailable_or_not_regular"))
        return events

    def sample(self):
        with self._lock:
            now = time.time()
            window = min(3600, max(30, int(self.config.get("ldap_window_seconds", 300))))
            self._state["failures"] = [f for f in self._state["failures"] if 0 <= now - f["at"] <= window]
            self._state["operations"] = {k: v for k, v in self._state["operations"].items() if 0 <= now - v["at"] <= window}
            events = self._paths()
            for source in self.config.get("ldap_log_paths", [])[:self.MAX_LOGS]:
                events.extend(self._tail(source))
            self._state["failures"] = self._state["failures"][-self.MAX_STATE:]
            self._state["operations"] = dict(sorted(self._state["operations"].items(), key=lambda p: p[1]["at"])[-self.MAX_STATE:])
            self._status = {"coverage": "partial" if any(e["kind"] == "access_sensor_gap" for e in events) else "configured_paths_and_logs_only",
                            "last_sample": _stamp(), "access_changes": sum(e["kind"] == "access_permission_changed" for e in events),
                            "ldap_failures": len(self._state["failures"]), "events_truncated": len(events) > 64}
            _save(self.path, self._state)
            return events[:64]
