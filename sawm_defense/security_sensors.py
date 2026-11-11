"""Read-only SSH/authentication observations with explicit provenance.

A root-owned text log is not proof of its producer: syslog tags can be forged.
Only journald's protected metadata from a protected native reader and sshd
executable can make a burst eligible for the local response policy.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time

from .config import private_dir

MAX_LINES = 256
MAX_READ_BYTES = 256 * 1024
MAX_LINE_BYTES = 8192
MAX_SOURCE_PATHS = 16
MAX_SEEN = 4096
MAX_FAILURES = 4096
SSHD_EXECUTABLES = frozenset({"/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session", "/usr/libexec/sshd-session", "/usr/sbin/sshd-session"})
SSH_FAILURE = re.compile(r"^Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?[^\s]{1,256} from (?P<ip>[0-9a-fA-F:.]{2,64}) port (?P<port>[0-9]{1,5}) ssh2(?: \[preauth\])?$")
SYSLOG_SSH = re.compile(r"^(?P<stamp>(?:[A-Z][a-z]{2} [ 0-9][0-9] [0-9:]{8})|(?:\d{4}-\d{2}-\d{2}T[^\s]+))\s+[^\s]+\s+sshd(?:-session)?\[[0-9]+\]:\s+(?P<message>.*)$")


def _now_iso(timestamp=None):
    return datetime.fromtimestamp(time.time() if timestamp is None else timestamp, timezone.utc).isoformat()


def _protected_native_file(path):
    """Resolve normal OS aliases (/var -> /private/var), reject writable ancestry."""
    try:
        original = Path(path)
        if original.is_symlink():
            return False
        resolved = original.resolve(strict=True)
        if not resolved.is_file() or os.name == "nt":
            return False
        for item in (resolved, *resolved.parents):
            info = item.stat()
            if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        return True
    except (OSError, ValueError):
        return False


def _failure(message):
    if not isinstance(message, str) or len(message) > MAX_LINE_BYTES or "\n" in message or "\r" in message:
        return None
    match = SSH_FAILURE.fullmatch(message)
    if not match:
        return None
    try:
        address = ipaddress.ip_address(match.group("ip"))
        port = int(match.group("port"))
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast or not 1 <= port <= 65535:
        return None
    return str(address)


class Sensor:
    def __init__(self, config, state_dir):
        self.state_dir = private_dir(Path(state_dir))
        self.path = self.state_dir / "security-sensors.json"
        self._lock = threading.RLock()
        self.config = dict(config)
        self._journal_status = "disabled"
        self._state = self._load()
        self._errors = {}

    def _load(self):
        empty = {"version": 1, "files": {}, "seen": [], "failures": [], "alerts": {}, "journal_cursor": None}
        if self.path.is_symlink():
            raise ValueError("Le curseur de surveillance ne doit pas être un lien.")
        if not self.path.exists():
            return empty
        try:
            if self.path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if value.get("version") != 1 or not isinstance(value.get("files"), dict):
                raise ValueError
            for key, kind in (("seen", list), ("failures", list), ("alerts", dict)):
                if not isinstance(value.get(key), kind):
                    raise ValueError
            if len(value["seen"]) > MAX_SEEN or len(value["failures"]) > MAX_FAILURES:
                raise ValueError
            if any(not isinstance(item, str) for item in value["seen"]):
                raise ValueError
            for row in value["failures"]:
                if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                        or not isinstance(row.get("source"), str) or type(row.get("trusted")) is not bool
                        or not isinstance(row.get("producer"), dict)
                        or type(row.get("timestamp")) not in {int, float} or not math.isfinite(row["timestamp"])):
                    raise ValueError
                ipaddress.ip_address(row["ip"])
            for row in value["files"].values():
                if not isinstance(row, dict) or type(row.get("offset")) is not int or row["offset"] < 0 or not isinstance(row.get("identity"), list):
                    raise ValueError
            for row in value["alerts"].values():
                if not isinstance(row, dict) or type(row.get("at")) not in {int, float} or not math.isfinite(row["at"]):
                    raise ValueError
            empty.update(value)
            return empty
        except (OSError, ValueError, TypeError, AttributeError, KeyError):
            # Never discard an unreadable cursor silently and replay historic
            # observations as new. Owner must explicitly repair the state.
            raise ValueError("Curseur de surveillance invalide ; reprise automatique refusée.") from None

    def _save(self):
        if self.path.is_symlink():
            raise ValueError("Curseur remplacé par un lien ; écriture refusée.")
        fd, temporary = tempfile.mkstemp(prefix=".security-", dir=self.state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(self._state, out, ensure_ascii=False, separators=(",", ":"))
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def update_config(self, config):
        with self._lock:
            previous = self.config
            self.config = dict(config)
            # A new source starts from its current end. Changes do not replay
            # revoked sources and never promote plain text to trusted evidence.
            active = set(self.config.get("auth_log_paths", [])[:MAX_SOURCE_PATHS])
            self._state["files"] = {p: row for p, row in self._state["files"].items() if p in active}
            if previous.get("auth_journal_enabled") and not self.config.get("auth_journal_enabled"):
                self._state["failures"] = [f for f in self._state["failures"] if f.get("source") != "journald"]
            self._save()

    def capabilities(self):
        paths = self.config.get("auth_log_paths", [])
        journal = bool(self.config.get("auth_journal_enabled"))
        available = platform.system() == "Linux" and bool(shutil.which("journalctl"))
        return [
            {"name": "Échecs SSH — journald", "available": available and journal and self._journal_status == "ok",
             "reason": "Métadonnées journald de sshd vérifiées ; fenêtre et seuil bornés." if self._journal_status == "ok" else "Activer journald et accorder la lecture du journal système Linux. État : " + self._journal_status},
            {"name": "Journaux texte d'authentification", "available": bool(paths),
             "reason": "Sources configurées, lecture bornée. Un tag syslog est falsifiable : indices pour alerte, jamais preuve d'autoblocage."},
            {"name": "Windows Security Event Log", "available": False,
             "reason": "Collecteur natif Event Log non implémenté dans cette version."},
            {"name": "Intrusions réseau exhaustives", "available": False,
             "reason": "Ce capteur détecte des échecs SSH répétés ; ce n'est pas une capture de tous les paquets ni un IDS universel."},
        ]

    def _issue(self, source, code, summary):
        now = time.time()
        key = source + ":" + code
        if now - self._errors.get(key, 0) < 60:
            return None
        self._errors[key] = now
        return {"kind": "security_sensor_gap", "severity": "warning", "summary": summary,
                "details": {"source": source, "reason": code, "verified_local": False}}

    def _record(self, identifier, ip, timestamp, source, trusted, producer=None):
        if identifier in self._state["seen"]:
            return False
        self._state["seen"].append(identifier)
        self._state["seen"] = self._state["seen"][-MAX_SEEN:]
        self._state["failures"].append({"id": identifier, "ip": ip, "timestamp": timestamp,
                                         "source": source, "trusted": bool(trusted), "producer": producer or {}})
        self._state["failures"] = self._state["failures"][-MAX_FAILURES:]
        return True

    def _tail_text(self, source):
        events = []
        path = Path(source).expanduser()
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as stream:
                st = os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError
                identity = [st.st_dev, st.st_ino]
                cursor = self._state["files"].get(source)
                def checkpoint(position):
                    stream.seek(max(0, position - 64))
                    anchor = hashlib.sha256(stream.read(min(position, 64))).hexdigest()
                    self._state["files"][source] = {"identity": identity, "offset": position, "anchor": anchor}
                if cursor is None:
                    checkpoint(st.st_size)
                    return events
                offset = int(cursor["offset"])
                stream.seek(max(0, offset - 64))
                anchor = hashlib.sha256(stream.read(min(offset, 64))).hexdigest()
                if cursor["identity"] != identity or st.st_size < offset or (cursor.get("anchor") and cursor["anchor"] != anchor):
                    issue = self._issue(source, "rotation_or_truncation", "Rotation ou troncature du journal ; couverture à vérifier.")
                    if issue:
                        events.append(issue)
                    offset = 0
                stream.seek(offset)
                data = stream.read(MAX_READ_BYTES + 1)
                clipped = len(data) > MAX_READ_BYTES
                data = data[:MAX_READ_BYTES]
                last_newline = data.rfind(b"\n")
                if last_newline < 0:
                    if clipped:
                        offset += len(data)
                        issue = self._issue(source, "oversized_line", "Ligne de journal trop longue ; ignorée.")
                        if issue:
                            events.append(issue)
                    checkpoint(offset)
                    return events
                complete = data[:last_newline + 1]
                for line in complete.splitlines(keepends=True):
                    position = offset
                    offset += len(line)
                    if len(line) > MAX_LINE_BYTES:
                        continue
                    # Windows-exported logs use CRLF. Remove only one terminal
                    # line delimiter; _failure still rejects embedded CR/LF.
                    text = line.decode("utf-8", errors="replace").removesuffix("\n").removesuffix("\r")
                    match = SYSLOG_SSH.fullmatch(text)
                    if not match:
                        continue
                    ip = _failure(match.group("message"))
                    if not ip:
                        continue
                    identifier = hashlib.sha256((source + str(identity) + str(position)).encode() + line).hexdigest()
                    # Receipt time is explicit for plain logs; their timestamps
                    # and process tags are not trusted to authorize intervention.
                    self._record(identifier, ip, time.time(), source, False)
                checkpoint(offset)
                if clipped:
                    issue = self._issue(source, "read_limit", "Rattrapage du journal en plusieurs passages ; lecture bornée.")
                    if issue:
                        events.append(issue)
        except (OSError, ValueError, KeyError, TypeError):
            issue = self._issue(source, "unreadable", "Journal d'authentification indisponible ou non ordinaire.")
            if issue:
                events.append(issue)
        return events

    @staticmethod
    def _trusted_fields(row):
        exe = row.get("_EXE")
        return (row.get("_UID") == "0" and row.get("_COMM") in {"sshd", "sshd-session"}
                and row.get("_TRANSPORT") == "syslog" and exe in SSHD_EXECUTABLES
                and _protected_native_file(exe))

    @staticmethod
    def _run_journal(cmd):
        # Bound stdout while the process runs: a single journal entry must not
        # allocate unbounded memory, even with --lines limiting record count.
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"})
        result = []
        def read():
            result.append(process.stdout.read(MAX_READ_BYTES + 1))
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        reader.join(timeout=5)
        if reader.is_alive():
            process.kill()
            process.wait(timeout=2)
            reader.join(timeout=1)
            process.stdout.close()
            raise subprocess.TimeoutExpired(cmd, 5)
        data = result[0] if result else b""
        if len(data) > MAX_READ_BYTES:
            process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
            raise
        finally:
            process.stdout.close()
        return subprocess.CompletedProcess(cmd, process.returncode, data.decode("utf-8", errors="replace"), "")

    def _journal(self):
        events = []
        executable = shutil.which("journalctl")
        if platform.system() != "Linux" or not executable or not _protected_native_file(executable):
            self._journal_status = "unavailable_or_untrusted_reader"
            issue = self._issue("journald", self._journal_status, "Lecteur journald système indisponible ou non vérifiable.")
            return [issue] if issue else []
        cmd = [executable, "--no-pager", "--output=json", "--quiet", "--lines=" + str(MAX_LINES),
               "--output-fields=MESSAGE,_PID,_UID,_COMM,_EXE,_TRANSPORT,__REALTIME_TIMESTAMP,__CURSOR",
               "_UID=0", "_COMM=sshd", "_COMM=sshd-session"]
        cursor = self._state.get("journal_cursor")
        if isinstance(cursor, str) and re.fullmatch(r"[A-Za-z0-9;=_:\-]{1,512}", cursor):
            cmd.append("--after-cursor=" + cursor)
        else:
            cmd.append("--since=@" + str(int(time.time() - self._window())))
        try:
            completed = self._run_journal(cmd)
            if len(completed.stdout.encode()) > MAX_READ_BYTES:
                self._journal_status = "read_limit"
                issue = self._issue("journald", "read_limit", "Volume du journal au-delà du budget ; aucune intervention autorisée sur ce passage.")
                return [issue] if issue else []
            if completed.returncode:
                self._journal_status = "permission_or_cursor_error"
                # A vacuumed cursor is not silently reset; the gap remains visible.
                issue = self._issue("journald", self._journal_status, "Journal système inaccessible ou curseur expiré ; couverture incomplète.")
                return [issue] if issue else []
            lines = completed.stdout.splitlines()
            if len(lines) >= MAX_LINES:
                issue = self._issue("journald", "backlog_may_be_truncated", "Journal intense : la fenêtre retournée peut omettre des événements ; couverture à vérifier.")
                if issue:
                    events.append(issue)
            for raw in lines:
                try:
                    row = json.loads(raw)
                    entry_cursor = row.get("__CURSOR")
                    if not isinstance(entry_cursor, str) or not re.fullmatch(r"[A-Za-z0-9;=_:\-]{1,512}", entry_cursor):
                        continue
                    timestamp = int(row["__REALTIME_TIMESTAMP"]) / 1_000_000
                    if timestamp > time.time() + 5 or timestamp < time.time() - self._window():
                        self._state["journal_cursor"] = entry_cursor
                        continue
                    ip = _failure(row.get("MESSAGE"))
                    if ip:
                        identifier = hashlib.sha256(("journald:" + entry_cursor).encode()).hexdigest()
                        producer = {k: row.get(k) for k in ("_PID", "_UID", "_COMM", "_EXE", "_TRANSPORT")}
                        self._record(identifier, ip, timestamp, "journald", self._trusted_fields(row), producer)
                    self._state["journal_cursor"] = entry_cursor
                except (ValueError, TypeError, KeyError, AttributeError):
                    continue
            self._journal_status = "ok"
            return events
        except (OSError, subprocess.TimeoutExpired):
            self._journal_status = "unavailable"
            issue = self._issue("journald", "unavailable", "Lecture du journal système non terminée.")
            return [issue] if issue else []

    def _window(self):
        return min(3600, max(30, int(self.config.get("auth_window_seconds", 300))))

    def sample(self):
        with self._lock:
            now = time.time()
            events = []
            for source in self.config.get("auth_log_paths", [])[:MAX_SOURCE_PATHS]:
                events.extend(self._tail_text(source))
            if self.config.get("auth_journal_enabled", False):
                events.extend(self._journal())
            cutoff = now - self._window()
            self._state["failures"] = [row for row in self._state["failures"] if cutoff <= row.get("timestamp", 0) <= now + 5]
            groups = {}
            for row in self._state["failures"]:
                # Plain log copies never inflate the verified system count.
                key = (row["ip"], bool(row["trusted"]))
                groups.setdefault(key, []).append(row)
            threshold = min(100, max(3, int(self.config.get("auth_failure_threshold", 5))))
            for (ip, trusted), rows in groups.items():
                if len(rows) < threshold:
                    continue
                key = ip + ":" + str(trusted)
                last = self._state["alerts"].get(key, {})
                if now - last.get("at", 0) < self._window():
                    continue
                self._state["alerts"][key] = {"at": now}
                newest = max(rows, key=lambda row: row["timestamp"])
                sources = sorted({row["source"] for row in rows})
                events.append({"kind": "auth_bruteforce", "severity": "warning",
                               "timestamp": _now_iso(newest["timestamp"]),
                               "summary": "Échecs SSH répétés depuis une même adresse" + (" (source système vérifiée)." if trusted else " (source à confirmer)."),
                               "details": {"remote_ip": ip, "failure_count": len(rows), "window_seconds": self._window(),
                                           "threshold": threshold, "verified_local": trusted,
                                           "verification_origin": "local_journald" if trusted else "untrusted_auth_text",
                                           "source_kind": "journald" if sources == ["journald"] else "auth_log_text",
                                           "sources": sources, "evidence_ids": [row["id"] for row in rows][-100:],
                                           "first_failure_at": _now_iso(min(row["timestamp"] for row in rows)),
                                           "last_failure_at": _now_iso(newest["timestamp"]), "producer": newest["producer"],
                                           "attacker_identity_known": False,
                                           "protected_remote_ip": ip in self.config.get("protected_remote_ips", [])}})
            self._state["alerts"] = {key: row for key, row in self._state["alerts"].items() if row.get("at", 0) >= now - 86400}
            self._save()
            return events
