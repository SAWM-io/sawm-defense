"""Persistent local alert inbox plus bounded desktop notification attempts.

Submission to the operating system is recorded truthfully; it is not proof that
an alert was displayed or read (Do Not Disturb, a locked session, or notification
permissions can suppress it). Nothing is sent to email, a webhook or a third party.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid

from .config import private_dir


_MAC_SCRIPT = '''on run argv
    display notification (item 2 of argv) with title (item 1 of argv)
end run'''
_WINDOWS_SCRIPT = r'''$ErrorActionPreference = 'Stop'
try {
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
  $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
  $xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>SAWM Defense</text><text /></binding></visual></toast>')
  $node = $xml.SelectSingleNode('//binding/text[2]')
  [void] $node.AppendChild($xml.CreateTextNode($env:SAWM_NOTIFICATION_BODY))
  $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('SAWM Defense').Show($toast)
  exit 0
} catch { exit 1 }
'''


def _iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def _text(value, length):
    if not isinstance(value, str):
        raise ValueError("Une notification exige un texte.")
    return value.replace("\x00", "").replace("\r", " ").replace("\n", " ")[:length]


class NotificationCenter:
    def __init__(self, state_dir, *, cooldown_seconds=60, per_minute=10, clock=None):
        if type(cooldown_seconds) is not int or not 1 <= cooldown_seconds <= 3600:
            raise ValueError("Délai de notification invalide.")
        if type(per_minute) is not int or not 1 <= per_minute <= 60:
            raise ValueError("Budget de notification invalide.")
        self.state_dir = private_dir(Path(state_dir))
        self.path = self.state_dir / "notifications.sqlite3"
        for suffix in ("", "-wal", "-shm"):
            if Path(str(self.path) + suffix).is_symlink():
                raise ValueError("La boîte d'alertes ne doit pas être un lien symbolique.")
        if not self.path.exists():
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        if os.name != "nt":
            self.path.chmod(0o600)
        self._clock = clock or time.time
        self._cooldown = cooldown_seconds
        self._per_minute = per_minute
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS notifications (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
              event_id TEXT UNIQUE NOT NULL, created REAL NOT NULL,
              kind TEXT NOT NULL, severity TEXT NOT NULL, summary TEXT NOT NULL,
              fingerprint TEXT NOT NULL, delivery TEXT NOT NULL, delivery_reason TEXT NOT NULL,
              acknowledged INTEGER NOT NULL DEFAULT 0, acknowledged_at REAL,
              suppressed_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS notification_fingerprint ON notifications(fingerprint,created);
            CREATE TABLE IF NOT EXISTS notification_attempts (created REAL NOT NULL);
        """)
        self._db.commit()

    @staticmethod
    def _row(row, *, deduplicated=False):
        if row is None:
            return None
        return {"id": row["id"], "event_id": row["event_id"], "timestamp": _iso(row["created"]),
                "kind": row["kind"], "severity": row["severity"], "summary": row["summary"],
                "status": "recorded", "delivery": row["delivery"], "delivery_reason": row["delivery_reason"],
                "acknowledged": bool(row["acknowledged"]),
                "acknowledged_at": _iso(row["acknowledged_at"]) if row["acknowledged_at"] else None,
                "suppressed_count": row["suppressed_count"], "deduplicated": deduplicated,
                "display_verified": False}

    def capabilities(self):
        system = platform.system()
        name = "osascript" if system == "Darwin" else "notify-send" if system == "Linux" else "powershell" if system == "Windows" else None
        return {"platform": system, "backend": name, "available": bool(name and shutil.which(name)),
                "inbox_available": True, "display_verified": False,
                "reason": "Une session graphique et l'autorisation des notifications sont nécessaires. La boîte locale conserve les alertes même sans notification système."}

    def publish(self, event, enabled=True):
        if not isinstance(event, dict) or type(enabled) is not bool:
            raise ValueError("Observation de notification invalide.")
        identifier = event.get("id")
        if not isinstance(identifier, str) or not 1 <= len(identifier) <= 160 or any(c in identifier for c in "\r\n\x00"):
            raise ValueError("Une notification exige l'identifiant stable de son observation.")
        kind = _text(event.get("kind", "observation"), 80)
        summary = _text(event.get("summary", "Observation à examiner."), 600)
        severity = event.get("severity", "info")
        if severity not in {"info", "warning", "critical"}:
            raise ValueError("Sévérité de notification invalide.")
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        target = {k: details[k] for k in ("path", "remote_ip", "pid", "resource") if k in details and isinstance(details[k], (str, int))}
        fingerprint = hashlib.sha256(json.dumps([kind, severity, target, summary], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        now = self._clock()
        notify = False
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                old = self._db.execute("SELECT * FROM notifications WHERE event_id=?", (identifier,)).fetchone()
                if old:
                    if (old["kind"], old["severity"], old["summary"], old["fingerprint"]) != (kind, severity, summary, fingerprint):
                        raise ValueError("Une observation déjà notifiée ne peut pas changer de contenu.")
                    self._db.commit()
                    return self._row(old, deduplicated=True)
                previous = self._db.execute("SELECT * FROM notifications WHERE fingerprint=? AND created>? ORDER BY seq DESC LIMIT 1", (fingerprint, now-self._cooldown)).fetchone()
                self._db.execute("DELETE FROM notification_attempts WHERE created<=?", (now-60,))
                attempts = self._db.execute("SELECT COUNT(*) FROM notification_attempts").fetchone()[0]
                if not enabled:
                    delivery, reason = "disabled", "Notifications système désactivées ; alerte conservée."
                elif severity == "info":
                    delivery, reason = "recorded", "Information conservée sans interruption du bureau."
                elif previous:
                    delivery, reason = "suppressed", "Alerte similaire récente ; nouvelle occurrence conservée."
                    self._db.execute("UPDATE notifications SET suppressed_count=suppressed_count+1 WHERE id=?", (previous["id"],))
                elif attempts >= self._per_minute:
                    delivery, reason = "suppressed", "Budget de notifications atteint ; alerte conservée."
                else:
                    delivery, reason = "pending", "Tentative de notification réservée ; affichage non confirmé."
                    notify = True
                    self._db.execute("INSERT INTO notification_attempts VALUES(?)", (now,))
                notification_id = "alert-" + uuid.uuid4().hex
                self._db.execute("INSERT INTO notifications(id,event_id,created,kind,severity,summary,fingerprint,delivery,delivery_reason) VALUES(?,?,?,?,?,?,?,?,?)",
                                 (notification_id, identifier, now, kind, severity, summary, fingerprint, delivery, reason))
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        if notify:
            outcome = self._deliver(summary, severity)
            with self._lock, self._db:
                self._db.execute("UPDATE notifications SET delivery=?,delivery_reason=? WHERE id=?",
                                 (outcome["delivery"], outcome["reason"], notification_id))
        with self._lock:
            return self._row(self._db.execute("SELECT * FROM notifications WHERE id=?", (notification_id,)).fetchone())

    def _deliver(self, summary, severity):
        system = platform.system()
        name = "osascript" if system == "Darwin" else "notify-send" if system == "Linux" else "powershell" if system == "Windows" else None
        executable = shutil.which(name) if name else None
        if executable is None:
            return {"delivery": "unavailable", "reason": "Backend de notification absent ; consulter la boîte d'alertes."}
        env = None
        if system == "Darwin":
            command = [executable, "-e", _MAC_SCRIPT, "--", "SAWM Defense", summary]
        elif system == "Linux":
            command = [executable, "--app-name=SAWM Defense", "--urgency=" + ("critical" if severity == "critical" else "normal"), "--", "SAWM Defense", html.escape(summary)]
        else:
            command = [executable, "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_SCRIPT]
            env = {**os.environ, "SAWM_NOTIFICATION_BODY": summary}
        try:
            result = subprocess.run(command, shell=False, capture_output=True, text=True, timeout=5, env=env)
            if result.returncode == 0:
                return {"delivery": "submitted", "reason": "Notification soumise au système ; affichage et lecture non confirmés."}
            return {"delivery": "error", "reason": "Le système a refusé la notification ; alerte conservée localement."}
        except (OSError, subprocess.TimeoutExpired):
            return {"delivery": "error", "reason": "Notification indisponible ou délai dépassé ; alerte conservée localement."}

    def list(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("Limite entre 1 et 10000 requise.")
        with self._lock:
            rows = self._db.execute("SELECT * FROM notifications ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(row) for row in rows]

    def acknowledge(self, identifier):
        with self._lock, self._db:
            row = self._db.execute("SELECT * FROM notifications WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise ValueError("Alerte inconnue.")
            self._db.execute("UPDATE notifications SET acknowledged=1,acknowledged_at=COALESCE(acknowledged_at,?) WHERE id=?", (self._clock(), identifier))
            return self._row(self._db.execute("SELECT * FROM notifications WHERE id=?", (identifier,)).fetchone())

    def close(self):
        with self._lock:
            self._db.close()
