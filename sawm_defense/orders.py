"""Durable, typed instructions from the local interface.

This queue is not an authentication server: the current OS user is the local
principal. Cloud text, recalled memory and log messages cannot grant rights.
The service must still recheck the current policy immediately before execution.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid

from .config import private_dir


_KINDS = {
    "scan": {"path"}, "inventory": set(), "analyze": {"event_id"},
    "act": {"action", "event_id"}, "restore": {"action_id"}, "report": {"path"},
}
_ACTIONS = {"observe", "quarantine", "terminate", "block_ip"}
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:+/=-]{1,160}\Z")


def _iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def _actor():
    if os.name != "nt":
        import pwd
        uid = os.geteuid()
        return {"username": pwd.getpwuid(uid).pw_name, "uid": uid, "source": "local_os_session"}
    # Do not trust a supplied actor or USERNAME environment variable as identity.
    try:
        import ctypes
        size = ctypes.c_ulong(257)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
            raise OSError("OS identity unavailable")
        return {"username": buffer.value, "uid": None, "source": "local_os_session"}
    except (AttributeError, OSError):
        return {"username": "unavailable", "uid": None, "source": "local_os_session_unavailable"}


def _payload(kind, payload):
    if kind not in _KINDS or not isinstance(payload, dict) or set(payload) != _KINDS[kind]:
        raise ValueError("Ordre inconnu ou paramètres non autorisés.")
    out = dict(payload)
    if "path" in out:
        path = out["path"]
        if not isinstance(path, str) or not path or len(path) > 4096 or any(c in path for c in "\r\n\x00"):
            raise ValueError("Chemin invalide.")
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            raise ValueError("Un chemin absolu est requis.")
        # Keep the named target. Resolution and symlink checks happen at execution.
        out["path"] = str(candidate.absolute())
        if kind == "report" and candidate.suffix.lower() not in {".html", ".json"}:
            raise ValueError("Le rapport doit être HTML ou JSON.")
    for field in ("event_id", "action_id"):
        if field in out and (not isinstance(out[field], str) or not _IDENTIFIER.fullmatch(out[field])):
            raise ValueError("Référence d'observation ou d'action invalide.")
    if kind == "act" and out["action"] not in _ACTIONS:
        raise ValueError("Aucune commande libre ne peut être exécutée.")
    return out


def _result(value):
    """Only safe structured receipts belong in the queue, never raw headers/keys."""
    blocked = {"api_key", "key", "token", "authorization", "headers", "secret", "password", "credential", "credentials", "lease_token"}
    def clean(item, depth=0):
        if depth > 6:
            return "[depth limited]"
        if item is None or isinstance(item, (bool, int, float)):
            return item
        if isinstance(item, str):
            return item[:16000]
        if isinstance(item, dict):
            return {str(k): clean(v, depth + 1) for k, v in list(item.items())[:100]
                    if isinstance(k, str) and k.lower() not in blocked}
        if isinstance(item, (list, tuple)):
            return [clean(v, depth + 1) for v in item[:100]]
        return str(type(item).__name__)
    text = json.dumps(clean(value), ensure_ascii=False, sort_keys=True, allow_nan=False)
    if len(text.encode()) > 131072:
        raise ValueError("Reçu de tâche trop volumineux.")
    return text


class OrderQueue:
    def __init__(self, state_dir, *, clock=None):
        self.state_dir = private_dir(Path(state_dir))
        self.path = self.state_dir / "orders.sqlite3"
        for suffix in ("", "-wal", "-shm"):
            if Path(str(self.path) + suffix).is_symlink():
                raise ValueError("La file d'ordres ne doit pas être un lien symbolique.")
        if not self.path.exists():
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        if os.name != "nt":
            self.path.chmod(0o600)
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS orders (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              id TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
              approved INTEGER NOT NULL, actor TEXT NOT NULL,
              idempotency_key TEXT UNIQUE, status TEXT NOT NULL,
              created REAL NOT NULL, updated REAL NOT NULL, expires REAL NOT NULL,
              lease_token TEXT, lease_until REAL,
              attempts INTEGER NOT NULL DEFAULT 0, result TEXT, error TEXT
            );
            CREATE INDEX IF NOT EXISTS orders_status ON orders(status,seq);
            CREATE TABLE IF NOT EXISTS order_history (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              order_id TEXT NOT NULL, timestamp REAL NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL
            );
        """)
        self._db.commit()

    def _history(self, order_id, stamp, status, reason):
        self._db.execute("INSERT INTO order_history(order_id,timestamp,status,reason) VALUES(?,?,?,?)",
                         (order_id, stamp, status, reason))

    @staticmethod
    def _row(row, *, include_lease=False):
        if row is None:
            return None
        out = {"id": row["id"], "kind": row["kind"], "payload": json.loads(row["payload"]),
               "approved": bool(row["approved"]), "actor": json.loads(row["actor"]),
               "origin": "local_interface", "status": row["status"],
               "created_at": _iso(row["created"]), "updated_at": _iso(row["updated"]),
               "expires_at": _iso(row["expires"]), "attempts": row["attempts"],
               "result": json.loads(row["result"]) if row["result"] else None, "error": row["error"]}
        if include_lease:
            out.update(lease_token=row["lease_token"], lease_expires_at=_iso(row["lease_until"]))
        return out

    @staticmethod
    def _limit(limit):
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("Limite entre 1 et 10000 requise.")
        return limit

    def submit(self, kind, payload, approved=False, idempotency_key=None, actor=None, ttl_seconds=3600):
        payload = _payload(kind, payload)
        if type(approved) is not bool:
            raise ValueError("L'approbation doit être explicite.")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86400:
            raise ValueError("La durée de validité doit être comprise entre 1 et 86400 secondes.")
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not _IDENTIFIER.fullmatch(idempotency_key)):
            raise ValueError("Clé d'idempotence invalide.")
        # actor deliberately ignored: only the OS account is authoritative locally.
        identity = _actor()
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        now = self._clock()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                if idempotency_key:
                    old = self._db.execute("SELECT * FROM orders WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                    if old:
                        if old["kind"] != kind or old["payload"] != encoded or old["approved"] != int(approved) or json.loads(old["actor"]) != identity:
                            raise ValueError("Cette clé d'idempotence désigne déjà un autre ordre.")
                        self._db.commit()
                        return self._row(old)
                identifier = "order-" + uuid.uuid4().hex
                self._db.execute("INSERT INTO orders(id,kind,payload,approved,actor,idempotency_key,status,created,updated,expires) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                 (identifier, kind, encoded, int(approved), json.dumps(identity), idempotency_key, "pending", now, now, now+ttl_seconds))
                self._history(identifier, now, "pending", "Instruction locale enregistrée ; droits à revérifier à l'exécution.")
                row = self._db.execute("SELECT * FROM orders WHERE id=?", (identifier,)).fetchone()
                self._db.commit()
                return self._row(row)
            except Exception:
                self._db.rollback()
                raise

    def _recover(self, now):
        for row in self._db.execute("SELECT * FROM orders WHERE status='running' AND lease_until<=?", (now,)).fetchall():
            if row["kind"] == "inventory" and row["expires"] > now:
                status = "pending"
                reason = "Lecture interrompue : nouvelle tentative permise."
            else:
                status = "needs_review"
                reason = "Exécution interrompue ; effet potentiellement produit, aucune reprise automatique."
            self._db.execute("UPDATE orders SET status=?,updated=?,lease_token=NULL,lease_until=NULL,error=? WHERE id=?",
                             (status, now, reason, row["id"]))
            self._history(row["id"], now, status, reason)
        for row in self._db.execute("SELECT id FROM orders WHERE status='pending' AND expires<=?", (now,)).fetchall():
            reason = "Instruction expirée avant exécution."
            self._db.execute("UPDATE orders SET status='expired',updated=?,error=? WHERE id=?", (now, reason, row["id"]))
            self._history(row["id"], now, "expired", reason)

    def claim(self, lease_seconds=300):
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise ValueError("Bail de tâche invalide.")
        now = self._clock()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._recover(now)
                row = self._db.execute("SELECT * FROM orders WHERE status='pending' ORDER BY seq LIMIT 1").fetchone()
                if row is None:
                    self._db.commit()
                    return None
                token = uuid.uuid4().hex
                self._db.execute("UPDATE orders SET status='running',updated=?,lease_token=?,lease_until=?,attempts=attempts+1 WHERE id=?",
                                 (now, token, now+lease_seconds, row["id"]))
                self._history(row["id"], now, "running", "Tâche prise en charge par le service local.")
                claimed = self._db.execute("SELECT * FROM orders WHERE id=?", (row["id"],)).fetchone()
                self._db.commit()
                return self._row(claimed, include_lease=True)
            except Exception:
                self._db.rollback()
                raise

    def _finish(self, identifier, status, result, error, lease_token):
        if not isinstance(lease_token, str) or not lease_token:
            raise ValueError("Le reçu d'exécution doit présenter son bail.")
        encoded = _result(result) if result is not None else None
        safe_error = str(error)[:1000] if error is not None else None
        now = self._clock()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute("SELECT * FROM orders WHERE id=?", (identifier,)).fetchone()
                if row is None or row["status"] != "running" or row["lease_token"] != lease_token:
                    raise ValueError("Bail périmé, tâche inconnue ou déjà terminée.")
                self._db.execute("UPDATE orders SET status=?,updated=?,result=?,error=?,lease_token=NULL,lease_until=NULL WHERE id=?",
                                 (status, now, encoded, safe_error, identifier))
                self._history(identifier, now, status, "Résultat enregistré." if status == "completed" else "Échec ou incertitude enregistré.")
                out = self._db.execute("SELECT * FROM orders WHERE id=?", (identifier,)).fetchone()
                self._db.commit()
                return self._row(out)
            except Exception:
                self._db.rollback()
                raise

    def complete(self, identifier, result, lease_token=None):
        return self._finish(identifier, "completed", result, None, lease_token)

    def fail(self, identifier, error, lease_token=None, uncertain=False):
        return self._finish(identifier, "needs_review" if uncertain else "failed", None, error, lease_token)

    def cancel(self, identifier):
        now = self._clock()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute("SELECT * FROM orders WHERE id=?", (identifier,)).fetchone()
                if row is None or row["status"] != "pending":
                    raise ValueError("Seul un ordre en attente peut être annulé.")
                self._db.execute("UPDATE orders SET status='cancelled',updated=? WHERE id=?", (now, identifier))
                self._history(identifier, now, "cancelled", "Annulation locale avant exécution.")
                self._db.commit()
                return self.get(identifier)
            except Exception:
                self._db.rollback()
                raise

    def get(self, identifier):
        with self._lock:
            return self._row(self._db.execute("SELECT * FROM orders WHERE id=?", (identifier,)).fetchone())

    def list(self, limit=100):
        with self._lock:
            rows = self._db.execute("SELECT * FROM orders ORDER BY seq DESC LIMIT ?", (self._limit(limit),)).fetchall()
        return [self._row(row) for row in rows]

    def pending(self, limit=100):
        with self._lock:
            rows = self._db.execute("SELECT * FROM orders WHERE status='pending' ORDER BY seq LIMIT ?", (self._limit(limit),)).fetchall()
        return [self._row(row) for row in rows]

    def history(self, identifier):
        with self._lock:
            rows = self._db.execute("SELECT * FROM order_history WHERE order_id=? ORDER BY seq", (identifier,)).fetchall()
        return [{"timestamp": _iso(row["timestamp"]), "status": row["status"], "reason": row["reason"]} for row in rows]

    def close(self):
        with self._lock:
            self._db.close()
