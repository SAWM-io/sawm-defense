"""Durable local evidence, delivery queue and bounded Cloud request budget.

The chain detects inconsistent edits. A host administrator can rewrite this
database and its anchor: this is not an external cryptographic attestation.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid

from .config import private_dir


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(text.encode("utf-8")) > 262144:
        raise ValueError("Enregistrement trop volumineux.")
    return text


def _digest(seq, kind, identifier, created, payload, previous):
    return hashlib.sha256(_json([seq, kind, identifier, created, payload, previous]).encode()).hexdigest()


class Store:
    def __init__(self, state_dir):
        self.state_dir = private_dir(Path(state_dir))
        self.path = self.state_dir / "evidence.sqlite3"
        for suffix in ("", "-wal", "-shm"):
            if Path(str(self.path) + suffix).is_symlink():
                raise ValueError("Le journal ne doit pas être un lien symbolique.")
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        if os.name != "nt":
            self.path.chmod(0o600)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS ledger (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL, identifier TEXT NOT NULL,
                created TEXT NOT NULL, payload TEXT NOT NULL,
                previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL,
                UNIQUE(kind,identifier)
            );
            CREATE INDEX IF NOT EXISTS ledger_kind ON ledger(kind,seq);
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
            INSERT OR IGNORE INTO metadata VALUES ('anchor_hash','');
            INSERT OR IGNORE INTO metadata VALUES ('anchor_seq','0');
            INSERT OR IGNORE INTO metadata VALUES ('head_hash','');
            INSERT OR IGNORE INTO metadata VALUES ('head_seq','0');
            CREATE TABLE IF NOT EXISTS queue (
                identifier TEXT PRIMARY KEY, enqueued REAL NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_queue (
                identifier TEXT PRIMARY KEY, enqueued REAL NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS budget (reserved REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS budget_time ON budget(reserved);
            CREATE TABLE IF NOT EXISTS local_work (
                kind TEXT NOT NULL, identifier TEXT NOT NULL, payload TEXT NOT NULL,
                enqueued REAL NOT NULL, PRIMARY KEY(kind,identifier)
            );
            CREATE TABLE IF NOT EXISTS effect_claims (identifier TEXT PRIMARY KEY, claimed REAL NOT NULL);
        """)
        self._db.commit()

    def _append(self, kind, value):
        if not isinstance(value, dict):
            raise ValueError("Un objet structuré est requis.")
        row = dict(value)
        row.setdefault("id", uuid.uuid4().hex)
        row.setdefault("timestamp", _now())
        if not isinstance(row["id"], str) or not 1 <= len(row["id"]) <= 160:
            raise ValueError("Identifiant invalide.")
        if not isinstance(row["timestamp"], str):
            raise ValueError("Horodatage invalide.")
        try:
            parsed = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("Horodatage avec fuseau requis.") from None
        payload = _json(row)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                existing = self._db.execute("SELECT payload FROM ledger WHERE kind=? AND identifier=?", (kind,row["id"])).fetchone()
                if existing:
                    if existing["payload"] != payload:
                        raise ValueError("Un identifiant existant ne peut pas être réécrit.")
                    self._db.commit()
                    return json.loads(existing["payload"])
                last = self._db.execute("SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
                previous = last["entry_hash"] if last else self._db.execute("SELECT value FROM metadata WHERE key='anchor_hash'").fetchone()[0]
                created = _now()
                cur = self._db.execute("INSERT INTO ledger(kind,identifier,created,payload,previous_hash,entry_hash) VALUES (?,?,?,?,?,?)", (kind,row["id"],created,payload,previous,""))
                digest = _digest(cur.lastrowid,kind,row["id"],created,payload,previous)
                self._db.execute("UPDATE ledger SET entry_hash=? WHERE seq=?", (digest,cur.lastrowid))
                self._db.execute("UPDATE metadata SET value=? WHERE key='head_hash'",(digest,))
                self._db.execute("UPDATE metadata SET value=? WHERE key='head_seq'",(str(cur.lastrowid),))
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return json.loads(payload)

    def add_event(self, event):
        value = dict(event)
        if value.get("severity", "info") not in {"info", "warning", "critical"}:
            raise ValueError("Sévérité invalide.")
        value.setdefault("severity", "info")
        value.setdefault("kind", "observation")
        value.setdefault("summary", "")
        value.setdefault("details", {})
        return self._append("event", value)

    def record_action(self, action):
        return self._append("action", action)

    def record_call(self, call):
        # Intentionally never store headers, URL queries, bodies or exceptions.
        allowed = {"id", "timestamp", "operation", "status", "latency_ms", "attempt", "http_status", "error_code", "usage", "turn_id", "event_count", "input_tokens", "output_tokens", "total_tokens"}
        value = {key: val for key, val in call.items() if key in allowed}
        return self._append("call", value)

    @staticmethod
    def _limit(limit):
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("Limite entre 1 et 10000 requise.")
        return limit

    def _list(self, kind, limit):
        with self._lock:
            rows = self._db.execute("SELECT payload FROM ledger WHERE kind=? ORDER BY seq DESC LIMIT ?", (kind,self._limit(limit))).fetchall()
        return [json.loads(row[0]) for row in rows]

    def events(self, limit=100):
        return self._list("event",limit)

    def actions(self, limit=100):
        return self._list("action",limit)

    def calls(self, limit=100):
        return self._list("call",limit)

    def get_event(self, identifier):
        with self._lock:
            row = self._db.execute("SELECT payload FROM ledger WHERE kind='event' AND identifier=?", (identifier,)).fetchone()
        return json.loads(row[0]) if row else None

    def enqueue(self, event):
        payload = _json(event)
        identifier = event.get("id")
        if not isinstance(identifier,str) or not identifier:
            raise ValueError("Un identifiant stable est requis pour la file.")
        with self._lock, self._db:
            existing = self._db.execute("SELECT payload FROM queue WHERE identifier=?",(identifier,)).fetchone()
            if existing and existing[0] != payload:
                raise ValueError("Une livraison en attente ne peut pas changer de contenu.")
            self._db.execute("INSERT OR IGNORE INTO queue VALUES (?,?,?)",(identifier,time.time(),payload))

    def pending(self, limit=20):
        with self._lock:
            rows = self._db.execute("SELECT payload FROM queue ORDER BY enqueued,identifier LIMIT ?",(self._limit(limit),)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def ack_pending(self, ids):
        identifiers = list(ids)
        if len(identifiers)>10000 or any(not isinstance(i,str) for i in identifiers):
            raise ValueError("Identifiants de livraison invalides.")
        with self._lock, self._db:
            self._db.executemany("DELETE FROM queue WHERE identifier=?",((i,) for i in identifiers))

    def enqueue_scan(self, event):
        payload = _json(event)
        identifier = event.get("id")
        if not isinstance(identifier,str) or not identifier:
            raise ValueError("Un identifiant stable est requis pour l'analyse.")
        with self._lock, self._db:
            existing = self._db.execute("SELECT payload FROM scan_queue WHERE identifier=?",(identifier,)).fetchone()
            if existing and existing[0] != payload:
                raise ValueError("Une analyse en attente ne peut pas changer de contenu.")
            self._db.execute("INSERT OR IGNORE INTO scan_queue VALUES (?,?,?)",(identifier,time.time(),payload))

    def pending_scans(self, limit=2):
        with self._lock:
            rows = self._db.execute("SELECT payload FROM scan_queue ORDER BY enqueued,identifier LIMIT ?",(self._limit(limit),)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def ack_scans(self, ids):
        identifiers = list(ids)
        if len(identifiers)>10000 or any(not isinstance(i,str) for i in identifiers):
            raise ValueError("Identifiants d'analyse invalides.")
        with self._lock, self._db:
            self._db.executemany("DELETE FROM scan_queue WHERE identifier=?",((i,) for i in identifiers))

    def reserve_cloud(self, limit_per_hour):
        if type(limit_per_hour) is not int or not 0 <= limit_per_hour <= 20000:
            raise ValueError("Budget Cloud invalide.")
        now = time.time()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute("DELETE FROM budget WHERE reserved < ?",(now-3600,))
                count = self._db.execute("SELECT COUNT(*) FROM budget").fetchone()[0]
                available = count < limit_per_hour
                if available:
                    self._db.execute("INSERT INTO budget VALUES (?)",(now,))
                self._db.commit()
                return available
            except Exception:
                self._db.rollback()
                raise

    def cloud_budget(self, limit_per_hour):
        if type(limit_per_hour) is not int or not 0 <= limit_per_hour <= 20000:
            raise ValueError("Budget Cloud invalide.")
        now = time.time()
        with self._lock:
            row = self._db.execute("SELECT COUNT(*),MIN(reserved) FROM budget WHERE reserved>=?", (now-3600,)).fetchone()
        return {"unit": "api_requests", "limit": limit_per_hour, "used": row[0],
                "remaining": max(0, limit_per_hour-row[0]), "resets_at": row[1]+3600 if row[1] is not None else None}

    def runtime_state(self, name):
        with self._lock:
            row = self._db.execute("SELECT value FROM metadata WHERE key=?", ("runtime:"+name,)).fetchone()
        return json.loads(row[0]) if row else {}

    def save_runtime_state(self, name, value):
        payload = _json(value)
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", ("runtime:"+name,payload))

    def review_stats(self):
        with self._lock:
            rows = self._db.execute("SELECT json_extract(payload,'$.severity'),COUNT(*) FROM local_work WHERE kind='review' GROUP BY json_extract(payload,'$.severity')").fetchall()
        counts = dict(rows)
        return {"queue_count": sum(counts.values()), "critical_count": counts.get("critical",0), "warning_count": counts.get("warning",0)}

    def review_batch(self, limit=5):
        """Prioritize urgent events, reserving one slot for the oldest waiting item."""
        self._limit(limit)
        with self._lock:
            urgent = self._db.execute("SELECT identifier,payload FROM local_work WHERE kind='review' ORDER BY CASE json_extract(payload,'$.severity') WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,enqueued,identifier LIMIT ?", (max(1,limit-1),)).fetchall()
            oldest = self._db.execute("SELECT identifier,payload FROM local_work WHERE kind='review' ORDER BY enqueued,identifier LIMIT ?", (limit,)).fetchall()
        chosen = list(urgent)
        known = {row[0] for row in chosen}
        for row in oldest:
            if len(chosen) >= limit:
                break
            if row[0] not in known:
                chosen.append(row)
                known.add(row[0])
        return [json.loads(row[1]) for row in chosen]

    def enqueue_work(self, kind, event):
        if kind not in {"notify", "respond", "review"}:
            raise ValueError("File locale inconnue")
        with self._lock, self._db:
            self._db.execute("INSERT OR IGNORE INTO local_work VALUES (?,?,?,?)",
                             (kind, event["id"], _json(event), time.time()))

    def pending_work(self, kind, limit=20):
        with self._lock:
            rows = self._db.execute("SELECT payload FROM local_work WHERE kind=? ORDER BY enqueued,identifier LIMIT ?",
                                    (kind, self._limit(limit))).fetchall()
        return [json.loads(row[0]) for row in rows]

    def ack_work(self, kind, identifier):
        with self._lock, self._db:
            self._db.execute("DELETE FROM local_work WHERE kind=? AND identifier=?", (kind, identifier))

    def claim_effect(self, identifier):
        """Persist before an automatic mutation. Uncertain effects are never replayed blindly."""
        with self._lock, self._db:
            row = self._db.execute("INSERT OR IGNORE INTO effect_claims VALUES (?,?)", (identifier, time.time()))
            return row.rowcount == 1

    def verify_chain(self):
        with self._lock:
            previous = self._db.execute("SELECT value FROM metadata WHERE key='anchor_hash'").fetchone()[0]
            anchor = int(self._db.execute("SELECT value FROM metadata WHERE key='anchor_seq'").fetchone()[0])
            rows = self._db.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
            checked = 0
            expected_seq = anchor + 1
            for row in rows:
                if row["seq"] != expected_seq or row["previous_hash"] != previous or row["entry_hash"] != _digest(row["seq"],row["kind"],row["identifier"],row["created"],row["payload"],previous):
                    return {"ok":False,"verified":checked,"invalid_sequence":row["seq"],"anchor_sequence":anchor,"external_attestation":False}
                checked += 1
                expected_seq += 1
                previous = row["entry_hash"]
            head_hash = self._db.execute("SELECT value FROM metadata WHERE key='head_hash'").fetchone()[0]
            head_seq = int(self._db.execute("SELECT value FROM metadata WHERE key='head_seq'").fetchone()[0])
            if previous != head_hash or expected_seq-1 != head_seq:
                return {"ok":False,"verified":checked,"error":"head_mismatch","anchor_sequence":anchor,"external_attestation":False}
            return {"ok":True,"verified":checked,"anchor_sequence":anchor,"last_hash":previous,"external_attestation":False}

    def prune(self, days):
        if type(days) is not int or not 1 <= days <= 3650:
            raise ValueError("Durée de conservation invalide.")
        cutoff = (datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                if not self.verify_chain()["ok"]:
                    raise ValueError("Journal altéré : nettoyage refusé.")
                rows = self._db.execute("SELECT seq,created,identifier,entry_hash FROM ledger ORDER BY seq").fetchall()
                pending = {row[0] for row in self._db.execute("SELECT identifier FROM queue UNION SELECT identifier FROM scan_queue UNION SELECT identifier FROM local_work")}
                last = None
                removed = 0
                for row in rows:
                    if row["created"] >= cutoff or row["identifier"] in pending:
                        break
                    last = row
                    removed += 1
                if last:
                    self._db.execute("UPDATE metadata SET value=? WHERE key='anchor_hash'",(last["entry_hash"],))
                    self._db.execute("UPDATE metadata SET value=? WHERE key='anchor_seq'",(str(last["seq"]),))
                    self._db.execute("DELETE FROM ledger WHERE seq <= ?",(last["seq"],))
                self._db.commit()
                return {"removed":removed,"anchor_retained":True}
            except Exception:
                self._db.rollback()
                raise

    def close(self):
        with self._lock:
            self._db.close()
