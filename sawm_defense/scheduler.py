"""Bounded SOC scheduling, independent from sensors and local authorization.

The selected interval is a target, not a response-time guarantee. A slow model,
an outage, a spending limit or a busy interactive request can defer a review.
Only scheduling receipts are persisted here; observations stay in the ledger.
"""
from __future__ import annotations

import math
import threading
import time


class SOCScheduler:
    def __init__(self, store, *, clock=None):
        self.store = store
        self.clock = clock or time.time
        self._lock = threading.RLock()
        self._state = {
            "last_review_at": None, "last_success_at": None,
            "consecutive_failures": 0, "backoff_until": 0,
            "last_event_ids": [], "last_reason": "Aucune analyse effectuée.",
            "next_upload_at": 0, "upload_failures": 0,
        }
        persisted = store.runtime_state("soc_scheduler")
        for key in self._state:
            value = persisted.get(key)
            if key in {"last_event_ids", "last_reason"}:
                if isinstance(value, type(self._state[key])):
                    self._state[key] = value
            elif type(value) in {int, float} and math.isfinite(value) and value >= 0:
                self._state[key] = value

    def _save(self):
        self.store.save_runtime_state("soc_scheduler", self._state)

    def status(self, settings, *, enabled=True):
        now = self.clock()
        counts = self.store.review_stats()
        budget = self.store.cloud_budget(settings["cloud_per_hour"])
        interval = settings["cloud_analysis_interval_seconds"]
        effective = interval
        if settings["cloud_adaptive_enabled"]:
            if counts["critical_count"]:
                effective = min(interval, 10)
            elif not counts["queue_count"] and not settings["cloud_heartbeat_enabled"]:
                effective = min(3600, interval*4)
        with self._lock:
            # The GUI may read a profile supervised by a separate service.
            state = {**self._state, **self.store.runtime_state("soc_scheduler")}
        last = state["last_review_at"]
        due = max(now if last is None else last+effective, state["backoff_until"])
        active = enabled and settings["autonomous_analysis_enabled"]
        has_work = counts["queue_count"] > 0 or settings["cloud_heartbeat_enabled"]
        label = "disabled" if not active else "idle" if not has_work else "backoff" if state["backoff_until"] > now else "budget_exhausted" if budget["remaining"] < 3 else "due" if now >= due else "scheduled"
        if label == "budget_exhausted":
            due = max(due, budget["resets_at"] or now+60)
        return {**state, **counts, "state": label, "interval_seconds": interval,
                "effective_interval_seconds": effective,
                "next_review_at": due if active and has_work else None,
                "next_review_in_seconds": max(0, round(due-now, 2)) if active and has_work else None,
                "heartbeat_enabled": settings["cloud_heartbeat_enabled"],
                "adaptive_enabled": settings["cloud_adaptive_enabled"], "budget": budget}

    def review_due(self, settings):
        return self.status(settings)["state"] == "due"

    def started(self, events):
        with self._lock:
            self._state.update(last_review_at=self.clock(), last_event_ids=[e["id"] for e in events],
                               last_reason="Analyse en cours ; aucune décision encore confirmée.")
            self._save()

    def succeeded(self):
        with self._lock:
            self._state.update(last_success_at=self.clock(), consecutive_failures=0, backoff_until=0,
                               last_reason="Analyse reçue ; toute intervention reste soumise à la politique locale.")
            self._save()

    def failed(self, settings, *, budget=False):
        with self._lock:
            failures = min(16, self._state["consecutive_failures"]+1)
            delay = min(300, settings["cloud_analysis_interval_seconds"]*(2**(failures-1)))
            until = self.clock()+delay
            if budget:
                until = max(until, self.store.cloud_budget(settings["cloud_per_hour"])["resets_at"] or until)
            self._state.update(consecutive_failures=failures, backoff_until=until,
                               last_reason="Budget atteint ; observations conservées." if budget else "Analyse indisponible ; observations conservées et reprise espacée.")
            self._save()

    def upload_due(self):
        with self._lock:
            return self.clock() >= self._state["next_upload_at"]

    def upload_finished(self, settings, *, failed=False, budget=False):
        with self._lock:
            failures = min(16, self._state["upload_failures"]+1) if failed else 0
            delay = min(300, settings["cloud_analysis_interval_seconds"]*(2**max(0,failures-1)))
            until = self.clock()+delay
            if budget:
                until = max(until, self.store.cloud_budget(settings["cloud_per_hour"])["resets_at"] or until)
            self._state.update(upload_failures=failures, next_upload_at=until)
            self._save()
