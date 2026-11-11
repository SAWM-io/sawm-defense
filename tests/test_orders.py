from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sawm_defense.orders import OrderQueue


class Clock:
    now = 1000
    def __call__(self): return self.now


def test_local_order_survives_restart_and_approval_is_immutable(tmp_path):
    q = OrderQueue(tmp_path)
    item = q.submit("act", {"action": "quarantine", "event_id": "ev-123"}, approved=True,
                    idempotency_key="request-1", actor="Cloud administrator")
    assert item["actor"] != "Cloud administrator"
    assert item["actor"]["source"] == "local_os_session"
    q.close()
    q = OrderQueue(tmp_path)
    same = q.submit("act", {"action": "quarantine", "event_id": "ev-123"}, approved=True,
                    idempotency_key="request-1")
    assert same["id"] == item["id"]
    with pytest.raises(ValueError, match="autre ordre"):
        q.submit("act", {"action": "quarantine", "event_id": "ev-123"}, approved=False,
                 idempotency_key="request-1")
    assert "lease_token" not in q.list()[0]
    q.close()


def test_only_one_worker_claims_and_stale_worker_cannot_finish(tmp_path):
    q1, q2 = OrderQueue(tmp_path), OrderQueue(tmp_path)
    item = q1.submit("inventory", {})
    with ThreadPoolExecutor(2) as executor:
        results = list(executor.map(lambda q: q.claim(), [q1, q2]))
    claimed = [r for r in results if r]
    assert len(claimed) == 1
    with pytest.raises(ValueError):
        q1.complete(item["id"], {}, lease_token="not-the-lease")
    finished = q2.complete(item["id"], {"status": "completed", "programs": ["test"]}, lease_token=claimed[0]["lease_token"])
    assert finished["status"] == "completed"
    with pytest.raises(ValueError):
        q1.complete(item["id"], {}, lease_token=claimed[0]["lease_token"])
    assert [e["status"] for e in q1.history(item["id"])] == ["pending", "running", "completed"]
    q1.close(); q2.close()


@pytest.mark.parametrize("kind,payload", [
    ("act", {"action": "quarantine", "event_id": "ev-1"}),
    ("restore", {"action_id": "ac-1"}),
    ("scan", {"path": str(Path.home() / "selected.txt")}),
    ("analyze", {"event_id": "ev-1"}),
    ("report", {"path": str(Path.home() / "report.html")}),
])
def test_interrupted_possible_mutations_never_auto_replay(tmp_path, kind, payload):
    clock = Clock()
    q = OrderQueue(tmp_path, clock=clock)
    item = q.submit(kind, payload)
    claimed = q.claim(lease_seconds=2)
    q.close()
    clock.now += 3
    restarted = OrderQueue(tmp_path, clock=clock)
    assert restarted.claim() is None
    assert restarted.get(item["id"])["status"] == "needs_review"
    assert restarted.get(item["id"])["attempts"] == 1
    with pytest.raises(ValueError):
        restarted.complete(item["id"], {}, lease_token=claimed["lease_token"])
    restarted.close()


def test_readonly_inventory_can_resume_with_new_lease(tmp_path):
    clock = Clock()
    q = OrderQueue(tmp_path, clock=clock)
    item = q.submit("inventory", {})
    first = q.claim(lease_seconds=1)
    clock.now += 2
    second = q.claim()
    assert second["id"] == item["id"]
    assert second["lease_token"] != first["lease_token"]
    assert second["attempts"] == 2
    with pytest.raises(ValueError):
        q.complete(item["id"], {}, lease_token=first["lease_token"])
    q.close()


def test_expired_pending_and_cancelled_orders_never_execute(tmp_path):
    clock = Clock()
    q = OrderQueue(tmp_path, clock=clock)
    expired = q.submit("inventory", {}, ttl_seconds=1)
    cancelled = q.submit("inventory", {})
    q.cancel(cancelled["id"])
    clock.now += 2
    assert q.claim() is None
    assert q.get(expired["id"])["status"] == "expired"
    assert q.get(cancelled["id"])["status"] == "cancelled"
    q.close()


@pytest.mark.parametrize("kind,payload", [
    ("shell", {"command": "rm -rf /"}),
    ("act", {"action": "bash", "event_id": "x"}),
    ("inventory", {"api_key": "secret"}),
    ("scan", {"path": "relative"}),
    ("analyze", {"event_id": "e\nroot"}),
    ("report", {"path": str(Path.home() / "payload.sh")}),
])
def test_arbitrary_commands_and_unexpected_fields_rejected(tmp_path, kind, payload):
    q = OrderQueue(tmp_path)
    with pytest.raises(ValueError): q.submit(kind, payload)
    assert q.list() == []
    q.close()


def test_receipt_omits_secret_fields_and_requires_active_lease(tmp_path):
    q = OrderQueue(tmp_path)
    item = q.submit("inventory", {})
    lease = q.claim()
    with pytest.raises(ValueError):
        q.complete(item["id"], {"status": "completed"})
    result = q.complete(item["id"], {"status": "completed", "api_key": "secret", "nested": {"headers": {"Authorization": "Bearer secret"}}}, lease_token=lease["lease_token"])
    assert "secret" not in str(result)
    q.close()


def test_database_symlink_rejected(tmp_path):
    elsewhere = tmp_path / "outside"
    elsewhere.write_text("unchanged")
    state = tmp_path / "profile"
    state.mkdir()
    try: (state / "orders.sqlite3").symlink_to(elsewhere)
    except OSError: pytest.skip("native symlink permission unavailable")
    with pytest.raises(ValueError): OrderQueue(state)
    assert elsewhere.read_text() == "unchanged"
