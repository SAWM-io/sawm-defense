"""End-to-end local autonomy. No Cloud, real malware, firewall change or OS alert."""
import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sawm_defense import service
from sawm_defense.downloads import StableFiles
from sawm_defense.policy import authorize, trusted_auth_event


class Vault:
    def __init__(self, *_): pass
    def get(self): return None


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "SecretVault", Vault)
    root = tmp_path / "downloads"
    root.mkdir()
    app = service.AgentService(tmp_path / "state")
    app.save_settings({"monitor_paths": [str(root)], "protect_downloads": False, "poll_seconds": 1,
                       "download_scan_settle_seconds": 1, "notifications_enabled": False})
    monkeypatch.setattr(app.av, "_engine", lambda: (None, None))
    monkeypatch.setattr(app.notifications, "_deliver", lambda *a: pytest.fail("Unexpected native alert"))
    yield app, root
    app.close()


def trusted_event(app):
    stamp = datetime.now(timezone.utc).isoformat()
    return app._event("auth_bruteforce", "warning", "Repeated authentication failures", {
        "remote_ip": "93.184.216.34", "verified_local": True, "verification_origin": "local_journald",
        "source_kind": "journald", "failure_count": 5, "window_seconds": 300,
        "last_failure_at": stamp, "first_failure_at": stamp, "evidence_ids": [str(n) for n in range(5)],
        "producer": {"_UID": "0", "_COMM": "sshd", "_EXE": "/usr/sbin/sshd", "_TRANSPORT": "syslog"}})


def wait_for(fn, timeout=8):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = fn()
        if result:
            return result
        time.sleep(.05)
    pytest.fail("Expected local result was not observed")


def test_inspects_download_without_antivirus_and_does_not_call_it_safe(agent):
    app, root = agent
    harmless = root / "notes.txt"
    harmless.write_text("Ordinary notes")
    result = app.scan(harmless)
    assert result["antivirus"]["status"] == "unavailable"
    assert result["static_inspection"]["actual_type"] == "text"
    assert result["status"] == "incomplete"
    assert result["sha256"] == hashlib.sha256(harmless.read_bytes()).hexdigest()
    assert any(e["kind"] == "antivirus_unavailable" for e in app.store.events())


def test_suspicious_metadata_is_not_malware_proof_even_with_grants(agent):
    app, root = agent
    app.save_settings({"automatic_actions": ["quarantine", "terminate", "block_ip"]})
    path = root / "invoice.pdf"
    path.write_text("#!/bin/sh\necho harmless-demo\n")
    result = app.scan(path)
    assert result["status"] == "suspicious"
    assert result["static_inspection"]["actual_type"] == "script"
    assert path.exists()
    for action in ("quarantine", "terminate", "block_ip"):
        assert app.act(action, result["event_id"])["status"] == "denied"
    assert app.store.pending_work("review")[0]["id"] == result["event_id"]


def test_real_continuous_watch_inspection_and_inbox_work_without_cloud(agent):
    app, root = agent
    app.tick()  # completed baseline
    assert app.start()["status"] == "completed"
    path = root / "download.pdf"
    path.write_text("#!/bin/sh\necho benign-fixture\n")
    found = wait_for(lambda: next((e for e in app.store.events() if e["kind"] == "file_suspicious"), None))
    alert = wait_for(lambda: next((n for n in app.notifications.list() if n["event_id"] == found["id"]), None))
    assert alert["delivery"] in {"disabled", "not_requested"}, alert
    assert path.exists() and app.store.calls() == []
    assert app.status()["running"]
    assert app.store.verify_chain()["ok"]


def test_stability_window_resets_after_write_and_partial_files_wait_longer(tmp_path):
    path = tmp_path / "test.part"
    path.write_text("one")
    stable = StableFiles()
    assert not stable.ready(path, 1, now=0)
    assert not stable.ready(path, 1, now=2)
    assert stable.ready(path, 1, now=16)
    path.write_text("two longer")
    assert not stable.ready(path, 1, now=17)
    assert not stable.ready(path, 1, now=18)
    assert not StableFiles().ready(path, 1, now=100)  # restart is conservative


def test_cloud_delay_does_not_stop_file_inspection(agent, monkeypatch):
    app, root = agent
    entered, release = threading.Event(), threading.Event()
    def stalled_cloud():
        entered.set()
        release.wait(10)
    monkeypatch.setattr(app, "_background", stalled_cloud)
    app.tick()
    app.start()
    try:
        assert entered.wait(1)
        path = root / "readme.txt"
        path.write_text("Safe local fixture")
        wait_for(lambda: any(e["kind"] == "file_inspected" for e in app.store.events()))
        assert not release.is_set()
    finally:
        release.set()
        app.stop()


def test_local_auth_response_is_authorized_deduplicated_and_revocable(agent, monkeypatch):
    app, _ = agent
    app.save_settings({"automatic_actions": ["block_ip"], "autoblock_auth_ips": True})
    event = trusted_event(app)
    assert trusted_auth_event(event, app.settings())
    calls = []
    monkeypatch.setattr(app.executor, "execute", lambda *args: calls.append(args) or {"status": "completed"})
    app._respond_pending()
    assert len(calls) == 1
    assert calls[0][2]["_automatic_response"] is True
    assert app.act("block_ip", event["id"])["status"] == "denied"
    app.config.save({"automatic_actions": []})
    newer = trusted_event(app)
    app._respond_pending()
    assert len(calls) == 1
    assert app.act("block_ip", newer["id"])["status"] == "denied"


def test_forged_auth_text_or_protected_ip_cannot_authorize_block(agent):
    app, _ = agent
    app.save_settings({"automatic_actions": ["block_ip"], "autoblock_auth_ips": True})
    event = trusted_event(app)
    event["details"]["producer"]["_TRANSPORT"] = "stdout"
    assert not authorize("block_ip", event, app.settings())[0]
    event["details"]["producer"]["_TRANSPORT"] = "syslog"
    app.save_settings({"protected_remote_ips": ["93.184.216.34"]})
    assert not authorize("block_ip", event, app.settings())[0]


def test_scan_mission_survives_reopen_and_records_result(agent):
    app, root = agent
    path = root / "invoice.pdf"
    path.write_text("#!/bin/sh\necho fixture\n")
    order = app.submit_order("scan", {"path": str(path)}, idempotency_key="fixture-scan")
    other = service.AgentService(app.state_dir)
    try:
        other.av._engine = lambda: (None, None)
        result = other._execute_next_order()
        assert result["status"] == "suspicious"
        record = app.orders.get(order["id"])
        assert record["status"] == "completed"
        assert record["result"]["event_id"] == result["event_id"]
        assert record["actor"]["source"] == "local_os_session"
    finally:
        other.close()


def test_queued_scan_rechecks_current_scope(agent):
    app, root = agent
    path = root / "test.txt"
    path.write_text("fixture")
    order = app.submit_order("scan", {"path": str(path)})
    app.config.save({"monitor_paths": []})
    app._execute_next_order()
    assert app.orders.get(order["id"])["status"] == "needs_review"
    assert not any(e["kind"] == "file_inspected" for e in app.store.events())


def test_report_order_never_overwrites_existing_document(agent, tmp_path):
    app, _ = agent
    target = tmp_path / "report.html"
    target.write_text("existing personal document")
    order = app.submit_order("report", {"path": str(target)})
    app._execute_next_order()
    assert target.read_text() == "existing personal document"
    assert app.orders.get(order["id"])["status"] == "failed"


def test_temporary_block_receipt_recovery_even_without_action_record(agent, monkeypatch):
    app, _ = agent
    receipt = {"receipt_id": "a"*32, "action": "block_ip", "expires_at": time.time()-1}
    app.executor._write_receipt(receipt)
    calls = []
    monkeypatch.setattr(app.executor, "rollback", lambda record, cfg: calls.append(record) or {"status": "completed"})
    app._expire_blocks()
    app._expire_blocks()
    assert len(calls) == 1
    assert app.store.actions()[0]["expired_receipt"] == "a"*32


def test_report_contains_auditable_missions_and_notifications(agent, tmp_path):
    app, _ = agent
    app.submit_order("inventory", {})
    signal = app._event("test", "warning", "Fixture alert")
    app.notifications.publish(signal, enabled=False)
    result = tmp_path / "status.json"
    app.export_report(result)
    report = json.loads(result.read_text())
    assert report["version"] == "0.2.0"
    assert report["orders"][0]["kind"] == "inventory"
    assert report["notifications"][0]["event_id"] == signal["id"]
    assert report["file_inspection"]["available"]


def test_slow_intervention_does_not_freeze_status_or_sampling(agent, monkeypatch):
    app, _ = agent
    app.save_settings({"automatic_actions": ["block_ip"], "autoblock_auth_ips": True})
    event = trusted_event(app)
    entered, release = threading.Event(), threading.Event()
    def slow(*_):
        entered.set()
        release.wait(5)
        return {"status": "completed"}
    monkeypatch.setattr(app.executor, "execute", slow)
    thread = threading.Thread(target=lambda: app.act("block_ip", event["id"]))
    thread.start()
    try:
        assert entered.wait(1)
        sampled = threading.Event()
        probe = threading.Thread(target=lambda: (app.status(), app.tick(), sampled.set()))
        probe.start()
        assert sampled.wait(2), "Intervention froze monitoring/status"
        probe.join()
    finally:
        release.set()
        thread.join(3)


def test_missing_engine_alert_is_health_change_not_one_alert_per_file(agent):
    app, root = agent
    for index in range(5):
        path = root / f"note-{index}.txt"
        path.write_text("safe example")
        assert app.scan(path)["status"] == "incomplete"
    events = app.store.events()
    assert sum(e["kind"] == "antivirus_unavailable" for e in events) == 1
    assert sum(e["kind"] == "file_inspected" for e in events) == 5
