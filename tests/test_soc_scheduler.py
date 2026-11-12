"""SOC cadence, failure recovery and real SDK protocol using MockTransport only."""
import json
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from sawm_defense import service, storage
from sawm_defense.cloud import CloudBridge, CloudBudgetExceeded
from sawm_defense.config import ConfigManager, validate_config
from sawm_defense.scheduler import SOCScheduler
from sawm_defense.storage import Store


class Clock:
    def __init__(self): self.now = 1800000000.0
    def __call__(self): return self.now
    def advance(self, seconds): self.now += seconds


class Vault:
    values = {}
    def __init__(self, path): self.path = str(path)
    def get(self): return self.values.get(self.path)
    def set(self, key, persist=True):
        self.values[self.path] = key
        return {"persisted": False, "backend": "test-only"}


class Server:
    """No host, radio, malware or Cloud contacted; HTTP contract fixture only."""
    def __init__(self):
        self.requests = []
        self.analyses = []
        self.fail_analysis = False
        self.action = "observe"
        self.after_recall = None
        self.before_answer = None

    def __call__(self, request):
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/recall:tsst"):
            if self.after_recall:
                self.after_recall()
            return httpx.Response(200, json={"evidence": [{"evidence_id": "ev-history", "content": "Prior observation"}], "memory_engine": "tsst"})
        if path.endswith("/odvl:rank"):
            return httpx.Response(200, json={"ranking": [{"candidate_id": "ev-history", "rank": 1}]})
        if path.endswith("/odvl:observe"):
            return httpx.Response(200, json={"available": True})
        if path.endswith("/sawm/responses"):
            body = json.loads(request.content)
            observations = json.loads(body["message"].split("\n", 1)[1])["observations_untrusted"]
            self.analyses.append(observations)
            if self.fail_analysis:
                return httpx.Response(503, json={"detail": {"code": "sawm_cloud_unavailable"}})
            if self.before_answer:
                self.before_answer()
            answer = {"summary": "Faits à examiner", "action": self.action, "event_id": observations[0]["id"],
                      "reason": "Proposition de test, aucune preuve de malware", "uncertainties": ["Attribution limitée"]}
            events = [{"type": "response.delta", "delta": json.dumps(answer)},
                      {"type": "usage.final", "input_tokens": 100, "output_tokens": 20}, {"type": "turn.done"}]
            return httpx.Response(200, headers={"Content-Type": "text/event-stream"},
                                  text="".join("data: "+json.dumps(e)+"\n\n" for e in events))
        if path.endswith("/events:batch"):
            return httpx.Response(202, json={"job_id": "job_"+"b"*32, "status": "pending"})
        if "/jobs/" in path:
            return httpx.Response(200, json={"job_id": "job_"+"b"*32, "status": "completed"})
        raise AssertionError(path)


@pytest.fixture
def soc(tmp_path, monkeypatch):
    clock, server = Clock(), Server()
    Vault.values.clear()
    monkeypatch.setattr(service, "SecretVault", Vault)
    monkeypatch.setattr(storage.time, "time", clock)
    monkeypatch.setattr(service, "CloudBridge", lambda *a, **kw: CloudBridge(*a, **kw,
        http_client=httpx.Client(transport=httpx.MockTransport(server))))
    app = service.AgentService(tmp_path/"state")
    app.scheduler = SOCScheduler(app.store, clock=clock)
    app.save_settings({"space_id": "soc-test", "entity_id": "ent_"+"a"*32,
        "cloud_enabled": True, "cloud_upload_enabled": True, "cloud_analysis_interval_seconds": 10,
        "cloud_per_hour": 1200, "protect_downloads": False, "notifications_enabled": False},
        api_key="mock-secret-never-real", persist_key=False)
    yield app, server, clock
    app.close()


def alert(app, name="first", severity="warning", kind="file_suspicious"):
    return app._event(kind, severity, name, {"path": "/bounded-fixture/"+name})


def test_new_defaults_do_not_raise_old_profile_budgets(tmp_path):
    cfg = ConfigManager(tmp_path)
    assert cfg.load()["cloud_per_hour"] == 1200
    cfg.config_path.write_text('{"cloud_enabled": true, "cloud_per_hour": 4}', encoding="utf-8")
    assert cfg.load()["cloud_per_hour"] == 4
    cfg.save({"cloud_analysis_interval_seconds": 10})
    assert cfg.load()["cloud_per_hour"] == 4
    cfg.config_path.write_text('{"cloud_enabled": true}', encoding="utf-8")
    assert cfg.load()["cloud_per_hour"] == 4


@pytest.mark.parametrize("patch", [{"cloud_analysis_interval_seconds": 9}, {"cloud_analysis_interval_seconds": 3601},
    {"cloud_analysis_interval_seconds": True}, {"cloud_heartbeat_enabled": 1}, {"cloud_adaptive_enabled": "yes"},
    {"cloud_per_hour": 20001}, {"denied_remote_ips": ["10.0.0.0/8"]}])
def test_invalid_soc_settings_rejected(patch):
    with pytest.raises(ValueError): validate_config(patch)


def test_ten_second_heartbeat_uses_real_sdk_memory_then_odvl_then_sawm(soc):
    app, server, clock = soc
    app.save_settings({"cloud_heartbeat_enabled": True})
    app._snapshot = {"cpu_percent": 12, "memory_percent": 30, "sampled_at": "fixture", "coverage": {"network_access_denied": True}}
    app._background_cycle()
    assert len(server.analyses) == 1
    assert server.analyses[0][0]["kind"] == "soc_heartbeat"
    assert server.analyses[0][0]["details"]["cpu_percent"] == 12
    assert server.analyses[0][0]["details"]["coverage"]["network_access_denied"] is True
    clock.advance(9.99)
    app._background_cycle()
    assert len(server.analyses) == 1
    clock.advance(.01)
    app._background_cycle()
    assert len(server.analyses) == 2
    assert [r.url.path.rsplit("/", 1)[-1] for r in server.requests[:3]] == ["recall:tsst", "odvl:rank", "responses"]
    budget = app.status()["cloud"]["scheduler"]["budget"]
    assert budget["unit"] == "api_requests"
    assert budget["used"] == len(server.requests) == len(app.store.calls(100))
    assert app.store.verify_chain()["ok"]
    assert "mock-secret-never-real" not in json.dumps(app.status())


def test_bursts_batched_deduplicated_and_old_warning_not_starved(soc):
    app, server, clock = soc
    old = alert(app, "old-warning")
    clock.advance(1)
    urgent = [alert(app, f"critical-{i}", "critical") for i in range(8)]
    for _ in range(10): app.store.enqueue_work("review", urgent[0])
    assert app.store.review_stats()["queue_count"] == 9
    app._background_cycle()
    batch = server.analyses[0]
    assert len(batch) == 5
    assert [e["severity"] for e in batch[:4]] == ["critical"]*4
    assert batch[-1]["id"] == old["id"]
    assert app.store.review_stats()["queue_count"] == 4
    for _ in range(10): app._background_cycle()
    assert len(server.analyses) == 1
    clock.advance(10)
    app._background_cycle()
    assert len(server.analyses) == 2
    assert not app.store.review_stats()["queue_count"]
    sent = [event["id"] for batch in server.analyses for event in batch]
    assert len(sent) == len(set(sent)) == 9


def test_adaptive_critical_can_accelerate_but_manual_fixed_cadence_is_respected(soc):
    app, server, clock = soc
    app.save_settings({"cloud_analysis_interval_seconds": 30})
    alert(app)
    app._background_cycle()
    clock.advance(10)
    alert(app, "critical", "critical")
    assert app.scheduler.status(app.settings())["effective_interval_seconds"] == 10
    app._background_cycle()
    assert len(server.analyses) == 2
    app.save_settings({"cloud_adaptive_enabled": False})
    alert(app, "another-critical", "critical")
    clock.advance(10)
    app._background_cycle()
    assert len(server.analyses) == 2
    clock.advance(20)
    app._background_cycle()
    assert len(server.analyses) == 3


def test_idle_no_heartbeat_does_not_invent_analysis_and_opt_out_blocks_cloud(soc):
    app, server, clock = soc
    app._background_cycle()
    assert not server.analyses
    assert app.scheduler.status(app.settings())["state"] == "idle"
    app.save_settings({"cloud_upload_enabled": False, "cloud_heartbeat_enabled": True})
    before = len(server.requests)
    alert(app)
    clock.advance(100)
    app._background_cycle()
    assert len(server.requests) == before
    assert app.store.review_stats()["queue_count"] == 1
    assert app.status()["cloud"]["scheduler"]["state"] == "disabled"


def test_failure_backoff_survives_restart_upload_independent_and_recovers(soc):
    app, server, clock = soc
    proof = alert(app)
    server.fail_analysis = True
    app._background_cycle()
    assert len(server.analyses) == 1
    assert proof["id"] not in {e["id"] for e in app.store.pending()}
    assert app.store.review_stats()["queue_count"] == 1
    app.scheduler = SOCScheduler(app.store, clock=clock)
    assert app.scheduler.status(app.settings())["state"] == "backoff"
    clock.advance(9)
    app._background_cycle()
    assert len(server.analyses) == 1
    clock.advance(1)
    app._background_cycle()
    assert len(server.analyses) == 2
    clock.advance(10)
    app._background_cycle()
    assert len(server.analyses) == 2  # Second failure doubles the delay.
    server.fail_analysis = False
    clock.advance(10)
    app._background_cycle()
    assert len(server.analyses) == 3
    assert app.scheduler.status(app.settings())["consecutive_failures"] == 0
    assert app.store.review_stats()["queue_count"] == 0


def test_budget_is_per_http_request_not_high_level_analysis(soc):
    app, server, clock = soc
    app.save_settings({"cloud_per_hour": 4})
    proof = alert(app)
    result = app.analyze(proof["id"])
    assert result["memory"]["odvl_order_applied"]
    assert len(server.requests) == 3
    with pytest.raises(CloudBudgetExceeded): app.check_connection()
    assert len(server.requests) == 4
    assert app.store.cloud_budget(4)["used"] == 4
    with pytest.raises(CloudBudgetExceeded): app.check_connection()
    assert len(server.requests) == 4
    assert len(app.store.calls()) == 4
    app._background_cycle()
    assert len(server.requests) == 4
    assert app.scheduler.status(app.settings())["state"] == "budget_exhausted"
    clock.advance(3601)
    app._background_cycle()
    assert len(server.analyses) == 2


def test_budget_atomic_across_service_instances_and_requests(tmp_path):
    a, b = Store(tmp_path), Store(tmp_path)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda n: (a if n%2 else b).reserve_cloud(7), range(40)))
        assert sum(results) == 7
        assert a.cloud_budget(7)["remaining"] == 0
        assert b.cloud_budget(7)["used"] == 7
    finally:
        a.close(); b.close()


def test_revocation_between_tsst_and_odvl_stops_next_request(soc):
    app, server, _ = soc
    proof = alert(app)
    server.after_recall = lambda: app.config.save({"cloud_upload_enabled": False})
    with pytest.raises(ValueError): app.analyze(proof["id"])
    assert len(server.requests) == 1
    assert app.store.cloud_budget(1200)["used"] == 1


def test_interactive_cloud_operation_prevents_autonomous_overlap(soc):
    app, server, _ = soc
    alert(app)
    app._cloud_lock.acquire()
    try: app._background_cycle()
    finally: app._cloud_lock.release()
    assert not server.requests
    assert app.scheduler.status(app.settings())["last_review_at"] is None
    app._background_cycle()
    assert len(server.analyses) == 1


@pytest.mark.parametrize("kind", ["network_suspicious", "access_policy_changed", "network_port_scan", "network_fanout",
    "network_policy_violation", "access_permission_changed", "ldap_auth_burst", "ldap_access_change"])
def test_new_security_sources_are_reviewed_without_expanding_authority(soc, monkeypatch, kind):
    app, server, _ = soc
    proof = alert(app, kind, "critical", kind)
    server.action = "block_ip"
    app.save_settings({"automatic_actions": ["block_ip"]})
    monkeypatch.setattr(app.executor, "execute", lambda *a: pytest.fail("Unattributed hypothesis cannot authorize a block"))
    app._background_cycle()
    assert server.analyses[0][0]["id"] == proof["id"]
    assert app.store.actions()[0]["status"] == "denied"
    assert app.store.actions()[0]["event_id"] == proof["id"]


def test_scheduler_progress_visible_to_external_gui(soc):
    app, _, clock = soc
    reader = SOCScheduler(app.store, clock=clock)
    proof = alert(app)
    app._background_cycle()
    state = reader.status(app.settings())
    assert state["last_event_ids"] == [proof["id"]]
    assert state["last_success_at"] == clock()


def test_network_and_access_context_preserves_attribution_limits_without_raw_secrets(soc):
    app, server, _ = soc
    proof = app._event("ldap_access_change", "warning", "Modification rapportée", {
        "verification_origin": "untrusted_ldap_text", "actor_attributed": False,
        "automatic_block_eligible": False, "subject_hash": "a"*64,
        "attributes": ["olcaccess"], "operation_result": "reported_success",
        "time_basis": "local_receipt_time", "raw_log": "PRIVATE-RAW-SECRET",
        "before": {"mode": 384, "uid": 1000}, "after": {"mode": 420, "uid": 1000}})
    app.analyze(proof["id"])
    detail = server.analyses[0][0]["details"]
    assert detail["actor_attributed"] is False
    assert detail["automatic_block_eligible"] is False
    assert detail["before"]["mode"] == 384 and detail["after"]["mode"] == 420
    assert detail["time_basis"] == "local_receipt_time"
    assert "PRIVATE-RAW-SECRET" not in json.dumps(server.analyses)


def test_transport_close_failure_cannot_strand_operation_locks(soc, monkeypatch):
    app, server, _ = soc
    original = CloudBridge.close
    def fail_close(self):
        original(self)
        raise OSError("simulated shutdown failure")
    monkeypatch.setattr(CloudBridge, "close", fail_close)
    with pytest.raises(OSError): app.check_connection()
    assert not app._cloud_lock.locked()
    assert app._operation_lock.file is None
    monkeypatch.setattr(CloudBridge, "close", original)
    assert app.check_connection()["status"] == "connected"
    assert len(server.requests) == app.store.cloud_budget(1200)["used"] == 4


def test_action_mandate_revoked_while_judge_runs_is_respected(soc, monkeypatch):
    app, server, _ = soc
    app.save_settings({"automatic_actions": ["quarantine"]})
    proof = app._event("antivirus_detection", "critical", "Test detection", {
        "verification_origin": "local_scanner", "scan_status": "detected", "sha256": "a"*64, "engine": "test"})
    server.action = "quarantine"
    server.before_answer = lambda: app.config.save({"automatic_actions": []})
    monkeypatch.setattr(app.executor, "execute", lambda *a: pytest.fail("Revoked mandate must stop execution"))
    result = app.analyze(proof["id"])
    assert result["action"] == "quarantine"
    assert result["execution"]["status"] == "denied"
    assert not app.config.load()["automatic_actions"]


def test_another_service_cannot_overlap_request_on_same_profile(soc):
    app, server, _ = soc
    other = service.AgentService(app.state_dir)
    try:
        def attempt_overlap():
            with pytest.raises(ValueError, match="déjà en cours"):
                other.check_connection()
        server.after_recall = attempt_overlap
        app.check_connection()
        assert len(server.requests) == 2
        assert app.store.cloud_budget(1200)["used"] == 2
        assert not other._cloud_lock.locked()
        server.after_recall = None
        assert other.check_connection()["status"] == "connected"
    finally:
        other.close()
