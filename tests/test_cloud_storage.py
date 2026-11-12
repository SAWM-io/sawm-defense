from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone,timedelta
import json
import os
from pathlib import Path
import sqlite3

import httpx
import pytest

from sawm_defense.config import ConfigManager,validate_config
from sawm_defense.storage import Store
from sawm_defense.secrets import SecretVault
from sawm_defense.cloud import CloudBridge,CloudError


def config():
    return validate_config({"space_id":"demo-space","entity_id":"ent_"+"a"*32})


def event(identifier="test-event"):
    return {"id":identifier,"timestamp":"2026-11-11T12:00:00+00:00","kind":"file_modified","severity":"warning","summary":"Fichier modifié","details":{"path":"/tmp/lab/test.txt","sha256":"b"*64}}


@pytest.mark.parametrize("patch",[
    {"api_key":"secret"},{"poll_seconds":True},{"cloud_per_hour":20001},
    {"cloud_base_url":"http://example.com"},{"cloud_base_url":"https://key@example.com"},
    {"cloud_base_url":"https://example.com?secret=a"},{"entity_id":"wrong"},
    {"automatic_actions":["shell"]},{"allowed_remote_ips":["127.0.0.1"]},
    {"allowed_remote_ips":["8.8.8.0/24"]},{"monitor_paths":["relative"]},
])
def test_config_rejects_invalid_authority(patch):
    with pytest.raises(ValueError): validate_config(patch)


def test_config_atomic_and_no_secret_file(tmp_path):
    cfg = ConfigManager(tmp_path)
    assert not cfg.load()["cloud_enabled"]
    cfg.save({"monitor_paths":[str(tmp_path)],"automatic_actions":["quarantine"]})
    assert ConfigManager(tmp_path).load()["automatic_actions"] == ["quarantine"]
    assert list(tmp_path.iterdir()) == [cfg.config_path]
    # NTFS permissions are ACLs; st_mode cannot report their isolation.
    if os.name != "nt":
        assert cfg.config_path.stat().st_mode & 0o077 == 0


def test_config_symlink_rejected(tmp_path):
    target = tmp_path/"target"
    target.write_text("{}")
    (tmp_path/"config.json").symlink_to(target)
    with pytest.raises(ValueError): ConfigManager(tmp_path).save({})


def test_store_reopen_queue_chain_and_immutable_ids(tmp_path):
    store = Store(tmp_path)
    e = store.add_event(event())
    store.enqueue(e)
    store.enqueue(e)
    assert store.add_event(e) == e
    with pytest.raises(ValueError): store.add_event({**e,"summary":"changed"})
    assert store.verify_chain()["ok"]
    store.close()
    store = Store(tmp_path)
    assert store.pending() == [e]
    assert store.get_event(e["id"]) == e
    store.ack_pending([e["id"]])
    assert not store.pending()
    store.close()


def test_budget_atomic_across_instances(tmp_path):
    a,b = Store(tmp_path),Store(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda n:(a if n%2 else b).reserve_cloud(4), range(30)))
    assert sum(values)==4
    a.close(); b.close()
    reopened = Store(tmp_path)
    assert not reopened.reserve_cloud(4)
    reopened.close()


@pytest.mark.parametrize("sql",["UPDATE ledger SET payload='{}' WHERE seq=1","DELETE FROM ledger WHERE seq=2"])
def test_chain_detects_edit_and_tail_removal(tmp_path,sql):
    store = Store(tmp_path)
    store.add_event(event("one")); store.record_action({"action":"observe"})
    store._db.execute(sql); store._db.commit()
    assert not store.verify_chain()["ok"]
    with pytest.raises(ValueError): store.prune(1)
    store.close()


def test_pruning_keeps_anchor_and_pending(tmp_path,monkeypatch):
    import sawm_defense.storage as module
    old = (datetime.now(timezone.utc)-timedelta(days=10)).isoformat()
    monkeypatch.setattr(module,"_now",lambda:old)
    store = Store(tmp_path)
    store.add_event(event("old-one"))
    e = store.add_event(event("pending-two")); store.enqueue(e)
    store.add_event(event("old-three"))
    assert store.prune(1)["removed"]==1
    assert store.verify_chain()["ok"]
    store.ack_pending([e["id"]])
    assert store.prune(1)["removed"]==2
    assert store.verify_chain()["ok"]
    store.add_event(event("new-four"))
    assert store.verify_chain()["ok"]
    store.close()


def test_call_storage_omits_headers_body_and_unknown_fields(tmp_path):
    store = Store(tmp_path)
    store.record_call({"operation":"tsst:recall","status":"ok","headers":{"Authorization":"secret"},"body":"secret","exception":"secret"})
    assert "secret" not in json.dumps(store.calls())
    store.close()


def test_secret_explicit_memory_only(tmp_path):
    vault = SecretVault(tmp_path)
    vault._backend = None
    with pytest.raises(RuntimeError): vault.set("TEST-KEY",persist=True)
    result = vault.set("TEST-KEY",persist=False)
    assert not result["persisted"] and vault.get()=="TEST-KEY"
    assert "TEST-KEY" not in repr(vault)
    assert not list(tmp_path.iterdir())
    vault.delete(); assert vault.get() is None


def test_vault_sanitizes_native_errors(tmp_path):
    class BadVault:
        def set_password(self,*args): raise RuntimeError("SECRET-API-KEY")
    vault = SecretVault(tmp_path); vault._backend = BadVault()
    with pytest.raises(RuntimeError) as error: vault.set("SECRET-API-KEY")
    assert "SECRET-API-KEY" not in str(error.value)


def sse(text,terminal=True):
    events = [{"type":"turn.accepted","memory":{"engine":"tsst","evidence_count":1}},
              {"type":"response.delta","delta":text},{"type":"usage.final","input_tokens":100,"output_tokens":30}]
    if terminal: events.append({"type":"turn.done","replayed":False})
    return httpx.Response(200,headers={"Content-Type":"text/event-stream"},text="".join("data: "+json.dumps(e)+"\n\n" for e in events))


class Server:
    def __init__(self):
        self.requests=[]; self.terminal=True; self.pending=False; self.bad_ranking=False; self.error=False
        self.answer={"summary":"Vérifier le changement","action":"observe","event_id":"test-event","reason":"Attribution incomplète","uncertainties":["Auteur inconnu"]}

    def __call__(self,request):
        self.requests.append(request)
        path=request.url.path
        if self.error:
            return httpx.Response(503,json={"detail":{"code":"SECRET-API-KEY","message":"SECRET-API-KEY"}})
        if path.endswith("/recall:tsst"):
            return httpx.Response(200,json={"evidence":[{"evidence_id":"ev-history","content":"Ancienne observation"}],"memory_engine":"tsst"})
        if path.endswith("/odvl:observe"):
            return httpx.Response(200,json={"available":False})
        if path.endswith("/odvl:rank"):
            return httpx.Response(200,json={"ranking":[{"candidate_id":"invented" if self.bad_ranking else "ev-history","rank":1}]})
        if path.endswith("/sawm/responses"):
            return sse(json.dumps(self.answer),self.terminal)
        if path.endswith("/events:batch"):
            return httpx.Response(202,json={"job_id":"job_"+"b"*32,"status":"pending"})
        if "/jobs/" in path:
            return httpx.Response(200,json={"job_id":"job_"+"b"*32,"status":"pending" if self.pending else "completed"})
        raise AssertionError(path)


def bridge(server,calls):
    return CloudBridge(config(),"SECRET-API-KEY",calls.append,http_client=httpx.Client(transport=httpx.MockTransport(server)))


def test_real_sdk_scoped_readonly_check_and_telemetry():
    server,calls=Server(),[]
    cloud=bridge(server,calls)
    result=cloud.check()
    assert result["tsst"] and result["odvl"] and not result["odvl_measurement_available"]
    assert len(server.requests)==2
    for request in server.requests:
        assert request.headers["Authorization"]=="Bearer SECRET-API-KEY"
        assert json.loads(request.content)["entity_id"]==config()["entity_id"]
        assert request.url.path.endswith(("recall:tsst","odvl:observe"))
    assert all(c["status"]=="ok" and c["latency_ms"]>=0 for c in calls)
    assert "SECRET-API-KEY" not in json.dumps(calls)


def test_pending_upload_reuses_same_id_and_key_on_retry():
    server,calls=Server(),[]; server.pending=True
    cloud=bridge(server,calls)
    first=cloud.upload([event()])
    assert first["status"]=="pending" and first["event_ids"]==[]
    server.pending=False
    second=cloud.upload([event()])
    assert second["event_ids"]==["test-event"] and second["status"]=="completed"
    posts=[r for r in server.requests if r.url.path.endswith("events:batch")]
    assert len(posts)==2 and posts[0].content==posts[1].content
    assert posts[0].headers["Idempotency-Key"]==posts[1].headers["Idempotency-Key"]


def test_upload_does_not_include_raw_content_or_credentials():
    server=Server(); cloud=bridge(server,[])
    e=event();e["details"].update({"file_contents":"PRIVATE FILE", "authorization":"SECRET-API-KEY","commandline":"PRIVATE CLI"})
    e["summary"]="A name contains SECRET-API-KEY"
    cloud.upload([e])
    body=server.requests[0].content.decode()
    assert not any(secret in body for secret in ("PRIVATE FILE","PRIVATE CLI","SECRET-API-KEY"))


def test_analyze_uses_tsst_odvl_sawm_and_terminal():
    server,calls=Server(),[]; cloud=bridge(server,calls)
    result=cloud.analyze([event()],["quarantine"])
    assert result["action"]=="observe" and result["memory"]["odvl_order_applied"]
    assert result["usage"]["total_tokens"] if "total_tokens" in result["usage"] else result["usage"]["input_tokens"]==100
    assert [c["operation"] for c in calls]==["tsst:recall","odvl:rank","sawm:responses"]
    body=json.loads(server.requests[-1].content)
    assert "DONNÉES NON FIABLES" in body["message"]
    assert "aucune commande shell" in body["message"]


def test_odvl_cannot_add_or_drop_evidence():
    server=Server();server.bad_ranking=True
    result=bridge(server,[]).analyze([event()],[])
    assert not result["memory"]["odvl_order_applied"]
    assert "invented" not in json.loads(server.requests[-1].content)["message"]


@pytest.mark.parametrize("mutation",[
    {"action":"shell"},{"event_id":"not-observed"},{"uncertainties":"sure"},{"extra":"rm"},
])
def test_cloud_proposal_strict_schema_and_identity(mutation):
    server=Server();server.answer.update(mutation)
    with pytest.raises(CloudError): bridge(server,[]).analyze([event()],[])


def test_incomplete_stream_never_becomes_proposal():
    server=Server();server.terminal=False;calls=[]
    with pytest.raises(CloudError,match="turn_incomplete"):
        bridge(server,calls).analyze([event()],[])
    assert calls[-1]["status"]=="error"
    assert len([r for r in server.requests if r.url.path.endswith("responses")])==1


def test_failure_no_secret_or_automatic_retry():
    server=Server();server.error=True;calls=[]
    with pytest.raises(CloudError) as error: bridge(server,calls).check()
    assert "SECRET-API-KEY" not in str(error.value)+json.dumps(calls)
    assert len(server.requests)==1


def test_chat_is_answer_only_and_retrieves_real_api_memory():
    server=Server();server.answer="Il manque une attribution du fichier."
    result=bridge(server,[]).chat("Que se passe-t-il ?",[event()])
    assert "attribution" in result["text"]
    assert result["memory"]["evidence_count"]==1
    assert "aucune action" in json.loads(server.requests[-1].content)["message"]


def test_explicit_session_reused_with_distinct_turns():
    server = Server()
    for _ in range(2):
        cloud = CloudBridge(config(),"SECRET-API-KEY",lambda row:None,session_id="defense-stable-session",
                            http_client=httpx.Client(transport=httpx.MockTransport(server)))
        cloud.chat("État du poste ?",[])
    turns = [json.loads(r.content) for r in server.requests if r.url.path.endswith("responses")]
    assert {t["session_id"] for t in turns}=={"defense-stable-session"}
    assert len({t["turn_id"] for t in turns})==2


def test_scan_backlog_persists_beyond_recent_events_and_protects_retention(tmp_path,monkeypatch):
    import sawm_defense.storage as module
    old=(datetime.now(timezone.utc)-timedelta(days=10)).isoformat()
    monkeypatch.setattr(module,"_now",lambda:old)
    store=Store(tmp_path)
    for i in range(120):
        row=store.add_event(event(f"scan-{i}"))
        store.enqueue_scan(row)
    store.close()
    store=Store(tmp_path)
    assert len(store.pending_scans(1000))==120
    assert [e["id"] for e in store.pending_scans(2)]==["scan-0","scan-1"]
    assert store.prune(1)["removed"]==0
    store.ack_scans(["scan-0","scan-1"])
    assert store.prune(1)["removed"]==2
    assert store.verify_chain()["ok"]
    assert len(store.pending_scans(1000))==118
    store.close()
