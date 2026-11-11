"""Service-level consent and restart checks, with no real keys/network/antivirus."""
import threading

import pytest

from sawm_defense import service


class MemoryVault:
    values = {}

    def __init__(self, state_dir):
        self.identity = str(state_dir)

    def get(self):
        return self.values.get(self.identity)

    def set(self, value, persist=True):
        if value == "simulate-vault-failure":
            raise RuntimeError("Coffre indisponible")
        self.values[self.identity] = value
        return {"persisted": True,"backend":"test-vault"}


@pytest.fixture
def agent(tmp_path,monkeypatch):
    MemoryVault.values.clear()
    monkeypatch.setattr(service,"SecretVault",MemoryVault)
    app = service.AgentService(tmp_path/"state")
    yield app
    app.close()


def configure(app,**patch):
    config = {"space_id":"app-demo","entity_id":"ent_"+"a"*32,
              "cloud_enabled":True,"cloud_upload_enabled":True,"cloud_per_hour":120}
    config.update(patch)
    app.save_settings(config,api_key="fake-service-key",persist_key=True)


def one_background_cycle(app):
    class Wake:
        count=0
        def wait(self,timeout=None):
            self.count+=1
            if self.count>1: app._stop.set()
        def clear(self): pass
        def set(self): pass
    old=app._wake
    app._wake=Wake(); app._stop.clear()
    try: app._background()
    finally: app._wake=old; app._stop.clear()


def test_failed_new_key_cannot_persist_an_endpoint_with_old_credential(agent):
    configure(agent,cloud_upload_enabled=False)
    before=agent.config.load()
    with pytest.raises(RuntimeError):
        agent.save_settings({"cloud_base_url":"https://new-cloud.example/api/v1/basira"},api_key="simulate-vault-failure")
    assert agent.config.load()==before
    reopened=service.AgentService(agent.state_dir)
    try:
        assert reopened.settings()["cloud_base_url"]==before["cloud_base_url"]
    finally: reopened.close()


def test_cloud_endpoint_change_never_reuses_old_key(agent):
    configure(agent,cloud_upload_enabled=False)
    agent.save_settings({"cloud_base_url":"https://different-cloud.example/api/v1/basira"})
    assert not agent.status()["cloud"]["configured"]
    reopened=service.AgentService(agent.state_dir)
    try:
        assert not reopened.status()["cloud"]["configured"]
    finally: reopened.close()


def test_background_cloud_off_leaves_observations_local(agent,monkeypatch):
    configure(agent,cloud_enabled=False)
    e=agent._event("file_modified","warning","Fichier local",{"path":"/tmp/demo"})
    monkeypatch.setattr(service,"CloudBridge",lambda *a,**kw:pytest.fail("Cloud désactivé"))
    one_background_cycle(agent)
    assert e["id"] in {v["id"] for v in agent.store.pending()}
    assert agent.store.verify_chain()["ok"]


def test_background_resume_after_failure_and_restart_acknowledges_only_confirmed(agent,monkeypatch):
    configure(agent)
    e=agent._event("file_modified","warning","Fichier modifié",{"path":"/tmp/demo"})
    sent=[]
    class Offline:
        def __init__(self,*a,**kw): pass
        def upload(self,events):
            sent.extend(row["id"] for row in events)
            raise RuntimeError("offline")
        def close(self): pass
    monkeypatch.setattr(service,"CloudBridge",Offline)
    initial={v["id"] for v in agent.store.pending()}
    one_background_cycle(agent)
    assert {v["id"] for v in agent.store.pending()}==initial
    reopened=service.AgentService(agent.state_dir)
    class Online(Offline):
        def upload(self,events):
            sent.extend(row["id"] for row in events)
            return {"status":"pending","event_ids":[e["id"]]}
    monkeypatch.setattr(service,"CloudBridge",Online)
    try:
        one_background_cycle(reopened)
        assert {v["id"] for v in reopened.store.pending()}==initial-{e["id"]}
        assert sent.count(e["id"])==2
        assert reopened.store.verify_chain()["ok"]
    finally: reopened.close()


def test_chat_without_upload_consent_has_no_observation_context(agent,monkeypatch):
    configure(agent,cloud_upload_enabled=False)
    agent._event("private","warning","PRIVATE HOST DETAILS")
    observed={}
    class Cloud:
        def __init__(self,*a,**kw): pass
        def chat(self,message,events):
            observed.update(message=message,events=events)
            return {"text":"Réponse","usage":{},"memory":{}}
        def close(self): pass
    monkeypatch.setattr(service,"CloudBridge",Cloud)
    agent.chat("Bonjour")
    assert observed=={"message":"Bonjour","events":[]}
    assert not agent.store.pending()
    with pytest.raises(ValueError): agent.analyze()


def test_destination_change_denied_while_cloud_operation_in_flight(agent):
    configure(agent,cloud_upload_enabled=False)
    agent._cloud_lock.acquire()
    try:
        with pytest.raises(ValueError):
            agent.save_settings({"cloud_base_url":"https://new-cloud.example"},api_key="new-test-key")
    finally: agent._cloud_lock.release()


def test_offline_mode_still_prunes_journal(agent,monkeypatch):
    calls=[]
    monkeypatch.setattr(agent.store,"prune",lambda days:calls.append(days) or {"removed":0})
    # Maintenance moved to the independent local response worker.
    stop = agent._stop
    class SingleCycle:
        stopped = False
        def is_set(self): return self.stopped
        def wait(self, *_): self.stopped = True
    agent._stop = SingleCycle()
    try: agent._responses()
    finally: agent._stop = stop
    assert calls==[agent.settings()["retention_days"]]


def test_more_than_two_files_are_not_permanently_skipped(agent,monkeypatch,tmp_path):
    agent.save_settings({"automatic_actions":[], "automatic_scan_enabled":True, "monitor_paths":[str(tmp_path)], "protect_downloads":False})
    paths=[]
    for i in range(3):
        path=tmp_path/f"file-{i}.txt";path.write_text("safe");paths.append(str(path))
        agent._event("file_created","info","Nouveau fichier",{"path":str(path)})
    scanned=[]
    monkeypatch.setattr(agent,"scan",lambda path:scanned.append(str(path)) or {"status":"no_indicator"})
    monkeypatch.setattr(agent._stable_files,"ready",lambda *a:True)
    agent._scan_pending()
    agent._scan_pending()
    assert sorted(scanned)==sorted(paths)


def test_daemon_respects_permission_revoked_by_another_application(agent,monkeypatch):
    agent.save_settings({"automatic_actions":["quarantine"]})
    proof=agent._event("antivirus_detection","critical","Détection locale",
                       {"verification_origin":"local_scanner","scan_status":"detected","sha256":"a"*64,"engine":"test"})
    # A separate UI process changes the durable mandate between sampling cycles.
    agent.config.save({"automatic_actions":[]})
    monkeypatch.setattr(agent.executor,"execute",lambda *a:pytest.fail("Révocation ignorée"))
    assert agent.act("quarantine",proof["id"])["status"]=="denied"


def test_daemon_refreshes_rotated_native_key_before_request(agent,monkeypatch):
    configure(agent,cloud_upload_enabled=False)
    MemoryVault.values[agent.vault.identity]="rotated-test-key"
    used=[]
    class Cloud:
        def __init__(self,settings,key,*args,**kwargs): used.append(key)
        def check(self): return {"status":"connected"}
        def close(self): pass
    monkeypatch.setattr(service,"CloudBridge",Cloud)
    agent.check_connection()
    assert used==["rotated-test-key"]


def test_durable_upload_consent_revocation_applies_before_cloud_call(agent,monkeypatch):
    configure(agent)
    proof=agent._event("private","warning","PRIVATE HOST DETAILS")
    agent.config.save({"cloud_upload_enabled":False})
    monkeypatch.setattr(service,"CloudBridge",lambda *a,**kw:pytest.fail("Métadonnées envoyées après révocation"))
    with pytest.raises(ValueError): agent.analyze(proof["id"])


def test_chat_cannot_attach_stale_context_after_consent_revocation(agent,monkeypatch):
    configure(agent)
    agent._event("private","warning","PRIVATE HOST DETAILS")
    agent.config.save({"cloud_upload_enabled":False})
    attached=[]
    class Cloud:
        def __init__(self,*args,**kwargs): pass
        def chat(self,message,events):
            attached.extend(events)
            return {"text":"Réponse","usage":{},"memory":{}}
        def close(self): pass
    monkeypatch.setattr(service,"CloudBridge",Cloud)
    try: agent.chat("Bonjour")
    except ValueError: pass  # Refuse or strip context; either respects revocation.
    assert attached==[]


def test_failed_judge_does_not_starve_evidence_upload(agent,monkeypatch):
    configure(agent)
    proof=agent._event("file_suspicious","warning","Local metadata indicator",{"path":"/tmp/fixture"})
    delivered=[]
    class Cloud:
        def __init__(self,*a,**kw): pass
        def upload(self,events):
            delivered.extend(e["id"] for e in events)
            return {"event_ids":[e["id"] for e in events],"status":"completed"}
        def analyze(self,*a): raise RuntimeError("Judge unavailable")
        def close(self): pass
    monkeypatch.setattr(service,"CloudBridge",Cloud)
    agent._review_first=True
    one_background_cycle(agent)
    assert proof["id"] in delivered
    assert agent.store.pending_work("review")[0]["id"]==proof["id"]


def test_daemon_discovers_first_key_added_after_start(agent,monkeypatch):
    agent.save_settings({"space_id":"app-demo","entity_id":"ent_"+"a"*32,
                         "cloud_enabled":True,"cloud_upload_enabled":True,"cloud_per_hour":10})
    assert agent._key is None
    ui=service.AgentService(agent.state_dir)
    try: ui.save_settings({},api_key="first-test-key")
    finally: ui.close()
    calls=[]
    class Cloud:
        def __init__(self,settings,key,*args,**kwargs): calls.append(key)
        def upload(self,events): return {"status":"completed","event_ids":[e["id"] for e in events]}
        def close(self): pass
    monkeypatch.setattr(service,"CloudBridge",Cloud)
    one_background_cycle(agent)
    assert calls==["first-test-key"]
