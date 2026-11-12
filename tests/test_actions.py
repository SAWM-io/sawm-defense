import hashlib
import os
import subprocess
import sys
import time
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sawm_defense.actions import ActionExecutor
from sawm_defense import actions
from sawm_defense.platforms import file_digest


@pytest.fixture
def setup(tmp_path):
    folder = tmp_path / "watched"
    folder.mkdir()
    file = folder / "sample.bin"
    file.write_bytes(b"safe fixture")
    config = {"monitor_paths": [str(folder)], "max_file_mb": 1, "protected_paths": []}
    event = {"id": "ev-1", "details": {"path": str(file), "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}}
    return ActionExecutor(tmp_path / "state"), config, event, file


def test_real_quarantine_restore(setup):
    executor, config, event, file = setup
    receipt = executor.execute("quarantine", event, config)
    assert receipt["status"] == "completed"
    assert not file.exists()
    isolated = Path(receipt["quarantine_path"])
    assert isolated.read_bytes() == b"safe fixture"
    restored = executor.restore(receipt, config)
    assert restored["status"] == "completed"
    assert file.read_bytes() == b"safe fixture"
    assert not isolated.exists()


def test_unicode_path_quarantine_restore_with_legacy_windows_locale(setup, monkeypatch):
    executor, config, event, old_path = setup
    file = old_path.rename(old_path.with_name("資料-عقد.pdf"))
    event["details"]["path"] = str(file)
    fdopen, read_text = os.fdopen, Path.read_text

    def legacy_open(fd, mode="r", *args, **kwargs):
        if "b" not in mode and not args:
            kwargs.setdefault("encoding", "cp1252")
        return fdopen(fd, mode, *args, **kwargs)

    def legacy_read(path, *args, **kwargs):
        if not args:
            kwargs.setdefault("encoding", "cp1252")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", legacy_open)
    monkeypatch.setattr(Path, "read_text", legacy_read)
    receipt = executor.execute("quarantine", event, config)
    assert receipt["status"] == "completed", receipt
    assert not file.exists()
    restored = executor.restore(receipt, config)
    assert restored["status"] == "completed", restored
    assert file.read_bytes() == b"safe fixture"


def test_hash_change_blocks_response(setup):
    executor, config, event, file = setup
    file.write_bytes(b"other content")
    assert executor.execute("quarantine", event, config)["status"] == "denied"
    assert file.exists()


def test_scope_and_protected_paths(setup):
    executor, config, event, file = setup
    config["monitor_paths"] = []
    assert executor.execute("quarantine", event, config)["status"] == "denied"
    config["monitor_paths"] = [str(file.parent)]
    config["protected_paths"] = [str(file)]
    assert executor.execute("quarantine", event, config)["status"] == "denied"


def test_restore_never_overwrites(setup):
    executor, config, event, file = setup
    receipt = executor.execute("quarantine", event, config)
    file.write_text("new legitimate data")
    assert executor.restore(receipt, config)["status"] == "denied"
    assert file.read_text() == "new legitimate data"


def test_quarantine_rejects_symlink_and_hardlinks(setup):
    executor, config, event, file = setup
    link = file.parent / "alias"
    try:
        link.symlink_to(file)
    except OSError:
        pytest.skip("Windows symlink creation requires Developer Mode or administrative privilege")
    event["details"]["path"] = str(link)
    assert executor.execute("quarantine", event, config)["status"] == "denied"


def test_quarantine_rejects_hardlinks_even_without_symlink_privilege(setup):
    executor, config, event, file = setup
    os.link(file, file.parent / "second-name")
    assert executor.execute("quarantine", event, config)["status"] == "denied"


def test_no_self_termination(setup):
    executor, config, _, _ = setup
    assert executor.execute("terminate", {"details": {"pid": os.getpid()}}, config)["status"] in {"denied", "unsupported"}


def test_ip_requires_global_explicit_scope(setup):
    executor, config, _, _ = setup
    config["allowed_remote_ips"] = ["127.0.0.1"]
    assert executor.execute("block_ip", {"details": {"remote_ip": "127.0.0.1"}}, config)["status"] == "denied"
    assert executor.execute("block_ip", {"details": {"remote_ip": "93.184.216.34"}}, config)["status"] == "denied"


def test_cloud_destination_never_blocked(setup, monkeypatch):
    executor, config, _, _ = setup
    config["allowed_remote_ips"] = ["93.184.216.34"]
    monkeypatch.setattr(actions.socket, "getaddrinfo", lambda *a: [(None, None, None, None, ("93.184.216.34", 443))])
    result = executor.execute("block_ip", {"details": {"remote_ip": "93.184.216.34"}}, config)
    assert result["status"] == "denied"
    assert "Cloud" in result["reason"]


def test_macos_firewall_explicitly_unsupported(setup, monkeypatch):
    executor, config, _, _ = setup
    config["allowed_remote_ips"] = ["93.184.216.34"]
    monkeypatch.setattr(actions.socket, "getaddrinfo", lambda *a: [(None, None, None, None, ("1.2.3.4", 443))])
    monkeypatch.setattr(actions.platform, "system", lambda: "Darwin")
    assert executor.execute("block_ip", {"details": {"remote_ip": "93.184.216.34"}}, config)["status"] == "unsupported"


def test_forged_restore_id_cannot_escape(setup):
    executor, config, _, _ = setup
    assert executor.restore({"receipt_id": "../../outside"}, config)["status"] == "denied"


def test_actual_owned_subprocess_termination_and_pid_identity(setup):
    if not actions.psutil:
        pytest.skip("psutil not installed")
    executor, config, _, _ = setup
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        process = actions.psutil.Process(child.pid)
        exe = str(Path(process.exe()).absolute())
        config["allowed_process_paths"] = [exe]
        event = {"details": {"pid": child.pid, "create_time": process.create_time() + 1,
                             "exe": exe, "exe_sha256": file_digest(Path(exe), 512 * 1024 * 1024)[0]}}
        assert executor.execute("terminate", event, config)["status"] == "denied"
        assert child.poll() is None
        event["details"]["create_time"] = process.create_time()
        result = executor.execute("terminate", event, config)
        assert result["status"] == "completed", result
        child.wait(timeout=5)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_ufw_foreign_rule_is_not_reused_or_deleted(setup, monkeypatch):
    executor, config, _, _ = setup
    config["allowed_remote_ips"] = ["93.184.216.34"]
    monkeypatch.setattr(actions.platform, "system", lambda: "Linux")
    monkeypatch.setattr(executor, "_admin", lambda: True)
    monkeypatch.setattr(actions.socket, "getaddrinfo", lambda *a: [(None, None, None, None, ("1.2.3.4", 443))])
    monkeypatch.setattr(actions.shutil, "which", lambda name: "/usr/sbin/ufw")
    real_read = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda path, **kw: "nameserver 8.8.8.8\n" if path.as_posix() == "/etc/resolv.conf" else real_read(path, **kw))
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="Status: active\n93.184.216.34 DENY IN Anywhere # Existing administrator rule\n")
    monkeypatch.setattr(actions.subprocess, "run", run)
    result = executor.execute("block_ip", {"details": {"remote_ip": "93.184.216.34"}}, config)
    assert result["status"] == "denied"
    assert commands == [["/usr/sbin/ufw", "status"]]


def firewall_stub(executor, monkeypatch, *, mode="normal"):
    """Native helper witness only: no actual firewall or networking mutation."""
    monkeypatch.setattr(actions.platform, "system", lambda: "Linux")
    monkeypatch.setattr(executor, "_admin", lambda: True)
    monkeypatch.setattr(actions.socket, "getaddrinfo", lambda *a: [(None, None, None, None, ("1.2.3.4", 443))])
    monkeypatch.setattr(actions.shutil, "which", lambda name: "/usr/sbin/ufw")
    real_read = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda path, **kw: "nameserver 8.8.8.8\n" if path.as_posix() == "/etc/resolv.conf" else real_read(path, **kw))
    state = {"rules": {}, "calls": [], "mode": mode}
    def run(cmd, **kwargs):
        state["calls"].append(cmd)
        if cmd[1:] == ["status"]:
            text = "Status: active\nTo                         Action      From\n--                         ------      ----\n"
            for direction, (ip, name) in state["rules"].items():
                text += (f"Anywhere                   DENY IN     {ip} # {name}\n" if direction == "in" else f"{ip}      DENY OUT    Anywhere # {name}\n")
            return SimpleNamespace(returncode=0, stdout=text)
        assert "deny" in cmd and "comment" in cmd and not kwargs.get("shell")
        direction = "in" if "in" in cmd else "out"
        ip = cmd[cmd.index("from")+1] if direction == "in" else cmd[cmd.index("to")+1]
        name = cmd[cmd.index("comment")+1]
        if "delete" in cmd:
            if state["mode"] != "cannot_remove":
                state["rules"].pop(direction, None)
        elif not (state["mode"] == "ignore_out" and direction == "out"):
            state["rules"][direction] = (ip,name)
            if state["mode"] == "timeout" and direction == "in":
                raise subprocess.TimeoutExpired(cmd, 10)
        return SimpleNamespace(returncode=0, stdout="ok")
    monkeypatch.setattr(actions.subprocess, "run", run)
    return state


def auth_event():
    return {"id": "ssh-burst", "kind": "auth_bruteforce", "timestamp": actions.utc_now(), "details": {
        "remote_ip": "93.184.216.34", "verified_local": True, "verification_origin": "local_journald",
        "source_kind": "journald", "failure_count": 5, "window_seconds": 300,
        "last_failure_at": actions.utc_now(), "evidence_ids": [str(i) for i in range(5)],
        "producer": {"_UID":"0","_COMM":"sshd","_EXE":"/usr/sbin/sshd","_TRANSPORT":"syslog"}}}


def test_verified_ssh_autoblock_has_durable_expiry_and_verified_rollback(setup, monkeypatch):
    executor, config, _, _ = setup
    config.update({"_automatic_response": True,"autoblock_auth_ips": True,"auto_block_seconds": 120})
    state = firewall_stub(executor,monkeypatch)
    result = executor.execute("block_ip",auth_event(),config)
    assert result["status"] == "completed" and result["verified"]
    assert 110 < result["expires_at"] - time.time() <= 120
    disk = json.loads((executor.receipts / (result["receipt_id"]+".json")).read_text())
    assert disk["expires_at"] == result["expires_at"]
    assert set(state["rules"]) == {"in","out"}
    assert executor.rollback(result,config)["status"] == "completed"
    assert not state["rules"]
    # Replaying removal after restart is idempotent and verified.
    assert executor.rollback(result,config)["status"] == "completed"


def test_text_spoofed_ssh_cannot_use_auto_scope(setup,monkeypatch):
    executor,config,_,_ = setup
    config.update({"_automatic_response":True,"autoblock_auth_ips":True})
    event=auth_event()
    event["details"]["verification_origin"]="untrusted_auth_text"
    monkeypatch.setattr(actions.subprocess,"run",lambda *a,**k: pytest.fail("Forged evidence must not touch firewall"))
    assert executor.execute("block_ip",event,config)["status"]=="denied"


def test_protected_ip_beats_manual_and_auto_grants(setup):
    executor,config,_,_=setup
    config.update({"allowed_remote_ips":["93.184.216.34"],"protected_remote_ips":["93.184.216.34"]})
    assert executor.execute("block_ip",auth_event(),config)["status"]=="denied"
    config.update({"_automatic_response":True,"autoblock_auth_ips":True})
    assert executor.execute("block_ip",auth_event(),config)["status"]=="denied"


def test_auto_optin_does_not_bypass_manual_ip_scope(setup):
    executor,config,_,_=setup
    config["autoblock_auth_ips"]=True
    assert executor.execute("block_ip",auth_event(),config)["status"]=="denied"


@pytest.mark.parametrize("mode", ["ignore_out","timeout"])
def test_native_zero_exit_or_timeout_not_success_without_two_rules(setup,monkeypatch,mode):
    executor,config,_,_=setup
    config["allowed_remote_ips"]=["93.184.216.34"]
    state=firewall_stub(executor,monkeypatch,mode=mode)
    result=executor.execute("block_ip",auth_event(),config)
    assert result["status"]=="error"
    assert result["receipt_id"] and (executor.receipts/(result["receipt_id"]+".json")).exists()
    assert result["rollback_verified"] is True
    assert not state["rules"]


def test_rollback_failed_native_removal_is_visible(setup,monkeypatch):
    executor,config,_,_=setup
    config["allowed_remote_ips"]=["93.184.216.34"]
    state=firewall_stub(executor,monkeypatch)
    receipt=executor.execute("block_ip",auth_event(),config)
    state["mode"]="cannot_remove"
    result=executor.rollback(receipt,config)
    assert result["status"]=="error" and result["verified"] is False
    assert result["receipt_id"]==receipt["receipt_id"]


def test_ufw_shape_requires_address_direction_and_exact_comment():
    name="SAWM-"+"a"*32
    assert actions._ufw_present(f"Anywhere DENY 93.184.216.34 # {name}\n93.184.216.34 DENY OUT Anywhere # {name}",name,"93.184.216.34")=={"in","out"}
    assert not actions._ufw_present(f"Anywhere ALLOW IN 93.184.216.34 # {name}\nAnywhere DENY IN 93.184.216.35 # {name}",name,"93.184.216.34")
    assert not actions._ufw_present(f"Anywhere DENY IN 93.184.216.34 # {name}-other",name,"93.184.216.34")


def test_windows_rule_verification_requires_exact_fields():
    name="SAWM-"+"b"*32
    good=f"Rule Name: {name}-in\nEnabled: Yes\nDirection: In\nAction: Block\nLocalIP: Any\nRemoteIP: 93.184.216.34/32\nProtocol: Any\n"
    assert actions._netsh_present(good,name,"93.184.216.34","in")
    assert not actions._netsh_present(good.replace("93.184.216.34/32","93.184.216.0/24"),name,"93.184.216.34","in")
    assert not actions._netsh_present(good.replace("Block","Allow"),name,"93.184.216.34","in")
    assert not actions._netsh_present("Ok.",name,"93.184.216.34","in")


def test_windows_native_rule_roundtrip_uses_scoped_argv(setup,monkeypatch):
    executor,config,_,_=setup
    config["allowed_remote_ips"]=["93.184.216.34"]
    monkeypatch.setattr(actions.platform,"system",lambda:"Windows")
    monkeypatch.setattr(executor,"_admin",lambda:True)
    monkeypatch.setattr(actions.socket,"getaddrinfo",lambda *a:[(None,None,None,None,("1.2.3.4",443))])
    installed={}
    commands=[]
    def run(cmd,**kwargs):
        commands.append(cmd)
        assert not kwargs.get("shell")
        if cmd[0]=="powershell.exe":
            return SimpleNamespace(returncode=0,stdout="8.8.8.8\n")
        if cmd[1:]==["advfirewall","show","allprofiles","state"]:
            return SimpleNamespace(returncode=0,stdout="State ON\nState ON\nState ON\n")
        assert cmd[:3]==["netsh","advfirewall","firewall"]
        name=next(item[5:] for item in cmd if item.startswith("name="))
        direction=name.rsplit("-",1)[1]
        if cmd[3]=="add":
            assert "remoteip=93.184.216.34" in cmd and "action=block" in cmd
            installed[name]=direction
            return SimpleNamespace(returncode=0,stdout="Ok.\n")
        if cmd[3]=="delete":
            installed.pop(name,None)
            return SimpleNamespace(returncode=0,stdout="Ok.\n")
        assert cmd[3]=="show"
        if name not in installed:
            return SimpleNamespace(returncode=1,stdout="No rules match the specified criteria.\n")
        return SimpleNamespace(returncode=0,stdout=f"Rule Name: {name}\nEnabled: Yes\nDirection: {direction}\nAction: Block\nLocalIP: Any\nRemoteIP: 93.184.216.34/32\nProtocol: Any\n")
    monkeypatch.setattr(actions.subprocess,"run",run)
    receipt=executor.execute("block_ip",auth_event(),config)
    assert receipt["status"]=="completed" and receipt["verified"]
    assert len(installed)==2
    result=executor.rollback(receipt,config)
    assert result["status"]=="completed" and result["verified"]
    assert not installed
    assert all("all" not in cmd for cmd in commands)


def network_policy_event():
    ip = "93.184.216.34"
    return {"id": "network-policy", "kind": "network_policy_violation", "timestamp": actions.utc_now(), "details": {
        "remote_ip": ip, "remote_port": 443, "verified_local": True, "verification_origin": "local_psutil_socket",
        "policy_violation": True, "policy_rule": "denied_remote_ips", "policy_value": ip,
        "observed_at": actions.utc_now(), "evidence_ids": ["a" * 64]}}


def test_explicit_network_policy_uses_existing_verified_expiring_firewall_path(setup, monkeypatch):
    executor, config, _, _ = setup
    config.update({"_automatic_response": True, "autoblock_network_policy": True,
                   "denied_remote_ips": ["93.184.216.34"], "allowed_remote_ips": ["93.184.216.34"],
                   "auto_block_seconds": 120})
    state = firewall_stub(executor, monkeypatch)
    result = executor.execute("block_ip", network_policy_event(), config)
    assert result["status"] == "completed" and result["verified"]
    assert set(state["rules"]) == {"in", "out"}
    assert 110 < result["expires_at"] - time.time() <= 120
    assert executor.rollback(result, config)["status"] == "completed"
    assert not state["rules"]


@pytest.mark.parametrize("patch", [{"allowed_remote_ips": []}, {"denied_remote_ips": []},
                                  {"autoblock_network_policy": False}, {"protected_remote_ips": ["93.184.216.34"]}])
def test_network_auto_response_rechecks_policy_without_touching_firewall(setup, monkeypatch, patch):
    executor, config, _, _ = setup
    config.update({"_automatic_response": True, "autoblock_network_policy": True,
                   "denied_remote_ips": ["93.184.216.34"], "allowed_remote_ips": ["93.184.216.34"], **patch})
    monkeypatch.setattr(actions.subprocess, "run", lambda *a, **k: pytest.fail("Revoked network policy must not reach firewall"))
    assert executor.execute("block_ip", network_policy_event(), config)["status"] == "denied"
