import hashlib
import os
import subprocess
import sys
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
