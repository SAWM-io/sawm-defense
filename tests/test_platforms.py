from pathlib import Path
from types import SimpleNamespace

import pytest

from sawm_defense.platforms import Collector, file_digest
from sawm_defense.antivirus import Antivirus
from sawm_defense import autorun


def test_file_changes_and_scoped_hash(tmp_path):
    folder = tmp_path / "files"
    folder.mkdir()
    item = folder / "invoice.txt"
    item.write_text("before")
    collector = Collector({"monitor_paths": [str(folder)], "max_file_mb": 1})
    initial, _ = collector._file_observations()
    assert initial == []
    item.write_text("after changed")
    events, coverage = collector._file_observations()
    assert events[0]["kind"] == "file_modified"
    assert events[0]["details"]["sha256"] == file_digest(item)[0]
    assert events[0]["details"]["actor_attributed"] is False
    item.unlink()
    events, _ = collector._file_observations()
    assert events[0]["kind"] == "file_deleted"
    assert coverage["scan_complete"]


def test_scan_does_not_follow_links(tmp_path):
    monitored = tmp_path / "visible"
    monitored.mkdir()
    outside = tmp_path / "secret"
    outside.write_text("private")
    try:
        (monitored / "link").symlink_to(outside)
    except OSError:
        pytest.skip("Windows symlink creation requires Developer Mode or administrative privilege")
    collector = Collector({"monitor_paths": [str(monitored)]})
    _, coverage = collector._file_observations()
    assert not collector._files
    assert coverage["files_skipped"] == 1
    with pytest.raises(ValueError):
        file_digest(monitored / "link")


def test_incomplete_scan_never_invents_deletions(tmp_path):
    for name in ("a", "b"):
        (tmp_path / name).write_text(name)
    collector = Collector({"monitor_paths": [str(tmp_path)]})
    collector._file_observations()
    collector.MAX_FILES = 1
    events, coverage = collector._file_observations()
    assert not events
    assert not coverage["scan_complete"]


def test_clamav_detection_and_error_are_distinct(tmp_path, monkeypatch):
    item = tmp_path / "test.bin"
    item.write_bytes(b"ordinary test")
    scanner = Antivirus()
    monkeypatch.setattr(scanner, "_engine", lambda: ("ClamAV", "/usr/bin/clamscan"))
    outputs = iter([SimpleNamespace(returncode=1, stdout=f"{item}: Example.Test FOUND\n"), SimpleNamespace(returncode=2, stdout="")])
    monkeypatch.setattr("sawm_defense.antivirus.subprocess.run", lambda *a, **k: next(outputs))
    result = scanner.scan(item)
    assert result["status"] == "detected"
    assert result["verified_local"]
    assert result["detections"] == ["Example.Test"]
    assert scanner.scan(item)["status"] == "error"


def test_defender_error_never_becomes_confirmed_malware(tmp_path, monkeypatch):
    item = tmp_path / "item"
    item.write_text("test")
    scanner = Antivirus()
    monkeypatch.setattr(scanner, "_engine", lambda: ("Microsoft Defender", "MpCmdRun.exe"))
    def run(command, **kwargs):
        assert "-DisableRemediation" in command
        return SimpleNamespace(returncode=2, stdout="scan failed")
    monkeypatch.setattr("sawm_defense.antivirus.subprocess.run", run)
    assert scanner.scan(item)["status"] == "error"


def test_antivirus_absence_explicit(monkeypatch, tmp_path):
    scanner = Antivirus()
    monkeypatch.setattr(scanner, "_engine", lambda: (None, None))
    assert scanner.scan(tmp_path / "not-needed")["status"] == "unavailable"
    assert scanner.capabilities()["available"] is False


@pytest.mark.parametrize("system", ["Darwin", "Linux", "Windows"])
def test_startup_plan_is_user_scoped(system, monkeypatch, tmp_path):
    monkeypatch.setattr(autorun.platform, "system", lambda: system)
    plan = autorun.startup_plan(["/trusted/SAWM", "--safe"], tmp_path)
    assert plan["command"][-1] == "watch"
    assert "User=root" not in plan["content"]
    assert "<string>root</string>" not in plan["content"]
    assert "sudo" not in plan["content"]
    assert "user" in plan["scope"]
    if system == "Windows":
        assert "LeastPrivilege" in plan["content"]


def test_startup_rejects_foreign_config(monkeypatch, tmp_path):
    path = tmp_path / "foreign.service"
    path.write_text("private existing service")
    monkeypatch.setattr(autorun, "startup_plan", lambda *args: {"available": True, "path": str(path), "content": "new", "platform": "Linux", "name": "test"})
    assert autorun.install_startup(["safe"], tmp_path)["status"] == "denied"
    assert path.read_text() == "private existing service"


def test_first_connection_after_empty_baseline_is_recorded(monkeypatch):
    import sawm_defense.platforms as module
    conn = SimpleNamespace(pid=123, laddr=SimpleNamespace(ip="127.0.0.1", port=45123),
                           raddr=SimpleNamespace(ip="93.184.216.34", port=443), status="ESTABLISHED")
    calls = iter([[], [conn]])
    stub = SimpleNamespace(cpu_percent=lambda: 0, virtual_memory=lambda: SimpleNamespace(percent=10),
                           process_iter=lambda attrs: [], net_connections=lambda **kwargs: next(calls),
                           AccessDenied=PermissionError, NoSuchProcess=ProcessLookupError)
    monkeypatch.setattr(module, "psutil", stub)
    collector = Collector({"monitor_paths": []})
    collector.sample()
    _, events = collector.sample()
    assert events[0]["kind"] == "network_connection"
    assert events[0]["details"]["remote_ip"] == "93.184.216.34"


def test_late_hash_is_observed_not_false_creation(tmp_path):
    item = tmp_path / "already-existed"
    item.write_bytes(b"longer than budget")
    collector = Collector({"monitor_paths": [str(tmp_path)]})
    collector.HASH_BUDGET = 1
    collector._file_observations()
    collector.HASH_BUDGET = 1024
    events, _ = collector._file_observations()
    assert events[0]["kind"] == "file_observed"


def test_unreadable_directory_does_not_invent_deleted_files(tmp_path, monkeypatch):
    item = tmp_path / "file"
    item.write_text("baseline")
    collector = Collector({"monitor_paths": [str(tmp_path)]})
    collector._file_observations()
    def failed_walk(root, **kwargs):
        kwargs["onerror"](PermissionError("directory unreadable"))
        return iter([])
    monkeypatch.setattr("sawm_defense.platforms.os.walk", failed_walk)
    events, coverage = collector._file_observations()
    assert not events
    assert not coverage["scan_complete"]
    assert str(item) in collector._files


def test_empty_directory_tree_still_has_a_work_bound(tmp_path):
    for n in range(10):
        (tmp_path / str(n)).mkdir()
    collector = Collector({"monitor_paths": [str(tmp_path)]})
    collector.MAX_DIRECTORIES = 3
    events, coverage = collector._file_observations()
    assert coverage["directories_seen"] == 3
    assert not coverage["scan_complete"]
