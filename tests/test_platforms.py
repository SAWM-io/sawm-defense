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


@pytest.mark.parametrize("failure_mode", ["iterator_creation", "during_iteration"])
def test_process_enumeration_denial_keeps_other_sensors_and_recovers(tmp_path, monkeypatch, failure_mode):
    import sawm_defense.platforms as module
    watched = tmp_path / "observed"
    watched.mkdir()
    document = watched / "invoice.txt"
    document.write_text("initial")
    executable = tmp_path / "allowed-program"
    executable.write_text("harmless executable fixture")
    processes = [SimpleNamespace(info={"pid": pid, "name": "demo", "username": "tester",
                                       "create_time": float(pid), "exe": str(executable)})
                 for pid in (101, 102)]
    state = {"mode": "complete", "connections": []}
    network_reads = []

    def process_iter(attrs):
        if state["mode"] == "iterator_creation":
            raise PermissionError("enumeration denied")
        if state["mode"] == "during_iteration":
            def partial():
                yield processes[0]
                raise PermissionError("enumeration interrupted")
            return partial()
        return iter(processes)

    def net_connections(**kwargs):
        network_reads.append(True)
        return state["connections"]

    stub = SimpleNamespace(cpu_percent=lambda: 12, virtual_memory=lambda: SimpleNamespace(percent=34),
                           process_iter=process_iter, net_connections=net_connections,
                           AccessDenied=PermissionError, NoSuchProcess=ProcessLookupError)
    monkeypatch.setattr(module, "psutil", stub)
    collector = Collector({"monitor_paths": [str(watched)], "allowed_process_paths": [str(executable)]})
    collector.sample()
    baseline = {(101, 101.0), (102, 102.0)}
    assert collector._process_identities == baseline
    state["mode"] = failure_mode
    document.write_text("changed while process enumeration is unavailable")
    state["connections"] = [SimpleNamespace(pid=101, laddr=SimpleNamespace(ip="127.0.0.1", port=45123),
                                             raddr=SimpleNamespace(ip="93.184.216.34", port=443), status="ESTABLISHED")]
    denied, events = collector.sample()
    assert denied["coverage"]["process_enumeration_error"] == "PermissionError"
    assert denied["coverage"]["process_scan_complete"] is False
    assert denied["cpu_percent"] == 12 and denied["memory_percent"] == 34
    assert denied["connections"] and len(network_reads) == 2
    assert {"file_modified", "network_connection"} <= {event["kind"] for event in events}
    process_capability = next(item for item in denied["capabilities"] if item["name"] == "Processus")
    assert process_capability["available"] is False
    assert collector._process_identities == baseline

    state["mode"] = "complete"
    document.write_text("changed again after access recovers")
    recovered, events = collector.sample()
    assert recovered["coverage"]["process_scan_complete"] is True
    assert "process_enumeration_error" not in recovered["coverage"]
    assert next(item for item in recovered["capabilities"] if item["name"] == "Processus")["available"] is True
    assert collector._process_identities == baseline
    assert any(event["kind"] == "file_modified" for event in events)
    assert not any(event["kind"] == "process_observed" for event in events)
    assert len(network_reads) == 3


@pytest.mark.parametrize("incomplete_mode", ["limit", "protected_item"])
def test_partial_process_sample_does_not_prune_known_identities(tmp_path, monkeypatch, incomplete_mode):
    import sawm_defense.platforms as module
    executable = tmp_path / "allowed-program"
    executable.write_text("harmless fixture")
    visible = SimpleNamespace(info={"pid": 101, "name": "demo", "username": "tester", "create_time": 1.0,
                                    "exe": str(executable)})
    hidden = SimpleNamespace(info={"pid": 102, "name": "demo", "username": "tester", "create_time": 2.0,
                                   "exe": str(executable)})

    class ProtectedProcess:
        @property
        def info(self):
            raise PermissionError("protected process")

    stub = SimpleNamespace(cpu_percent=lambda: 0, virtual_memory=lambda: SimpleNamespace(percent=10),
                           process_iter=lambda attrs: iter([visible, hidden]), net_connections=lambda **kwargs: [],
                           AccessDenied=PermissionError, NoSuchProcess=ProcessLookupError)
    monkeypatch.setattr(module, "psutil", stub)
    collector = Collector({"monitor_paths": [], "allowed_process_paths": [str(executable)]})
    collector.sample()
    baseline = set(collector._process_identities)
    assert len(baseline) == 2
    if incomplete_mode == "limit":
        collector.MAX_PROCESSES = 1
    else:
        stub.process_iter = lambda attrs: iter([visible, ProtectedProcess()])
    snapshot, events = collector.sample()
    assert not snapshot["coverage"]["process_scan_complete"]
    assert collector._process_identities == baseline
    assert snapshot["coverage"]["processes_truncated"] is (incomplete_mode == "limit")
    assert snapshot["coverage"]["process_access_denied"] == (1 if incomplete_mode == "protected_item" else 0)
    assert not any(event["kind"] == "process_observed" for event in events)
