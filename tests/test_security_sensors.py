import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from sawm_defense import security_sensors as sensors
from sawm_defense import kernel
from sawm_defense.config import DEFAULTS


def text_failures(n, start=0):
    return "".join(f"Nov 11 12:00:00 lab sshd[{300+i}]: Failed password for invalid user demo from 93.184.216.34 port {40000+i} ssh2\n" for i in range(start, start+n))


def burst(events):
    return [e for e in events if e["kind"] == "auth_bruteforce"]


def journal_rows(n=5, start=0, **fields):
    return [{"MESSAGE": f"Failed password for demo from 93.184.216.34 port {40000+i} ssh2",
             "_UID": "0", "_COMM": "sshd", "_PID": str(300+i), "_EXE": "/usr/sbin/sshd", "_TRANSPORT": "syslog",
             "__CURSOR": f"s=abc;i={i}", "__REALTIME_TIMESTAMP": str(int(time.time()*1_000_000)), **fields}
            for i in range(start, start+n)]


def journal_stub(monkeypatch, rows):
    monkeypatch.setattr(sensors.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sensors.shutil, "which", lambda name: "/usr/bin/journalctl")
    monkeypatch.setattr(sensors, "_protected_native_file", lambda path: True)
    monkeypatch.setattr(sensors.Sensor, "_run_journal", staticmethod(lambda cmd: subprocess.CompletedProcess(cmd, 0, "\n".join(json.dumps(row) for row in rows), "")))


def test_text_baseline_then_persistent_burst_is_untrusted(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(text_failures(5))
    config = {"auth_log_paths": [str(log)]}
    sensor = sensors.Sensor(config, tmp_path / "state")
    assert sensor.sample() == []
    with log.open("a") as stream:
        stream.write(text_failures(3, 10))
    assert sensor.sample() == []
    # Same source and cursor after an application/OS restart; no replay.
    resumed = sensors.Sensor(config, tmp_path / "state")
    assert resumed.sample() == []
    with log.open("a") as stream:
        stream.write(text_failures(2, 20))
    event = burst(resumed.sample())[0]
    assert event["details"]["failure_count"] == 5
    assert event["details"]["verification_origin"] == "untrusted_auth_text"
    assert event["details"]["verified_local"] is False
    assert not burst(sensors.Sensor(config, tmp_path / "state").sample())


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_text_log_accepts_native_line_delimiters_but_not_embedded_cr(tmp_path, ending):
    log = tmp_path / "auth.log"
    log.write_bytes(b"")
    sensor = sensors.Sensor({"auth_log_paths": [str(log)]}, tmp_path / "state")
    sensor.sample()
    log.write_bytes(text_failures(5).encode().replace(b"\n", ending))
    events = burst(sensor.sample())
    assert len(events) == 1
    assert events[0]["details"]["failure_count"] == 5
    assert events[0]["details"]["verified_local"] is False
    assert sensors._failure("Failed password for demo\r from 93.184.216.34 port 40000 ssh2") is None


def test_rotation_and_copytruncate_report_gap(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("old contents\n")
    sensor = sensors.Sensor({"auth_log_paths": [str(log)]}, tmp_path / "state")
    sensor.sample()
    log.rename(tmp_path / "auth.old")
    log.write_text(text_failures(5))
    events = sensor.sample()
    assert any(e["kind"] == "security_sensor_gap" for e in events)
    assert burst(events)[0]["details"]["verified_local"] is False
    # A second file of equal size with changed bytes still invalidates anchor.
    log2 = tmp_path / "copy.log"
    log2.write_text("original content\n")
    sensor2 = sensors.Sensor({"auth_log_paths": [str(log2)]}, tmp_path / "state2")
    sensor2.sample()
    log2.write_text("replaced content\n")
    assert sensor2.sample()[0]["details"]["reason"] == "rotation_or_truncation"


def test_symlink_log_and_local_file_are_not_trusted(tmp_path):
    target = tmp_path / "target"
    target.write_text(text_failures(5))
    alias = tmp_path / "log"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("Symlink unsupported for this test user")
    events = sensors.Sensor({"auth_log_paths": [str(alias)]}, tmp_path / "state").sample()
    assert not burst(events)
    assert events[0]["kind"] == "security_sensor_gap"
    assert not sensors._protected_native_file(target)


def test_journal_trusted_distinct_entries_and_restart(tmp_path, monkeypatch):
    journal_stub(monkeypatch, journal_rows(3))
    config = {"auth_journal_enabled": True, "protected_remote_ips": ["93.184.216.34"]}
    sensor = sensors.Sensor(config, tmp_path / "state")
    assert sensor.sample() == []
    journal_stub(monkeypatch, journal_rows(2, 3))
    resumed = sensors.Sensor(config, tmp_path / "state")
    event = burst(resumed.sample())[0]
    assert event["details"]["verified_local"] is True
    assert event["details"]["verification_origin"] == "local_journald"
    assert event["details"]["failure_count"] == 5
    assert len(set(event["details"]["evidence_ids"])) == 5
    assert event["details"]["protected_remote_ip"]
    assert not event["details"]["attacker_identity_known"]
    assert resumed.sample() == []


@pytest.mark.parametrize("bad", [{"_UID":"501"}, {"_EXE":"/usr/bin/logger"}, {"_TRANSPORT":"stdout"}, {"_COMM":"logger", "SYSLOG_IDENTIFIER":"sshd"}])
def test_forged_journal_tags_never_authorize(tmp_path, monkeypatch, bad):
    journal_stub(monkeypatch, journal_rows(**bad))
    event = burst(sensors.Sensor({"auth_journal_enabled": True}, tmp_path / "state").sample())[0]
    assert not event["details"]["verified_local"]


@pytest.mark.parametrize("offset", [-600, 100])
def test_journal_old_or_future_never_triggers(tmp_path, monkeypatch, offset):
    journal_stub(monkeypatch, journal_rows(__REALTIME_TIMESTAMP=str(int((time.time()+offset)*1_000_000))))
    assert not burst(sensors.Sensor({"auth_journal_enabled": True}, tmp_path / "state").sample())


def test_duplicate_journal_cursor_is_one_observation(tmp_path, monkeypatch):
    journal_stub(monkeypatch, journal_rows(__CURSOR="s=abc;i=1"))
    assert not burst(sensors.Sensor({"auth_journal_enabled": True}, tmp_path / "state").sample())


def test_text_copies_do_not_inflate_verified_count(tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("")
    config = {"auth_journal_enabled": True, "auth_log_paths": [str(log)]}
    journal_stub(monkeypatch, [])
    sensor = sensors.Sensor(config, tmp_path / "state")
    sensor.sample()
    log.write_text(text_failures(3))
    journal_stub(monkeypatch, journal_rows(3))
    assert not burst(sensor.sample())


def test_timeout_is_coverage_gap_not_intrusion(tmp_path, monkeypatch):
    journal_stub(monkeypatch, [])
    def timeout(cmd):
        raise subprocess.TimeoutExpired(cmd, 5)
    monkeypatch.setattr(sensors.Sensor, "_run_journal", staticmethod(timeout))
    events = sensors.Sensor({"auth_journal_enabled": True}, tmp_path / "state").sample()
    assert not burst(events)
    assert events[0]["kind"] == "security_sensor_gap"


def test_bounded_native_output():
    result = sensors.Sensor._run_journal([sys.executable, "-c", "import sys;sys.stdout.write('x' * 1000000)"])
    assert len(result.stdout) == sensors.MAX_READ_BYTES + 1


def test_corrupt_cursor_not_silently_replayed(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "security-sensors.json").write_text('{"version":1,"files":{},"seen":[],"failures":[42],"alerts":{}}')
    with pytest.raises(ValueError, match="Curseur"):
        sensors.Sensor({}, state)


def kernel_setup(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("Linux auditctl requires POSIX filesystem paths; exercised by the Linux CI runner")
    monitored = tmp_path / "files"
    monitored.mkdir()
    monkeypatch.setattr(kernel.platform, "system", lambda: "Linux")
    monkeypatch.setattr(kernel.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(kernel.shutil, "which", lambda name: "/usr/sbin/auditctl")
    monkeypatch.setattr(kernel, "_protected_native_file", lambda path: True)
    monkeypatch.setattr(kernel.os, "geteuid", lambda: 0, raising=False)
    return {"monitor_paths": [str(monitored.resolve())]}


def test_kernel_plan_and_approval_never_run_commands(tmp_path, monkeypatch):
    config = kernel_setup(tmp_path, monkeypatch)
    monkeypatch.setattr(kernel, "_run", lambda *a: pytest.fail("No command before approval"))
    plan = kernel.install_audit(config, tmp_path / "state")
    assert plan["status"] == "approval_required"
    assert len(plan["rules"]) == 1
    assert "perm=wa" in plan["rules"][0]["arguments"]
    assert not plan["persistent"]
    monkeypatch.setattr(kernel.os, "geteuid", lambda: 501, raising=False)
    assert kernel.install_audit(config, tmp_path / "state", approved=True)["status"] == "denied"


@pytest.mark.parametrize("path", ["/", "/tmp/../etc", "/tmp/abc\n-D", "/tmp/--something ; evil"])
def test_kernel_rejects_unsafe_paths(path):
    with pytest.raises(ValueError):
        kernel.audit_plan({"monitor_paths": [path]})


def test_kernel_installs_only_scoped_runtime_rule(tmp_path, monkeypatch):
    config = kernel_setup(tmp_path, monkeypatch)
    rule = kernel.audit_plan(config)["rules"][0]["rule"]
    commands = []
    def run(exe, args):
        commands.append(args)
        out = "enabled 1\npid 200\nlost 0\n" if args == ["-s"] else (rule if len(commands) >= 4 else "")
        return subprocess.CompletedProcess([exe,*args], 0, out, "")
    monkeypatch.setattr(kernel, "_run", run)
    result = kernel.install_audit(config, tmp_path / "state", approved=True)
    assert result["status"] == "installed_runtime"
    assert result["verified"] and result["added"] == 1
    assert Path(result["artifact"]).read_text().startswith("# Runtime")
    assert not any("-D" in c or "-e" in c for c in commands)


def test_kernel_failed_verification_rolls_back_only_new_rule(tmp_path, monkeypatch):
    config = kernel_setup(tmp_path, monkeypatch)
    commands = []
    def run(exe, args):
        commands.append(args)
        return subprocess.CompletedProcess([exe,*args], 0, "enabled 1\npid 200\n" if args == ["-s"] else "", "")
    monkeypatch.setattr(kernel, "_run", run)
    result = kernel.install_audit(config, tmp_path / "state", approved=True)
    assert result["status"] == "error"
    assert result["rollback"][0]["removed"]
    assert commands[-1][0] == "-d"
    assert not any("-D" in c for c in commands)


def test_kernel_immutable_or_prior_never_rule_refuses(tmp_path, monkeypatch):
    config = kernel_setup(tmp_path, monkeypatch)
    monkeypatch.setattr(kernel, "_run", lambda exe,args: subprocess.CompletedProcess([],0,"enabled 2\npid 200\n",""))
    assert kernel.install_audit(config,tmp_path / "state",approved=True)["status"] == "denied"
    monkeypatch.setattr(kernel, "_run", lambda exe,args: subprocess.CompletedProcess([],0,"enabled 1\npid 200\n" if args == ["-s"] else "-a never,task", ""))
    assert kernel.install_audit(config,tmp_path / "state",approved=True)["status"] == "denied"


def test_kernel_empty_explicit_paths_fall_back_to_monitored_defaults(tmp_path, monkeypatch):
    config = {**DEFAULTS, **kernel_setup(tmp_path, monkeypatch), "kernel_audit_paths": []}
    assert kernel.audit_plan(config)["paths"] == config["monitor_paths"]


def test_kernel_windows_is_explicitly_unsupported_without_native_call(tmp_path, monkeypatch):
    monkeypatch.setattr(kernel.platform, "system", lambda: "Windows")
    monkeypatch.setattr(kernel, "_run", lambda *a: pytest.fail("No auditctl on Windows"))
    result = kernel.install_audit({"monitor_paths": [], "kernel_audit_paths": []}, tmp_path / "state", approved=True)
    assert result["status"] == "unsupported"
