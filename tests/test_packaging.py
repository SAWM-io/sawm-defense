"""Release gates reject false or incomplete native validation, without Cloud."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "packaging" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = load_tool("verify_bundle")
release = load_tool("release_bundle")


@pytest.fixture
def proof_fixture(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(b"inert packaging test fixture")
    proof = {field: True for field in release._REQUIRED_CHECKS}
    proof.update(proof_schema=2, validation_status="passed", binary_version="0.2.0",
                 binary_version_source="executable --version", binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                 platform="Linux", architecture="x86_64", bounded_watch_exit_code=0,
                 cloud_calls=0, cloud_enabled=False, native_notification_delivery="disabled",
                 events_recorded=7, actions_recorded=2, journal_entries_verified=9,
                 download_type_detected="script", static_findings=["extension_type_mismatch"])
    path = tmp_path / "proof.json"
    def check(value=proof):
        path.write_text(json.dumps(value), encoding="utf-8")
        return release._proof(path, "0.2.0", "linux", "x86_64", binary=binary)
    return check, proof, binary


def test_complete_current_proof_accepted(proof_fixture):
    check, proof, _ = proof_fixture
    assert check() == proof


@pytest.mark.parametrize("field", release._REQUIRED_CHECKS)
@pytest.mark.parametrize("bad", [False, 1, "true", None])
def test_each_failed_or_untyped_check_refuses_publication(proof_fixture, field, bad):
    check, proof, _ = proof_fixture
    invalid = {**proof, field: bad}
    with pytest.raises(ValueError): check(invalid)


@pytest.mark.parametrize("field", release._REQUIRED_CHECKS)
def test_each_missing_check_refuses_publication(proof_fixture, field):
    check, proof, _ = proof_fixture
    invalid = dict(proof); invalid.pop(field)
    with pytest.raises(ValueError): check(invalid)


@pytest.mark.parametrize("patch", [
    {"proof_schema": 1}, {"validation_status": "failed"}, {"binary_version": "0.1.0"},
    {"binary_version_source": "hardcoded"}, {"platform": "Windows"}, {"platform": {}},
    {"architecture": "arm64"}, {"cloud_calls": 1}, {"cloud_calls": False}, {"cloud_enabled": True},
    {"bounded_watch_exit_code": 1}, {"bounded_watch_exit_code": False},
    {"events_recorded": 2}, {"actions_recorded": 1}, {"journal_entries_verified": 8},
    {"native_notification_delivery": "submitted"}, {"download_type_detected": "text"},
    {"static_findings": []}, {"binary_sha256": "0"*64},
])
def test_inconsistent_measurements_refuse_publication(proof_fixture, patch):
    check, proof, _ = proof_fixture
    with pytest.raises(ValueError): check({**proof, **patch})


def test_old_minimal_proof_is_not_an_attestation(proof_fixture):
    check, _, _ = proof_fixture
    with pytest.raises(ValueError):
        check({"packaged_cli": True, "binary_version": "0.2.0", "platform": "Linux", "architecture": "x86_64"})


def test_binary_changed_after_validation_refuses_publication(proof_fixture):
    check, _, binary = proof_fixture
    binary.write_bytes(b"different build")
    with pytest.raises(ValueError, match="different executable"): check()


def test_archive_requires_proof_before_creating_output(tmp_path, monkeypatch):
    dist = tmp_path / "dist"; source = dist / "sawm-defense"
    source.mkdir(parents=True); (source / "sawm-defense").write_bytes(b"fixture")
    monkeypatch.setattr(release, "_native_target", lambda: ("linux", "x86_64"))
    with pytest.raises(ValueError, match="proof is required"):
        release.create_archive(dist, tmp_path / "out", version="0.2.0")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("stdout", ["SAWM Defense 0.1.0\n", "0.2.0", "SAWM Defense 0.2.0 extra", ""])
def test_wrong_or_missing_version_from_executable_refused(tmp_path, monkeypatch, stdout):
    monkeypatch.setattr(verify.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=stdout))
    with pytest.raises(AssertionError): verify.read_binary_version(tmp_path / "binary", "0.2.0")


def test_version_is_read_from_executable_argument(tmp_path, monkeypatch):
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs)); return SimpleNamespace(stdout="SAWM Defense 0.2.0\n")
    monkeypatch.setattr(verify.subprocess, "run", run)
    binary = tmp_path / "binary"
    assert verify.read_binary_version(binary, "0.2.0") == "0.2.0"
    assert calls[0][0] == [str(binary.resolve()), "--version"]
    assert calls[0][1]["check"] is True


def snapshot():
    return {"version": "0.2.0", "journal": {"ok": True, "verified": 2},
            "events": [{"id": "event-a"}], "actions": [{"id": "action-a"}],
            "calls": [], "cloud": {"enabled": False},
            "settings": {"cloud_enabled": False, "cloud_upload_enabled": False}}


@pytest.mark.parametrize("patch", [
    {"journal": {"ok": False, "verified": 2}}, {"journal": {"ok": True, "verified": 0}},
    {"events": []}, {"actions": []}, {"calls": [{"operation": "cloud"}]},
    {"cloud": {"enabled": True}}, {"settings": {"cloud_enabled": False, "cloud_upload_enabled": True}},
])
def test_bad_runtime_evidence_cannot_be_reported_as_passed(patch):
    with pytest.raises(AssertionError):
        verify.validate_snapshot({**snapshot(), **patch}, ["event-a"], ["action-a"])


def test_report_content_not_only_existence(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("{}")
    with pytest.raises(AssertionError): verify.validate_json_report(report, ["event-a"], ["action-a"], "0.2.0")
    report.write_text(json.dumps(snapshot()))
    assert verify.validate_json_report(report, ["event-a"], ["action-a"], "0.2.0")["journal"]["ok"]
    html = tmp_path / "report.html"
    html.write_text("<!doctype html><h1>SAWM Defense</h1>")
    with pytest.raises(AssertionError): verify.validate_html_report(html, ["event-a", "action-a"])
    html.write_text("<!doctype html><h1>SAWM Defense</h1><pre>event-a action-a</pre>")
    verify.validate_html_report(html, ["event-a", "action-a"])


def test_failure_removes_stale_success_proof(tmp_path, monkeypatch):
    path = tmp_path / "success.json"; path.write_text('{"validation_status":"passed"}')
    monkeypatch.setattr(sys, "argv", ["verify_bundle.py", "missing-binary", "--output", str(path)])
    def fail(*args): raise AssertionError("Failed validation")
    monkeypatch.setattr(verify, "verify", fail)
    with pytest.raises(AssertionError): verify.main()
    assert not path.exists()


def test_release_require_is_not_disabled_by_optimized_python():
    source = "import importlib.util; s=importlib.util.spec_from_file_location('v',%r);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.require(False,'still enforced')" % str(ROOT / "packaging/verify_bundle.py")
    result = subprocess.run([sys.executable, "-O", "-c", source], capture_output=True, text=True)
    assert result.returncode != 0
    assert "still enforced" in result.stderr


@pytest.mark.parametrize("reader", ["read_ledger_events", "count_ledger_cloud_calls"])
def test_verifier_closes_sqlite_reader_before_profile_cleanup(tmp_path, monkeypatch, reader):
    import sqlite3
    original_connect = sqlite3.connect
    opened = []
    def tracked_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        opened.append(connection)
        return connection
    database = tmp_path / "evidence.sqlite3"
    connection = original_connect(database)
    try:
        connection.execute("create table ledger(seq integer, kind text, payload text)")
        connection.execute("insert into ledger values(1,'event',?)", (json.dumps({"id": "fixture"}),))
        connection.commit()
    finally:
        connection.close()
    monkeypatch.setattr(verify.sqlite3, "connect", tracked_connect)
    result = getattr(verify, reader)(tmp_path)
    assert result == ([{"id": "fixture"}] if reader == "read_ledger_events" else 0)
    assert len(opened) == 1
    # Keep a strong reference to prove explicit closure, not a GC side effect.
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("select 1")
    database.unlink()  # Windows rejects this while an SQLite handle remains open.


def test_verifier_closes_sqlite_reader_when_bad_evidence_raises(tmp_path, monkeypatch):
    import sqlite3
    original_connect = sqlite3.connect
    connection = original_connect(tmp_path / "evidence.sqlite3")
    try:
        connection.execute("create table ledger(seq integer, kind text, payload text)")
        connection.execute("insert into ledger values(1,'event','not JSON')")
        connection.commit()
    finally:
        connection.close()
    opened = []
    def tracked_connect(*args, **kwargs):
        value = original_connect(*args, **kwargs); opened.append(value); return value
    monkeypatch.setattr(verify.sqlite3, "connect", tracked_connect)
    with pytest.raises(json.JSONDecodeError): verify.read_ledger_events(tmp_path)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("select 1")
