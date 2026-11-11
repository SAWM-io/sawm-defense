"""Exercise an actual bundled CLI on disposable files, with Cloud disabled.

Proof is written only after the real executable, observations, effects, exported
content and journal checks pass. This does not test real Cloud or native GUI use.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import platform
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import tomllib


def require(condition, message):
    # Do not remove the release gate when Python runs with -O.
    if not condition:
        raise AssertionError(message)


def binary_digest(binary):
    with Path(binary).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_binary_version(binary, expected_version):
    done = subprocess.run([str(Path(binary).resolve()), "--version"], check=True,
                          capture_output=True, text=True, timeout=30)
    match = re.fullmatch(r"SAWM Defense (\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?)", done.stdout.strip())
    require(match is not None, "The executable did not return a recognized --version response")
    version = match.group(1)
    require(version == expected_version, "Executable version differs from the release version")
    return version


def validate_snapshot(value, event_ids, action_ids):
    require(isinstance(value, dict), "Missing structured status or report")
    require(isinstance(value.get("journal"), dict) and value["journal"].get("ok") is True,
            "Journal integrity check did not pass")
    events, actions = value.get("events"), value.get("actions")
    require(isinstance(events, list) and isinstance(actions, list), "Missing observations or actions")
    require(set(event_ids) <= {e.get("id") for e in events if isinstance(e, dict)}, "Evidence events missing from status/report")
    require(set(action_ids) <= {a.get("id") for a in actions if isinstance(a, dict)}, "Executed actions missing from status/report")
    count = value["journal"].get("verified")
    require(type(count) is int and count >= len(events) + len(actions), "Journal validation does not cover the recorded entries")
    require(value.get("calls") == [], "The offline validation recorded a Cloud call")
    require(isinstance(value.get("cloud"), dict) and value["cloud"].get("enabled") is False,
            "Cloud is not explicitly disabled")
    settings = value.get("settings", {})
    require(settings.get("cloud_enabled") is False and settings.get("cloud_upload_enabled") is False,
            "Offline settings were not preserved")
    return value


def validate_json_report(path, event_ids, action_ids, version):
    require(path.is_file() and path.stat().st_size > 0, "JSON report was not exported")
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict) and value.get("version") == version, "JSON report has a different version")
    return validate_snapshot(value, event_ids, action_ids)


def validate_html_report(path, evidence_ids):
    require(path.is_file() and path.stat().st_size > 0, "HTML report was not exported")
    text = path.read_text(encoding="utf-8")
    require(text.lstrip().lower().startswith("<!doctype html>") and "SAWM Defense" in text,
            "The exported file is not a SAWM HTML report")
    require(all(identifier in text for identifier in evidence_ids), "HTML report does not contain the exercised evidence")


def read_ledger_events(state):
    # sqlite3's own context manager commits/rolls back, but does not close.
    # Windows cannot remove the disposable database while a reader remains open.
    with closing(sqlite3.connect(state / "evidence.sqlite3")) as db:
        return [json.loads(row[0]) for row in db.execute("select payload from ledger where kind='event' order by seq")]


def count_ledger_cloud_calls(state):
    with closing(sqlite3.connect(state / "evidence.sqlite3")) as db:
        return db.execute("select count(*) from ledger where kind='call'").fetchone()[0]


def verify(binary, expected_version):
    binary = Path(binary).resolve(strict=True)
    initial_digest = binary_digest(binary)
    version = read_binary_version(binary, expected_version)
    with tempfile.TemporaryDirectory(prefix="sawm-bundle-proof-") as work:
        folder = Path(work).resolve()
        state, observed = folder / "state", folder / "observed"
        observed.mkdir()
        target = observed / "harmless-demo.txt"
        target.write_text("baseline", encoding="utf-8")
        base = [str(binary), "--state-dir", str(state)]

        def call(*parts):
            done = subprocess.run([*base, *map(str, parts)], check=True, capture_output=True, text=True, timeout=30)
            return json.loads(done.stdout)

        configured = call("configure", "--watch-path", observed, "--no-cloud", "--no-upload-events", "--no-protect-downloads", "--no-notifications")
        require(configured.get("status") == "completed", "The test profile was not configured")
        config = json.loads((state / "config.json").read_text(encoding="utf-8"))
        require(config.get("cloud_enabled") is False and config.get("cloud_upload_enabled") is False,
                "The test profile must not use Cloud")
        require(config.get("monitor_paths") == [str(observed)] and config.get("protect_downloads") is False,
                "The test must observe only the disposable folder")
        require(config.get("automatic_actions") == [], "The test must not authorize autonomous mutations")
        config["poll_seconds"] = 1
        config["download_scan_settle_seconds"] = 1
        (state / "config.json").write_text(json.dumps(config), encoding="utf-8")
        watch = subprocess.Popen([*base, "watch", "--seconds", "40"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def events():
            return read_ledger_events(state)

        def wait_for(fn):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                value = fn()
                if value:
                    return value
                require(watch.poll() is None, "The watcher exited before the expected observation")
                time.sleep(.1)
            raise AssertionError("Expected observation not received")

        try:
            wait_for(lambda: (state / "last-snapshot.json").exists())
            changed_bytes = b"modified harmless demonstration"
            target.write_bytes(changed_bytes)
            changed_sha = hashlib.sha256(changed_bytes).hexdigest()
            modified = wait_for(lambda: next((e for e in events() if e["kind"] == "file_modified" and e.get("details", {}).get("path") == str(target)), None))
            require(modified["details"].get("sha256") == changed_sha, "The modification event has a different file hash")
            action = call("act", "quarantine", modified["id"], "--approve")
            require(action.get("status") == "completed" and action.get("event_id") == modified["id"] and not target.exists(),
                    "Manual quarantine did not produce the expected effect")
            isolated = Path(action["quarantine_path"])
            require(isolated.is_relative_to(state) and isolated.is_file() and binary_digest(isolated) == changed_sha,
                    "The isolated file does not match the observed file")
            restored = call("restore", action["id"], "--approve")
            require(restored.get("status") == "completed" and restored.get("restores") == action["id"], "Restore receipt is not linked to quarantine")
            require(target.is_file() and target.read_bytes() == changed_bytes and not isolated.exists(), "Restore did not restore the expected bytes")
            # Wait until the sampler sees the restored file before deleting it.
            # Otherwise an earlier quarantine deletion could falsely satisfy this test.
            wait_for(lambda: next((e for e in events() if e["kind"] in {"file_created", "file_modified"}
                                   and e["id"] != modified["id"] and e.get("details", {}).get("path") == str(target)
                                   and e["details"].get("sha256") == changed_sha), None))
            previous_deletions = {e["id"] for e in events() if e["kind"] == "file_deleted"}
            target.unlink()
            deleted = wait_for(lambda: next((e for e in events() if e["kind"] == "file_deleted"
                                             and e["id"] not in previous_deletions and e.get("details", {}).get("path") == str(target)), None))
            # Harmless text, never executed by the inspector.
            download = observed / "invoice.pdf.part"
            download_bytes = b"#!/bin/sh\necho harmless-inspection-fixture\n"
            download.write_bytes(download_bytes)
            download = download.rename(observed / "invoice.pdf")
            inspected = wait_for(lambda: next((e for e in events() if e["kind"] == "file_suspicious" and e.get("details", {}).get("path") == str(download)), None))
            inspection = inspected["details"]["static_inspection"]
            findings = [f["code"] for f in inspection.get("findings", [])]
            require(inspection.get("status") == "suspicious" and inspection.get("actual_type") == "script", "Disguised script was not recognized")
            require(inspection.get("sha256") == hashlib.sha256(download_bytes).hexdigest() and "extension_type_mismatch" in findings,
                    "Static inspection evidence is incomplete")
            alert = wait_for(lambda: next((n for n in call("notifications") if n["event_id"] == inspected["id"]), None))
            require(alert.get("delivery") == "disabled", "Native notifications must remain disabled in this offline test")
            report_path = folder / "mission-proof.json"
            order = call("order", "report", "--path", report_path)
            require(order.get("kind") == "report" and order.get("payload") == {"path": str(report_path)}, "Incorrect report order receipt")
            completed = wait_for(lambda: next((o for o in call("orders") if o["id"] == order["id"] and o["status"] == "completed"), None))
            require(completed.get("result", {}).get("status") == "completed" and completed["result"].get("path") == str(report_path),
                    "The daemon did not return the expected report result")
            out, err = watch.communicate(timeout=45)
            require(watch.returncode == 0, "Bounded watcher exited unsuccessfully")
            require(download.is_file() and download.read_bytes() == download_bytes, "Static suspicion modified or removed the file")
            event_ids = [modified["id"], deleted["id"], inspected["id"]]
            action_ids = [action["id"], restored["id"]]
            status = validate_snapshot(call("status"), event_ids, action_ids)
            require(status.get("running") is False, "The bounded watcher is still running")
            require(any(n.get("id") == alert["id"] and n.get("event_id") == inspected["id"] for n in status.get("notifications", [])),
                    "The alert did not persist across a separate CLI invocation")
            require(any(o.get("id") == order["id"] and o.get("status") == "completed" for o in status.get("orders", [])),
                    "The completed order did not persist")
            validate_json_report(report_path, event_ids, action_ids, version)
            html_path = folder / "proof.html"
            exported = call("report", html_path)
            require(exported.get("status") == "completed" and exported.get("path") == str(html_path), "HTML export receipt failed")
            validate_html_report(html_path, [*event_ids, *action_ids])
            cloud_calls = count_ledger_cloud_calls(state)
            require(cloud_calls == 0, "The full ledger contains a Cloud call")
            require(binary_digest(binary) == initial_digest, "The executable changed during validation")
            return {
                "proof_schema": 2, "validation_status": "passed", "binary_version": version,
                "binary_version_source": "executable --version", "binary_sha256": initial_digest,
                "platform": platform.system(), "architecture": platform.machine(), "packaged_cli": True,
                "file_change_detected": True, "manual_quarantine_verified": True, "restore_verified": True,
                "deletion_detected": True, "bounded_watch_exit_code": watch.returncode,
                "journal_verified": True, "journal_entries_verified": status["journal"]["verified"],
                "events_recorded": len(status["events"]), "actions_recorded": len(status["actions"]),
                "cloud_calls": cloud_calls, "cloud_enabled": False, "offline_configuration_verified": True,
                "disposable_scope_verified": True, "binary_unchanged": True,
                "report_exported": True, "report_content_verified": True,
                "antivirus_engine_available": status["antivirus"]["available"],
                "automatic_file_inspection": True, "download_type_detected": inspection["actual_type"],
                "static_findings": findings, "persistent_alert": True, "native_notification_delivery": alert["delivery"],
                "mission_submitted_and_executed_by_daemon": True, "order_receipt_verified": True,
                "suspicion_did_not_quarantine_without_proof": True,
                "notes": "Harmless files; no real malware, firewall changes, Cloud calls or native GUI validation.",
            }
        finally:
            if watch.poll() is None:
                watch.terminate()
                watch.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with (Path(__file__).resolve().parents[1] / "pyproject.toml").open("rb") as stream:
        expected_version = tomllib.load(stream)["project"]["version"]
    # A failed rerun must not leave an earlier success proof at its target path.
    args.output.unlink(missing_ok=True)
    result = verify(args.binary, expected_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
