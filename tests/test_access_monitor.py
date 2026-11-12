import json
import os
from pathlib import Path
import stat

import pytest

from sawm_defense.access_monitor import AccessMonitor
from sawm_defense.policy import authorize


def ldap_line(conn, op, message):
    return f'Nov 12 12:00:00 host slapd[1234]: conn={conn} op={op} {message}\n'


def setup_ldap(tmp_path, **config):
    log = tmp_path / "slapd.log"
    log.write_text("")
    settings = {"ldap_log_paths": [str(log)], "ldap_failure_threshold": 3, **config}
    monitor = AccessMonitor(settings, tmp_path / "state")
    assert monitor.sample() == []
    return monitor, settings, log


def append(log, text):
    with log.open("a", encoding="utf-8") as stream:
        stream.write(text)


def bind_failure(conn):
    return ldap_line(conn, 0, 'BIND dn="cn=test,dc=example" method=128') + ldap_line(conn, 0, 'RESULT tag=97 err=49 text=')


def test_actual_chmod_detected_after_restart_without_changing_unselected_files(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX mode transitions are validated on native Unix; Windows DACLs are explicitly unsupported")
    item = tmp_path / "fixture"
    item.write_text("ordinary fixture, no contents read")
    item.chmod(0o600)
    settings = {"access_monitor_paths": [str(item)]}
    monitor = AccessMonitor(settings, tmp_path / "state")
    assert monitor.sample() == []
    item.chmod(0o640)
    monitor = AccessMonitor(settings, tmp_path / "state")
    event = monitor.sample()[0]
    assert event["kind"] == "access_permission_changed"
    assert event["details"]["before"]["mode"] == 0o600
    assert event["details"]["after"]["mode"] == 0o640
    assert not event["details"]["actor_attributed"]
    assert not authorize("terminate", event, {"automatic_actions": ["terminate"]})[0]
    assert monitor.sample() == []


def test_directory_scope_is_metadata_only_and_symlink_is_not_followed(tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    child = folder / "child"
    child.write_text("secret")
    monitor = AccessMonitor({"access_monitor_paths": [str(folder)]}, tmp_path / "state")
    assert monitor.sample() == []
    child.chmod(0o400)
    assert monitor.sample() == []  # Explicitly no recursive ACL claim.
    link = tmp_path / "link"
    try:
        link.symlink_to(child)
    except OSError:
        pytest.skip("Creating a symlink requires additional privileges on this Windows host")
    monitor.update_config({"access_monitor_paths": [str(link)]})
    assert monitor.sample()[0]["kind"] == "access_sensor_gap"


def test_ldap_failures_persist_without_replay_and_never_autoblock(tmp_path):
    monitor, config, log = setup_ldap(tmp_path)
    append(log, bind_failure(1)+bind_failure(2))
    assert monitor.sample() == []
    monitor = AccessMonitor(config, tmp_path / "state")
    assert monitor.sample() == []
    append(log, bind_failure(3))
    events = monitor.sample()
    assert len(events) == 1 and events[0]["kind"] == "ldap_auth_burst"
    details = events[0]["details"]
    assert details["failure_count"] == 3 and len(set(details["evidence_ids"])) == 3
    assert not details["verified_local"] and not details["automatic_block_eligible"]
    assert not authorize("block_ip", events[0], {"automatic_actions": ["block_ip"]})[0]
    assert monitor.sample() == []


@pytest.mark.parametrize("attribute,result", [("olcAccess", 0), ("member", 0), ("userPassword", 50)])
def test_ldap_access_change_needs_matching_mod_and_result_and_hides_values(tmp_path, attribute, result):
    monitor, config, log = setup_ldap(tmp_path)
    append(log, ldap_line(8, 1, 'MOD dn="cn=secret-group,dc=private"')+ldap_line(8, 1, f'MOD attr={attribute}'))
    assert monitor.sample() == []
    monitor = AccessMonitor(config, tmp_path / "state")
    append(log, ldap_line(8, 1, f'RESULT tag=103 err={result} text=password=DO-NOT-STORE'))
    event = monitor.sample()[0]
    assert event["kind"] == "ldap_access_change" and event["details"]["attributes"] == [attribute.lower()]
    assert event["details"]["operation_result"] == ("reported_success" if result == 0 else "reported_failure")
    serialized = json.dumps(event) + monitor.path.read_text()
    assert "DO-NOT-STORE" not in serialized and "secret-group" not in serialized and "dc=private" not in serialized
    assert not event["details"]["verified_local"]


def test_ldap_forged_tags_unmatched_result_and_ordinary_attribute_not_evidence(tmp_path):
    monitor, _, log = setup_ldap(tmp_path)
    append(log, ''.join(bind_failure(i).replace('slapd[1234]', 'logger[1234]') for i in range(3)))
    append(log, ldap_line(4, 1, 'RESULT tag=103 err=0 text='))
    append(log, ldap_line(5, 1, 'MOD dn="cn=person"')+ldap_line(5, 1, 'MOD attr=mail')+ldap_line(5, 1, 'RESULT tag=103 err=0 text='))
    assert monitor.sample() == []


def test_initial_log_history_not_replayed_and_rotation_reports_gap(tmp_path):
    log = tmp_path / "history.log"
    log.write_text(''.join(bind_failure(i) for i in range(10)))
    monitor = AccessMonitor({"ldap_log_paths": [str(log)]}, tmp_path / "state")
    assert monitor.sample() == []
    log.rename(tmp_path / "history.1")
    log.write_text(bind_failure(20))
    assert monitor.sample()[0]["kind"] == "access_sensor_gap"
    assert monitor.status()["ldap_failures"] == 1


def test_receipt_window_expires_and_removed_source_stops_contributing(tmp_path):
    monitor, config, log = setup_ldap(tmp_path, ldap_window_seconds=30)
    append(log, bind_failure(1)+bind_failure(2))
    monitor.sample()
    for entry in monitor._state["failures"]:
        entry["at"] -= 31
    append(log, bind_failure(3))
    assert monitor.sample() == []
    assert monitor.status()["ldap_failures"] == 1
    monitor.update_config({})
    assert monitor._state["failures"] == []


def test_partial_lines_crlf_and_bounded_backlog_keep_cursor(tmp_path):
    monitor, _, log = setup_ldap(tmp_path)
    monitor.MAX_LINES = 2
    text = ''.join(bind_failure(i) for i in range(3)).replace('\n', '\r\n')
    append(log, text[:-5])
    first = monitor.sample()
    assert any(e["kind"] == "access_sensor_gap" for e in first)
    assert not any(e["kind"] == "ldap_auth_burst" for e in first)
    monitor.sample()
    monitor.sample()  # Last result is partial and must not be consumed.
    append(log, text[-5:])
    assert any(e["kind"] == "ldap_auth_burst" for e in monitor.sample())
    assert monitor.sample() == []


def test_oversized_log_line_does_not_allocate_unbounded_state(tmp_path):
    monitor, _, log = setup_ldap(tmp_path)
    append(log, 'x'*(monitor.MAX_BYTES+100)+'\n')
    assert monitor.sample()[0]["kind"] == "access_sensor_gap"
    monitor.sample()
    assert len(monitor.path.read_bytes()) < 10000


def test_embedded_carriage_return_cannot_forge_a_record_or_stall_following_lines(tmp_path):
    monitor, _, log = setup_ldap(tmp_path)
    append(log, 'attacker\r'+bind_failure(1))
    append(log, bind_failure(2)+bind_failure(3))
    assert monitor.sample() == []  # Only two complete matching bind operations.
    append(log, bind_failure(4))
    assert monitor.sample()[0]["kind"] == "ldap_auth_burst"
