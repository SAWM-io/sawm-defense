from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket

import pytest

from sawm_defense.network_security import NetworkSecurity
from sawm_defense import network_security
from sawm_defense.policy import authorize, trusted_network_policy_event

IP = "93.184.216.34"


def stamp():
    return datetime.now(timezone.utc).isoformat()


def connection(ip=IP, port=443, local_port=45001, **fields):
    return {"pid": 555, "create_time": 1000.0, "exe": "/opt/app", "username": "demo", "protocol": "tcp",
            "local": f"127.0.0.1:{local_port}", "remote": f"{ip}:{port}", "remote_ip": ip, "remote_port": port,
            "status": "ESTABLISHED", **fields}


def sample(*rows, **overrides):
    return {"sampled_at": stamp(), "connections": list(rows), "coverage": {"network_source": "psutil.net_connections"}, **overrides}


def test_persistent_baseline_distinguishes_new_service_without_claiming_malware(tmp_path):
    monitor = NetworkSecurity({}, tmp_path)
    assert monitor.sample(sample(connection())) == []
    monitor = NetworkSecurity({}, tmp_path)
    assert monitor.sample(sample(connection())) == []
    events = monitor.sample(sample(connection(port=8443)))
    assert [e["kind"] for e in events] == ["network_baseline_change"]
    assert not events[0]["details"]["suspicious"] and not events[0]["details"]["malware_proven"]
    assert not authorize("block_ip", events[0], {"automatic_actions": ["block_ip"]})[0]
    assert monitor.status()["baseline_count"] == 2


def test_port_scan_requires_distinct_new_contacts_not_repeated_polling(tmp_path):
    monitor = NetworkSecurity({"network_port_scan_threshold": 3}, tmp_path)
    monitor.sample(sample())
    first = connection(port=80)
    monitor.sample(sample(first))
    for _ in range(5):
        assert not [e for e in monitor.sample(sample(first)) if e["kind"] == "network_port_scan"]
    monitor.sample(sample(first, connection(port=81)))
    monitor = NetworkSecurity({"network_port_scan_threshold": 3}, tmp_path)
    events = monitor.sample(sample(first, connection(port=81), connection(port=82)))
    alert = next(e for e in events if e["kind"] == "network_port_scan")
    assert alert["details"]["distinct_count"] == 3
    assert len(set(alert["details"]["evidence_ids"])) == 3
    assert not alert["details"]["automatic_block_eligible"]
    assert not authorize("block_ip", alert, {"automatic_actions": ["block_ip"], "autoblock_network_policy": True})[0]


def test_fanout_separate_processes_not_merged_and_pid_reuse_not_merged(tmp_path):
    monitor = NetworkSecurity({"network_fanout_threshold": 3}, tmp_path)
    monitor.sample(sample())
    events = monitor.sample(sample(*(connection(ip=f"93.184.216.{n}", pid=n) for n in range(10, 14))))
    assert not any(e["kind"] == "network_fanout" for e in events)
    events = monitor.sample(sample(*(connection(ip=f"93.184.216.{n}") for n in range(10, 13))))
    assert any(e["kind"] == "network_fanout" for e in events)
    events = monitor.sample(sample(connection(ip="93.184.216.99", create_time=2000)))
    assert not any(e["kind"] == "network_fanout" for e in events)


def test_unattributed_processes_never_group_into_scan(tmp_path):
    monitor = NetworkSecurity({"network_port_scan_threshold": 3}, tmp_path)
    monitor.sample(sample())
    events = monitor.sample(sample(*(connection(port=n, exe=None, username=None) for n in range(80, 84))))
    assert not any(e["severity"] != "info" for e in events)


def test_old_contacts_expire_and_partial_samples_do_not_invent_new_connections(tmp_path, monkeypatch):
    monitor = NetworkSecurity({"network_port_scan_threshold": 3, "network_window_seconds": 30}, tmp_path)
    monitor.sample(sample())
    monitor.sample(sample(connection(port=80), connection(port=81)))
    for item in monitor._state["contacts"]:
        item["at"] -= 31
    monitor.sample(sample(coverage={"network_source": "psutil.net_connections", "connections_truncated": True}))
    assert monitor.sample(sample(connection(port=80), connection(port=81))) == []
    events = monitor.sample(sample(connection(port=82)))
    assert not any(e["kind"] == "network_port_scan" for e in events)


def violation(tmp_path):
    config = {"denied_remote_ips": [IP], "allowed_remote_ips": [IP], "autoblock_network_policy": True,
              "automatic_actions": ["block_ip"]}
    event = NetworkSecurity(config, tmp_path).sample(sample(connection()))[0]
    return event, config


def test_explicit_policy_violation_can_authorize_scoped_response(tmp_path):
    event, config = violation(tmp_path)
    assert event["kind"] == "network_policy_violation"
    assert trusted_network_policy_event(event, config)
    assert authorize("block_ip", event, config)[0]
    assert not event["details"]["malware_proven"]  # Forbidden does not mean malicious.


@pytest.mark.parametrize("patch", [{"autoblock_network_policy": False}, {"allowed_remote_ips": []},
                                  {"denied_remote_ips": []}, {"protected_remote_ips": [IP]},
                                  {"network_security_enabled": False}])
def test_policy_rechecks_current_grants_at_action_time(tmp_path, patch):
    event, config = violation(tmp_path)
    config.update(patch)
    assert not trusted_network_policy_event(event, config)
    assert not authorize("block_ip", event, config)[0]


@pytest.mark.parametrize("patch", [{"verification_origin": "cloud"}, {"verified_local": False},
                                  {"policy_value": "other"}, {"remote_port": 0}, {"evidence_ids": []},
                                  {"observed_at": "invalid"},
                                  {"observed_at": (datetime.now(timezone.utc)-timedelta(seconds=31)).isoformat()}])
def test_forged_or_stale_policy_evidence_never_authorizes(tmp_path, patch):
    event, config = violation(tmp_path)
    event["details"].update(patch)
    assert not trusted_network_policy_event(event, config)


def test_local_addresses_cannot_autoblock_even_if_deny_listed(tmp_path):
    config = {"denied_remote_ips": ["127.0.0.1"], "allowed_remote_ips": ["127.0.0.1"],
              "autoblock_network_policy": True, "automatic_actions": ["block_ip"]}
    event = NetworkSecurity(config, tmp_path).sample(sample(connection(ip="127.0.0.1")))[0]
    assert not trusted_network_policy_event(event, config)


def test_unattributed_denied_or_stale_snapshot_not_used(tmp_path):
    monitor = NetworkSecurity({"denied_remote_ips": [IP]}, tmp_path)
    for source in ({}, {"network_source": "cloud"}, {"network_source": "psutil.net_connections", "network_access_denied": True}):
        assert monitor.sample(sample(connection(), coverage=source)) == []
    assert monitor.sample(sample(connection(), sampled_at=(datetime.now(timezone.utc)-timedelta(seconds=31)).isoformat())) == []


def test_corrupt_persistent_state_not_silently_erased(tmp_path):
    path = tmp_path / "network-security.json"
    path.write_text('{"version":1}')
    with pytest.raises(ValueError, match="invalide"):
        NetworkSecurity({}, tmp_path)
    assert json.loads(path.read_text()) == {"version": 1}


def test_actual_loopback_socket_is_observed_without_external_network_or_firewall(tmp_path):
    import psutil
    monitor = NetworkSecurity({}, tmp_path)
    monitor.sample(sample())
    process = psutil.Process()
    with socket.socket() as server, socket.socket() as client:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client.connect(server.getsockname())
        accepted, _ = server.accept()
        with accepted:
            try:
                observed = process.net_connections(kind="inet")
            except psutil.AccessDenied:
                pytest.skip("This OS denies even current-process socket metadata; capability remains explicitly unavailable")
            rows = [connection(ip=c.raddr.ip, port=c.raddr.port, local_port=c.laddr.port,
                               pid=os.getpid(), exe=process.exe(), username=process.username(), create_time=process.create_time())
                    for c in observed if c.raddr and c.raddr.ip == "127.0.0.1" and c.raddr.port == server.getsockname()[1]]
            assert rows, "The process's established loopback client socket must be visible"
            events = monitor.sample(sample(*rows))
            assert any(e["kind"] == "network_baseline_change" for e in events)
            assert all(e["severity"] == "info" and not e["details"]["malware_proven"] for e in events)


def test_coarse_system_clock_datetime_rounding_preserves_scan_window_across_restart(tmp_path, monkeypatch):
    # Windows clocks can return the same epoch value for adjacent calls. The
    # datetime representation rounds that value to microseconds and can place
    # sampled_at a fraction of a microsecond above the next time.time() result.
    epoch = 1762963200.1234567
    timestamp = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    assert 0 < datetime.fromisoformat(timestamp).timestamp() - epoch < 0.000001
    monkeypatch.setattr(network_security.time, "time", lambda: epoch)
    monitor = NetworkSecurity({"network_port_scan_threshold": 3}, tmp_path)
    monitor.sample(sample(sampled_at=timestamp))
    monitor.sample(sample(connection(port=80), sampled_at=timestamp))
    monitor.sample(sample(connection(port=80), connection(port=81), sampled_at=timestamp))
    monitor = NetworkSecurity({"network_port_scan_threshold": 3}, tmp_path)
    events = monitor.sample(sample(connection(port=80), connection(port=81), connection(port=82), sampled_at=timestamp))
    assert monitor.status()["coverage"] == "sampled_sockets_only"
    assert any(e["kind"] == "network_port_scan" and e["details"]["distinct_count"] == 3 for e in events)


def test_future_snapshot_outside_submillisecond_rounding_is_rejected(tmp_path, monkeypatch):
    epoch = 1762963200.0
    monkeypatch.setattr(network_security.time, "time", lambda: epoch)
    monitor = NetworkSecurity({"denied_remote_ips": [IP]}, tmp_path)
    future = datetime.fromtimestamp(epoch + .1, timezone.utc).isoformat()
    assert monitor.sample(sample(connection(), sampled_at=future)) == []
    assert monitor.status()["coverage"] == "stale_snapshot"
