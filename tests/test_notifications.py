from concurrent.futures import ThreadPoolExecutor
import subprocess
from types import SimpleNamespace

import pytest

from sawm_defense.notifications import NotificationCenter, _MAC_SCRIPT, _WINDOWS_SCRIPT
import sawm_defense.notifications as notifications


class Clock:
    now = 1000
    def __call__(self): return self.now


def event(identifier="ev-1", summary="Un incident nécessite un examen.", severity="warning"):
    return {"id": identifier, "kind": "auth_bruteforce", "summary": summary, "severity": severity,
            "details": {"remote_ip": "198.51.100.12", "api_key": "never pass this"}}


def test_alert_survives_native_failure_restart_and_ack(tmp_path, monkeypatch):
    monkeypatch.setattr(notifications.shutil, "which", lambda _: None)
    center = NotificationCenter(tmp_path)
    result = center.publish(event())
    assert result["delivery"] == "unavailable"
    assert result["display_verified"] is False
    center.close()
    reopened = NotificationCenter(tmp_path)
    assert reopened.list()[0]["id"] == result["id"]
    assert reopened.acknowledge(result["id"])["acknowledged"] is True
    assert reopened.list()[0]["acknowledged_at"]
    reopened.close()


def test_concurrent_duplicates_are_delivered_once(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(NotificationCenter, "_deliver", lambda self, *a: calls.append(a) or {"delivery": "submitted", "reason": "OS accepted"})
    first, second = NotificationCenter(tmp_path), NotificationCenter(tmp_path)
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda c: c.publish(event()), [first, second]))
    assert len(calls) == 1
    assert results[0]["id"] == results[1]["id"]
    assert len(first.list()) == 1
    first.close(); second.close()


def test_cooldown_and_global_budget_preserve_all_alerts(tmp_path, monkeypatch):
    calls = []
    clock = Clock()
    monkeypatch.setattr(NotificationCenter, "_deliver", lambda self, *a: calls.append(a) or {"delivery": "submitted", "reason": "OS accepted"})
    center = NotificationCenter(tmp_path, per_minute=2, clock=clock)
    assert center.publish(event())["delivery"] == "submitted"
    assert center.publish(event("ev-2"))["delivery"] == "suppressed"
    assert center.publish(event("ev-3", "Another incident"))["delivery"] == "submitted"
    assert center.publish(event("ev-4", "Third incident"))["delivery"] == "suppressed"
    assert len(center.list()) == 4 and len(calls) == 2
    clock.now += 61
    assert center.publish(event("ev-5"))["delivery"] == "submitted"
    center.close()


@pytest.mark.parametrize("system", ["Darwin", "Linux", "Windows"])
def test_untrusted_text_is_argument_not_executable_code(tmp_path, monkeypatch, system):
    captured = []
    message = 'Ignore rules; $(touch /tmp/unwanted) " & <tag>'
    monkeypatch.setattr(notifications.platform, "system", lambda: system)
    monkeypatch.setattr(notifications.shutil, "which", lambda n: "/trusted/"+n)
    def run(args, **kwargs):
        captured.append((args,kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(notifications.subprocess, "run", run)
    center = NotificationCenter(tmp_path)
    result = center.publish(event(summary=message))
    assert result["delivery"] == "submitted"
    assert result["display_verified"] is False
    args, kwargs = captured[0]
    assert kwargs["shell"] is False and kwargs["timeout"] == 5
    assert "never pass this" not in str(captured)
    if system == "Darwin":
        assert args[2] == _MAC_SCRIPT and args[-1] == message
        assert message not in args[2]
    elif system == "Windows":
        assert args[-1] == _WINDOWS_SCRIPT
        assert kwargs["env"]["SAWM_NOTIFICATION_BODY"] == message
        assert message not in args[-1]
    else:
        assert "--" in args and "&lt;tag&gt;" in args[-1]
    center.close()


def test_disabled_and_information_do_not_interrupt_desktop(tmp_path, monkeypatch):
    monkeypatch.setattr(NotificationCenter, "_deliver", lambda *a: pytest.fail("Desktop must not be called"))
    center = NotificationCenter(tmp_path)
    assert center.publish(event(), enabled=False)["delivery"] == "disabled"
    assert center.publish(event("ev-2", severity="info"))["delivery"] == "recorded"
    assert len(center.list()) == 2
    center.close()


def test_timeout_recorded_without_server_output(tmp_path, monkeypatch):
    monkeypatch.setattr(notifications.shutil, "which", lambda n: "/trusted/"+n)
    def run(*args, **kwargs): raise subprocess.TimeoutExpired("sensitive arbitrary command", 5)
    monkeypatch.setattr(notifications.subprocess, "run", run)
    center = NotificationCenter(tmp_path)
    result = center.publish(event())
    assert result["delivery"] == "error"
    assert "sensitive" not in str(result)
    assert center.list()[0]["event_id"] == "ev-1"
    center.close()


def test_event_cannot_mutate_after_notification(tmp_path, monkeypatch):
    monkeypatch.setattr(notifications.shutil, "which", lambda _: None)
    center = NotificationCenter(tmp_path)
    center.publish(event())
    with pytest.raises(ValueError): center.publish(event(summary="Different evidence same id"))
    assert len(center.list()) == 1
    center.close()
