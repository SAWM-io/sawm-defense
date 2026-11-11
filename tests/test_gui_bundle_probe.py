"""The packaging probe must not mistake another process or a splash for the app."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def probe():
    path = Path(__file__).resolve().parents[1] / "packaging" / "verify_gui_bundle.py"
    spec = importlib.util.spec_from_file_location("sawm_gui_bundle_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def linux_stub(probe, monkeypatch, *, owner=1234, title="SAWM Defense — Protection & activité", width=1280, height=870, visible=True):
    monkeypatch.setenv("DISPLAY", ":99")
    monkeypatch.setattr(probe.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(probe, "linux_owner_pid", lambda identifier: owner)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[0] == "xdotool":
            assert "--name" in command and "--pid" not in command
            return SimpleNamespace(returncode=0, stdout="6291460\n")
        assert command == ["xwininfo", "-id", "6291460", "-stats"]
        return SimpleNamespace(returncode=0, stdout=f'xwininfo: Window id: 0x600004 "{title}"\n  Width: {width}\n  Height: {height}\n  Map State: ' + ("IsViewable" if visible else "IsUnMapped"))

    monkeypatch.setattr(probe.subprocess, "run", run)
    return calls


def test_linux_probe_accepts_server_attributed_large_window_without_net_wm_pid(probe, monkeypatch):
    linux_stub(probe, monkeypatch)
    found = probe.linux_window(1234)
    assert found["owner_pid"] == 1234 and found["width"] == 1280
    assert found["method"].startswith("XRes 1.2")


@pytest.mark.parametrize("owner", [4321, None])
def test_linux_probe_rejects_unknown_or_other_pid_even_with_matching_title(probe, monkeypatch, owner):
    calls = linux_stub(probe, monkeypatch, owner=owner)
    assert probe.linux_window(1234) is None
    assert len(calls) == 1  # Do not even inspect another process's window.


@pytest.mark.parametrize("overrides", [{"title":"Other application"}, {"width":799}, {"height":499}, {"visible":False}])
def test_linux_probe_rejects_wrong_title_small_or_hidden_window(probe, monkeypatch, overrides):
    linux_stub(probe, monkeypatch, **overrides)
    assert probe.linux_window(1234) is None


def test_linux_probe_refuses_missing_owner_api_without_name_only_fallback(probe, monkeypatch):
    linux_stub(probe, monkeypatch)
    def missing(_):
        raise RuntimeError("XRes not available")
    monkeypatch.setattr(probe,"linux_owner_pid", missing)
    with pytest.raises(RuntimeError,match="XRes"):
        probe.linux_window(1234)
