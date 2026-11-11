"""Installer refusal paths must not alter unrelated installations."""
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys

import pytest


def installer():
    path = Path(__file__).resolve().parents[1] / "packaging/install.py"
    spec = importlib.util.spec_from_file_location("sawm_source_installer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_installer_preserves_foreign_folder(tmp_path, monkeypatch):
    app = installer()
    (tmp_path / "important.txt").write_text("keep me")
    monkeypatch.setattr(sys, "argv", ["install.py", "--prefix", str(tmp_path)])
    with pytest.raises(SystemExit):
        app.main()
    assert (tmp_path / "important.txt").read_text() == "keep me"
    assert not (tmp_path / "venv").exists()


def test_installer_rejects_invalid_marker(tmp_path, monkeypatch):
    app = installer()
    (tmp_path / "installation.json").write_text("[]")
    monkeypatch.setattr(sys, "argv", ["install.py", "--prefix", str(tmp_path)])
    with pytest.raises(SystemExit):
        app.main()
    assert not (tmp_path / "venv").exists()


def test_installer_does_not_follow_replaced_environment(tmp_path, monkeypatch):
    app = installer()
    prefix, outside = tmp_path / "app", tmp_path / "unrelated"
    prefix.mkdir()
    outside.mkdir()
    (outside / "keep").write_text("not ours")
    launcher = prefix / ("SAWM Defense.cmd" if os.name == "nt" else "sawm-defense")
    (prefix / "installation.json").write_text(json.dumps({"version": "0.1.0", "platform": platform.system(), "launcher": str(launcher)}))
    try:
        (prefix / "venv").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink privilege unavailable")
    monkeypatch.setattr(sys, "argv", ["install.py", "--prefix", str(prefix)])
    with pytest.raises(SystemExit):
        app.main()
    assert (outside / "keep").read_text() == "not ours"


def test_installer_resumes_its_partial_install_after_pip_failure(tmp_path, monkeypatch):
    app = installer()
    prefix = tmp_path / "client app"
    attempts = []
    markers_seen = []
    monkeypatch.setattr(sys, "argv", ["install.py", "--prefix", str(prefix)])
    # Any platform-specific shortcut stays inside the disposable test tree.
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))

    class Venv:
        def create(self, folder):
            markers_seen.append(json.loads((prefix / "installation.json").read_text()))
            assert markers_seen[-1]["state"] == "installing"
            python = folder / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            python.parent.mkdir(parents=True, exist_ok=True)
            python.write_text("harmless venv fixture")

    def run(command, **kwargs):
        if command[1:4] == ["-m", "pip", "install"]:
            attempts.append(tuple(command))
            if len(attempts) == 1:
                raise app.subprocess.CalledProcessError(1, command)
        return app.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(app.venv, "EnvBuilder", lambda **kwargs: Venv())
    monkeypatch.setattr(app.subprocess, "run", run)
    with pytest.raises(app.subprocess.CalledProcessError):
        app.main()
    marker = json.loads((prefix / "installation.json").read_text())
    assert marker["state"] == "installing"
    assert marker["installer"] == app.INSTALLER_ID
    assert (prefix / "venv").is_dir()
    app.main()
    final = json.loads((prefix / "installation.json").read_text())
    assert final["state"] == "installed"
    assert final["platform"] == platform.system()
    assert Path(final["launcher"]).is_file()
    assert len(attempts) == 2 and len(markers_seen) == 2
    assert not list(prefix.glob(".installation-*"))


@pytest.mark.parametrize("changed", [
    {"launcher": "/another/application"},
    {"platform": "unrelated-platform"},
    {"installer": "foreign-installer"},
    {"state": "arbitrary"},
    {"version": {"invalid": "type"}},
])
def test_resuming_revalidates_pending_owner_and_destination(tmp_path, monkeypatch, changed):
    app = installer()
    launcher = tmp_path / ("SAWM Defense.cmd" if os.name == "nt" else "sawm-defense")
    marker = {"version": "0.2.0", "launcher": str(launcher), "platform": platform.system(),
              "installer": app.INSTALLER_ID, "state": "installing", **changed}
    marker_path = tmp_path / "installation.json"
    marker_path.write_text(json.dumps(marker))
    original = marker_path.read_bytes()
    monkeypatch.setattr(sys, "argv", ["install.py", "--prefix", str(tmp_path)])
    with pytest.raises(SystemExit):
        app.main()
    assert marker_path.read_bytes() == original
    assert not (tmp_path / "venv").exists()


def test_pending_marker_link_is_never_followed(tmp_path, monkeypatch):
    app = installer()
    prefix = tmp_path / "app"
    prefix.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"version": "0.2.0", "platform": platform.system(),
                                  "launcher": str(prefix / ("SAWM Defense.cmd" if os.name == "nt" else "sawm-defense")),
                                  "installer": app.INSTALLER_ID, "state": "installing"}))
    original = outside.read_bytes()
    try:
        (prefix / "installation.json").symlink_to(outside)
    except OSError:
        pytest.skip("Symlink privilege unavailable")
    monkeypatch.setattr(sys, "argv", ["install.py", "--prefix", str(prefix)])
    with pytest.raises(SystemExit):
        app.main()
    assert outside.read_bytes() == original
    assert not (prefix / "venv").exists()
