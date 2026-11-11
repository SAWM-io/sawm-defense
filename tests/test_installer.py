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
