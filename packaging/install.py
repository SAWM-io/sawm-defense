"""Per-user source installer. No service, key or automatic action is enabled."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib
import venv



INSTALLER_ID = "sawm-defense-source"


def _is_link(path):
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _write_marker(marker, contents):
    """Commit an ownership/state marker without following a substituted link."""
    if _is_link(marker):
        raise SystemExit("Le marqueur d’installation ne doit pas être un lien.")
    fd, temporary = tempfile.mkstemp(prefix=".installation-", dir=marker.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(contents, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, marker)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description="Installer SAWM Defense pour l'utilisateur courant")
    parser.add_argument("--prefix", type=Path)
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        raise SystemExit("Python 3.12 ou ultérieur est requis.")
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    default = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SAWM Defense App" if os.name == "nt" else Path.home() / ".local/share/sawm-defense-app"
    prefix = (args.prefix or default).expanduser().absolute()
    marker = prefix / "installation.json"
    expected_launcher = prefix / ("SAWM Defense.cmd" if os.name == "nt" else "sawm-defense")
    environment = prefix / "venv"
    if _is_link(prefix) or _is_link(marker) or (prefix.exists() and (not prefix.is_dir() or (any(prefix.iterdir()) and not marker.exists()))):
        raise SystemExit("Le dossier existe et n'appartient pas à cet installateur ; aucun écrasement.")
    if marker.exists():
        try:
            if not marker.is_file() or marker.stat().st_size > 65536:
                raise ValueError("invalid installation marker")
            installed = json.loads(marker.read_text(encoding="utf-8"))
            if not isinstance(installed, dict):
                raise ValueError("invalid installation marker")
            if (installed.get("launcher") != str(expected_launcher)
                    or installed.get("platform") != platform.system()
                    or not isinstance(installed.get("version"), str) or not installed["version"]):
                raise ValueError("foreign installation")
            # Markers written before resumable installation are still ours.
            # New transactional markers must carry the known owner and state.
            if ("state" in installed or "installer" in installed) and (
                    installed.get("installer") != INSTALLER_ID
                    or installed.get("state") not in {"installing", "installed"}):
                raise ValueError("unknown installer state")
        except (OSError, ValueError, TypeError):
            raise SystemExit("Marqueur d'installation invalide ; aucun écrasement.")
    if _is_link(environment) or _is_link(expected_launcher):
        raise SystemExit("Les dépendances et le lanceur ne doivent pas être des liens ou jonctions.")
    prefix.mkdir(parents=True, exist_ok=True)
    marker_data = {"version": version, "launcher": str(expected_launcher),
                   "platform": platform.system(), "installer": INSTALLER_ID, "state": "installing"}
    # Establish ownership before pip, Tk validation or shortcut creation can
    # fail. A later invocation revalidates this marker and can resume in place.
    _write_marker(marker, marker_data)
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", str(root)], check=True)
    subprocess.run([str(python), "-c", "import tkinter, psutil, httpx, keyring"], check=True)
    if os.name == "nt":
        launcher = prefix / "SAWM Defense.cmd"
        if launcher.is_symlink():
            raise SystemExit("Le lanceur ne doit pas être un lien symbolique.")
        launcher.write_text('@echo off\r\nchcp 65001 >nul\r\n"' + str(python) + '" -m sawm_defense %*\r\n', encoding="utf-8")
        pythonw = python.with_name("pythonw.exe")
        # Names and targets come only from the installer, not Cloud output.
        link = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/SAWM Defense.lnk"
        link.parent.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "SAWM_LINK": str(link), "SAWM_PYTHONW": str(pythonw)}
        code = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:SAWM_LINK);$s.TargetPath=$env:SAWM_PYTHONW;$s.Arguments='-m sawm_defense gui';$s.Save()"
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", code], env=env, check=True)
    else:
        launcher = prefix / "sawm-defense"
        if launcher.is_symlink():
            raise SystemExit("Le lanceur ne doit pas être un lien symbolique.")
        import shlex
        launcher.write_text("#!/bin/sh\nexec " + shlex.quote(str(python)) + ' -m sawm_defense "$@"\n')
        launcher.chmod(0o755)
        if sys.platform.startswith("linux"):
            apps = Path.home() / ".local/share/applications"
            apps.mkdir(parents=True, exist_ok=True)
            desktop = apps / "sawm-defense.desktop"
            if desktop.is_symlink():
                raise SystemExit("Le raccourci existant est un lien symbolique ; aucun écrasement.")
            # .desktop quoting uses double quotes, not shell interpolation.
            escaped = str(launcher).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
            desktop.write_text('[Desktop Entry]\nType=Application\nName=SAWM Defense\nComment=Defense avec SAWM et Basira Cloud\nExec="' + escaped + '" gui\nTerminal=false\nCategories=System;Security;\n', encoding="utf-8")
    _write_marker(marker, {**marker_data, "state": "installed"})
    print("Installé :", launcher)
    print("Aucun service ni échange Cloud activé. Ouvrez l'application pour configurer les autorisations.")


if __name__ == "__main__":
    main()
