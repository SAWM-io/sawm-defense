"""Explicit, user-session startup. Never enables root services or kernel modules."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .platforms import no_symlink


def _identity(state_dir):
    return hashlib.sha256(str(Path(state_dir).absolute()).encode()).hexdigest()[:12]


def startup_plan(executable, state_dir):
    state_dir = Path(state_dir).absolute()
    if not executable or any(not isinstance(part, str) or any(c in part for c in "\n\r\x00") for part in executable):
        raise ValueError("Commande de démarrage invalide")
    command = [*executable, "--state-dir", str(state_dir), "watch"]
    suffix = _identity(state_dir)
    system = platform.system()
    if system == "Darwin":
        name = "io.sawm.defense." + suffix
        path = Path.home() / "Library/LaunchAgents" / (name + ".plist")
        content = plistlib.dumps({"Label": name, "ProgramArguments": command, "RunAtLoad": True,
                                 "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 15,
                                 "ProcessType": "Background", "EnvironmentVariables": {"PYTHONUNBUFFERED": "1"}}).decode()
        return {"platform": system, "name": name, "path": str(path), "content": content, "command": command,
                "scope": "current user login session", "available": bool(shutil.which("launchctl"))}
    if system == "Linux":
        name = "sawm-defense-" + suffix + ".service"
        path = Path.home() / ".config/systemd/user" / name
        quoted = " ".join('"' + part.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"' for part in command)
        content = ("[Unit]\nDescription=SAWM Defense user monitor\nAfter=network-online.target\n\n[Service]\nType=simple\n"
                   f"ExecStart={quoted}\nRestart=on-failure\nRestartSec=15\nUMask=0077\nNoNewPrivileges=true\n\n[Install]\nWantedBy=default.target\n")
        return {"platform": system, "name": name, "path": str(path), "content": content, "command": command,
                "scope": "current user service; logout persistence depends on administrator configuration", "available": bool(shutil.which("systemctl"))}
    if system == "Windows":
        name = "SAWM-Defense-" + suffix
        path = state_dir / "startup-task.xml"
        ns = "http://schemas.microsoft.com/windows/2004/02/mit/task"
        ET.register_namespace("", ns)
        tag = lambda value: "{" + ns + "}" + value
        task = ET.Element(tag("Task"), {"version": "1.2"})
        reg = ET.SubElement(task, tag("RegistrationInfo"))
        ET.SubElement(reg, tag("Description")).text = "SAWM Defense user monitor " + suffix
        triggers = ET.SubElement(task, tag("Triggers"))
        trigger = ET.SubElement(triggers, tag("LogonTrigger"))
        ET.SubElement(trigger, tag("Enabled")).text = "true"
        # Interactive current account only. Domain qualification avoids ambiguities.
        username = os.environ.get("USERNAME", "")
        domain = os.environ.get("USERDOMAIN", "")
        principal_id = (domain + "\\" if domain else "") + username
        ET.SubElement(trigger, tag("UserId")).text = principal_id
        principals = ET.SubElement(task, tag("Principals"))
        principal = ET.SubElement(principals, tag("Principal"), {"id": "Author"})
        ET.SubElement(principal, tag("UserId")).text = principal_id
        ET.SubElement(principal, tag("LogonType")).text = "InteractiveToken"
        ET.SubElement(principal, tag("RunLevel")).text = "LeastPrivilege"
        settings = ET.SubElement(task, tag("Settings"))
        ET.SubElement(settings, tag("MultipleInstancesPolicy")).text = "IgnoreNew"
        ET.SubElement(settings, tag("DisallowStartIfOnBatteries")).text = "false"
        ET.SubElement(settings, tag("StopIfGoingOnBatteries")).text = "false"
        ET.SubElement(settings, tag("ExecutionTimeLimit")).text = "PT0S"
        restart = ET.SubElement(settings, tag("RestartOnFailure"))
        ET.SubElement(restart, tag("Interval")).text = "PT1M"
        ET.SubElement(restart, tag("Count")).text = "3"
        actions = ET.SubElement(task, tag("Actions"), {"Context": "Author"})
        execute = ET.SubElement(actions, tag("Exec"))
        ET.SubElement(execute, tag("Command")).text = command[0]
        ET.SubElement(execute, tag("Arguments")).text = subprocess.list2cmdline(command[1:])
        content = ET.tostring(task, encoding="unicode")
        return {"platform": system, "name": name, "path": str(path), "content": content, "command": command,
                "scope": "current user logon task, least privilege", "available": bool(shutil.which("schtasks"))}
    return {"platform": system, "available": False, "reason": "Système non pris en charge"}


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20)


def install_startup(executable, state_dir):
    plan = startup_plan(executable, state_dir)
    if not plan.get("available"):
        return {"status": "unsupported", "reason": "Gestionnaire de démarrage utilisateur indisponible", "plan": plan}
    state_dir = Path(state_dir).absolute()
    record_path = state_dir / "startup-registration.json"
    path = Path(plan["path"])
    try:
        if not no_symlink(path) or not no_symlink(record_path):
            raise ValueError("Lien symbolique dans la destination")
        if path.exists() and path.read_text(encoding="utf-8") != plan["content"]:
            raise ValueError("Configuration existante différente ; aucun écrasement")
        if plan["platform"] == "Windows":
            existing = _run(["schtasks", "/Query", "/TN", plan["name"]])
            if existing.returncode == 0:
                return {"status": "denied", "reason": "Tâche déjà présente ; la retirer explicitement avant réinstallation"}
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.write(plan["content"])
        if plan["platform"] == "Darwin":
            cmds = [["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)]]
        elif plan["platform"] == "Linux":
            cmds = [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", plan["name"]]]
        else:
            cmds = [["schtasks", "/Create", "/TN", plan["name"], "/XML", str(path)], ["schtasks", "/Run", "/TN", plan["name"]]]
        # Persist registration before applying so partial failures remain removable.
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        receipt = {"name": plan["name"], "path": str(path), "platform": plan["platform"],
                   "sha256": hashlib.sha256(plan["content"].encode()).hexdigest()}
        fd = os.open(record_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(receipt, out)
        for cmd in cmds:
            if _run(cmd).returncode:
                return {"status": "error", "reason": "Configuration conservée mais démarrage non confirmé ; gestionnaire utilisateur à vérifier", "name": plan["name"]}
        return {"status": "completed", "reason": "Surveillance enregistrée pour cet utilisateur", "name": plan["name"], "scope": plan["scope"]}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"status": "denied", "reason": "Destination existante, permissions ou gestionnaire de démarrage indisponible"}


def remove_startup(state_dir):
    state_dir = Path(state_dir).absolute()
    record_path = state_dir / "startup-registration.json"
    try:
        if not no_symlink(record_path):
            raise ValueError("Reçu invalide")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        expected = startup_plan(["placeholder"], state_dir)
        if record["name"] != expected.get("name") or record["path"] != expected.get("path") or record["platform"] != platform.system():
            raise ValueError("Service étranger")
        path = Path(record["path"])
        if not no_symlink(path) or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            raise ValueError("Configuration modifiée ; suppression refusée")
        if platform.system() == "Darwin":
            cmds = [["launchctl", "bootout", f"gui/{os.getuid()}", str(path)]]
        elif platform.system() == "Linux":
            cmds = [["systemctl", "--user", "disable", "--now", record["name"]]]
        else:
            query = _run(["schtasks", "/Query", "/TN", record["name"], "/XML"])
            if query.returncode:
                raise ValueError("Tâche non vérifiable")
            actual = SafeET.fromstring(query.stdout)
            saved = SafeET.fromstring(path.read_text(encoding="utf-8"))
            ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
            for field in ("Command", "Arguments"):
                if actual.findtext("t:Actions/t:Exec/t:" + field, namespaces=ns) != saved.findtext("t:Actions/t:Exec/t:" + field, namespaces=ns):
                    raise ValueError("Tâche modifiée hors de SAWM")
            cmds = [["schtasks", "/Delete", "/TN", record["name"], "/F"]]
        for cmd in cmds:
            if _run(cmd).returncode:
                return {"status": "error", "reason": "Arrêt non confirmé ; configuration conservée"}
        path.unlink()
        record_path.unlink()
        if platform.system() == "Linux":
            _run(["systemctl", "--user", "daemon-reload"])
        return {"status": "completed", "reason": "Démarrage automatique retiré"}
    except FileNotFoundError:
        return {"status": "denied", "reason": "Aucune inscription de démarrage vérifiable"}
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired, ET.ParseError, DefusedXmlException):
        return {"status": "denied", "reason": "Inscription modifiée ou suppression non autorisée"}
