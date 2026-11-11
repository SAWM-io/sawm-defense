"""Explicit, scoped Linux audit installation; SAWM never executes in the kernel.

No arbitrary commands, module loading, global audit reset or silent elevation.
Rules observe writes/attribute changes; response remains the local policy's job.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import tempfile

from .config import private_dir
from .security_sensors import _protected_native_file


def _paths(config):
    values = config.get("kernel_audit_paths") or config.get("monitor_paths", [])
    if not isinstance(values, list) or len(values) > 32:
        raise ValueError("Au maximum 32 chemins d'audit explicites sont acceptés.")
    result = []
    for value in values:
        if not isinstance(value, str) or len(value) > 4096 or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value):
            raise ValueError("L'audit exige un chemin absolu sans espaces ni caractères de commande.")
        path = Path(value)
        # Canonical paths make the generated auditctl grammar unambiguous and
        # prevent approving one tree then following a different symbolic link.
        if ".." in path.parts or path == Path("/") or str(path.resolve()) != str(path) or not path.is_dir():
            raise ValueError("Le périmètre d'audit doit être un répertoire existant, canonique et distinct de /.")
        if str(path) not in result:
            result.append(str(path))
    return result


def audit_plan(config, state_dir=None):
    """Pure inspection/plan: no privileged writes and no commands executed."""
    paths = _paths(config)
    architectures = ["b64"]
    if platform.machine().lower() in {"x86_64", "amd64"}:
        architectures.append("b32")
    rules = []
    for path in paths:
        for arch in architectures:
            key = "sawm_" + hashlib.sha256((path + ":" + arch).encode()).hexdigest()[:16]
            args = ["-a", "always,exit", "-F", "arch=" + arch, "-F", "dir=" + path, "-F", "perm=wa", "-k", key]
            rules.append({"path": path, "architecture": arch, "key": key, "arguments": args,
                          "rule": " ".join(args)})
    executable = shutil.which("auditctl")
    return {"status": "planned", "platform": platform.system(), "paths": paths, "rules": rules,
            "reader": executable, "supported": platform.system() == "Linux" and bool(executable),
            "scope": "Écritures et changements d'attributs dans les répertoires explicitement choisis.",
            "persistent": False, "requires_root": True, "requires_approval": True,
            "limits": ["Pas de capture exhaustive des fichiers, lectures ou paquets réseau.",
                       "auditd doit être actif ; les règles never et les pertes du journal réduisent la couverture.",
                       "Les sous-montages et io_uring nécessitent une configuration audit dédiée.",
                       "L'application ne consomme pas encore les événements auditd ; ces traces se consultent avec ausearch.",
                       "Aucun module noyau ou programme eBPF n'est chargé par cette version."]}


def _run(executable, args):
    completed = subprocess.run([executable, *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, timeout=10, check=False, env={**os.environ, "LC_ALL": "C"})
    if len(completed.stdout) > 1024 * 1024:
        raise ValueError("Réponse auditctl trop volumineuse.")
    return completed


def _contains_rule(output, rule):
    # auditctl normalizes arch identifiers and permission order. Key + exact
    # path + action + permissions suffice to recognize our existing scope.
    for line in output.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if "dir=" + rule["path"] not in tokens or "always,exit" not in tokens:
            continue
        pairs = list(zip(tokens, tokens[1:]))
        key_matches = ("-k", rule["key"]) in pairs or "key=" + rule["key"] in tokens
        permission = next((p[5:] for p in tokens if p.startswith("perm=")), "")
        architectures = {"b64", "c000003e", "c00000b7"} if rule["architecture"] == "b64" else {"b32", "40000003"}
        architecture = next((p[5:] for p in tokens if p.startswith("arch=")), "")
        if key_matches and set(permission) == {"w", "a"} and architecture in architectures:
            return True
    return False


def _artifact(state_dir, plan, status):
    directory = private_dir(Path(state_dir))
    target = directory / "sawm-defense-audit.rules"
    receipt = directory / "kernel-audit-install.json"
    for path, content in ((target, "# Runtime rules; operator must review persistence separately.\n" + "\n".join(r["rule"] for r in plan["rules"]) + "\n"),
                          (receipt, json.dumps({"status": status, "persistent": False, "keys": [r["key"] for r in plan["rules"]]}, indent=2))):
        if path.is_symlink():
            raise ValueError("Artefact d'audit remplacé par un lien ; écriture refusée.")
        fd, name = tempfile.mkstemp(prefix=".kernel-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    return str(target)


def install_audit(config, state_dir, approved=False):
    """Install only planned runtime rules after explicit operator approval.

    Invoked by an already privileged CLI process; never invokes sudo. A failure
    attempts to remove only the exact rules added during this invocation.
    """
    plan = audit_plan(config, state_dir)
    if not approved:
        return {**plan, "status": "approval_required"}
    if not plan["supported"]:
        return {**plan, "status": "unsupported", "reason": "Linux et auditctl sont nécessaires."}
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return {**plan, "status": "denied", "reason": "Exécuter la commande explicitement en administrateur Linux."}
    if not plan["rules"]:
        return {**plan, "status": "denied", "reason": "Aucun répertoire d'audit configuré."}
    executable = plan["reader"]
    if not _protected_native_file(executable):
        return {**plan, "status": "denied", "reason": "auditctl n'est pas un exécutable système protégé."}
    added = []
    try:
        state = _run(executable, ["-s"])
        if state.returncode or not re.search(r"^enabled\s+1\s*$", state.stdout, re.M) or not re.search(r"^pid\s+[1-9][0-9]*\s*$", state.stdout, re.M):
            return {**plan, "status": "denied", "reason": "auditd doit être actif et l'audit modifiable ; aucune politique globale ne sera changée."}
        existing = _run(executable, ["-l"])
        if existing.returncode:
            raise RuntimeError("existing_rules_unreadable")
        if re.search(r"(?:never,task|task,never|never,exit|exit,never)", existing.stdout):
            return {**plan, "status": "denied", "reason": "Des règles never peuvent neutraliser la collecte ; revue par l'administrateur nécessaire."}
        # Save before mutation, so an unwritable state directory never leaves
        # newly installed rules without their reviewable manifest.
        artifact = _artifact(state_dir, plan, "prepared")
        for rule in plan["rules"]:
            if _contains_rule(existing.stdout, rule):
                continue
            # A timeout can occur after the kernel applied the rule. Include
            # that exact attempted rule in recovery before invoking auditctl.
            added.append(rule)
            if _run(executable, rule["arguments"]).returncode:
                raise RuntimeError("rule_install_failed")
        checked = _run(executable, ["-l"])
        if checked.returncode or not all(_contains_rule(checked.stdout, rule) for rule in plan["rules"]):
            raise RuntimeError("rule_verification_failed")
        _artifact(state_dir, plan, "installed_runtime")
        return {**plan, "status": "installed_runtime", "artifact": artifact, "added": len(added),
                "verified": True, "reason": "Règles présentes dans le noyau jusqu'au redémarrage ; validation d'événements à effectuer."}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        rollback = []
        for rule in reversed(added):
            try:
                args = ["-d", *rule["arguments"][1:]]
                rollback.append({"key": rule["key"], "removed": _run(executable, args).returncode == 0})
            except (OSError, ValueError, subprocess.TimeoutExpired):
                rollback.append({"key": rule["key"], "removed": False})
        return {**plan, "status": "error", "verified": False, "rollback": rollback,
                "reason": "Installation non vérifiée ; seules les nouvelles règles ont fait l'objet d'un retrait. Contrôler l'état auditctl."}
