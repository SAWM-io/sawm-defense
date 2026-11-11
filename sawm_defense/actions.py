"""Small, scoped response vocabulary. A Cloud response is never a shell command."""
from __future__ import annotations

import hashlib
from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import uuid
from urllib.parse import urlparse

from .platforms import file_digest, no_symlink, psutil, utc_now
from .policy import trusted_auth_event


def _inside(path, roots):
    return any(path.is_relative_to(Path(os.path.abspath(os.path.expanduser(root)))) for root in roots)


def _address_equal(value, expected):
    try:
        # Windows lists a host RemoteIP as /32 or /128 on some versions.
        network = ipaddress.ip_network(value.strip(), strict=False)
        return network.prefixlen == network.max_prefixlen and str(network.network_address) == expected
    except ValueError:
        return False


def _ufw_present(output, name, ip):
    found = set()
    for line in output.splitlines():
        body, marker, comment = line.partition("#")
        if not marker or comment.strip() != name:
            continue
        body = body.replace("(v6)", "").strip()
        match = re.fullmatch(r"(\S+)\s+DENY(?:\s+(IN|OUT))?\s+(\S+)", body)
        if not match:
            continue
        destination, direction, source = match.groups()
        if direction in {None, "IN"} and destination == "Anywhere" and _address_equal(source, ip):
            found.add("in")
        if direction == "OUT" and source == "Anywhere" and _address_equal(destination, ip):
            found.add("out")
    return found


def _netsh_present(output, name, ip, direction):
    # Fail closed on unsupported/localized output instead of treating exit 0
    # as proof that the exact requested firewall rule exists.
    fields = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            key = key.strip().lower().replace(" ", "")
            if key in fields:
                return False
            fields[key] = value.strip()
    return (fields.get("rulename") == name + "-" + direction
            and fields.get("enabled", "").lower() == "yes"
            and fields.get("direction", "").lower() == direction
            and fields.get("action", "").lower() == "block"
            and fields.get("localip", "").lower() == "any"
            and fields.get("protocol", "").lower() == "any"
            and _address_equal(fields.get("remoteip", ""), ip))


class ActionExecutor:
    def __init__(self, state_dir):
        self.state_dir = Path(state_dir).absolute()
        self.quarantine = self.state_dir / "quarantine"
        self.receipts = self.state_dir / "response-receipts"
        for directory in (self.quarantine, self.receipts):
            if not no_symlink(directory):
                raise ValueError("État local traversant un lien symbolique")
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)

    @staticmethod
    def _result(kind, status, reason, **fields):
        return {"action": kind, "status": status, "reason": reason, "timestamp": utc_now(), **fields}

    def _write_receipt(self, record):
        path = self.receipts / (record["receipt_id"] + ".json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(record, out, ensure_ascii=False)
            out.flush()
            os.fsync(out.fileno())

    def _read_receipt(self, record):
        receipt_id = record.get("receipt_id") or record.get("result", {}).get("receipt_id")
        if not isinstance(receipt_id, str) or len(receipt_id) != 32 or any(c not in "0123456789abcdef" for c in receipt_id):
            raise ValueError("Référence de reçu invalide")
        path = self.receipts / (receipt_id + ".json")
        if not no_symlink(path):
            raise ValueError("Reçu invalide")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("receipt_id") != receipt_id:
            raise ValueError("Reçu incohérent")
        return data

    def _scoped_file(self, path, config):
        path = Path(os.path.abspath(os.path.expanduser(path)))
        if not _inside(path, config.get("monitor_paths", [])):
            raise ValueError("Fichier hors des dossiers autorisés")
        if _inside(path, [str(self.state_dir), *config.get("protected_paths", [])]):
            raise ValueError("Fichier protégé")
        if not no_symlink(path) or not path.is_file():
            raise ValueError("Fichier absent ou lien symbolique exclu")
        return path

    def execute(self, action, event, config):
        try:
            if action == "quarantine":
                return self._quarantine(event, config)
            if action == "terminate":
                return self._terminate(event, config)
            if action == "block_ip":
                return self._block_ip(event, config)
            return self._result(action, "denied", "Action inconnue")
        except (ValueError, KeyError, TypeError, OSError) as exc:
            # Errors are generated locally; no commands, keys or Cloud text are included.
            return self._result(action, "denied", str(exc)[:300])
        except subprocess.TimeoutExpired:
            return self._result(action, "error", "Délai système dépassé ; contrôler l'état avant toute reprise")

    def _quarantine(self, event, config):
        details = event.get("details", {})
        path = self._scoped_file(details["path"], config)
        limit = int(config.get("max_file_mb", 100)) * 1024 * 1024
        sha, st = file_digest(path, limit)
        if not details.get("sha256") or sha != details["sha256"]:
            raise ValueError("Empreinte différente de l'observation ; nouvelle vérification requise")
        if st.st_nlink > 1:
            raise ValueError("Fichier à liens multiples : quarantaine partielle refusée")
        receipt_id = uuid.uuid4().hex
        destination = self.quarantine / (receipt_id + ".isolated")
        # Save before mutation. A failed move has an auditable prepared receipt.
        receipt = {"receipt_id": receipt_id, "action": "quarantine", "path": str(path),
                   "quarantine_path": str(destination), "sha256": sha, "size": st.st_size,
                   "original_mode": stat.S_IMODE(st.st_mode), "event_id": event.get("id"), "timestamp": utc_now()}
        self._write_receipt(receipt)
        # Copy on a separate filesystem without exposing an executable intermediate.
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with ExitStack() as stack:
                target = stack.enter_context(os.fdopen(fd, "wb"))
                source_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                source = stack.enter_context(os.fdopen(source_fd, "rb"))
                current_source = os.fstat(source_fd)
                if not stat.S_ISREG(current_source.st_mode) or (current_source.st_ino, current_source.st_dev) != (st.st_ino, st.st_dev):
                    raise ValueError("Source remplacée avant isolation")
                copied_size = 0
                while block := source.read(1024 * 1024):
                    copied_size += len(block)
                    if copied_size > limit:
                        raise ValueError("Fichier devenu trop grand")
                    target.write(block)
                target.flush()
                os.fsync(target.fileno())
            copied, _ = file_digest(destination, limit)
            current, latest = file_digest(path, limit)
            if copied != sha or current != sha or (st.st_ino, st.st_dev) != (latest.st_ino, latest.st_dev):
                raise ValueError("Le fichier a changé ; isolation annulée")
            path.unlink()
            return self._result("quarantine", "completed", "Fichier isolé ; restauration explicite possible", **receipt)
        except Exception:
            destination.unlink(missing_ok=True)
            raise

    def restore(self, action_record, config):
        try:
            receipt = self._read_receipt(action_record)
            if receipt["action"] != "quarantine":
                raise ValueError("Ce reçu ne concerne pas une quarantaine")
            destination = Path(receipt["path"])
            source = self.quarantine / (receipt["receipt_id"] + ".isolated")
            if destination.exists() or destination.is_symlink():
                raise ValueError("Destination déjà occupée ; aucun écrasement autorisé")
            if not _inside(destination, config.get("monitor_paths", [])) or _inside(destination, config.get("protected_paths", [])):
                raise ValueError("Destination hors autorisation actuelle")
            if not no_symlink(destination.parent) or not destination.parent.is_dir():
                raise ValueError("Dossier de restauration absent ou lié")
            sha, _ = file_digest(source, int(config.get("max_file_mb", 100)) * 1024 * 1024)
            if sha != receipt["sha256"]:
                raise ValueError("Quarantaine altérée")
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(fd, "wb") as target, open(source, "rb") as inp:
                    copied_size = 0
                    while block := inp.read(1024 * 1024):
                        copied_size += len(block)
                        if copied_size > int(config.get("max_file_mb", 100)) * 1024 * 1024:
                            raise ValueError("Quarantaine devenue trop grande")
                        target.write(block)
                    target.flush()
                    os.fsync(target.fileno())
                restored, _ = file_digest(destination)
                if restored != sha:
                    raise ValueError("Vérification de restauration échouée")
                # Remains non-executable intentionally. Re-execution is a separate human decision.
                source.unlink()
            except Exception:
                destination.unlink(missing_ok=True)
                raise
            return self._result("restore", "completed", "Fichier restauré sans droit d'exécution", receipt_id=receipt["receipt_id"], path=str(destination), sha256=sha)
        except (ValueError, OSError, KeyError, TypeError):
            return self._result("restore", "denied", "Restauration refusée : reçu, intégrité, destination ou autorisation à vérifier")

    def _terminate(self, event, config):
        if not psutil:
            return self._result("terminate", "unsupported", "psutil absent")
        details = event.get("details", {})
        pid = int(details["pid"])
        if pid <= 1 or pid == os.getpid() or pid == os.getppid():
            raise ValueError("Processus système ou agent protégé")
        try:
            process = psutil.Process(pid)
            if process.name().lower() in {"systemd", "init", "launchd", "kernel_task", "sshd", "wininit.exe", "lsass.exe", "csrss.exe", "services.exe", "system", "registry"}:
                raise ValueError("Processus de base du système protégé")
            if process.username() != psutil.Process().username():
                raise ValueError("Seuls les processus de l'utilisateur courant sont autorisés")
            if not details.get("create_time") or abs(process.create_time() - float(details["create_time"])) > 0.001:
                raise ValueError("Identité PID périmée ou incomplète")
            exe = Path(process.exe()).absolute()
            if str(exe) not in config.get("allowed_process_paths", []):
                raise ValueError("Exécutable absent de la liste autorisée")
            if _inside(exe, config.get("protected_paths", [])) or str(exe) != details.get("exe"):
                raise ValueError("Exécutable protégé ou identité différente")
            sha, _ = file_digest(exe, 512 * 1024 * 1024)
            if sha != details.get("exe_sha256"):
                raise ValueError("Empreinte de l'exécutable absente ou différente")
            process.terminate()
            try:
                process.wait(timeout=3)
                return self._result("terminate", "completed", "Arrêt gracieux constaté", pid=pid, create_time=details["create_time"], exe=str(exe))
            except psutil.TimeoutExpired:
                return self._result("terminate", "error", "Signal envoyé, processus toujours actif ; aucun SIGKILL automatique", pid=pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return self._result("terminate", "denied", "Processus absent ou accès insuffisant")

    @staticmethod
    def _admin():
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0

    def _block_ip(self, event, config):
        ip = str(ipaddress.ip_address(event.get("details", {})["remote_ip"]))
        automatic = config.get("_automatic_response") is True
        auth_autoscope = (automatic and config.get("autoblock_auth_ips") is True
                          and trusted_auth_event(event, config))
        if automatic and not trusted_auth_event(event, config):
            raise ValueError("Le blocage automatique exige des échecs SSH système vérifiés et récents")
        if not ipaddress.ip_address(ip).is_global or (ip not in config.get("allowed_remote_ips", []) and not auth_autoscope):
            raise ValueError("L'IP publique doit être autorisée explicitement ou par la politique SSH vérifiée")
        if ip in config.get("protected_remote_ips", []):
            raise ValueError("Adresse distante protégée")
        if ip in {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}:
            raise ValueError("Résolveur DNS protégé")
        hostname = urlparse(config.get("cloud_base_url", "https://basira-api.sawm.io")).hostname
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            addresses = {item[4][0] for item in pool.submit(socket.getaddrinfo, hostname, 443).result(timeout=3)}
        except (OSError, FutureTimeout):
            raise ValueError("Adresse Cloud non vérifiable ; blocage refusé")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        if ip in addresses:
            raise ValueError("Destination Cloud protégée")
        system = platform.system()
        if system not in {"Linux", "Windows"}:
            return self._result("block_ip", "unsupported", "Blocage IP macOS non implémenté ; aucun changement PF global")
        if not self._admin():
            return self._result("block_ip", "denied", "Droits administrateur requis ; aucune élévation automatique")
        # Never isolate the host's configured DNS resolver, including a custom public one.
        if system == "Linux":
            try:
                dns_servers = {line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines()
                               if line.strip().startswith("nameserver ") and len(line.split()) >= 2}
            except OSError:
                raise ValueError("Résolveurs DNS non vérifiables")
        else:
            dns_result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                                         "Get-DnsClientServerAddress | ForEach-Object { $_.ServerAddresses }"],
                                        capture_output=True, text=True, timeout=10)
            if dns_result.returncode:
                raise ValueError("Résolveurs DNS non vérifiables")
            dns_servers = {line.strip() for line in dns_result.stdout.splitlines()}
        if ip in dns_servers:
            raise ValueError("Résolveur DNS configuré protégé")
        receipt_id = uuid.uuid4().hex
        name = "SAWM-" + receipt_id
        if system == "Linux":
            ufw = shutil.which("ufw")
            if not ufw:
                return self._result("block_ip", "unsupported", "UFW actif requis pour une règle ciblée")
            status = subprocess.run([ufw, "status"], capture_output=True, text=True, timeout=10, env={**os.environ, "LC_ALL": "C"})
            if status.returncode or "Status: active" not in status.stdout:
                return self._result("block_ip", "denied", "UFW n'est pas actif ; aucune activation globale")
            if re.search(r"(?<![0-9a-fA-F:.])" + re.escape(ip) + r"(?![0-9a-fA-F:.])", status.stdout):
                return self._result("block_ip", "denied", "Une règle existe déjà pour cette IP ; aucune règle étrangère ne sera modifiée")
            commands = [[ufw, "deny", "in", "from", ip, "comment", name], [ufw, "deny", "out", "to", ip, "comment", name]]
            rollback = [[ufw, "--force", "delete", "deny", "in", "from", ip, "comment", name], [ufw, "--force", "delete", "deny", "out", "to", ip, "comment", name]]
        else:
            profiles = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, timeout=10)
            states = re.findall(r"^State\s+(ON|OFF)\s*$", profiles.stdout, re.M)
            if profiles.returncode or len(states) != 3 or any(value != "ON" for value in states):
                return self._result("block_ip", "denied", "Profils pare-feu actifs non vérifiables ; aucune activation globale")
            commands = [["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}-{d}", f"dir={d}", "action=block", f"remoteip={ip}", "enable=yes"] for d in ("in", "out")]
            rollback = [["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}-{d}"] for d in ("in", "out")]
        receipt = {"receipt_id": receipt_id, "action": "block_ip", "remote_ip": ip, "rule_name": name,
                   "platform": system, "timestamp": utc_now(), "event_id": event.get("id"), "automatic": automatic}
        if automatic:
            receipt["expires_at"] = time.time() + min(3600, max(60, int(config.get("auto_block_seconds", 600))))
        self._write_receipt(receipt)
        try:
            for cmd in commands:
                response = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env={**os.environ, "LC_ALL": "C"})
                if response.returncode:
                    raise RuntimeError("Firewall declined rule")
            checked = self._inspect_firewall(receipt)
            if not checked["ok"] or checked["present"] != {"in", "out"} or len(checked["named"]) != 2:
                raise RuntimeError("Exact firewall rules not verified")
            return self._result("block_ip", "completed", "Deux règles ciblées présentes et vérifiées ; effet sur le trafic à contrôler séparément", verified=True, **receipt)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            # The timed-out command may have succeeded. Keep the prepared
            # receipt and inspect/remove both exact possible rules.
            recovered = self._remove_firewall(receipt, rollback)
            return self._result("block_ip", "error", "Installation non vérifiée ; retrait ciblé " + ("vérifié" if recovered else "à contrôler"),
                                verified=False, rollback_verified=recovered, **receipt)

    @staticmethod
    def _inspect_firewall(receipt):
        name, ip = receipt["rule_name"], receipt["remote_ip"]
        if receipt["platform"] == "Linux":
            executable = shutil.which("ufw")
            if not executable:
                return {"ok": False, "present": set(), "named": set()}
            result = subprocess.run([executable, "status"], capture_output=True, text=True, timeout=10, env={**os.environ, "LC_ALL": "C"})
            active = result.returncode == 0 and "Status: active" in result.stdout
            named = {line for line in result.stdout.splitlines() if line.partition("#")[2].strip() == name}
            return {"ok": active, "present": _ufw_present(result.stdout, name, ip), "named": named}
        present, named, ok = set(), set(), True
        for direction in ("in", "out"):
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}-{direction}", "verbose"],
                                    capture_output=True, text=True, timeout=10)
            if "No rules match the specified criteria." in result.stdout:
                continue
            if result.returncode or not result.stdout.strip():
                ok = False
                continue
            if re.search(r"^Rule Name:\s*" + re.escape(name + "-" + direction) + r"\s*$", result.stdout, re.M):
                named.add(direction)
            else:
                ok = False
            if _netsh_present(result.stdout, name, ip, direction):
                present.add(direction)
        return {"ok": ok, "present": present, "named": named}

    def _remove_firewall(self, receipt, commands):
        for cmd in commands:
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=10, env={**os.environ, "LC_ALL": "C"})
            except (OSError, subprocess.TimeoutExpired):
                # Still inspect actual state: a timed-out native command may
                # have completed, and absence is what the receipt must prove.
                pass
        try:
            checked = self._inspect_firewall(receipt)
            return checked["ok"] and not checked["named"]
        except (OSError, subprocess.TimeoutExpired):
            return False

    def rollback(self, record, config):
        try:
            receipt = self._read_receipt(record)
            if receipt.get("action") == "quarantine":
                return self.restore(record, config)
            if receipt.get("action") != "block_ip" or receipt.get("platform") != platform.system() or not self._admin():
                raise ValueError("Retour arrière non autorisé")
            ip = str(ipaddress.ip_address(receipt["remote_ip"]))
            name = "SAWM-" + receipt["receipt_id"]
            if receipt.get("rule_name") != name or not ipaddress.ip_address(ip).is_global:
                raise ValueError("Identité de règle incohérente")
            if platform.system() == "Windows":
                commands = [["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}-{d}"] for d in ("in", "out")]
            else:
                ufw = shutil.which("ufw")
                if not ufw:
                    raise ValueError("UFW absent")
                commands = [[ufw, "--force", "delete", "deny", "in", "from", ip, "comment", name], [ufw, "--force", "delete", "deny", "out", "to", ip, "comment", name]]
            removed = self._remove_firewall(receipt, commands)
            return self._result("unblock_ip", "completed" if removed else "error", "Retrait des règles ciblées " + ("vérifié" if removed else "non vérifié"),
                                verified=bool(removed), receipt_id=receipt["receipt_id"], remote_ip=ip)
        except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
            return self._result("unblock_ip", "denied", "Reçu, plateforme ou autorisation indisponible")
