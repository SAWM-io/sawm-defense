"""Bounded, read-only host observations. No kernel-wide coverage is implied."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import threading
import time

try:
    import psutil
except ImportError:  # A degraded installation remains inspectable.
    psutil = None


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def no_symlink(path: Path) -> bool:
    """Reject symlinks in every existing component, including the leaf."""
    path = Path(os.path.abspath(path))
    return not any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents))


def file_digest(path: Path, max_bytes: int = 100 * 1024 * 1024) -> tuple[str, os.stat_result]:
    """Hash an ordinary file without following a leaf symlink; detect concurrent edits."""
    if not no_symlink(path):
        raise ValueError("Lien symbolique exclu")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise ValueError("Fichier non ordinaire ou taille hors limite")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("Fichier devenu trop grand")
            digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ValueError("Fichier modifié pendant la lecture")
        return digest.hexdigest(), after
    finally:
        os.close(fd)


class Collector:
    MAX_FILES = 2000
    MAX_DIRECTORIES = 2000
    MAX_PROCESSES = 250
    MAX_CONNECTIONS = 400
    SCAN_SECONDS = 1.5
    HASH_BUDGET = 32 * 1024 * 1024

    def __init__(self, config):
        self._lock = threading.RLock()
        self.config = dict(config)
        self._files = {}
        self._initialized_roots = set()
        self._seen_paths = set()
        self._connections = set()
        self._network_initialized = False
        self._process_identities = set()
        self._last_alert = {}
        self._denied_network = False
        self._denied_processes = False
        self._incomplete_processes = False

    def update_config(self, config):
        with self._lock:
            if config.get("monitor_paths") != self.config.get("monitor_paths"):
                self._files = {}
                self._initialized_roots = set()
                self._seen_paths = set()
            if config.get("allowed_process_paths") != self.config.get("allowed_process_paths"):
                self._process_identities = set()
            self.config = dict(config)

    def capabilities(self):
        return [
            {"name": "Fichiers sélectionnés", "available": True,
             "reason": "Sondage borné, sans liens symboliques ; les changements entre deux sondages peuvent échapper."},
            {"name": "CPU et RAM", "available": psutil is not None,
             "reason": "Mesures disponibles avec les droits du compte." if psutil else "Dépendance psutil absente."},
            {"name": "Processus", "available": psutil is not None and not self._denied_processes,
             "reason": "Dépendance psutil absente." if not psutil else
                       "Énumération indisponible ou interrompue ; les autres capteurs continuent." if self._denied_processes else
                       "Liste partielle : limite atteinte ou processus protégés ; historique conservé." if self._incomplete_processes else
                       "Lecture utilisateur ; certains processus peuvent rester protégés."},
            {"name": "Connexions réseau", "available": psutil is not None and not self._denied_network,
             "reason": "Connexions accessibles à cet utilisateur ; aucune capture du contenu des paquets."},
            {"name": "Surveillance noyau exhaustive", "available": False,
             "reason": "Aucun pilote noyau installé ; ce client ne remplace pas un EDR système."},
            {"name": "Attribution des écritures à un utilisateur", "available": False,
             "reason": "Le propriétaire du fichier est connu, pas l'identité de son dernier rédacteur."},
        ]

    def _file_observations(self):
        deadline = time.monotonic() + self.SCAN_SECONDS
        budget = self.HASH_BUDGET
        events, seen, roots_complete = [], set(), set()
        scanned = skipped = directories_seen = 0
        roots = [Path(os.path.abspath(os.path.expanduser(p))) for p in self.config.get("monitor_paths", [])]
        max_bytes = min(int(self.config.get("max_file_mb", 100)) * 1024 * 1024, self.HASH_BUDGET)
        for root in roots:
            if not root.is_dir() or not no_symlink(root):
                skipped += 1
                continue
            complete = True
            walk_errors = []
            for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_errors.append):
                if directories_seen >= self.MAX_DIRECTORIES or time.monotonic() >= deadline:
                    complete = False
                    break
                directories_seen += 1
                dirs[:] = sorted(d for d in dirs if no_symlink(Path(directory) / d))
                for filename in sorted(files):
                    if scanned >= self.MAX_FILES or time.monotonic() >= deadline:
                        complete = False
                        break
                    path = Path(directory) / filename
                    key = str(path)
                    seen_before = key in self._seen_paths
                    seen.add(key)
                    self._seen_paths.add(key)
                    scanned += 1
                    try:
                        st = path.lstat()
                        if not stat.S_ISREG(st.st_mode) or not no_symlink(path) or st.st_size > max_bytes:
                            skipped += 1
                            continue
                        fingerprint = (st.st_size, st.st_mtime_ns, st.st_ino)
                        old = self._files.get(key)
                        if old and old["fingerprint"] == fingerprint:
                            continue
                        if st.st_size > budget:
                            skipped += 1
                            complete = False
                            continue
                        sha256, st = file_digest(path, max_bytes)
                        budget -= st.st_size
                        details = {"path": key, "sha256": sha256, "size": st.st_size,
                                   "mtime_ns": st.st_mtime_ns, "owner_uid": getattr(st, "st_uid", None),
                                   "actor_attributed": False}
                        self._files[key] = {"fingerprint": (st.st_size, st.st_mtime_ns, st.st_ino), "details": details}
                        if str(root) in self._initialized_roots:
                            kind = "file_modified" if old else "file_observed" if seen_before else "file_created"
                            events.append({"kind": kind, "severity": "info",
                                           "summary": f"Fichier {'modifié' if old else 'observé' if seen_before else 'créé'} : {path.name}", "details": details})
                    except (OSError, ValueError):
                        skipped += 1
                if not complete:
                    break
            if walk_errors:
                complete = False
                skipped += len(walk_errors)
            self._initialized_roots.add(str(root))
            if complete:
                roots_complete.add(str(root))
        for key in list(self._files):
            if key not in seen and any(Path(key).is_relative_to(r) for r in roots_complete):
                previous = self._files.pop(key)
                self._seen_paths.discard(key)
                events.append({"kind": "file_deleted", "severity": "info", "summary": f"Fichier supprimé : {Path(key).name}",
                               "details": previous["details"]})
        return events, {"files_seen": scanned, "files_skipped": skipped, "directories_seen": directories_seen,
                        "known_files": len(self._files),
                        "file_limit": self.MAX_FILES, "scan_complete": len(roots_complete) == len(roots) and skipped == 0,
                        "monitored_roots": len(roots), "scope": "selected folders, polling only"}

    def sample(self):
        with self._lock:
            return self._sample()

    def _sample(self):
        events, coverage = self._file_observations()
        processes, connections = [], []
        cpu = memory = None
        if psutil:
            cpu, memory = psutil.cpu_percent(), psutil.virtual_memory().percent
            denied = 0
            allowed_processes = set(self.config.get("allowed_process_paths", []))
            observed_processes = set()
            hashes_left = 2
            process_complete = True
            process_error = None
            process_truncated = False
            self._denied_processes = False
            try:
                # process_iter can fail while being created or only on next().
                # Keep the failure local to this sensor, including partial lists.
                for process in psutil.process_iter(["pid", "name", "username", "create_time", "exe"]):
                    if len(processes) >= self.MAX_PROCESSES:
                        process_complete = False
                        process_truncated = True
                        break
                    try:
                        info = dict(process.info)
                        processes.append(info)
                        identity = (info["pid"], info.get("create_time"))
                        observed_processes.add(identity)
                        if info.get("exe") in allowed_processes and identity not in self._process_identities and hashes_left:
                            hashes_left -= 1
                            try:
                                digest, _ = file_digest(Path(info["exe"]), 32 * 1024 * 1024)
                                events.append({"kind": "process_observed", "severity": "info", "summary": "Processus autorisé observé",
                                               "details": {**info, "exe_sha256": digest, "malware_proven": False}})
                                self._process_identities.add(identity)
                            except (OSError, ValueError):
                                pass
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        denied += 1
                        process_complete = False
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError) as error:
                process_error = type(error).__name__
                process_complete = False
                self._denied_processes = True
            self._incomplete_processes = not process_complete
            coverage["process_access_denied"] = denied
            coverage["process_scan_complete"] = process_complete
            coverage["processes_truncated"] = process_truncated
            if process_error:
                coverage["process_enumeration_error"] = process_error
            if process_complete:
                # Absence from a partial/denied sample is not a disappearance.
                self._process_identities.intersection_update(observed_processes)
            try:
                raw = psutil.net_connections(kind="inet")
                self._denied_network = False
                current = set()
                for conn in raw[:self.MAX_CONNECTIONS]:
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    row = {"pid": conn.pid, "local": local, "remote": remote, "status": conn.status}
                    connections.append(row)
                    if conn.raddr:
                        key = (conn.pid, conn.raddr.ip, conn.raddr.port)
                        current.add(key)
                        if self._network_initialized and key not in self._connections and len(events) < 100:
                            events.append({"kind": "network_connection", "severity": "info", "summary": "Nouvelle connexion observée",
                                           "details": {**row, "remote_ip": conn.raddr.ip, "remote_port": conn.raddr.port,
                                                       "suspicious": False, "attribution": "OS socket PID"}})
                self._connections = current
                self._network_initialized = True
                coverage["connections_truncated"] = len(raw) > self.MAX_CONNECTIONS
            except (psutil.AccessDenied, OSError):
                self._denied_network = True
                coverage["network_access_denied"] = True
            for label, value in (("cpu", cpu), ("memory", memory)):
                if value >= 90 and time.monotonic() - self._last_alert.get(label, -1000) >= 120:
                    self._last_alert[label] = time.monotonic()
                    events.append({"kind": "resource_pressure", "severity": "warning", "summary": f"Utilisation {label.upper()} élevée",
                                   "details": {"resource": label, "percent": value, "malware_proven": False}})
        coverage["events_truncated"] = len(events) > 200
        return {"platform": platform.system(), "cpu_percent": cpu, "memory_percent": memory,
                "processes": processes, "connections": connections, "capabilities": self.capabilities(),
                "coverage": coverage, "sampled_at": utc_now()}, events[:200]

    def inventory(self):
        system = platform.system()
        if system == "Darwin":
            items = sorted({p.name for root in (Path("/Applications"), Path.home() / "Applications")
                            if root.is_dir() for p in root.glob("*.app")})[:500]
            return {"status": "completed", "programs": items, "source": "Application bundles", "complete": False,
                    "note": "Applications visibles uniquement ; aucun verdict sur leur innocuité."}
        if system == "Windows":
            import winreg
            items = set()
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                    try:
                        with winreg.OpenKey(hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | view) as key:
                            for i in range(min(winreg.QueryInfoKey(key)[0], 2000)):
                                try:
                                    with winreg.OpenKey(key, winreg.EnumKey(key, i)) as sub:
                                        items.add(str(winreg.QueryValueEx(sub, "DisplayName")[0]))
                                except OSError:
                                    continue
                    except OSError:
                        continue
            return {"status": "completed", "programs": sorted(items)[:500], "source": "Windows uninstall registry", "complete": False}
        cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"] if shutil.which("dpkg-query") else ["rpm", "-qa"] if shutil.which("rpm") else None
        if not cmd:
            return {"status": "unsupported", "programs": [], "reason": "Aucun gestionnaire de paquets reconnu"}
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
            return {"status": "completed" if result.returncode == 0 else "error", "programs": result.stdout.splitlines()[:500],
                    "source": cmd[0], "complete": False}
        except (OSError, subprocess.TimeoutExpired):
            return {"status": "error", "programs": [], "reason": "Inventaire indisponible ou délai dépassé"}
