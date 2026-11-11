"""Read-only integration with an already installed antivirus scanner."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import subprocess

from .platforms import file_digest


class Antivirus:
    def _engine(self):
        clam = shutil.which("clamscan")
        if clam:
            return "ClamAV", clam
        if platform.system() == "Windows":
            roots = [Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft/Windows Defender/Platform",
                     Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender"]
            for root in roots:
                candidates = sorted(root.glob("*/MpCmdRun.exe"), reverse=True) if root.name == "Platform" else [root / "MpCmdRun.exe"]
                for path in candidates:
                    if path.is_file():
                        return "Microsoft Defender", str(path)
        return None, None

    def capabilities(self):
        name, exe = self._engine()
        return {"available": bool(exe), "engine": name, "mode": "scan-only",
                "reason": "Moteur installé ; signatures gérées par son administrateur." if exe else "Installer ClamAV (Linux/macOS) ou activer Microsoft Defender (Windows). Aucun verdict antivirus sans moteur."}

    def scan(self, path):
        path = Path(os.path.abspath(os.path.expanduser(path)))
        engine, exe = self._engine()
        result = {"status": "unavailable", "engine": engine, "path": str(path), "sha256": None, "detections": []}
        if not exe:
            return {**result, "reason": "Aucun moteur antivirus installé accessible"}
        try:
            sha, before = file_digest(path)
            result["sha256"] = sha
            if engine == "ClamAV":
                cmd = [exe, "--no-summary", "--", str(path)]
            else:
                cmd = [exe, "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"]
            scanned = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            after_sha, after = file_digest(path)
            if sha != after_sha or before.st_ino != after.st_ino:
                return {**result, "status": "error", "reason": "Le fichier a changé pendant le scan"}
            if engine == "ClamAV":
                if scanned.returncode == 0:
                    return {**result, "status": "clean"}
                if scanned.returncode == 1:
                    detections = [line.rsplit(": ", 1)[-1][:-6][:200] for line in scanned.stdout.splitlines() if line.endswith(" FOUND")]
                    if detections:
                        return {**result, "status": "detected", "detections": detections, "verified_local": True}
                return {**result, "status": "error", "reason": "Le scanner n'a pas produit un résultat exploitable", "exit_code": scanned.returncode}
            # Microsoft documents: 0=no malware OR successful remediation, 2=unremediated
            # threat OR scan error. Here remediation is disabled AND the file/hash remain
            # unchanged, so a successful scan is a scanner-negative result, not a safety proof.
            # https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
            if scanned.returncode == 0:
                return {**result, "status": "clean"}
            return {**result, "status": "error", "reason": "Defender signale une détection non remédiée ou une erreur ; sortie du scanner à examiner. Ce mode ne remplit pas l'historique Defender.",
                    "exit_code": scanned.returncode, "requires_review": True}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return {**result, "status": "error", "reason": "Fichier illisible, modifié, non ordinaire ou délai du scanner dépassé"}
