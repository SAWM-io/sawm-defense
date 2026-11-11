"""Validated, atomic user configuration. Credentials never belong here."""
from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
from urllib.parse import urlsplit

DEFAULTS = {
    "cloud_enabled": False, "cloud_upload_enabled": False,
    "cloud_base_url": "https://basira-api.sawm.io/api/v1/basira",
    "space_id": "", "entity_id": "", "monitor_paths": [],
    "poll_seconds": 5, "cloud_per_hour": 4, "automatic_actions": [],
    "allowed_process_paths": [], "allowed_remote_ips": [], "protected_paths": [],
    "max_file_mb": 100, "retention_days": 30,
    "monitor_on_launch": True, "notifications_enabled": True,
    "protect_downloads": True, "automatic_scan_enabled": True,
    "download_scan_settle_seconds": 3, "autonomous_analysis_enabled": True,
    "auth_log_paths": [], "auth_journal_enabled": False,
    "auth_failure_threshold": 5, "auth_window_seconds": 300,
    "autoblock_auth_ips": False, "protected_remote_ips": [], "auto_block_seconds": 600,
    "kernel_audit_paths": [],
}


def default_state_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "SAWM Defense"
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/SAWM Defense"
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "sawm-defense"


def private_dir(path: Path) -> Path:
    path = Path(path).expanduser().absolute()
    if path.is_symlink():
        raise ValueError("Le répertoire d'état ne doit pas être un lien symbolique.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def validate_config(config: dict) -> dict:
    if not isinstance(config, dict) or set(config) - set(DEFAULTS):
        raise ValueError("Champ de configuration inconnu ; aucune clé API n'est acceptée ici.")
    out = copy.deepcopy(DEFAULTS)
    out.update(copy.deepcopy(config))
    for key in ("cloud_enabled", "cloud_upload_enabled", "monitor_on_launch", "notifications_enabled",
                "protect_downloads", "automatic_scan_enabled", "autonomous_analysis_enabled",
                "auth_journal_enabled", "autoblock_auth_ips"):
        if type(out[key]) is not bool:
            raise ValueError(f"{key} doit être un booléen.")
    for key, low, high in (("poll_seconds", 1, 3600), ("cloud_per_hour", 0, 120),
                           ("max_file_mb", 1, 2048), ("retention_days", 1, 3650),
                           ("download_scan_settle_seconds", 1, 120), ("auth_failure_threshold", 3, 100),
                           ("auth_window_seconds", 30, 3600), ("auto_block_seconds", 60, 3600)):
        if type(out[key]) is not int or not low <= out[key] <= high:
            raise ValueError(f"{key} doit être un entier entre {low} et {high}.")
    base = out["cloud_base_url"]
    if not isinstance(base, str) or len(base) > 2048:
        raise ValueError("URL Cloud invalide.")
    parsed = urlsplit(base)
    if (parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"})) or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Le Cloud exige une URL HTTPS sans identifiant, paramètres ni fragment.")
    out["cloud_base_url"] = base.rstrip("/")
    for key, pattern in (("space_id", r"[A-Za-z0-9._~:+/=-]{1,160}"), ("entity_id", r"ent_[0-9a-f]{32}")):
        value = out[key]
        if not isinstance(value, str) or (value and not re.fullmatch(pattern, value)):
            raise ValueError(f"{key} invalide.")
    for key in ("monitor_paths", "protected_paths", "allowed_process_paths", "auth_log_paths", "kernel_audit_paths"):
        values = out[key]
        if not isinstance(values, list) or len(values) > 100:
            raise ValueError(f"{key} exige une liste de 100 chemins au maximum.")
        normalized = []
        for value in values:
            if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > 4096:
                raise ValueError(f"Chemin invalide dans {key}.")
            path = Path(value).expanduser()
            if not path.is_absolute():
                raise ValueError("Un chemin absolu est requis.")
            normalized.append(str(path.absolute()))
        out[key] = list(dict.fromkeys(normalized))
    actions = out["automatic_actions"]
    if not isinstance(actions, list) or len(actions) > 3 or any(not isinstance(a, str) or a not in {"quarantine", "terminate", "block_ip"} for a in actions):
        raise ValueError("Autorisation automatique inconnue.")
    out["automatic_actions"] = list(dict.fromkeys(actions))
    ips = out["allowed_remote_ips"]
    if not isinstance(ips, list) or len(ips) > 100:
        raise ValueError("Liste d'adresses IP invalide.")
    normalized_ips = []
    for value in ips:
        try:
            address = ipaddress.ip_address(value) if isinstance(value, str) else None
        except ValueError:
            address = None
        if address is None or not address.is_global:
            raise ValueError("Seules des adresses IP publiques individuelles sont autorisées.")
        normalized_ips.append(str(address))
    out["allowed_remote_ips"] = list(dict.fromkeys(normalized_ips))
    protected = out["protected_remote_ips"]
    if not isinstance(protected, list) or len(protected) > 100 or any(not isinstance(v, str) for v in protected):
        raise ValueError("Liste d'adresses protégées invalide.")
    try:
        out["protected_remote_ips"] = list(dict.fromkeys(str(ipaddress.ip_address(v)) for v in protected if isinstance(v, str)))
    except ValueError:
        raise ValueError("Adresses protégées : IP individuelles requises.") from None
    return out


class ConfigManager:
    def __init__(self, state_dir=None):
        self.state_dir = private_dir(Path(state_dir) if state_dir else default_state_dir())
        self.config_path = self.state_dir / "config.json"
        self._lock = threading.RLock()

    def load(self) -> dict:
        with self._lock:
            if self.config_path.is_symlink():
                raise ValueError("Le fichier de configuration ne doit pas être un lien.")
            if not self.config_path.exists():
                return copy.deepcopy(DEFAULTS)
            if self.config_path.stat().st_size > 131072:
                raise ValueError("Configuration trop volumineuse.")
            return validate_config(json.loads(self.config_path.read_text(encoding="utf-8")))

    def save(self, patch: dict) -> dict:
        with self._lock:
            if not isinstance(patch, dict) or set(patch) - set(DEFAULTS):
                raise ValueError("Champ de configuration inconnu.")
            merged = self.load()
            merged.update(patch)
            validated = validate_config(merged)
            fd, temp = tempfile.mkstemp(prefix=".config-", dir=self.state_dir)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(validated, stream, ensure_ascii=False, indent=2)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, self.config_path)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
            return copy.deepcopy(validated)
