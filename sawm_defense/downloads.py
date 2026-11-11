"""Download observation, stability checks and effective local scope; never executes files."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import stat
import sys
import time

from .platforms import no_symlink


def downloads_directory():
    """Default downloads location. Custom browser locations need explicit monitor_paths."""
    fallback = Path.home() / "Downloads"
    if sys.platform.startswith("linux"):
        settings = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "user-dirs.dirs"
        try:
            if settings.stat().st_size < 32768:
                for line in settings.read_text().splitlines():
                    match = re.fullmatch(r'XDG_DOWNLOAD_DIR="([^"\n]+)"', line.strip())
                    if match:
                        value = match[1].replace("${HOME}", str(Path.home())).replace("$HOME", str(Path.home()))
                        if "$" not in value and "`" not in value and Path(value).is_absolute():
                            return Path(value)
        except (OSError, UnicodeError):
            pass
    if sys.platform == "win32":
        # Known Folder redirection is resolved by the OS, without invoking PowerShell.
        try:
            import ctypes
            import uuid
            class GUID(ctypes.Structure):
                _fields_ = [("data", ctypes.c_ubyte * 16)]
            guid = GUID((ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID("374DE290-123F-4565-9164-39C4925E467B").bytes_le))
            value = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(value)) == 0:
                try:
                    return Path(value.value)
                finally:
                    ctypes.windll.ole32.CoTaskMemFree(value)
        except (OSError, ValueError, AttributeError):
            pass
    return fallback


def effective_config(config):
    effective = copy.deepcopy(config)
    roots = list(effective.get("monitor_paths", []))
    if effective.get("protect_downloads", False):
        root = downloads_directory()
        if root.is_dir() and no_symlink(root):
            roots.append(str(root))
    effective["monitor_paths"] = list(dict.fromkeys(roots))
    return effective


class StableFiles:
    """Wait after each size/mtime/inode change; a restart starts a fresh waiting period."""
    def __init__(self):
        self._seen = {}

    def ready(self, path, seconds=3, *, now=None):
        path = Path(path)
        if not no_symlink(path):
            raise ValueError("Lien symbolique exclu")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Fichier non ordinaire")
        stamp = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        now = time.monotonic() if now is None else now
        old = self._seen.get(str(path))
        if old is None or old[0] != stamp:
            if len(self._seen) >= 2000:
                self._seen.pop(next(iter(self._seen)))
            self._seen[str(path)] = (stamp, now)
            return False
        partial = path.name.lower().endswith((".crdownload", ".part", ".partial", ".download"))
        # Also inspect abandoned partial downloads, but never claim transfer completion.
        return now - old[1] >= max(seconds, 15 if partial else seconds)
