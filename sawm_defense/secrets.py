"""OS credential vault, with an explicit memory-only mode and no plaintext fallback."""
from __future__ import annotations

import hashlib
from pathlib import Path
import threading


class SecretVault:
    def __init__(self, state_dir):
        digest = hashlib.sha256(str(Path(state_dir).expanduser().absolute()).encode()).hexdigest()[:24]
        self._service = "io.sawm.defense." + digest
        self._username = "cloud-api-key"
        self._memory = None
        self._lock = threading.RLock()
        self._backend = None
        self._persisted = False
        try:
            import keyring
            backend = keyring.get_keyring()
            # Only native credential stores; no file-based fallback backend.
            native_modules = ("keyring.backends.macOS", "keyring.backends.Windows", "keyring.backends.SecretService", "keyring.backends.kwallet")
            candidates = [backend]
            if type(backend).__module__ == "keyring.backends.chainer":
                candidates = list(backend.backends)
            for candidate in candidates:
                if type(candidate).__module__.startswith(native_modules):
                    self._backend = candidate
                    break
        except Exception:
            pass

    def __repr__(self):
        return "SecretVault(api_key=<masquée>)"

    def get(self) -> str | None:
        with self._lock:
            if self._memory is not None:
                return self._memory
            if self._backend is None:
                return None
            try:
                key = self._backend.get_password(self._service, self._username)
                self._persisted = bool(key)
                return key
            except Exception:
                return None

    def set(self, key, persist=True) -> dict:
        if not isinstance(key, str) or not 1 <= len(key.strip()) <= 8192 or any(c in key for c in "\r\n\x00"):
            raise ValueError("Clé API invalide.")
        with self._lock:
            if persist:
                if self._backend is None:
                    raise RuntimeError("Coffre système indisponible. Choisissez explicitement une clé en mémoire pour cette session.")
                try:
                    self._backend.set_password(self._service, self._username, key.strip())
                except Exception:
                    raise RuntimeError("Impossible d'enregistrer la clé dans le coffre système.") from None
                self._memory = None
                self._persisted = True
            else:
                # Do not silently revive a previously persisted key on restart.
                self.delete()
                self._memory = key.strip()
                self._persisted = False
            return self.info()

    def delete(self):
        with self._lock:
            self._memory = None
            if self._backend is not None:
                try:
                    previous = self._backend.get_password(self._service, self._username)
                    if previous is not None:
                        self._backend.delete_password(self._service, self._username)
                except Exception:
                    raise RuntimeError("Impossible de supprimer la clé du coffre système.") from None
            self._persisted = False

    def info(self) -> dict:
        return {"persisted": self._persisted, "backend": type(self._backend).__name__ if self._backend else "mémoire uniquement"}
