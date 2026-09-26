"""OS secure storage for class-B secrets (SPEC 1.2 principle 7, 5.1).

Only OS-backed keyrings are accepted (macOS Keychain, Windows Credential Manager, Linux Secret
Service / KWallet). File-based keyrings (e.g. keyrings.alt) and the null/fail backends are
rejected, so secrets can never silently end up in a plaintext file.
"""

from __future__ import annotations

import contextlib
from typing import Any, Protocol

from dpg.core.auth.errors import InsecureSecretStore

SERVICE_NAME = "drive-privacy-guardian"
KEY_CLIENT = "oauth-client"
KEY_TOKEN = "oauth-token"  # noqa: S105 — keyring entry name, not a secret

# Windows Credential Manager stores at most 2560 bytes (UTF-16 => ~1280 chars).
MAX_VALUE_CHARS = 1200

_SECURE_BACKEND_MODULES = (
    "keyring.backends.macOS",
    "keyring.backends.Windows",
    "keyring.backends.SecretService",
    "keyring.backends.libsecret",
    "keyring.backends.kwallet",
)


class SecretStore(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...
    def delete(self, key: str) -> None: ...


def is_secure_backend(backend: Any) -> bool:
    module = type(backend).__module__
    if module == "keyring.backends.chainer":
        members = list(getattr(backend, "backends", []))
        return bool(members) and all(is_secure_backend(b) for b in members)
    return module.startswith(_SECURE_BACKEND_MODULES)


class KeyringSecretStore:
    def __init__(self, service: str = SERVICE_NAME, backend: Any = None) -> None:
        import keyring

        self._backend = backend if backend is not None else keyring.get_keyring()
        if not is_secure_backend(self._backend):
            raise InsecureSecretStore()
        self._service = service

    def get(self, key: str) -> str | None:
        value = self._backend.get_password(self._service, key)
        return value if isinstance(value, str) else None

    def set(self, key: str, value: str) -> None:
        if len(value) > MAX_VALUE_CHARS:
            raise ValueError("secret too large for OS credential store")
        self._backend.set_password(self._service, key, value)

    def delete(self, key: str) -> None:
        from keyring.errors import PasswordDeleteError

        with contextlib.suppress(PasswordDeleteError):
            self._backend.delete_password(self._service, key)
