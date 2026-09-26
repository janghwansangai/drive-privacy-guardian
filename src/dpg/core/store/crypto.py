"""AES-GCM column encryption for class-C metadata (SPEC 5.1). The key lives in the OS keyring."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dpg.core.auth.secret_store import SecretStore

_NONCE_BYTES = 12


class DecryptError(Exception):
    pass


def account_key_id(account: str) -> str:
    """Stable, non-identifying ID for an account (used in DB file names and keyring keys)."""
    return hashlib.sha256(account.strip().lower().encode("utf-8")).hexdigest()[:16]


class ColumnCipher:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 key required")
        self._aead = AESGCM(key)

    def encrypt(self, obj: Any, aad: str) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        plaintext = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return nonce + self._aead.encrypt(nonce, plaintext, aad.encode("utf-8"))

    def decrypt(self, blob: bytes, aad: str) -> Any:
        try:
            plaintext = self._aead.decrypt(
                blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], aad.encode("utf-8")
            )
        except (InvalidTag, ValueError):
            raise DecryptError("cannot decrypt stored record") from None
        return json.loads(plaintext.decode("utf-8"))


def db_key_name(account: str) -> str:
    return f"db-key-{account_key_id(account)}"


def load_key(store: SecretStore, account: str) -> bytes | None:
    raw = store.get(db_key_name(account))
    return base64.b64decode(raw) if raw else None


def create_key(store: SecretStore, account: str) -> bytes:
    key = AESGCM.generate_key(bit_length=256)
    store.set(db_key_name(account), base64.b64encode(key).decode("ascii"))
    return key


def delete_key(store: SecretStore, account: str) -> None:
    store.delete(db_key_name(account))
