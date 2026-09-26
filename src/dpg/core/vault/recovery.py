"""Recovery key for encrypted archives (user request, D-074).

A "master password reset" is impossible for encryption: nobody can open an archive without
its password. Instead, one recovery key is created once and kept on paper. Every archive's
password is *derived* from that key and the archive's random tag (in its file name), so even
with the keychain and all passwords lost, typing the recovery key re-creates the password.

- Nothing is sent anywhere (no e-mail, no server). The key lives in the OS keychain and on paper.
- Whoever has the recovery key can open every archive made with it: keep it like a safe key.
- Archives made before the recovery key existed keep their own random passwords.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import string

RECOVERY_KEY_NAME = "vault:recovery-key"
_KEY_BYTES = 20  # 160 bits
_ALPHABET = string.ascii_letters + string.digits
_TAG_RE = re.compile(r"_([0-9a-f]{8})\.(?:7z|zip)$")
_CONFUSABLE = str.maketrans({"0": "O", "1": "I", "8": "B"})


class InvalidRecoveryKey(ValueError):
    """Typo or not a recovery key (checksum mismatch)."""


def _checksum(raw: bytes) -> str:
    return base64.b32encode(hashlib.sha256(b"dpg-rk" + raw).digest())[:3].decode("ascii")


def new_recovery_key() -> str:
    raw = secrets.token_bytes(_KEY_BYTES)
    text = base64.b32encode(raw).decode("ascii").rstrip("=") + _checksum(raw)  # 32 + 3 chars
    return "-".join(text[i : i + 5] for i in range(0, len(text), 5))


def parse_recovery_key(text: str) -> bytes:
    """Accepts spaces/dashes/lower case and the usual 0/O, 1/I, 8/B mix-ups."""
    clean = re.sub(r"[\s\-]", "", text).upper().translate(_CONFUSABLE)
    if len(clean) != 35 or not re.fullmatch(r"[A-Z2-7]+", clean):
        raise InvalidRecoveryKey("복구 키는 35자(5자씩 7묶음)입니다.")
    try:
        raw = base64.b32decode(clean[:32])
    except ValueError:
        raise InvalidRecoveryKey("복구 키 형식이 아닙니다.") from None
    if _checksum(raw) != clean[32:]:
        raise InvalidRecoveryKey("복구 키가 맞지 않습니다. 오타가 없는지 확인해 주세요.")
    return raw


def fingerprint(raw: bytes) -> str:
    """Non-secret short id to recognise the same key later (safe to store in prefs)."""
    return hmac.new(raw, b"dpg-fingerprint", hashlib.sha256).hexdigest()[:8].upper()


def tag_from_name(archive_name: str) -> str | None:
    m = _TAG_RE.search(archive_name)
    return m.group(1) if m else None


def derive_password(raw: bytes, tag: str) -> str:
    """Deterministic 24-char password (same shape as `archive.generate_password`)."""
    counter = 0
    while True:
        stream = hmac.new(raw, f"dpg-vault-v1|{tag}|{counter}".encode(), hashlib.sha512).digest()
        chars = [_ALPHABET[b % 62] for b in stream if b < 248][:24]  # unbiased: 248 = 62 * 4
        if (
            len(chars) == 24
            and any(c.islower() for c in chars)
            and any(c.isupper() for c in chars)
            and any(c.isdigit() for c in chars)
        ):
            return "-".join("".join(chars[i : i + 4]) for i in range(0, 24, 4))
        counter += 1
