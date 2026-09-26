"""Encrypted archive containers, entirely in memory (SPEC 6.5 steps 3–5, V12).

- 7z (default): AES-256 + header encryption, so even the file names inside are hidden.
- AES-ZIP (compatibility option): WinZip AES-256. File names are visible and Windows
  Explorer cannot open it — the UI must say so (`AES_ZIP_WARNING_KO`).

Passwords are handed over as Python objects only (never a command line, env var, or log).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import posixpath
import secrets
import string
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import py7zr
import py7zr.io
import pyzipper

MAX_ARCHIVE_BYTES = 2 * 1024**3  # refuse to inflate more than this into memory
PASSWORD_LENGTH = 24
_ALPHABET = string.ascii_letters + string.digits

AES_ZIP_WARNING_KO = (
    "AES-ZIP은 호환용입니다. 압축 안의 파일 이름이 암호 없이 보이고, "
    "Windows 기본 탐색기로는 열리지 않습니다(7-Zip·반디집·Keka 또는 이 앱 필요)."
)


class ArchiveFormat(StrEnum):
    SEVEN_ZIP = "7z"
    AES_ZIP = "zip"


class WrongPassword(Exception):
    """The password does not open this archive."""


class ArchiveError(Exception):
    """Not an archive we can open (damaged, unsupported, too large, unsafe names)."""


def generate_password(length: int = PASSWORD_LENGTH) -> str:
    """Random letters+digits from `secrets`, grouped by 4 for reading aloud (≈143 bits).

    Guaranteed to contain upper, lower and digit so every password policy accepts it.
    """
    while True:
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(length))
        if (
            any(c.islower() for c in raw)
            and any(c.isupper() for c in raw)
            and any(c.isdigit() for c in raw)
        ):
            return "-".join(raw[i : i + 4] for i in range(0, length, 4))


def archive_name(fmt: ArchiveFormat, today: dt.date | None = None) -> str:
    """A name that says nothing about the contents, e.g. `보관_2026-09-26_7f3a9c2e.7z`.

    The random tag is also the salt for recovery-key passwords (vault.recovery)."""
    today = today or dt.date.today()
    return f"보관_{today.isoformat()}_{secrets.token_hex(4)}.{fmt.value}"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_member_name(name: str) -> str:
    """Reject names that could escape the output folder when extracting (zip-slip)."""
    norm = posixpath.normpath(name.replace("\\", "/"))
    if (
        not norm
        or norm in (".", "..")
        or norm.startswith(("/", "../"))
        or (len(norm) > 1 and norm[1] == ":")
        or "\x00" in norm
    ):
        raise ArchiveError("안전하지 않은 파일 이름이 들어 있습니다.")
    return norm


def unique_names(names: list[str]) -> list[str]:
    """Make member names unique (Drive allows duplicate names in one folder)."""
    seen: dict[str, int] = {}
    out = []
    for name in names:
        base = name.replace("/", "_").replace("\\", "_") or "이름없음"
        n = seen.get(base, 0)
        seen[base] = n + 1
        if n:
            stem, dot, ext = base.rpartition(".")
            base = f"{stem} ({n}).{ext}" if dot and stem else f"{base} ({n})"
        out.append(base)
    return out


def create(files: dict[str, bytes], password: str, fmt: ArchiveFormat) -> bytes:
    if not password:
        raise ValueError("password required")
    for name in files:
        safe_member_name(name)
    buf = io.BytesIO()
    if fmt is ArchiveFormat.SEVEN_ZIP:
        filters = [
            {"id": py7zr.FILTER_LZMA2, "preset": 7},
            {"id": py7zr.FILTER_CRYPTO_AES256_SHA256},
        ]
        with py7zr.SevenZipFile(
            buf, "w", password=password, header_encryption=True, filters=filters
        ) as z:
            for name, data in files.items():
                z.writestr(data, name)
    else:
        with pyzipper.AESZipFile(
            buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as z:
            z.setpassword(password.encode("utf-8"))
            z.setencryption(pyzipper.WZ_AES, nbits=256)
            for name, data in files.items():
                z.writestr(name, data)
    return buf.getvalue()


def detect_format(data: bytes) -> ArchiveFormat:
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return ArchiveFormat.SEVEN_ZIP
    if data.startswith(b"PK\x03\x04"):
        return ArchiveFormat.AES_ZIP
    raise ArchiveError("7z 또는 ZIP 보관 파일이 아닙니다.")


def open_archive(data: bytes, password: str) -> dict[str, bytes]:
    """Decrypt into memory. Raises WrongPassword / ArchiveError (never leaks library text)."""
    fmt = detect_format(data)
    if fmt is ArchiveFormat.SEVEN_ZIP:
        return _open_7z(data, password)
    return _open_zip(data, password)


def _open_7z(data: bytes, password: str) -> dict[str, bytes]:
    try:
        factory = py7zr.io.BytesIOFactory(MAX_ARCHIVE_BYTES)
        with py7zr.SevenZipFile(
            io.BytesIO(data), "r", password=password, max_extract_size=MAX_ARCHIVE_BYTES
        ) as z:
            names = [safe_member_name(n) for n in z.getnames()]
            z.extractall(factory=factory)
    except ArchiveError:
        raise
    except py7zr.exceptions.PasswordRequired:
        raise WrongPassword() from None
    except Exception:  # noqa: BLE001 — a wrong key surfaces as random parse/CRC errors
        # With header encryption a wrong password makes the header garbage, so py7zr fails
        # with assorted errors (TypeError, Bad7zFile, CrcError...). Try to tell "damaged"
        # apart from "wrong password" only by the signature we already checked.
        raise WrongPassword() from None
    out: dict[str, bytes] = {}
    for name, product in factory.products.items():
        product.seek(0)
        out[safe_member_name(name)] = product.read()
    if set(out) - set(names):
        raise ArchiveError("보관 파일 목록이 일치하지 않습니다.")
    return out


def _open_zip(data: bytes, password: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    try:
        with pyzipper.AESZipFile(io.BytesIO(data)) as z:
            z.setpassword(password.encode("utf-8"))
            total = 0
            for info in z.infolist():
                if info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise ArchiveError("보관 파일이 너무 큽니다.")
                out[safe_member_name(info.filename)] = z.read(info)
    except ArchiveError:
        raise
    except RuntimeError as exc:
        if "password" in str(exc).lower():
            raise WrongPassword() from None
        raise ArchiveError("보관 파일을 열 수 없습니다.") from None
    except Exception:  # noqa: BLE001
        raise ArchiveError("보관 파일을 열 수 없습니다(손상 또는 지원하지 않는 형식).") from None
    return out


@dataclass(frozen=True)
class Verification:
    ok: bool
    missing: tuple[str, ...] = ()
    mismatched: tuple[str, ...] = ()


def verify(archive: bytes, password: str, originals: dict[str, bytes]) -> Verification:
    """SPEC 6.5 step 5: decrypt the new archive in memory and compare SHA-256 per file."""
    try:
        restored = open_archive(archive, password)
    except (WrongPassword, ArchiveError):
        return Verification(False, missing=tuple(originals))
    missing = tuple(n for n in originals if n not in restored)
    mismatched = tuple(
        n for n in originals if n in restored and sha256(restored[n]) != sha256(originals[n])
    )
    return Verification(not missing and not mismatched, missing, mismatched)


def extract_to(files: dict[str, bytes], out_dir: Path) -> list[Path]:
    """Write decrypted files under `out_dir` only; never overwrite an existing file."""
    root = out_dir.resolve()
    written = []
    for name, data in files.items():
        target = (root / safe_member_name(name)).resolve()
        if root not in target.parents:
            raise ArchiveError("안전하지 않은 파일 이름이 들어 있습니다.")
        if target.exists():
            stem, suffix, n = target.stem, target.suffix, 1
            while target.exists():
                target = target.with_name(f"{stem} ({n}){suffix}")
                n += 1
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as fh:
            fh.write(data)
        written.append(target)
    return written
