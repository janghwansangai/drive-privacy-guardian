"""Encrypted archive containers, entirely in memory (SPEC 6.5 steps 3–5, V12, D-107).

- Standard ZIP (default since D-107): the classic ZIP password ("ZipCrypto"). Windows Explorer
  and macOS open it with just the password — no program needed, even if this app is gone.
  It only keeps contents from being seen at a glance: names are visible and the cipher is
  weak against a determined attacker (the UI says so, `STANDARD_ZIP_NOTE_KO`).
- 7z (high-security option): AES-256 + header encryption, so even the file names inside are
  hidden. Needs this app, 7-Zip, Keka or the recovery tool.
- AES-ZIP (older option, still opened): WinZip AES-256.

Passwords are handed over as Python objects only (never a command line, env var, or log).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import posixpath
import secrets
import string
import struct
import zipfile
import zlib
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


STANDARD_ZIP_NOTE_KO = (
    "기본 ZIP은 윈도우·맥에서 비밀번호만 넣으면 열립니다(프로그램 필요 없음). 내용이 바로 "
    "보이지 않게 하는 정도의 보호이고, 압축 안의 파일 이름은 보이며, 작정한 해독에는 약합니다."
)
SEVEN_ZIP_NOTE_KO = (
    "높은 보안(7z AES-256)은 파일 이름까지 숨기고 해독에 강합니다. 대신 이 프로그램, "
    "7-Zip(Windows)·Keka(Mac), 또는 비밀번호 복구 도구가 있어야 열 수 있습니다."
)


class ArchiveFormat(StrEnum):
    SEVEN_ZIP = "7z"
    AES_ZIP = "zip"
    STANDARD_ZIP = "zipcrypto"

    @property
    def extension(self) -> str:
        return "7z" if self is ArchiveFormat.SEVEN_ZIP else "zip"


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


def archive_name(
    fmt: ArchiveFormat, today: dt.date | None = None, names: list[str] | None = None
) -> str:
    """The archive's name shows what is inside (D-087), e.g. `상담기록.hwp (암호화 7f3a9c2e).7z`
    or `상담기록.hwp 외 2개 (암호화 7f3a9c2e).7z`. Without names: `보관_2026-09-26_7f3a9c2e.7z`.

    The random tag is also the salt for recovery-key passwords (vault.recovery)."""
    tag = secrets.token_hex(4)
    if not names:
        today = today or dt.date.today()
        return f"보관_{today.isoformat()}_{tag}.{fmt.extension}"
    base = display_base(names[0])
    if len(names) > 1:
        base = f"{base} 외 {len(names) - 1}개"
    return f"{base} (암호화 {tag}).{fmt.extension}"


def display_base(name: str, limit: int = 80) -> str:
    """A file name made safe for the archive name: no path separators or control characters."""
    clean = "".join("_" if c in "/\\" or ord(c) < 32 else c for c in name).strip() or "파일"
    return clean if len(clean) <= limit else clean[: limit - 1] + "…"


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
    elif fmt is ArchiveFormat.STANDARD_ZIP:
        return _standard_zip(files, password)
    else:
        with pyzipper.AESZipFile(
            buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as z:
            z.setpassword(password.encode("utf-8"))
            z.setencryption(pyzipper.WZ_AES, nbits=256)
            for name, data in files.items():
                z.writestr(name, data)
    return buf.getvalue()


# -- standard ZIP encryption (PKWARE "traditional", APPNOTE 6.1) ---------------------------------
# No library writes it (pyzipper reads it only), so it is written here; reading back for the
# verification uses pyzipper / zipfile, and the tests open the result with 7-Zip and libarchive.

_CRC_TABLE = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC_TABLE[_i] = _c


def _crc_byte(crc: int, b: int) -> int:
    return _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)


class _ZipCrypto:
    def __init__(self, password: bytes) -> None:
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in password:
            self._update(b)

    def _update(self, b: int) -> None:
        self.k0 = _crc_byte(self.k0, b)
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _crc_byte(self.k2, (self.k1 >> 24) & 0xFF)

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            t = (self.k2 | 2) & 0xFFFF
            out[i] = b ^ (((t * (t ^ 1)) >> 8) & 0xFF)
            self._update(b)
        return bytes(out)


def standard_zip_password_ok(password: str) -> str | None:
    """None if usable, else why not (Korean). Windows and macOS read the password bytes in
    different encodings, so only printable ASCII is safe for "open anywhere"."""
    if len(password) < 8:
        return "비밀번호는 8자 이상이어야 합니다."
    if not all(32 < ord(c) < 127 for c in password):
        return (
            "영문·숫자·기호만 쓸 수 있습니다"
            "(한글·띄어쓰기는 운영체제마다 달라 열리지 않을 수 있음)."
        )
    return None


def _standard_zip(files: dict[str, bytes], password: str) -> bytes:
    if standard_zip_password_ok(password) is not None:
        raise ValueError("password must be 8+ printable ASCII characters")
    if len(files) > 60000 or sum(len(d) for d in files.values()) > 3_500_000_000:
        raise ArchiveError("기본 ZIP으로는 너무 큽니다. 높은 보안(7z)을 쓰거나 나눠 주세요.")
    now = dt.datetime.now()
    dos_time = (now.hour << 11) | (now.minute << 5) | (now.second // 2)
    dos_date = ((max(now.year, 1980) - 1980) << 9) | (now.month << 5) | now.day
    flags = 0x0001 | 0x0800  # encrypted | names in UTF-8 (Windows and macOS honour it)
    pw = password.encode("ascii")
    out = io.BytesIO()
    central = io.BytesIO()
    for name, data in files.items():
        crc = zlib.crc32(data) & 0xFFFFFFFF
        comp = zlib.compressobj(6, zlib.DEFLATED, -15)
        packed = comp.compress(data) + comp.flush()
        method = 8
        if len(packed) >= len(data):  # incompressible: store
            packed, method = data, 0
        header = secrets.token_bytes(11) + bytes([crc >> 24])  # last byte checks the password
        body = _ZipCrypto(pw).encrypt(header + packed)
        raw_name = name.encode("utf-8")
        offset = out.tell()
        out.write(
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                flags,
                method,
                dos_time,
                dos_date,
                crc,
                len(body),
                len(data),
                len(raw_name),
                0,
            )
        )
        out.write(raw_name)
        out.write(body)
        central.write(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                flags,
                method,
                dos_time,
                dos_date,
                crc,
                len(body),
                len(data),
                len(raw_name),
                0,
                0,
                0,
                0,
                0,
                offset,
            )
        )
        central.write(raw_name)
    cd_offset = out.tell()
    cd = central.getvalue()
    out.write(cd)
    out.write(
        struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(cd), cd_offset, 0)
    )
    return out.getvalue()


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
    except (zlib.error, zipfile.BadZipFile) as exc:
        # Standard ZIP checks the password with one byte (1 in 256 wrong passwords pass it);
        # the data then fails to inflate or its CRC differs: that is a wrong password too.
        if _encrypted(data):
            raise WrongPassword() from None
        raise ArchiveError("보관 파일을 열 수 없습니다.") from exc
    except Exception:  # noqa: BLE001
        raise ArchiveError("보관 파일을 열 수 없습니다(손상 또는 지원하지 않는 형식).") from None
    return out


def _encrypted(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return any(i.flag_bits & 1 for i in z.infolist())
    except zipfile.BadZipFile:
        return False


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
