"""Common types and guards for in-memory text extraction (SPEC 5.2, 6.3).

Rules:
- Everything happens on bytes in memory (`io.BytesIO`); nothing is written to disk.
- Locations are positional only ("시트 2, 15행", "3쪽", "문단 12") — never the user's own text
  (a sheet or heading could itself be a person's name).
- Extractors raise `Unscannable(reason)` for files we cannot inspect. They must never put
  document text into an exception message.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from enum import StrEnum

MAX_FILE_BYTES = 50 * 1024 * 1024  # SPEC 5.2
MAX_UNZIPPED_BYTES = 300 * 1024 * 1024  # zip-bomb guard for DOCX/XLSX/HWPX
MAX_ZIP_RATIO = 200
MAX_TEXT_CHARS = 20_000_000
MAX_TABLE_ROWS = 100_000


class UnscannableReason(StrEnum):
    TOO_LARGE = "too_large"  # 크기 초과
    EXPORT_LIMIT = "export_limit"  # 내보내기 한도 초과
    ENCRYPTED = "encrypted"  # 암호 걸린 파일
    DISTRIBUTION = "distribution"  # 배포용/DRM 문서
    CORRUPT = "corrupt"  # 손상 파일
    UNSUPPORTED = "unsupported"  # 미지원 형식
    IMAGE_ONLY = "image_only"  # 이미지·스캔 문서 (OCR 필요)
    NOT_DOWNLOADABLE = "not_downloadable"  # 다운로드 금지 등


UNSCANNABLE_LABEL_KO = {
    UnscannableReason.TOO_LARGE: "크기 초과",
    UnscannableReason.EXPORT_LIMIT: "내보내기 한도(10MB) 초과",
    UnscannableReason.ENCRYPTED: "암호 걸린 파일",
    UnscannableReason.DISTRIBUTION: "배포용·보안 문서",
    UnscannableReason.CORRUPT: "손상되었거나 읽을 수 없는 파일",
    UnscannableReason.UNSUPPORTED: "지원하지 않는 형식",
    UnscannableReason.IMAGE_ONLY: "이미지·스캔 문서(글자 인식 미지원)",
    UnscannableReason.NOT_DOWNLOADABLE: "내려받을 수 없는 파일",
}


class Unscannable(Exception):
    def __init__(self, reason: UnscannableReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True)
class Segment:
    text: str
    location: str


@dataclass
class Table:
    location: str  # e.g. "시트 1", "표 2"
    rows: list[list[str]]
    row_label: str = "행"  # "행" -> "시트 1, 15행"


@dataclass
class Extracted:
    segments: list[Segment] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    truncated: bool = False
    partial: bool = False  # some parts could not be read (e.g. image-only PDF pages)

    def add_text(self, text: str, location: str) -> None:
        text = text.strip()
        if text:
            self.segments.append(Segment(text, location))

    @property
    def char_count(self) -> int:
        return sum(len(s.text) for s in self.segments) + sum(
            len(c) for t in self.tables for r in t.rows for c in r
        )


def check_size(data: bytes) -> None:
    if len(data) > MAX_FILE_BYTES:
        raise Unscannable(UnscannableReason.TOO_LARGE)


CFB_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")


def open_zip_safely(data: bytes) -> zipfile.ZipFile:
    """Open a zip container after checking for zip bombs and encryption.

    A password-protected DOCX/XLSX is not a zip at all but an OLE container holding an
    "EncryptedPackage" stream — report that as encrypted, not corrupt.
    """
    if data.startswith(CFB_SIGNATURE):
        import olefile

        try:
            with olefile.OleFileIO(io.BytesIO(data)) as ole:
                encrypted = ole.exists("EncryptedPackage")
        except (OSError, ValueError):
            encrypted = False
        raise Unscannable(UnscannableReason.ENCRYPTED if encrypted else UnscannableReason.CORRUPT)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError):
        raise Unscannable(UnscannableReason.CORRUPT) from None
    total = 0
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            raise Unscannable(UnscannableReason.ENCRYPTED)
        total += info.file_size
        if (
            info.compress_size
            and info.file_size / max(info.compress_size, 1) > MAX_ZIP_RATIO
            and info.file_size > 10 * 1024 * 1024
        ):
            raise Unscannable(UnscannableReason.TOO_LARGE)
    if total > MAX_UNZIPPED_BYTES:
        raise Unscannable(UnscannableReason.TOO_LARGE)
    return zf


def decode_text(data: bytes) -> str:
    """Decode plain text: BOMs, then UTF-8, then CP949 (common for Korean CSV/TXT)."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp949")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")
