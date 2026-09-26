"""In-memory text extraction per file format (SPEC 6.3).

1st-phase formats: Google Docs (text export), Google Sheets (xlsx export), Google Slides (text
export), DOCX, XLSX, CSV/TSV, TXT, text PDF, HWPX, HWP 5.0. Everything else is reported as
`검사 불가 (지원하지 않는 형식)` — never as "safe".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from dpg.core.extract.base import (
    UNSCANNABLE_LABEL_KO,
    Extracted,
    Segment,
    Table,
    Unscannable,
    UnscannableReason,
)
from dpg.core.extract.formats import (
    extract_csv,
    extract_docx,
    extract_hwpx,
    extract_pdf,
    extract_txt,
    extract_xlsx,
)
from dpg.core.extract.hwp import extract_hwp

__all__ = [
    "UNSCANNABLE_LABEL_KO",
    "Extracted",
    "Plan",
    "Segment",
    "Table",
    "Unscannable",
    "UnscannableReason",
    "extract",
    "plan_for",
]

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

Extractor = Callable[[bytes], Extracted]

_BY_MIME: dict[str, Extractor] = {
    "text/plain": extract_txt,
    "text/csv": extract_csv,
    "text/tab-separated-values": lambda d: extract_csv(d, "\t"),
    DOCX_MIME: extract_docx,
    XLSX_MIME: extract_xlsx,
    "application/pdf": extract_pdf,
    "application/x-hwp": extract_hwp,
    "application/haansofthwp": extract_hwp,
    "application/vnd.hancom.hwp": extract_hwp,
    "application/hwp+zip": extract_hwpx,
    "application/vnd.hancom.hwpx": extract_hwpx,
}
_BY_EXT: dict[str, Extractor] = {
    ".txt": extract_txt,
    ".csv": extract_csv,
    ".tsv": lambda d: extract_csv(d, "\t"),
    ".docx": extract_docx,
    ".xlsx": extract_xlsx,
    ".pdf": extract_pdf,
    ".hwp": extract_hwp,
    ".hwpx": extract_hwpx,
}
# Google Workspace types: (export MIME, extractor)
_GOOGLE_EXPORT: dict[str, tuple[str, Extractor]] = {
    "application/vnd.google-apps.document": ("text/plain", extract_txt),
    "application/vnd.google-apps.spreadsheet": (XLSX_MIME, extract_xlsx),
    "application/vnd.google-apps.presentation": ("text/plain", extract_txt),
}
_IMAGE_PREFIXES = ("image/",)


@dataclass(frozen=True)
class Plan:
    """How to fetch and read a file. `export_mime` set => files.export, else download."""

    extractor: Extractor
    export_mime: str | None = None


def plan_for(mime_type: str, name: str) -> Plan:
    """Decide how to read a file, or raise Unscannable (e.g. unsupported / image)."""
    if mime_type in _GOOGLE_EXPORT:
        export_mime, extractor = _GOOGLE_EXPORT[mime_type]
        return Plan(extractor, export_mime)
    if mime_type in _BY_MIME:
        return Plan(_BY_MIME[mime_type])
    dot = name.rfind(".")
    ext = name[dot:].lower() if dot >= 0 else ""
    if ext in _BY_EXT:
        return Plan(_BY_EXT[ext])
    if mime_type.startswith(_IMAGE_PREFIXES):
        raise Unscannable(UnscannableReason.IMAGE_ONLY)
    raise Unscannable(UnscannableReason.UNSUPPORTED)


def extract(data: bytes, plan: Plan) -> Extracted:
    """Run the extractor. Any unexpected library error becomes `CORRUPT` without its message
    (messages may contain document text)."""
    try:
        return plan.extractor(data)
    except Unscannable:
        raise
    except MemoryError:
        raise Unscannable(UnscannableReason.TOO_LARGE) from None
    except Exception:  # noqa: BLE001
        raise Unscannable(UnscannableReason.CORRUPT) from None
