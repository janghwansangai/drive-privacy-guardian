"""Audit report export (SPEC 5.5): local CSV only.

Defaults protect privacy: file names are masked and account e-mails show only a masked local
part. Detection values are never part of a report. Cells are hardened against spreadsheet
formula injection (a shared file's name is attacker-controlled).
"""

from __future__ import annotations

import csv
import os
from collections.abc import Iterable
from pathlib import Path

from dpg.core.audit.model import (
    EXPOSURE_LABEL_KO,
    ORIGIN_LABEL_KO,
    ROLE_LABEL_KO,
    STATUS_LABEL_KO,
    UNKNOWN_EXPOSURE_LABEL_KO,
    FileAudit,
)
from dpg.core.detect.rules import CONFIDENCE_LABEL_KO, KIND_LABEL_KO
from dpg.core.extract.base import UNSCANNABLE_LABEL_KO
from dpg.core.policy import (
    DETECT_STATUS_LABEL_KO,
    LEVEL_LABEL_KO,
    FileDetection,
    Recommendation,
    recommend,
)

EXPORT_WARNING_KO = (
    "이 보고서에는 파일명과 공유 대상 이메일이 포함될 수 있습니다. "
    "보고서 파일은 이 컴퓨터에만 저장되며, 다른 곳에 올리거나 보내기 전에 내용을 확인해 주세요."
)

HEADERS = [
    "파일ID",
    "파일명",
    "종류",
    "위치",
    "소유자",
    "조회 상태",
    "노출도",
    "위험 점수",
    "링크 공개 권한",
    "웹 검색 가능",
    "도메인 공유",
    "외부 계정 수",
    "외부 계정",
    "내부 계정 수",
    "편집자 수",
    "편집자 재공유 허용",
    "다운로드·복사 제한",
    "권한 출처",
    "제한된 액세스 폴더",
    "마지막 수정",
    "비고",
    "개인정보 상태",
    "탐지 유형(건수·신뢰도)",
    "탐지 위치(일부)",
    "권장 조치",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: str) -> str:
    """Neutralize spreadsheet formula injection (OWASP CSV injection)."""
    return "'" + value if value.startswith(_FORMULA_PREFIXES) else value


def mask_name(name: str) -> str:
    stem, dot, ext = name.rpartition(".")
    if not dot or len(ext) > 6 or not stem:
        stem, ext = name, ""
    if not stem:
        return ""
    masked = stem[0] + "*" * min(len(stem) - 1, 8)
    return f"{masked}.{ext}" if ext else masked


def mask_email(email: str) -> str:
    local, at, domain = email.partition("@")
    if not at:
        return mask_name(email)
    return f"{local[:2]}{'*' * max(1, min(len(local) - 2, 6))}@{domain}"


def _kind(a: FileAudit) -> str:
    if a.is_folder:
        return "폴더"
    if a.mime_type.startswith("application/vnd.google-apps."):
        return "Google " + a.mime_type.rsplit(".", 1)[-1]
    return a.mime_type or "알 수 없음"


def _yes_no(v: bool | None) -> str:
    return "알 수 없음" if v is None else ("예" if v else "아니오")


def _detection_cells(det: FileDetection | None, recs: list[Recommendation]) -> list[str]:
    if det is None:
        return ["미실행", "", "", ""]
    status = DETECT_STATUS_LABEL_KO[det.status]
    if det.reason is not None:
        status += f" ({UNSCANNABLE_LABEL_KO[det.reason]})"
    elif det.partial:
        status += " (일부 검사 불가)"
    kinds = "; ".join(
        f"{KIND_LABEL_KO.get(k, k)} {v.count}건({CONFIDENCE_LABEL_KO[v.confidence]})"
        for k, v in sorted(det.kinds.items(), key=lambda kv: -kv[1].confidence)
    )
    locations = "; ".join(loc for v in det.kinds.values() for loc in v.locations[:2])[:200]
    advice = " / ".join(
        (f"[{LEVEL_LABEL_KO[r.level]}] " if LEVEL_LABEL_KO[r.level] else "") + r.text for r in recs
    )
    return [status, kinds, locations, advice]


def rows_for(
    items: Iterable[FileAudit],
    *,
    mask: bool = True,
    detections: dict[str, FileDetection] | None = None,
) -> list[list[str]]:
    em = mask_email if mask else (lambda e: e)
    out: list[list[str]] = []
    recs = {a.file_id: recommend(a, (detections or {}).get(a.file_id)) for a in items}

    def order(x: FileAudit) -> tuple[int, int, str]:
        top = recs[x.file_id][0].level if recs[x.file_id] else 0
        # Unknown risk sorts first within a level: principle 6 — it needs a human look.
        return (-top, -(x.risk_score if x.risk_score is not None else 101), x.file_id)

    items = list(items)
    for a in sorted(items, key=order):
        origins = sorted(ORIGIN_LABEL_KO[o] for o in a.origins)
        out.append(
            [
                safe_cell(c)
                for c in [
                    a.file_id,
                    mask_name(a.name) if mask else a.name,
                    _kind(a),
                    "공유 드라이브" if a.drive_id else "내 드라이브",
                    em(a.owner_email) if a.owner_email else ("공유 드라이브" if a.drive_id else ""),
                    STATUS_LABEL_KO[a.status],
                    EXPOSURE_LABEL_KO[a.exposure]
                    if a.exposure is not None
                    else UNKNOWN_EXPOSURE_LABEL_KO,
                    "" if a.risk_score is None else str(a.risk_score),
                    ROLE_LABEL_KO.get(a.link_role, a.link_role) if a.link_role else "",
                    _yes_no(a.link_discoverable) if a.link_role or a.link_discoverable else "",
                    "; ".join(f"{d}({ROLE_LABEL_KO.get(r, r)})" for d, r in a.domain_shares),
                    str(len(a.external_accounts)),
                    "; ".join(
                        f"{em(e)}({ROLE_LABEL_KO.get(r, r)})" for e, r in a.external_accounts
                    ),
                    str(a.internal_accounts),
                    str(a.editor_count),
                    _yes_no(a.writers_can_share),
                    _yes_no(a.download_restricted),
                    ", ".join(origins),
                    "예" if a.limited_access_folder else "",
                    a.modified_time or "",
                    " / ".join(a.notes + ([f"오류 {a.error_code}"] if a.error_code else [])),
                    *_detection_cells(
                        (detections or {}).get(a.file_id) if detections is not None else None,
                        recs[a.file_id],
                    ),
                ]
            ]
        )
    return out


def write_csv(
    path: Path,
    items: Iterable[FileAudit],
    *,
    mask: bool = True,
    detections: dict[str, FileDetection] | None = None,
) -> int:
    """Write a UTF-8 (BOM, for Excel) CSV readable only by the current user."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    rows = rows_for(items, mask=mask, detections=detections)
    with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(HEADERS)
        writer.writerows(rows)
    if os.name == "posix":
        os.chmod(path, 0o600)
    return len(rows)


def write_xlsx(
    path: Path,
    items: Iterable[FileAudit],
    *,
    mask: bool = True,
    detections: dict[str, FileDetection] | None = None,
) -> int:
    """Write an XLSX report readable only by the current user.

    Every cell is written as an explicit string (or int for the score), so nothing a file owner
    put in a name can become a formula.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Font
    from openpyxl.utils import get_column_letter

    rows = rows_for(items, mask=mask, detections=detections)
    score_col = HEADERS.index("위험 점수")
    wb = Workbook()
    ws = wb.active
    ws.title = "권한 감사"
    ws.append(HEADERS)
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for r, row in enumerate(rows, start=2):
        for c, value in enumerate(row, start=1):
            cell = ws.cell(row=r, column=c)
            if c - 1 == score_col and value.isdigit():
                cell.value = int(value)
            else:
                cell.value = value
                cell.data_type = "s"
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for c, header in enumerate(HEADERS, start=1):
        width = max([len(header) * 2] + [min(len(row[c - 1]), 50) for row in rows[:500]])
        ws.column_dimensions[get_column_letter(c)].width = min(max(width, 8), 60)

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as fh:
        wb.save(fh)
    if os.name == "posix":
        os.chmod(path, 0o600)
    return len(rows)


def write_report(
    path: Path,
    items: Iterable[FileAudit],
    *,
    mask: bool = True,
    detections: dict[str, FileDetection] | None = None,
) -> int:
    """Choose CSV or XLSX by file extension."""
    if path.suffix.lower() == ".xlsx":
        return write_xlsx(path, items, mask=mask, detections=detections)
    return write_csv(path, items, mask=mask, detections=detections)
