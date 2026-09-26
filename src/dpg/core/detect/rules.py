"""Korean personal-data detection (SPEC 6.3).

Layered rules: pattern → validation (date, checksum, Luhn) → context (nearby keywords,
table column headers) → confidence. Output is `Finding(kind, confidence, location)` only —
matched values never leave this module (principle 2).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import IntEnum

from dpg.core.detect.patterns import MASK_RULES
from dpg.core.detect.validators import digits_only, luhn_ok, rrn_birth_date, rrn_checksum_ok
from dpg.core.extract.base import Extracted, Table


class Confidence(IntEnum):
    LOW = 1  # 의심 — needs a human look
    MEDIUM = 2
    HIGH = 3


KIND_LABEL_KO = {
    "rrn": "주민·외국인등록번호",
    "rrn_suspect": "주민등록번호 의심(검증식 불일치)",
    "passport": "여권번호",
    "driver_license": "운전면허번호",
    "mobile": "휴대전화",
    "landline": "일반전화",
    "account": "계좌번호",
    "card": "카드번호",
    "email": "이메일",
    "address": "주소",
    "student_roster": "학생 명단·주소록",
    "sensitive_suspect": "민감정보 의심",
    "filename_hint": "파일명에 개인정보 암시",
}
CONFIDENCE_LABEL_KO = {
    Confidence.LOW: "낮음(의심)",
    Confidence.MEDIUM: "중간",
    Confidence.HIGH: "높음",
}

# Kinds that make a file "high sensitivity" for the policy (SPEC 6.4).
HIGH_SENSITIVITY = frozenset(
    {"rrn", "passport", "driver_license", "account", "card", "student_roster"}
)

CONTEXT_CHARS = 30

BANKS = (
    "국민",
    "KB",
    "신한",
    "우리",
    "하나",
    "농협",
    "NH",
    "기업",
    "IBK",
    "SC제일",
    "제일",
    "씨티",
    "카카오뱅크",
    "케이뱅크",
    "토스뱅크",
    "새마을",
    "신협",
    "우체국",
    "수협",
    "대구은행",
    "부산은행",
    "경남은행",
    "광주은행",
    "전북은행",
    "제주은행",
    "산업은행",
    "은행",
)
ACCOUNT_WORDS = ("계좌", "예금주", "입금", "환불", "이체", "송금")
SENSITIVE_WORDS = (
    "상담",
    "진단",
    "병명",
    "복약",
    "투약",
    "장애",
    "학교폭력",
    "학폭",
    "정신과",
    "치료",
    "가정폭력",
    "자해",
    "자살",
    "우울",
    "ADHD",
    "심리검사",
)
FILENAME_WORDS = (
    "명단",
    "연락처",
    "주소록",
    "상담",
    "생활기록",
    "생기부",
    "성적",
    "건강",
    "신상",
    "개인정보",
    "보호자",
)

_RRN = re.compile(r"(?<!\d)(\d{6})(\s?[-–]\s?|)(\d{7})(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d{4}[-\s]?){3}\d{4}(?!\d)")
_MOBILE = re.compile(r"(?<!\d)01[016789][-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)")
_LANDLINE = re.compile(
    r"(?<!\d)\(?0(?:2|3[1-3]|4[1-4]|5[1-5]|6[1-4]|70)\)?[-.)\s]\s?\d{3,4}[-.\s]\d{4}(?!\d)"
)
_PASSPORT = re.compile(r"(?<![A-Za-z0-9])([A-Z])(\d{8}|\d{3}[A-Z]\d{4})(?![A-Za-z0-9])")
_LICENSE = re.compile(r"(?<!\d)(\d{2})-(\d{2})-(\d{6})-(\d{2})(?!\d)")
_ACCOUNT = re.compile(r"(?<!\d)\d{2,6}(?:-\d{2,7}){1,3}(?!\d)|(?<!\d)\d{10,14}(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_ADDRESS = next(r.pattern for r in MASK_RULES if r.kind == "address")
_KOREAN_NAME = re.compile(r"^[가-힣]{2,4}$")
_NAME_NEAR = re.compile(
    r"[가-힣]{2,4}\s?(?:학생|님|군|양|어린이|아동)|(?:성명|이름)\s?[:：]?\s?[가-힣]{2,4}"
)

ROSTER_HEADER_GROUPS: tuple[tuple[str, ...], ...] = (
    ("성명", "이름", "학생명"),
    ("학번", "번호", "출석번호"),
    ("반", "학년반", "학급"),
    ("생년월일", "생일"),
    ("보호자", "학부모", "부모"),
    ("연락처", "전화", "휴대폰", "핸드폰"),
    ("주소",),
)
ROSTER_MIN_ROWS = 5


@dataclass(frozen=True)
class Finding:
    kind: str
    confidence: Confidence
    location: str


@dataclass
class KindSummary:
    count: int = 0
    confidence: Confidence = Confidence.LOW
    locations: list[str] = field(default_factory=list)


def _window(text: str, start: int, end: int) -> str:
    return text[max(0, start - CONTEXT_CHARS) : end + CONTEXT_CHARS]


def _overlaps(spans: list[tuple[int, int]], s: int, e: int) -> bool:
    return any(s < te and ts < e for ts, te in spans)


def _foreigner_checksum_ok(value: str) -> bool:
    d = digits_only(value)
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    total = sum(int(c) * w for c, w in zip(d[:12], weights, strict=True))
    return (13 - total % 11) % 10 == int(d[12])


Span = tuple[int, int] | None


def detect_text(text: str, location: str, column_header: str | None = None) -> list[Finding]:
    return [f for f, _span in detect_text_spans(text, location, column_header)]


def detect_text_spans(
    text: str, location: str, column_header: str | None = None
) -> list[tuple[Finding, Span]]:
    """Like detect_text, plus the character span of each match (used only for the in-memory,
    masked review preview; spans are never stored)."""
    found: list[tuple[Finding, Span]] = []
    taken: list[tuple[int, int]] = []
    header = column_header or ""

    def add(kind: str, conf: Confidence, s: int, e: int) -> None:
        found.append((Finding(kind, conf, location), (s, e)))
        taken.append((s, e))

    for m in _RRN.finditer(text):
        value = m.group(1) + m.group(3)
        born = rrn_birth_date(value)
        if born is None or value[6] not in "12345678":
            continue
        has_sep = bool(m.group(2))
        keyword = any(
            k in _window(text, m.start(), m.end()) + header for k in ("주민", "등록번호", "외국인")
        )
        if rrn_checksum_ok(value) or (value[6] in "5678" and _foreigner_checksum_ok(value)):
            add("rrn", Confidence.HIGH, m.start(), m.end())
        elif has_sep or keyword:
            # Numbers issued since 2020-10 are random after the gender digit (V10).
            add("rrn_suspect", Confidence.LOW, m.start(), m.end())

    for m in _CARD.finditer(text):
        if not _overlaps(taken, m.start(), m.end()) and luhn_ok(m.group()):
            add("card", Confidence.HIGH, m.start(), m.end())

    for m in _MOBILE.finditer(text):
        if not _overlaps(taken, m.start(), m.end()):
            add("mobile", Confidence.HIGH, m.start(), m.end())

    for m in _LANDLINE.finditer(text):
        if not _overlaps(taken, m.start(), m.end()):
            add("landline", Confidence.MEDIUM, m.start(), m.end())

    for m in _PASSPORT.finditer(text):
        if _overlaps(taken, m.start(), m.end()):
            continue
        ctx = _window(text, m.start(), m.end()) + header
        if "여권" in ctx or "passport" in ctx.lower():
            add("passport", Confidence.HIGH, m.start(), m.end())
        elif m.group(1) in "MSRGD":
            add("passport", Confidence.LOW, m.start(), m.end())

    for m in _LICENSE.finditer(text):
        if _overlaps(taken, m.start(), m.end()) or not 11 <= int(m.group(1)) <= 28:
            continue
        ctx = _window(text, m.start(), m.end()) + header
        conf = Confidence.MEDIUM if ("면허" in ctx or "운전" in ctx) else Confidence.LOW
        add("driver_license", conf, m.start(), m.end())

    for m in _ACCOUNT.finditer(text):
        if _overlaps(taken, m.start(), m.end()) or not 10 <= len(digits_only(m.group())) <= 14:
            continue
        ctx = _window(text, m.start(), m.end()) + " " + header
        bank = any(b in ctx for b in BANKS)
        word = any(w in ctx for w in ACCOUNT_WORDS)
        if bank and word:
            add("account", Confidence.HIGH, m.start(), m.end())
        elif bank or word:
            add("account", Confidence.MEDIUM, m.start(), m.end())
        # no context => not reported (SPEC 6.3: context required)

    for m in _ADDRESS.finditer(text):
        if not _overlaps(taken, m.start(), m.end()):
            conf = Confidence.HIGH if "주소" in header else Confidence.MEDIUM
            add("address", conf, m.start(), m.end())

    for m in _EMAIL.finditer(text):
        if not _overlaps(taken, m.start(), m.end()):
            add("email", Confidence.LOW, m.start(), m.end())

    if any(w in text for w in SENSITIVE_WORDS) and _NAME_NEAR.search(text):
        found.append((Finding("sensitive_suspect", Confidence.LOW, location), None))
    return found


def _header_row(rows: list[list[str]]) -> tuple[int, list[str]] | None:
    for index, row in enumerate(rows[:5]):
        groups = sum(
            1
            for group in ROSTER_HEADER_GROUPS
            if any(any(k == c.replace(" ", "") or k in c for k in group) for c in row)
        )
        if groups >= 2:
            return index, row
    return None


def detect_table(table: Table) -> list[Finding]:
    found: list[Finding] = []
    header = _header_row(table.rows)
    start = header[0] + 1 if header else 0
    headers = header[1] if header else []
    for r_index, row in enumerate(table.rows[start:], start=start + 1):
        for c_index, cell in enumerate(row):
            if not cell:
                continue
            col_header = headers[c_index] if c_index < len(headers) else None
            found += detect_text(cell, f"{table.location}, {r_index}{table.row_label}", col_header)
    if header is not None:
        name_cols = [
            i for i, c in enumerate(headers) if any(k in c for k in ROSTER_HEADER_GROUPS[0])
        ]
        candidates = name_cols or list(range(len(headers)))
        name_rows = sum(
            1
            for row in table.rows[start:]
            if any(i < len(row) and _KOREAN_NAME.match(row[i]) for i in candidates)
        )
        if name_rows >= ROSTER_MIN_ROWS:
            found.append(Finding("student_roster", Confidence.HIGH, table.location))
    return found


def detect_extracted(doc: Extracted) -> list[Finding]:
    found: list[Finding] = []
    for seg in doc.segments:
        found += detect_text(seg.text, seg.location)
    for table in doc.tables:
        found += detect_table(table)
    return found


def detect_filename(name: str) -> list[Finding]:
    """SPEC 6.3: file and folder names are checked too (e.g. "6-2 학생 연락처.xlsx")."""
    found = detect_text(name, "파일명")
    if any(w in name for w in FILENAME_WORDS):
        found.append(Finding("filename_hint", Confidence.LOW, "파일명"))
    return found


def summarize(findings: Iterable[Finding], max_locations: int = 5) -> dict[str, KindSummary]:
    out: dict[str, KindSummary] = {}
    for f in findings:
        s = out.setdefault(f.kind, KindSummary())
        s.count += 1
        s.confidence = max(s.confidence, f.confidence)
        if f.location not in s.locations and len(s.locations) < max_locations:
            s.locations.append(f.location)
    return out
