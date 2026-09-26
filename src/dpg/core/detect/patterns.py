"""Broad personal-data patterns shared by the log masking filter and the leak scanner.

These rules are intentionally *over-inclusive*: they are used where a false positive only costs a
masked token in a log line, and a false negative would be a leak. The precise, context-aware
detector for user files (SPEC 6.3) is built on top of these in Phase 4.

Order matters: specific rules run before the generic long-number rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MaskRule:
    kind: str
    pattern: re.Pattern[str]
    token: str


_SIDO = (
    "서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|충청북|충청남|"
    "전북|전남|전라북|전라남|경북|경남|경상북|경상남|제주"
)

MASK_RULES: tuple[MaskRule, ...] = (
    # --- OAuth secrets (class B data). Random strings: PII patterns would never catch them. ---
    MaskRule(
        "oauth_token",  # access token (ya29.), refresh token (1//), authorization code (4/)
        re.compile(
            r"(?<![A-Za-z0-9])(?:ya29\.[A-Za-z0-9_\-.]{20,}|1//[A-Za-z0-9_\-]{20,}"
            r"|4/[A-Za-z0-9_\-]{20,})"
        ),
        "<TOKEN>",
    ),
    MaskRule(
        "oauth_client_secret",
        re.compile(r"GOCSPX-[A-Za-z0-9_\-]{10,}"),
        "<SECRET>",
    ),
    # --- Personal data ---
    MaskRule(
        "rrn",  # 주민등록번호 / 외국인등록번호 (any 6+7 digit shape, checksum not required)
        re.compile(r"(?<!\d)\d{6}\s?[-–]?\s?\d{7}(?!\d)"),
        "<RRN>",
    ),
    MaskRule(
        "card",
        re.compile(r"(?<!\d)\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}(?!\d)"),
        "<CARD>",
    ),
    MaskRule(
        "mobile",
        re.compile(r"(?<!\d)01[016789][-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"),
        "<PHONE>",
    ),
    MaskRule(
        "landline",
        re.compile(r"(?<!\d)0(?:2|[3-6][1-5]|70)[-.)\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"),
        "<PHONE>",
    ),
    MaskRule(
        "passport",  # legacy A12345678 and next-generation A123B4567
        re.compile(r"(?<![A-Za-z0-9])[A-Za-z](?:\d{8}|\d{3}[A-Za-z]\d{4})(?![A-Za-z0-9])"),
        "<PASSPORT>",
    ),
    MaskRule(
        "email",
        re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
        "<EMAIL>",
    ),
    MaskRule(
        "address",
        re.compile(
            rf"(?:{_SIDO})(?:특별자치시|특별자치도|특별시|광역시|도)?\s*"
            r"[가-힣]{1,10}(?:시|군|구)(?:\s*[가-힣]{1,10}(?:시|군|구))?\s*"
            r"[가-힣0-9]{1,20}(?:로|길)\s*\d{1,5}(?:-\d{1,5})?"
        ),
        "<ADDRESS>",
    ),
    MaskRule(
        # Account numbers, driver licences, unbroken card numbers, ...: any run of 10+ digits
        # optionally separated by single hyphens. Spaces are *not* separators here so that
        # timestamps like "2026-09-26 12:00" stay readable.
        "long_number",
        re.compile(r"(?<!\d)\d(?:-?\d){9,}(?!\d)"),
        "<NUM>",
    ),
)


def mask_text(text: str) -> str:
    """Replace every broad personal-data match in `text` with a type token."""
    for rule in MASK_RULES:
        text = rule.pattern.sub(rule.token, text)
    return text


def count_matches(text: str) -> dict[str, int]:
    """Count matches per kind. Returns counts only — never the matched values.

    Rules are applied in order on progressively masked text so one value is counted once.
    """
    counts: dict[str, int] = {}
    for rule in MASK_RULES:
        text, n = rule.pattern.subn(rule.token, text)
        if n:
            counts[rule.kind] = counts.get(rule.kind, 0) + n
    return counts
