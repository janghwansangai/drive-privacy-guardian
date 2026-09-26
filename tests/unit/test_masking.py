from __future__ import annotations

import logging
import re

import pytest

from dpg.core.detect.patterns import count_matches, mask_text
from dpg.core.logging import MaskingFilter

# All values below are synthetic (future birth years, unassigned ranges, reserved domains).
CASES = [
    ("주민번호 750101-3123456 확인", "<RRN>"),
    ("주민번호 7501013123456 확인", "<RRN>"),
    ("연락처 010-1234-5678", "<PHONE>"),
    ("연락처 01012345678", "<PHONE>"),
    ("교무실 02-0123-4567", "<PHONE>"),
    ("카드 9999 1234 5678 9012", "<CARD>"),
    ("여권 M00001234", "<PASSPORT>"),
    ("여권 M000A1234", "<PASSPORT>"),
    ("메일 abcdefg@example.com", "<EMAIL>"),
    ("주소 서울특별시 가상구 샘플로 12", "<ADDRESS>"),
    ("계좌 국민은행 999-12-345678", "<NUM>"),
    ("면허 11-22-123456-78", "<NUM>"),
]


@pytest.mark.parametrize(("text", "token"), CASES)
def test_mask_text_replaces_values(text: str, token: str) -> None:
    masked = mask_text(text)
    assert token in masked
    assert not re.search(r"\d{4,}", masked.replace(token, "")), masked


@pytest.mark.parametrize(
    "text",
    [
        "2026-09-26 12:00:01,123 INFO dpg.audit scanned 1532 files",
        "file_id=1AbCdEfGhIjKlMnOpQrStUvWxYz_0123",  # Drive file IDs must stay readable
        "retry 3 of 5 after HTTP 429",
    ],
)
def test_mask_text_keeps_operational_text(text: str) -> None:
    assert mask_text(text) == text


def test_count_matches_returns_counts_only() -> None:
    counts = count_matches("750101-3123456 / 010-1234-5678 / 010-0000-1111")
    assert counts == {"rrn": 1, "mobile": 2}


def _record(msg: str, *args: object, exc: bool = False) -> logging.LogRecord:
    exc_info = None
    if exc:
        try:
            raise ValueError("본문 750101-3123456 포함")
        except ValueError:
            import sys

            exc_info = sys.exc_info()
    return logging.LogRecord("dpg.t", logging.INFO, __file__, 1, msg, args, exc_info)


def test_filter_masks_args_and_message() -> None:
    rec = _record("user %s phone %s", "abcdefg@example.com", "010-1234-5678")
    assert MaskingFilter().filter(rec)
    assert rec.getMessage() == "user <EMAIL> phone <PHONE>"
    assert rec.args is None


def test_filter_masks_exception_text() -> None:
    rec = _record("failed", exc=True)
    MaskingFilter().filter(rec)
    assert rec.exc_info is None
    assert rec.exc_text is not None
    assert "<RRN>" in rec.exc_text
    assert "750101" not in rec.exc_text
    formatted = logging.Formatter("%(message)s").format(rec)
    assert "ValueError" in formatted
    assert "750101" not in formatted


def test_filter_survives_bad_format_string() -> None:
    rec = _record("value %d", "750101-3123456")
    MaskingFilter().filter(rec)
    assert "750101" not in rec.getMessage()


def test_leak_scanner_does_not_join_non_adjacent_bytes() -> None:
    from dpg.core.detect.leakscan import scan_bytes

    # "ab" <invalid byte> "@x.com": not an e-mail in the file, but "ignore" decoding joins it
    assert scan_bytes(b"ab\xff@x.com") == {}
    assert scan_bytes("연락 abcdefg@example.com".encode()) == {"email": 1}
    assert scan_bytes("750101-3123454".encode("utf-16-le")) == {"rrn": 1}
