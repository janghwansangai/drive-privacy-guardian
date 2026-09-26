"""Detection rules (SPEC 6.3). All values are synthetic (future birth years, reserved ranges)."""

from __future__ import annotations

import pytest

from dpg.core.detect.mask import mask_value, masked_snippet
from dpg.core.detect.rules import (
    Confidence,
    detect_filename,
    detect_table,
    detect_text,
    detect_text_spans,
    summarize,
)
from dpg.core.extract.base import Table
from tools.measure_detection import PRECISION_TARGETS, RECALL_TARGETS, measure

RRN_OK = "750101-3123454"  # checksum-valid, born 2075
RRN_BAD_CHECK = "750101-3123455"


def kinds(text: str, header: str | None = None) -> dict[str, Confidence]:
    return {f.kind: f.confidence for f in detect_text(text, "t", header)}


def test_rrn_levels() -> None:
    assert kinds(f"번호 {RRN_OK}") == {"rrn": Confidence.HIGH}
    assert kinds(RRN_OK.replace("-", "")) == {"rrn": Confidence.HIGH}
    # post-2020 style: date valid, checksum random -> suspect only
    assert kinds(f"{RRN_BAD_CHECK}") == {"rrn_suspect": Confidence.LOW}
    # 13 digits, no separator, no keyword, bad checksum -> not reported (barcode-like)
    assert kinds(RRN_BAD_CHECK.replace("-", "")) == {}
    assert kinds("주민번호 " + RRN_BAD_CHECK.replace("-", "")) == {"rrn_suspect": Confidence.LOW}
    assert kinds("991332-1234567") == {}  # month 13
    assert kinds("750101-9123454") == {}  # 7th digit out of range


def test_phone_card_email() -> None:
    assert kinds("010-0123-4567") == {"mobile": Confidence.HIGH}
    assert kinds("01001234567") == {"mobile": Confidence.HIGH}
    assert kinds("교무실 02-0123-4567") == {"landline": Confidence.MEDIUM}
    assert kinds("대표번호 1588-1234") == {}
    assert kinds("카드 4111 1111 1111 1111") == {"card": Confidence.HIGH}
    assert kinds("카드 4111 1111 1111 1112") == {}  # Luhn fails
    assert kinds("abcdefg@example.com") == {"email": Confidence.LOW}


def test_passport_needs_keyword_for_high() -> None:
    assert kinds("여권번호 M00001234") == {"passport": Confidence.HIGH}
    assert kinds("여권 M000A1234") == {"passport": Confidence.HIGH}
    assert kinds("코드 M00001234") == {"passport": Confidence.LOW}
    assert kinds("코드 X00001234") == {}


def test_driver_license() -> None:
    assert kinds("운전면허 11-22-123456-78") == {"driver_license": Confidence.MEDIUM}
    assert kinds("번호 11-22-123456-78") == {"driver_license": Confidence.LOW}


def test_account_requires_context() -> None:
    assert kinds("신한은행 계좌 999-12-345678") == {"account": Confidence.HIGH}
    assert kinds("환불 999-12-345678") == {"account": Confidence.MEDIUM}
    assert kinds("재고 코드 999-12-345678") == {}
    assert kinds("999-12-345678", header="계좌번호") == {"account": Confidence.MEDIUM}


def test_address() -> None:
    assert kinds("서울특별시 가상구 샘플로 12") == {"address": Confidence.MEDIUM}
    assert kinds("서울특별시 가상구 샘플로 12", header="주소") == {"address": Confidence.HIGH}


def test_sensitive_suspect() -> None:
    assert kinds("김가나 학생 상담 기록") == {"sensitive_suspect": Confidence.LOW}
    assert kinds("상담 주간 안내") == {}


def test_no_double_counting() -> None:
    found = detect_text(f"{RRN_OK} 010-0123-4567", "t")
    assert sorted(f.kind for f in found) == ["mobile", "rrn"]


def test_roster_table() -> None:
    rows = [["번호", "성명", "연락처"]] + [
        [str(i), n, "010-0123-4567"]
        for i, n in enumerate(["김가나", "이다라", "박마바", "최사아", "정자차"])
    ]
    found = detect_table(Table("표 1", rows))
    assert sum(f.kind == "student_roster" for f in found) == 1
    assert sum(f.kind == "mobile" for f in found) == 5
    assert {f.location for f in found if f.kind == "mobile"} >= {"표 1, 2행"}
    # 4 name rows: not a roster
    assert not any(f.kind == "student_roster" for f in detect_table(Table("표", rows[:5])))


def test_filename() -> None:
    names = {f.kind for f in detect_filename("6-2 학생 연락처.xlsx")}
    assert "filename_hint" in names
    assert {f.kind for f in detect_filename(f"보호자 {RRN_OK}.hwp")} >= {"rrn"}
    assert detect_filename("수업 자료.pptx") == []


def test_summarize_counts_and_positions() -> None:
    found = detect_text("010-0123-4567, 010-1234-5678", "3쪽") + detect_text("x", "4쪽")
    s = summarize(found)
    assert s["mobile"].count == 2
    assert s["mobile"].locations == ["3쪽"]


def test_display_masking() -> None:
    assert mask_value("rrn", RRN_OK) == "750101-3******"
    assert mask_value("mobile", "010-0123-4567") == "010-****-4567"
    assert mask_value("account", "999-12-345678") == "***-**-***678"
    assert mask_value("email", "abcdefg@example.com") == "ab*****@example.com"
    assert mask_value("address", "서울특별시 가상구 샘플로 12") == "서울특별시 가상구 ***"
    text = f"김가나 주민번호 {RRN_OK}, 연락처 010-0123-4567"
    (finding, span), *_ = detect_text_spans(text, "t")
    snippet = masked_snippet(text, span, finding.kind)
    assert "3123454" not in snippet
    assert "0123-4567" not in snippet  # other values in the context are masked too


def test_accuracy_targets_on_synthetic_set() -> None:
    """Phase 4 gate: SPEC 6.3 initial targets on the synthetic dataset."""
    scores, unscannable = measure(
        __import__("pathlib").Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
    )
    for kind, target in RECALL_TARGETS.items():
        assert scores[kind].recall >= target, kind
    for kind, target in PRECISION_TARGETS.items():
        assert scores[kind].precision >= target, kind
    assert all(v == "ok" for v in unscannable.values()), unscannable
    assert all(s.fp == 0 for s in scores.values()), {k: s.fp for k, s in scores.items()}


@pytest.mark.parametrize(
    "text",
    [
        "회의 2026-09-26 14:00",
        "주문번호 20260926-0001",
        "버전 3.12.14",
        "우편번호 04524",
        "학번 2026123456",
        "ISBN 978-89-1234-567-8",
        "IP 192.168.0.1",
    ],
)
def test_common_non_personal_numbers(text: str) -> None:
    assert detect_text(text, "t") == []
