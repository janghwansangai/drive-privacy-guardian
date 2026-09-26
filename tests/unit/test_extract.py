"""Format extractors: text/tables from every 1st-phase format, and 검사 불가 cases."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from dpg.core.extract import Unscannable, UnscannableReason, extract, plan_for
from dpg.core.extract.base import MAX_FILE_BYTES, decode_text
from dpg.core.extract.hwp import para_text
from tools.doc_writers import build_hwp, build_hwpx, build_pdf

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"


def _run(name: str, mime: str = "") -> object:
    return extract((FIXTURES / name).read_bytes(), plan_for(mime, name))


@pytest.mark.parametrize(
    ("name", "min_segments", "min_tables"),
    [
        ("업무메모.txt", 5, 0),
        ("6-2_학생_연락처.csv", 0, 1),
        ("6-2_학생_연락처.xlsx", 0, 1),
        ("가정통신문_체험학습.docx", 5, 0),
        ("보호자_안내문.pdf", 4, 0),
        ("상담기록_가상.hwp", 4, 1),
        ("학생명단_가상.hwpx", 2, 1),
    ],
)
def test_fixture_formats(name: str, min_segments: int, min_tables: int) -> None:
    doc = _run(name)
    assert len(doc.segments) >= min_segments  # type: ignore[attr-defined]
    assert len(doc.tables) >= min_tables  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("스캔_가상.pdf", UnscannableReason.IMAGE_ONLY),
        ("암호_가상.hwp", UnscannableReason.ENCRYPTED),
        ("배포용_가상.hwp", UnscannableReason.DISTRIBUTION),
    ],
)
def test_unscannable_fixtures(name: str, reason: UnscannableReason) -> None:
    with pytest.raises(Unscannable) as exc:
        _run(name)
    assert exc.value.reason is reason


def test_locations_are_positional_not_content() -> None:
    doc = _run("6-2_학생_연락처.xlsx")
    assert doc.tables[0].location == "시트 1"  # type: ignore[attr-defined]


def test_hwp_table_both_list_header_layouts() -> None:
    rows = [["성명", "연락처"], ["김가나", "010-0123-4567"], ["이다라", "010-1234-0000"]]
    for lhb in (6, 8):
        doc = extract(
            build_hwp(["머리말", rows, "끝"], list_header_bytes=lhb), plan_for("", "a.hwp")
        )
        assert doc.tables[0].rows == rows
        assert [s.text for s in doc.segments] == ["머리말", "끝"]


def test_hwp_uncompressed_and_long_records() -> None:
    long_text = "가" * 3000  # > 4095 bytes => extended record size
    doc = extract(build_hwp([long_text], compressed=False), plan_for("", "a.hwp"))
    assert doc.segments[0].text == long_text


def test_hwp_control_characters_are_skipped() -> None:
    import struct

    tab = struct.pack("<H", 9) + b"\0" * 12 + struct.pack("<H", 9)  # inline control, 8 WCHARs
    data = "가".encode("utf-16-le") + tab + "나".encode("utf-16-le") + struct.pack("<H", 13)
    assert para_text(data) == "가\t나\n"


def test_hwpx_encrypted_is_unscannable() -> None:
    with pytest.raises(Unscannable) as exc:
        extract(build_hwpx(["x"], encrypted=True), plan_for("", "a.hwpx"))
    assert exc.value.reason is UnscannableReason.ENCRYPTED


@pytest.mark.parametrize("name", ["a.docx", "a.xlsx", "a.hwpx", "a.hwp", "a.pdf"])
def test_corrupt_files(name: str) -> None:
    with pytest.raises(Unscannable) as exc:
        extract(b"PK\x03\x04 definitely not a valid file 750101-3123454", plan_for("", name))
    assert exc.value.reason is UnscannableReason.CORRUPT
    assert "750101" not in str(exc.value)  # never echo content


def test_zip_bomb_guard() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Contents/section0.xml", b"\0" * (60 * 1024 * 1024))
    with pytest.raises(Unscannable) as exc:
        extract(buf.getvalue(), plan_for("", "bomb.hwpx"))
    assert exc.value.reason is UnscannableReason.TOO_LARGE


def test_encrypted_zip_member() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", b"x")
    data = bytearray(buf.getvalue())
    # zipfile clears the encryption bit on write, so set it in both headers by hand
    data[data.find(b"PK\x03\x04") + 6] |= 0x1
    data[data.find(b"PK\x01\x02") + 8] |= 0x1
    with pytest.raises(Unscannable) as exc:
        extract(bytes(data), plan_for("", "a.docx"))
    assert exc.value.reason is UnscannableReason.ENCRYPTED


@pytest.mark.parametrize("name", ["보안.docx", "보안.xlsx"])
def test_password_protected_office_file(name: str) -> None:
    from tools.cfb_writer import build_cfb

    data = build_cfb(
        {"EncryptionInfo": b"\x04\x00\x04\x00" + b"\0" * 60, "EncryptedPackage": b"\0" * 5000}
    )
    with pytest.raises(Unscannable) as exc:
        extract(data, plan_for("", name))
    assert exc.value.reason is UnscannableReason.ENCRYPTED


def test_size_limit() -> None:
    with pytest.raises(Unscannable) as exc:
        extract(b"a" * (MAX_FILE_BYTES + 1), plan_for("text/plain", "a.txt"))
    assert exc.value.reason is UnscannableReason.TOO_LARGE


def test_pdf_multi_page_with_one_blank_page_still_scans() -> None:
    doc = extract(build_pdf([["보호자 연락처 010-0123-4567 입니다"], []]), plan_for("", "a.pdf"))
    assert doc.segments[0].location == "1쪽"
    assert doc.partial  # page 2 is an image: reported as partly unscanned, never "clean"


def test_plan_for() -> None:
    assert plan_for("application/vnd.google-apps.document", "x").export_mime == "text/plain"
    assert plan_for("application/vnd.google-apps.spreadsheet", "x").export_mime.endswith("sheet")
    assert plan_for("application/octet-stream", "명단.HWP").export_mime is None
    with pytest.raises(Unscannable) as exc:
        plan_for("image/jpeg", "scan.jpg")
    assert exc.value.reason is UnscannableReason.IMAGE_ONLY
    with pytest.raises(Unscannable) as exc:
        plan_for("application/zip", "backup.zip")
    assert exc.value.reason is UnscannableReason.UNSUPPORTED


def test_decode_text_cp949_and_bom() -> None:
    assert decode_text("주소록".encode("cp949")) == "주소록"
    assert decode_text(b"\xef\xbb\xbf" + "명단".encode()) == "명단"
    assert decode_text("명단".encode("utf-16")) == "명단"
