"""SPEC 6.5 / Phase 6 gate: correct password decrypts, wrong one fails, hashes match."""

from __future__ import annotations

import datetime as dt
import io
import re
from pathlib import Path

import pytest
import pyzipper

from dpg.core.vault import archive
from dpg.core.vault.archive import ArchiveError, ArchiveFormat, WrongPassword

FILES = {"학생명단_가상.xlsx": b"PK fake xlsx " * 500, "메모.txt": "가상 내용".encode()}


@pytest.mark.parametrize("fmt", list(ArchiveFormat))
def test_roundtrip_and_wrong_password(fmt: ArchiveFormat) -> None:
    pw = archive.generate_password()
    blob = archive.create(FILES, pw, fmt)
    assert archive.open_archive(blob, pw) == FILES
    assert archive.verify(blob, pw, FILES).ok
    with pytest.raises(WrongPassword):
        archive.open_archive(blob, pw + "x")
    with pytest.raises(WrongPassword):
        archive.open_archive(blob, "")
    assert not archive.verify(blob, "wrong", FILES).ok


def test_7z_hides_file_names_and_content() -> None:
    blob = archive.create(FILES, "Aa1-secret", ArchiveFormat.SEVEN_ZIP)
    for name, data in FILES.items():
        for enc in ("utf-8", "utf-16-le"):
            assert name.encode(enc) not in blob
        assert data[:12] not in blob


def test_aes_zip_is_aes256_but_names_visible() -> None:
    blob = archive.create(FILES, "Aa1-secret", ArchiveFormat.AES_ZIP)
    with pyzipper.AESZipFile(io.BytesIO(blob)) as z:
        assert {i.filename for i in z.infolist()} == set(FILES)  # the documented trade-off
    assert b"PK fake xlsx" not in blob
    assert "파일 이름" in archive.AES_ZIP_WARNING_KO


def test_verify_detects_mismatch() -> None:
    blob = archive.create(FILES, "Aa1", ArchiveFormat.SEVEN_ZIP)
    other = dict(FILES)
    other["메모.txt"] = b"changed"
    v = archive.verify(blob, "Aa1", other)
    assert not v.ok
    assert v.mismatched == ("메모.txt",)
    v2 = archive.verify(blob, "Aa1", {**FILES, "없는파일": b""})
    assert not v2.ok
    assert v2.missing == ("없는파일",)


def test_password_generator() -> None:
    seen = set()
    for _ in range(200):
        pw = archive.generate_password()
        raw = pw.replace("-", "")
        assert len(raw) >= 20
        assert raw.isalnum()
        assert raw.isascii()
        assert re.search("[a-z]", raw)
        assert re.search("[A-Z]", raw)
        assert re.search("[0-9]", raw)
        seen.add(pw)
    assert len(seen) == 200


def test_archive_name_shows_the_contents() -> None:
    """D-087: the user must be able to find what was encrypted."""
    name = archive.archive_name(ArchiveFormat.SEVEN_ZIP, dt.date(2026, 9, 26))
    assert re.fullmatch(r"보관_2026-09-26_[0-9a-f]{8}\.7z", name)  # no names given
    one = archive.archive_name(ArchiveFormat.SEVEN_ZIP, names=["상담기록.hwp"])
    assert re.fullmatch(r"상담기록\.hwp \(암호화 [0-9a-f]{8}\)\.7z", one)
    many = archive.archive_name(ArchiveFormat.AES_ZIP, names=["a/b.hwp", "c.xlsx", "d.pdf"])
    assert re.fullmatch(r"a_b\.hwp 외 2개 \(암호화 [0-9a-f]{8}\)\.zip", many)
    long = archive.archive_name(ArchiveFormat.SEVEN_ZIP, names=["가" * 200 + ".hwp"])
    assert len(long) < 110
    assert "…" in long


@pytest.mark.parametrize("bad", ["../x", "/etc/x", "a/../../x", "C:/x", "..", "a\x00b"])
def test_unsafe_member_names_rejected(bad: str) -> None:
    with pytest.raises(ArchiveError):
        archive.safe_member_name(bad)


def test_zip_slip_archive_refused(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"pw")
        z.writestr("../evil.txt", b"x")
    with pytest.raises(ArchiveError):
        archive.open_archive(buf.getvalue(), "pw")
    assert not (tmp_path.parent / "evil.txt").exists()


def test_extract_never_overwrites(tmp_path: Path) -> None:
    (tmp_path / "메모.txt").write_bytes(b"existing")
    written = archive.extract_to(FILES, tmp_path)
    assert (tmp_path / "메모.txt").read_bytes() == b"existing"
    assert {p.name for p in written} == {"학생명단_가상.xlsx", "메모 (1).txt"}


def test_unique_names() -> None:
    assert archive.unique_names(["a.txt", "a.txt", "b", "b", "x/y"]) == [
        "a.txt",
        "a (1).txt",
        "b",
        "b (1)",
        "x_y",
    ]


def test_not_an_archive() -> None:
    with pytest.raises(ArchiveError):
        archive.open_archive(b"hello", "pw")
