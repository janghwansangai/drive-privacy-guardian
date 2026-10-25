"""E3 interop: an archive made by the Chrome extension (7-Zip WASM) opens in the desktop app
with the same recovery key. Fixture: extension/app/test/make_interop.mjs (synthetic data)."""

from __future__ import annotations

from pathlib import Path

from dpg.core.vault import archive
from dpg.core.vault.recovery import derive_password, parse_recovery_key, tag_from_name

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "extension" / "app" / "test" / "fixtures"
SYN = ROOT / "tests" / "fixtures" / "synthetic"
NAME = "확장_2026-09-27_5a6b7c8d.7z"


def test_desktop_opens_extension_made_archive() -> None:
    key = (FIX / "recovery.txt").read_text(encoding="utf-8").splitlines()[0].strip()
    tag = tag_from_name(NAME)
    assert tag == "5a6b7c8d"
    data = (FIX / NAME).read_bytes()
    files = archive.open_archive(data, derive_password(parse_recovery_key(key), tag))
    assert files["상담기록_가상.hwp"] == (SYN / "상담기록_가상.hwp").read_bytes()
    assert files["폴더/6-2_학생_연락처.xlsx"] == (SYN / "6-2_학생_연락처.xlsx").read_bytes()
    assert "상담기록".encode() not in data  # header encryption: names are hidden


def test_extension_made_standard_zip_opens_with_the_common_password() -> None:
    """D-107: the extension's default ZIP opens with the password alone — in the desktop app
    and in a plain ZIP reader (what Windows Explorer / macOS do), Korean names intact."""
    import io
    import zipfile

    data = (FIX / "확장_2026-10-25_9a8b7c6d.zip").read_bytes()
    key = (FIX / "recovery.txt").read_text(encoding="utf-8").splitlines()[0].strip()
    common = derive_password(parse_recovery_key(key), "c0ffee00")  # as make_interop.mjs
    files = archive.open_archive(data, common)
    assert files["상담기록_가상.hwp"] == (SYN / "상담기록_가상.hwp").read_bytes()
    assert files["폴더/6-2_학생_연락처.xlsx"] == (SYN / "6-2_학생_연락처.xlsx").read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        info = z.getinfo("상담기록_가상.hwp")
        assert info.flag_bits & 0x0001  # ZipCrypto
        assert info.flag_bits & 0x0800  # UTF-8 name
        assert z.read(info, pwd=common.encode()) == (SYN / "상담기록_가상.hwp").read_bytes()
