"""The Korean disclaimer stays visible everywhere a user meets the program."""

from pathlib import Path

from dpg import DISCLAIMER_KO
from dpg.gui.main_window import ABOUT_TEXT

ROOT = Path(__file__).resolve().parents[2]
KEY = "책임을 지지 않"


def test_about_box_shows_disclaimer() -> None:
    assert KEY in DISCLAIMER_KO
    assert DISCLAIMER_KO in ABOUT_TEXT


def test_notices_site_and_extension_carry_disclaimer() -> None:
    for rel in (
        "packaging/NOTICE_KO.txt",
        "extension/app/NOTICE_KO.txt",
        "extension/app/viewer.html",
        "site/public/index.html",
        "site/public/desktop.html",
        "site/public/setup.html",
        "README.md",
    ):
        assert KEY in (ROOT / rel).read_text(encoding="utf-8"), rel
    assert (ROOT / "extension/app/LICENSE").read_text() == (ROOT / "LICENSE").read_text()
