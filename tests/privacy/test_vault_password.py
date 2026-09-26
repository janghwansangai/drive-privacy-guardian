"""Phase 6 gate: the archive password never reaches the command line, logs, or app files."""

from __future__ import annotations

import getpass
from pathlib import Path

import pytest

from dpg.cli.main import build_parser, main
from dpg.core.vault import archive
from dpg.core.vault.archive import ArchiveFormat

FILES = {"가상명단.csv": b"name\nA\n"}


def _all_bytes(root: Path) -> list[bytes]:
    return [p.read_bytes() for p in root.rglob("*") if p.is_file()] if root.exists() else []


def test_there_is_no_password_option() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["vault", "open", "a.7z", "--out", "x", "--password", "pw"])
    help_text = parser.format_help()
    assert "password" not in help_text.lower()


def test_vault_open_prompts_hidden_and_leaves_no_trace(
    tmp_path: Path,
    isolated_app_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pw = archive.generate_password()
    src = tmp_path / "보관.7z"
    src.write_bytes(archive.create(FILES, pw, ArchiveFormat.SEVEN_ZIP))
    out = tmp_path / "풀기"
    prompts: list[str] = []

    def fake_getpass(prompt: str = "") -> str:
        prompts.append(prompt)
        return pw

    monkeypatch.setattr(getpass, "getpass", fake_getpass)
    assert main(["vault", "open", str(src), "--out", str(out)]) == 0
    assert prompts
    assert "표시되지 않음" in prompts[0]
    assert (out / "가상명단.csv").read_bytes() == FILES["가상명단.csv"]
    captured = capsys.readouterr()
    assert pw not in captured.out + captured.err
    assert all(pw.encode() not in b for b in _all_bytes(isolated_app_home))

    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "Wrong-0000")
    assert main(["vault", "open", str(src), "--out", str(tmp_path / "x")]) == 1
    assert "비밀번호가 틀렸" in capsys.readouterr().err
    assert not (tmp_path / "x").exists()


def test_vault_code_has_no_subprocess() -> None:
    """In-process only (SPEC 6.5-3): no external 7z binary that would see the password."""
    root = Path(__file__).resolve().parents[2] / "src" / "dpg"
    for path in [*(root / "core" / "vault").glob("*.py"), root / "cli" / "vault_cmd.py"]:
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "os.system" not in text, path
