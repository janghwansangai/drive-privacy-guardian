"""`--selftest` passes in the development environment (the release build runs it too)."""

from __future__ import annotations

from dpg.gui.app import main
from dpg.selftest import run


def test_selftest_passes_without_network() -> None:
    lines: list[str] = []
    # The CI/test keychain may be a non-secure backend; that check is exercised on real OSes.
    assert run(lines.append, skip={"OS 보안 저장소"}) == 0, "\n".join(lines)
    assert lines[-1] == "결과: 정상"
    assert any("외부 호스트 차단됨" in line for line in lines)


def test_version_flag(capsys: object) -> None:
    assert main(["dpg-gui", "--version"]) == 0
