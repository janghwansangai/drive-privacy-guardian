"""Login item for scheduled scans: only the user's own, only for an installed app (D-099)."""

from __future__ import annotations

import plistlib
from pathlib import Path

import pytest

from dpg.gui import autostart
from dpg.gui.autostart import AutostartError, Target


def test_only_an_installed_app_can_be_started_at_login() -> None:
    with pytest.raises(AutostartError, match="설치한 앱"):
        autostart.current_target("/usr/bin/python3", frozen=False)
    with pytest.raises(AutostartError, match="응용 프로그램"):
        autostart.current_target(
            "/private/var/folders/x/AppTranslocation/ABC/d/Drive Privacy Guardian.app/"
            "Contents/MacOS/Drive Privacy Guardian",
            frozen=True,
        )
    with pytest.raises(AutostartError):
        autostart.current_target("/Volumes/개인정보 보안관/App.app/Contents/MacOS/x", frozen=True)
    exe = "/Applications/Drive Privacy Guardian.app/Contents/MacOS/Drive Privacy Guardian"
    assert autostart.current_target(exe, frozen=True) == Target(exe)


def test_macos_launch_agent_in_the_users_own_folder(tmp_path: Path) -> None:
    exe = "/Applications/Drive Privacy Guardian.app/Contents/MacOS/Drive Privacy Guardian"
    assert not autostart.is_enabled(platform="darwin", home=tmp_path)
    autostart.enable(Target(exe), platform="darwin", home=tmp_path)
    path = tmp_path / "Library" / "LaunchAgents" / f"{autostart.LABEL}.plist"
    data = plistlib.loads(path.read_bytes())
    assert data["ProgramArguments"] == [exe, "--background"]
    assert data["RunAtLoad"] is True
    assert autostart.is_enabled(platform="darwin", home=tmp_path)
    autostart.disable(platform="darwin", home=tmp_path)
    assert not path.exists()
    autostart.disable(platform="darwin", home=tmp_path)  # already off: fine


def test_windows_run_command_is_quoted() -> None:
    cmd = autostart._win_command(Target(r"C:\Users\선생님\보안관\Drive Privacy Guardian.exe"))
    assert cmd == r'"C:\Users\선생님\보안관\Drive Privacy Guardian.exe" --background'


def test_unsupported_platform() -> None:
    assert not autostart.supported("linux")
    with pytest.raises(AutostartError):
        autostart.enable(Target("/x"), platform="linux")
    assert not autostart.is_enabled(platform="linux")
