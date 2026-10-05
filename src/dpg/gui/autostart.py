"""Start the app in the background when the user logs in, for scheduled scans (D-099).

Only the user's own login items, no administrator rights:
- macOS: a LaunchAgent file in ~/Library/LaunchAgents (RunAtLoad), removed when turned off.
- Windows: a value under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.

It can only point at an installed app: a copy run from a disk image or quarantined download
(macOS "App Translocation" gives it a random, temporary path) or from source would leave a
login item that breaks, so those are refused with an explanation.
"""

from __future__ import annotations

import importlib
import plistlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dpg.core.logging import get_logger

log = get_logger("gui")

LABEL = "kr.privacy-guardian.background"  # the LaunchAgent label / file name
RUN_VALUE = "개인정보 보안관"  # the Windows Run value name
BACKGROUND_ARG = "--background"
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


class AutostartError(Exception):
    """Shown to the user as is (Korean)."""


@dataclass(frozen=True)
class Target:
    executable: str


def launch_agent_path(home: Path | None = None) -> Path:
    return (home or Path.home()) / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def current_target(executable: str | None = None, frozen: bool | None = None) -> Target:
    """The installed app this login item should start, or AutostartError explaining why not."""
    exe = executable if executable is not None else sys.executable
    is_frozen = frozen if frozen is not None else bool(getattr(sys, "frozen", False))
    if not is_frozen:
        raise AutostartError("설치한 앱에서만 켤 수 있습니다 (개발용 실행에서는 쓸 수 없음).")
    if "/AppTranslocation/" in exe or exe.startswith("/Volumes/"):
        raise AutostartError(
            "앱이 임시 위치에서 실행 중입니다. Finder에서 앱을 「응용 프로그램」 폴더로 옮긴 뒤 "
            "그곳에서 다시 열고 켜 주세요."
        )
    return Target(exe)


# -- macOS ---------------------------------------------------------------------------------------


def _mac_enable(target: Target, home: Path | None) -> None:
    path = launch_agent_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    plist = {
        "Label": LABEL,
        "ProgramArguments": [target.executable, BACKGROUND_ARG],
        "RunAtLoad": True,
        "ProcessType": "Interactive",
    }
    path.write_bytes(plistlib.dumps(plist))
    path.chmod(0o644)


def _mac_disable(home: Path | None) -> None:
    launch_agent_path(home).unlink(missing_ok=True)


def _mac_enabled(home: Path | None) -> bool:
    return launch_agent_path(home).is_file()


# -- Windows -------------------------------------------------------------------------------------


def _winreg() -> Any:
    return importlib.import_module("winreg")  # Windows-only module (typed per platform)


def _win_command(target: Target) -> str:
    return f'"{target.executable}" {BACKGROUND_ARG}'


def _win_enable(target: Target) -> None:
    winreg = _winreg()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, _win_command(target))


def _win_disable() -> None:
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, RUN_VALUE)
    except FileNotFoundError:
        pass


def _win_enabled() -> bool:
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
            winreg.QueryValueEx(key, RUN_VALUE)
    except FileNotFoundError:
        return False
    return True


# -- public --------------------------------------------------------------------------------------


def supported(platform: str | None = None) -> bool:
    return (platform or sys.platform) in ("darwin", "win32")


def is_enabled(*, platform: str | None = None, home: Path | None = None) -> bool:
    plat = platform or sys.platform
    if plat == "darwin":
        return _mac_enabled(home)
    if plat == "win32":
        return _win_enabled()
    return False


def enable(
    target: Target | None = None, *, platform: str | None = None, home: Path | None = None
) -> None:
    plat = platform or sys.platform
    if not supported(plat):
        raise AutostartError("이 운영체제에서는 자동 실행을 지원하지 않습니다.")
    tgt = target or current_target()
    if plat == "darwin":
        _mac_enable(tgt, home)
    else:
        _win_enable(tgt)
    log.info("autostart on")


def disable(*, platform: str | None = None, home: Path | None = None) -> None:
    plat = platform or sys.platform
    if plat == "darwin":
        _mac_disable(home)
    elif plat == "win32":
        _win_disable()
    log.info("autostart off")
