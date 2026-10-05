"""Keep the computer from idle-sleeping while a long scan runs (D-098).

macOS: the built-in `/usr/bin/caffeinate -i -w <this app's pid>` (ends by itself if the app
quits). Windows: SetThreadExecutionState on the GUI thread. Nothing else: no network, no
settings changed — closing a laptop lid still puts it to sleep.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from dpg.core.logging import get_logger

log = get_logger("gui")

CAFFEINATE = Path("/usr/bin/caffeinate")
_ES_CONTINUOUS = 0x80000000
_ES_SYSTEM_REQUIRED = 0x00000001


def _kernel32(ctypes: Any) -> Any:
    return getattr(ctypes, "windll").kernel32  # noqa: B009 — Windows-only attribute


class KeepAwake:
    def __init__(self) -> None:
        self._proc: subprocess.Popen[bytes] | None = None
        self._windows = False

    @property
    def active(self) -> bool:
        return self._proc is not None or self._windows

    def start(self) -> None:
        if self.active:
            return
        try:
            if sys.platform == "darwin" and CAFFEINATE.exists():
                self._proc = subprocess.Popen(  # noqa: S603 — fixed system binary, no shell
                    [str(CAFFEINATE), "-i", "-w", str(os.getpid())],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            elif sys.platform == "win32":
                import ctypes

                _kernel32(ctypes).SetThreadExecutionState(_ES_CONTINUOUS | _ES_SYSTEM_REQUIRED)
                self._windows = True
        except OSError as exc:  # not being able to stay awake must never stop a scan
            log.info("keep-awake unavailable (%s)", type(exc).__name__)

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._windows:
            import ctypes

            _kernel32(ctypes).SetThreadExecutionState(_ES_CONTINUOUS)
            self._windows = False
