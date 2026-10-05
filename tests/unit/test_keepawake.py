"""Keep-awake during long scans: the system's own caffeinate on macOS, nothing on the network."""

from __future__ import annotations

import os
import subprocess
from typing import Any

import pytest

from dpg.gui import keepawake


class FakeProc:
    def __init__(self, args: list[str], **kw: Any) -> None:
        self.args = args
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        return 0


def test_macos_uses_caffeinate_tied_to_this_process(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[FakeProc] = []

    def popen(args: list[str], **kw: Any) -> FakeProc:
        assert kw.get("shell") is not True
        started.append(FakeProc(args))
        return started[-1]

    monkeypatch.setattr(keepawake.sys, "platform", "darwin")
    monkeypatch.setattr(keepawake.Path, "exists", lambda self: True)
    monkeypatch.setattr(subprocess, "Popen", popen)
    ka = keepawake.KeepAwake()
    ka.start()
    ka.start()  # idempotent
    assert len(started) == 1
    assert started[0].args == ["/usr/bin/caffeinate", "-i", "-w", str(os.getpid())]
    assert ka.active
    ka.stop()
    assert started[0].terminated
    assert not ka.active


def test_no_tool_means_no_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keepawake.sys, "platform", "linux")
    ka = keepawake.KeepAwake()
    ka.start()
    assert not ka.active
    ka.stop()
