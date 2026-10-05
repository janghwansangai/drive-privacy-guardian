"""Shares the GUI test environment fixture across GUI test modules."""

from __future__ import annotations

import pytest

from dpg.gui import keepawake
from tests.gui.test_gui import env  # noqa: F401


@pytest.fixture(autouse=True)
def no_real_keep_awake(monkeypatch: pytest.MonkeyPatch) -> None:
    """GUI tests must not start the system's caffeinate (or touch Windows power state)."""
    monkeypatch.setattr(keepawake.KeepAwake, "start", lambda self: None)
    monkeypatch.setattr(keepawake.KeepAwake, "stop", lambda self: None)
