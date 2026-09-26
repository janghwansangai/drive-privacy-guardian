"""Suite-wide safety nets (SPEC 3.4, 8).

1. pytest-socket (`--disable-socket` in pyproject addopts) blocks socket creation for every test.
2. A session-wide NetGuard records any attempt to resolve/connect to a non-allowed host. Tests
   that exercise the guard use their own NetGuard instance, so anything recorded here is a real,
   unintended attempt and fails the run.
"""

from __future__ import annotations

import os
from pathlib import Path

# GUI tests run headless (also on CI).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from dpg.core.net_guard import NetGuard
from dpg.core.paths import ENV_HOME

_SESSION_GUARD = NetGuard()


def pytest_configure(config: pytest.Config) -> None:
    _SESSION_GUARD.install()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    _SESSION_GUARD.uninstall()
    if _SESSION_GUARD.blocked:
        hosts = sorted({b.host for b in _SESSION_GUARD.blocked})
        session.config.stash[_BLOCKED_KEY] = hosts
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


_BLOCKED_KEY = pytest.StashKey[list[str]]()


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    hosts = terminalreporter.config.stash.get(_BLOCKED_KEY, None)
    if hosts:
        terminalreporter.section("net_guard: blocked outbound attempts", red=True)
        for host in hosts:
            terminalreporter.line(f"  {host}")


@pytest.fixture
def session_guard() -> NetGuard:
    return _SESSION_GUARD


@pytest.fixture(autouse=True)
def isolated_app_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tests never touch the real per-user app data folder."""
    home = tmp_path / "dpg-home"
    monkeypatch.setenv(ENV_HOME, str(home))
    return home
