"""Principle 1: the app must not talk to anything except the Google auth/Drive hosts."""

from __future__ import annotations

import ast
import socket
import tomllib
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError

from dpg.core.net_guard import NetGuard

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "dpg"

# Telemetry / error reporting / external AI / generic HTTP clients / Qt networking.
FORBIDDEN_MODULES = {
    "sentry_sdk",
    "posthog",
    "mixpanel",
    "analytics",
    "segment",
    "bugsnag",
    "rollbar",
    "datadog",
    "ddtrace",
    "newrelic",
    "opentelemetry",
    "honeybadger",
    "amplitude",
    "openai",
    "anthropic",
    "google.generativeai",
    "google.genai",
    "cohere",
    "mistralai",
    "google.cloud.dlp",
    "boto3",
    "botocore",
    "azure",
    "urllib.request",
    "http.client",
    "aiohttp",
    "httpx",
    "urllib3",
    "websocket",
    "websockets",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
    "paramiko",
    "PySide6.QtNetwork",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PyQt5",
    "PyQt6",
}
# Only the net_guard package may touch sockets directly.
SOCKET_ALLOWED = {SRC / "core" / "net_guard" / "__init__.py"}


def test_suite_runs_with_sockets_disabled() -> None:
    with pytest.raises(SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_pytest_config_keeps_socket_block() -> None:
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    addopts = cfg["tool"]["pytest"]["ini_options"]["addopts"]
    assert "--disable-socket" in addopts


def test_session_guard_is_active_and_clean(session_guard: NetGuard) -> None:
    assert session_guard.installed
    assert session_guard.blocked == []


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _is_forbidden(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in FORBIDDEN_MODULES)


def test_no_forbidden_imports_in_app_code() -> None:
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        for name in _imports(path):
            if _is_forbidden(name):
                offenders.append(f"{path.relative_to(ROOT)}: {name}")
            if name.split(".")[0] == "socket" and path not in SOCKET_ALLOWED:
                offenders.append(f"{path.relative_to(ROOT)}: socket (only net_guard may)")
    assert offenders == []


def test_no_bundled_oauth_client_or_secrets() -> None:
    """SPEC 9: the repo/installer must never contain an OAuth client JSON or tokens."""
    suspicious: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(
            p in path.parts
            for p in (".venv", ".git", ".mypy_cache", ".ruff_cache", ".pytest_cache")
        ):
            continue
        if path.suffix == ".json" and path.stat().st_size < 1_000_000:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if '"client_secret"' in text or '"refresh_token"' in text:
                suspicious.append(str(path.relative_to(ROOT)))
    assert suspicious == []
