from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from dpg.core.net_guard import DEFAULT_POLICY, BlockedConnectionError, NetGuard

ALLOWED = [
    "accounts.google.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "WWW.GOOGLEAPIS.COM.",
    "doc-0s-8c-docs.googleusercontent.com",
    "127.0.0.1",
    "::1",
    "[::1]",
]
BLOCKED = [
    "evil.example",
    "googleapis.com",  # bare apex is not on the list
    "drive.googleapis.com.evil.example",
    "www.googleapis.com.evil.example",
    "evilgoogleusercontent.com",  # suffix must match on a label boundary
    "googleusercontent.com",
    "localhost",  # only literal loopback IPs are allowed
    "8.8.8.8",
    "203.0.113.7",
    "sentry.io",
    "api.anthropic.com",
    "",
    "wwẇ.googleapis.com",  # non-ASCII lookalike
]


@pytest.mark.parametrize("host", ALLOWED)
def test_allowed_hosts(host: str) -> None:
    assert DEFAULT_POLICY.is_allowed_host(host)


@pytest.mark.parametrize("host", BLOCKED)
def test_blocked_hosts(host: str) -> None:
    assert not DEFAULT_POLICY.is_allowed_host(host)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.googleapis.com/drive/v3/files",
        "https://oauth2.googleapis.com/token",
        "https://accounts.google.com/o/oauth2/v2/auth?x=1",
        "http://127.0.0.1:53682/?code=abc",
    ],
)
def test_check_url_allows(url: str) -> None:
    DEFAULT_POLICY.check_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://www.googleapis.com/drive/v3/files",  # plain http to Google
        "https://evil.example/",
        "https://www.googleapis.com@evil.example/",  # userinfo trick
        "https://evil.example/?next=https://www.googleapis.com",
        "ftp://www.googleapis.com/",
        "http://localhost:8080/",
        "https://127.0.0.1/",
        "file:///etc/passwd",
    ],
)
def test_check_url_blocks(url: str) -> None:
    with pytest.raises(BlockedConnectionError):
        DEFAULT_POLICY.check_url(url)


# --- socket-level guard -----------------------------------------------------------------------


@pytest.fixture
def stub_resolver(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the real resolver so no DNS query can ever leave the machine in tests."""
    looked_up: list[str] = []

    def fake_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        looked_up.append(str(host))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.0.10", port or 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", lambda h: looked_up.append(h) or "142.250.0.10")
    return looked_up


@pytest.fixture
def guard(stub_resolver: list[str]) -> Iterator[NetGuard]:
    g = NetGuard()
    g.install()
    try:
        yield g
    finally:
        g.uninstall()


def test_resolution_of_blocked_host_never_reaches_resolver(
    guard: NetGuard, stub_resolver: list[str]
) -> None:
    with pytest.raises(BlockedConnectionError):
        socket.getaddrinfo("evil.example", 443)
    with pytest.raises(BlockedConnectionError):
        socket.gethostbyname("evil.example")
    assert stub_resolver == []
    assert [b.host for b in guard.blocked] == ["evil.example", "evil.example"]


def test_resolution_of_allowed_host_passes(guard: NetGuard, stub_resolver: list[str]) -> None:
    infos = socket.getaddrinfo("www.googleapis.com", 443)
    assert infos[0][4][0] == "142.250.0.10"
    assert stub_resolver == ["www.googleapis.com"]
    assert guard.blocked == []


def test_create_connection_to_blocked_host_is_refused(guard: NetGuard) -> None:
    with pytest.raises(BlockedConnectionError):
        socket.create_connection(("evil.example", 443), timeout=0.1)


def test_uninstall_restores_originals(stub_resolver: list[str]) -> None:
    before = (socket.getaddrinfo, socket.socket.connect)
    g = NetGuard()
    g.install()
    assert socket.getaddrinfo is not before[0]
    g.uninstall()
    assert (socket.getaddrinfo, socket.socket.connect) == before


@pytest.mark.enable_socket
def test_connect_to_unresolved_ip_is_refused_before_sending(guard: NetGuard) -> None:
    # 203.0.113.0/24 is TEST-NET-3 (documentation range); the guard refuses before connecting.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(BlockedConnectionError):
            s.connect(("203.0.113.7", 443))
        with pytest.raises(BlockedConnectionError):
            s.connect(("evil.example", 443))
        assert s.connect_ex is not None
        with pytest.raises(BlockedConnectionError):
            s.connect_ex(("203.0.113.7", 443))
    finally:
        s.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(BlockedConnectionError):
            u.sendto(b"x", ("203.0.113.7", 53))
    finally:
        u.close()
    assert len(guard.blocked) == 4


@pytest.mark.enable_socket
def test_loopback_connection_is_allowed(guard: NetGuard) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted: list[bool] = []

    def accept() -> None:
        conn, _ = server.accept()
        accepted.append(True)
        conn.close()

    t = threading.Thread(target=accept)
    t.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(("127.0.0.1", port))
    finally:
        client.close()
        t.join(timeout=2)
        server.close()
    assert accepted == [True]
    assert guard.blocked == []


def test_cli_installs_global_guard(capsys: pytest.CaptureFixture[str]) -> None:
    from dpg.cli.main import main
    from dpg.core.net_guard import global_guard

    try:
        assert main(["netpolicy"]) == 0
        assert global_guard().installed
        out = capsys.readouterr().out
        assert "www.googleapis.com" in out
    finally:
        global_guard().uninstall()
