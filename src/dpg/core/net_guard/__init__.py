"""Network allow-list enforcement (SPEC 1.2 principle 1, 3.4).

Two layers:

1. `HostPolicy.check_url()` — used by the HTTP transport wrapper (Phase 1) before every request.
2. `NetGuard.install()` — process-wide socket-level guard. It wraps name resolution
   (`getaddrinfo`, `gethostbyname*`) and `socket.connect/connect_ex/sendto`, so *any* Python
   library (httplib2, requests, urllib, ...) is covered, not just the ones we remembered to wrap.
   Resolution of a non-allowed host is refused before any DNS query is made, and a connection to
   an IP that was not obtained by resolving an allowed host is refused before any packet is sent.

Known limits (documented in DECISIONS.md D-008): native code that opens sockets without going
through Python's `socket` module (e.g. Qt's QtNetwork) is not covered — the GUI must not use
QtNetwork. Blocked attempts are recorded as host/port/reason only.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "DEFAULT_POLICY",
    "BlockedAttempt",
    "BlockedConnectionError",
    "HostPolicy",
    "NetGuard",
    "global_guard",
]


class BlockedConnectionError(ConnectionRefusedError):
    """Raised when code tries to reach a host outside the allow-list."""


@dataclass(frozen=True)
class HostPolicy:
    exact_hosts: frozenset[str]
    suffixes: tuple[str, ...]  # each starts with "." so matches respect label boundaries
    loopback_ips: frozenset[str] = frozenset({"127.0.0.1", "::1"})

    @staticmethod
    def normalize(host: str) -> str | None:
        host = host.strip().lower().rstrip(".")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if not host or not host.isascii():
            return None
        return host

    @staticmethod
    def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            return ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            return None

    def is_loopback_ip(self, host: str) -> bool:
        ip = self._as_ip(host)
        return ip is not None and str(ip) in self.loopback_ips

    def is_allowed_host(self, host: str | None) -> bool:
        if host is None:
            return False
        norm = self.normalize(host)
        if norm is None:
            return False
        if self._as_ip(norm) is not None:
            # IP literals are allowed only for loopback (OAuth redirect).
            return self.is_loopback_ip(norm)
        if norm in self.exact_hosts:
            return True
        return any(norm.endswith(sfx) and len(norm) > len(sfx) for sfx in self.suffixes)

    def check_url(self, url: str) -> None:
        """Raise BlockedConnectionError unless `url` uses an allowed scheme and host."""
        parts = urlsplit(url)
        host = parts.hostname
        if parts.scheme == "https" and self.is_allowed_host(host):
            if host is not None and self.is_loopback_ip(host):
                raise BlockedConnectionError("https to loopback is not expected")
            return
        if parts.scheme == "http" and host is not None and self.is_loopback_ip(host):
            return
        raise BlockedConnectionError(f"blocked url host={host!r} scheme={parts.scheme!r}")


# Draft allow-list (SPEC 3.4). V8 in SPEC 11 must confirm the download redirect hosts.
DEFAULT_POLICY = HostPolicy(
    exact_hosts=frozenset(
        {
            "accounts.google.com",
            "oauth2.googleapis.com",
            "www.googleapis.com",
        }
    ),
    suffixes=(".googleusercontent.com",),
)


@dataclass(frozen=True)
class BlockedAttempt:
    host: str
    port: int | None
    reason: str
    at: float = field(default_factory=time.time)


_Addr = Any  # socket address tuples vary by family


class NetGuard:
    def __init__(self, policy: HostPolicy = DEFAULT_POLICY) -> None:
        self.policy = policy
        self.blocked: list[BlockedAttempt] = []
        self._resolved_ips: set[str] = set()
        self._lock = threading.Lock()
        self._originals: dict[str, Callable[..., Any]] = {}
        self._installed = False

    # -- bookkeeping ---------------------------------------------------------------------------

    @property
    def installed(self) -> bool:
        return self._installed

    def _block(self, host: str, port: int | None, reason: str) -> BlockedConnectionError:
        with self._lock:
            self.blocked.append(BlockedAttempt(host=host, port=port, reason=reason))
        return BlockedConnectionError(f"net_guard: {reason} (host={host!r}, port={port})")

    def _remember(self, infos: list[tuple[Any, ...]]) -> None:
        with self._lock:
            for info in infos:
                sockaddr = info[4]
                if isinstance(sockaddr, tuple) and sockaddr:
                    self._resolved_ips.add(str(sockaddr[0]).split("%", 1)[0])

    def _ip_allowed(self, ip: str) -> bool:
        ip = ip.split("%", 1)[0]
        if self.policy.is_loopback_ip(ip):
            return True
        with self._lock:
            return ip in self._resolved_ips

    def _check_sockaddr(self, sock: socket.socket, address: _Addr) -> None:
        if sock.family not in (socket.AF_INET, socket.AF_INET6):
            return  # AF_UNIX etc.: local IPC only
        if not isinstance(address, tuple) or not address:
            raise self._block(repr(address), None, "unrecognized socket address")
        host = str(address[0])
        port = address[1] if len(address) > 1 and isinstance(address[1], int) else None
        if self.policy._as_ip(host) is None:
            # Python resolves hostnames inside connect(); run the policy on the name itself.
            if not self.policy.is_allowed_host(host):
                raise self._block(host, port, "host not in allow-list")
            return
        if not self._ip_allowed(host):
            raise self._block(host, port, "ip not resolved from an allowed host")

    def probe_blocks(self, host: str = "example.com") -> bool:
        """Self-test: resolving a non-allowed host must fail inside the guard (no traffic)."""
        if not self.policy.is_allowed_host(host):
            try:
                socket.getaddrinfo(host, 443)
            except BlockedConnectionError:
                return True
        return False

    # -- install / uninstall -------------------------------------------------------------------

    def install(self) -> None:
        if self._installed:
            return
        guard = self
        orig_getaddrinfo = socket.getaddrinfo
        orig_gethostbyname = socket.gethostbyname
        orig_gethostbyname_ex = socket.gethostbyname_ex
        sock_cls = socket.socket
        orig_connect = sock_cls.connect
        orig_connect_ex = sock_cls.connect_ex
        orig_sendto = sock_cls.sendto

        def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            name = host.decode() if isinstance(host, bytes) else host
            if name is None:
                return orig_getaddrinfo(host, port, *args, **kwargs)  # passive/loopback lookup
            if not guard.policy.is_allowed_host(str(name)):
                raise guard._block(
                    str(name),
                    port if isinstance(port, int) else None,
                    "resolution of non-allowed host",
                )
            infos = orig_getaddrinfo(host, port, *args, **kwargs)
            guard._remember(infos)
            return infos

        def guarded_gethostbyname(host: str) -> str:
            if not guard.policy.is_allowed_host(host):
                raise guard._block(host, None, "resolution of non-allowed host")
            ip = orig_gethostbyname(host)
            with guard._lock:
                guard._resolved_ips.add(ip)
            return ip

        def guarded_gethostbyname_ex(host: str) -> tuple[str, list[str], list[str]]:
            if not guard.policy.is_allowed_host(host):
                raise guard._block(host, None, "resolution of non-allowed host")
            result = orig_gethostbyname_ex(host)
            with guard._lock:
                guard._resolved_ips.update(result[2])
            return result

        def guarded_connect(self: socket.socket, address: _Addr) -> None:
            guard._check_sockaddr(self, address)
            orig_connect(self, address)

        def guarded_connect_ex(self: socket.socket, address: _Addr) -> int:
            guard._check_sockaddr(self, address)
            return orig_connect_ex(self, address)

        def guarded_sendto(self: socket.socket, data: Any, *args: Any) -> int:
            address = args[-1]
            guard._check_sockaddr(self, address)
            return orig_sendto(self, data, *args)

        self._originals = {
            "getaddrinfo": orig_getaddrinfo,
            "gethostbyname": orig_gethostbyname,
            "gethostbyname_ex": orig_gethostbyname_ex,
            "connect": orig_connect,
            "connect_ex": orig_connect_ex,
            "sendto": orig_sendto,
        }
        self._sock_cls = sock_cls
        socket.getaddrinfo = guarded_getaddrinfo
        socket.gethostbyname = guarded_gethostbyname
        socket.gethostbyname_ex = guarded_gethostbyname_ex
        sock_cls.connect = guarded_connect  # type: ignore[method-assign,assignment]
        sock_cls.connect_ex = guarded_connect_ex  # type: ignore[method-assign,assignment]
        sock_cls.sendto = guarded_sendto  # type: ignore[method-assign,assignment]
        self._installed = True

    def uninstall(self) -> None:
        if not self._installed:
            return
        o = self._originals
        socket.getaddrinfo = o["getaddrinfo"]
        socket.gethostbyname = o["gethostbyname"]
        socket.gethostbyname_ex = o["gethostbyname_ex"]
        self._sock_cls.connect = o["connect"]  # type: ignore[method-assign]
        self._sock_cls.connect_ex = o["connect_ex"]  # type: ignore[method-assign]
        self._sock_cls.sendto = o["sendto"]  # type: ignore[method-assign]
        self._originals = {}
        self._installed = False

    def __enter__(self) -> NetGuard:
        self.install()
        return self

    def __exit__(self, *exc: object) -> None:
        self.uninstall()


_GLOBAL: NetGuard | None = None


def global_guard() -> NetGuard:
    """The process-wide guard used by the app entry points (CLI/GUI install it at startup)."""
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = NetGuard()
    return _GLOBAL
