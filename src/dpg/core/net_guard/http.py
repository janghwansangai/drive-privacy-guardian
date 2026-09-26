"""HTTP transport with allow-list enforcement (SPEC 3.4, layer 1 of D-008).

Every HTTP request the app makes — token exchange, refresh, revocation, Drive API — goes
through `GuardedHttp`. httplib2 follows redirects by calling `request()` again, so redirect
targets are checked too. The socket-level `NetGuard` remains the backstop.
"""

from __future__ import annotations

from typing import Any

import httplib2

from dpg.core.net_guard import DEFAULT_POLICY, HostPolicy

__all__ = ["GuardedHttp"]


class GuardedHttp(httplib2.Http):  # type: ignore[misc]
    def __init__(self, policy: HostPolicy = DEFAULT_POLICY, timeout: float = 60) -> None:
        # proxy_info=None: ignore *_PROXY environment variables. A proxy would be an extra,
        # unvetted host (DECISIONS.md D-021).
        super().__init__(timeout=timeout, proxy_info=None)
        self._dpg_policy = policy

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: Any = None,
        headers: dict[str, str] | None = None,
        redirections: int = httplib2.DEFAULT_MAX_REDIRECTS,
        connection_type: Any = None,
    ) -> tuple[httplib2.Response, bytes]:
        self._dpg_policy.check_url(uri)
        return self._send(uri, method, body, headers, redirections, connection_type)

    def _send(
        self,
        uri: str,
        method: str,
        body: Any,
        headers: dict[str, str] | None,
        redirections: int,
        connection_type: Any,
    ) -> tuple[httplib2.Response, bytes]:
        response, content = super().request(
            uri,
            method,
            body=body,
            headers=headers,
            redirections=redirections,
            connection_type=connection_type,
        )
        return response, content
