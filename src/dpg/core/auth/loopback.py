"""Desktop OAuth: loopback redirect + PKCE (SPEC 3.1; verified against Google docs, V2).

- Listens on 127.0.0.1 with an OS-assigned port, only for the duration of the login, and
  closes the listener as soon as the redirect arrives (or on timeout / cancel).
- PKCE S256 with a 86-char verifier; `state` is checked in constant time. Requests with a wrong
  state are answered with 400 and ignored (the real redirect may still come).
- The request log is disabled: the redirect query string contains the authorization code.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import socketserver
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httplib2

from dpg.core.auth.client import ClientConfig
from dpg.core.auth.errors import AuthError, LoginCancelled, LoginTimeout, NetworkError

AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 — endpoint URL
REVOKE_URI = "https://oauth2.googleapis.com/revoke"
LOOPBACK_HOST = "127.0.0.1"

_DONE_HTML = """<!doctype html><html lang="ko"><meta charset="utf-8">
<title>Drive Privacy Guardian</title>
<body style="font-family:sans-serif;max-width:32rem;margin:4rem auto;line-height:1.6">
<h1>{title}</h1><p>{body}</p></body></html>"""


def make_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)  # 86 chars from [A-Za-z0-9_-]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@dataclass(frozen=True)
class TokenResult:
    access_token: str
    refresh_token: str | None
    scopes: tuple[str, ...]
    expires_in: int

    def __repr__(self) -> str:  # never print tokens
        return f"TokenResult(scopes={self.scopes!r}, expires_in={self.expires_in})"


class _LoopbackServer(HTTPServer):
    allow_reuse_address = False
    expected_state: str
    result: dict[str, str] | None = None

    def server_bind(self) -> None:
        # Skip HTTPServer.server_bind's getfqdn() reverse lookup.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _LoopbackServer
    server_version = "dpg"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        return  # the query string holds the authorization code — never log it

    def _reply(self, status: int, title: str, body: str) -> None:
        payload = _DONE_HTML.format(title=title, body=body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if parts.path != "/":
            self._reply(404, "Not found", "")
            return
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        state = params.get("state", "")
        if not state or not hmac.compare_digest(state, self.server.expected_state):
            self._reply(400, "잘못된 요청", "이 요청은 무시되었습니다.")
            return
        if "error" in params:
            self.server.result = {"error": params["error"]}
            self._reply(200, "로그인이 취소되었습니다", "이 창을 닫고 앱으로 돌아가세요.")
        elif "code" in params:
            self.server.result = {"code": params["code"]}
            self._reply(
                200,
                "로그인 완료",
                "✓ 로그인되었습니다. 이 탭을 닫고 Drive Privacy Guardian으로 돌아가세요.",
            )
        else:
            self._reply(400, "잘못된 요청", "인증 코드가 없습니다.")


class LoopbackLogin:
    def __init__(
        self,
        client: ClientConfig,
        scopes: list[str],
        http_factory: Callable[[], httplib2.Http],
        open_browser: Callable[[str], bool],
        *,
        timeout: float = 300.0,
        on_url: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.client = client
        self.scopes = scopes
        self.http_factory = http_factory
        self.open_browser = open_browser
        self.timeout = timeout
        self.on_url = on_url
        self.cancel = cancel

    def authorization_url(self, redirect_uri: str, state: str, challenge: str) -> str:
        query = {
            "client_id": self.client.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "include_granted_scopes": "true",
            # Always show consent so staged scope upgrades are explicit to the user.
            "prompt": "consent",
        }
        return f"{AUTH_URI}?{urlencode(query)}"

    def run(self) -> TokenResult:
        verifier, challenge = make_pkce_pair()
        state = secrets.token_urlsafe(32)
        server = _LoopbackServer((LOOPBACK_HOST, 0), _CallbackHandler)
        try:
            server.expected_state = state
            server.timeout = 0.25
            redirect_uri = f"http://{LOOPBACK_HOST}:{server.server_port}/"
            url = self.authorization_url(redirect_uri, state, challenge)
            if self.on_url is not None:
                self.on_url(url)
            self.open_browser(url)
            deadline = time.monotonic() + self.timeout
            while server.result is None:
                if self.cancel is not None and self.cancel.is_set():
                    raise LoginCancelled()
                if time.monotonic() > deadline:
                    raise LoginTimeout()
                server.handle_request()
            result = server.result
        finally:
            server.server_close()

        if "error" in result:
            if result["error"] == "access_denied":
                raise LoginCancelled("구글 로그인 화면에서 허용하지 않아 로그인이 취소되었습니다.")
            raise AuthError(f"구글 로그인 오류: {result['error'][:64]}")
        return exchange_code(
            self.http_factory(), self.client, result["code"], verifier, redirect_uri
        )


def _post_form(http: httplib2.Http, uri: str, fields: dict[str, str]) -> tuple[int, Any]:
    try:
        response, content = http.request(
            uri,
            "POST",
            body=urlencode(fields),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except (OSError, httplib2.HttpLib2Error) as exc:
        raise NetworkError() from exc
    try:
        body = json.loads(content.decode("utf-8")) if content else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        body = {}
    return int(response.status), body


def exchange_code(
    http: httplib2.Http, client: ClientConfig, code: str, verifier: str, redirect_uri: str
) -> TokenResult:
    status, body = _post_form(
        http,
        TOKEN_URI,
        {
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        },
    )
    if status != 200 or "access_token" not in body:
        error = str(body.get("error", status))[:64] if isinstance(body, dict) else str(status)
        if error == "invalid_client":
            raise AuthError(
                "클라이언트 정보가 올바르지 않습니다 (invalid_client). "
                "클라이언트 JSON을 다시 불러와 주세요."
            )
        raise AuthError(f"로그인 토큰을 받지 못했습니다 ({error}).")
    return TokenResult(
        access_token=str(body["access_token"]),
        refresh_token=body.get("refresh_token"),
        scopes=tuple(str(body.get("scope", "")).split()),
        expires_in=int(body.get("expires_in", 3600)),
    )


def revoke_token(http: httplib2.Http, token: str) -> bool:
    """Revoke a token. The token goes in the POST body, never the URL (D-019)."""
    try:
        status, _ = _post_form(http, REVOKE_URI, {"token": token})
    except NetworkError:
        return False
    return status == 200
