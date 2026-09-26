"""Fake Google OAuth endpoints + fake browser + in-memory keychain for auth tests.

- `FakeGoogle.http()` returns a `GuardedHttp` subclass: the real allow-list check runs, then the
  request is answered in memory (token exchange, refresh, revoke, Drive about.get).
- `FakeGoogle.browser` plays the user's browser: it validates the authorization URL and calls
  the app's real loopback listener from a thread (tests using it need `enable_socket`).
- Every secret the fake issues is recorded in `issued_secrets` so leak scans can search for it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httplib2

from dpg.core.auth.loopback import AUTH_URI, REVOKE_URI, TOKEN_URI
from dpg.core.net_guard.http import GuardedHttp

CLIENT_ID = "123456789012-fakeclientidfortests0000000000.apps.googleusercontent.com"


def make_client_secret() -> str:
    return "GOCSPX-FAKE" + secrets.token_urlsafe(18)


def make_client_json(
    client_id: str = CLIENT_ID, client_secret: str | None = None, **overrides: Any
) -> str:
    installed = {
        "client_id": client_id,
        "project_id": "dpg-test-project",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": make_client_secret() if client_secret is None else client_secret,
        "redirect_uris": ["http://localhost"],
    }
    installed.update(overrides)
    return json.dumps({"installed": installed})


class MemorySecretStore:
    """Stands in for the OS keychain. `history` keeps every value ever written."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.history: list[tuple[str, str]] = []

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def set(self, key: str, value: str) -> None:
        self.data[key] = value
        self.history.append((key, value))

    def delete(self, key: str) -> None:
        self.data.pop(key, None)


@dataclass
class FakeGoogle:
    client_id: str = CLIENT_ID
    client_secret: str = field(default_factory=make_client_secret)
    email: str = "tester@school.example"
    # behaviour switches
    deny: bool = False
    granted_scopes_override: list[str] | None = None
    drive_api_enabled: bool = True
    revoke_fails: bool = False
    send_bad_state_first: bool = False
    # state
    codes: dict[str, dict[str, Any]] = field(default_factory=dict)
    refresh_tokens: dict[str, list[str]] = field(default_factory=dict)
    access_tokens: dict[str, list[str]] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)
    user_grants: set[str] = field(default_factory=set)  # scopes granted so far (per user)
    issued_secrets: list[str] = field(default_factory=list)
    requests: list[tuple[str, str]] = field(default_factory=list)
    browser_threads: list[threading.Thread] = field(default_factory=list)
    last_auth_params: dict[str, str] = field(default_factory=dict)

    def client_json(self) -> str:
        return make_client_json(self.client_id, self.client_secret)

    def _issue(self, prefix: str) -> str:
        value = prefix + secrets.token_urlsafe(32)
        self.issued_secrets.append(value)
        return value

    def all_secrets(self) -> list[str]:
        return [self.client_secret, *self.issued_secrets]

    def expire_all_refresh_tokens(self) -> None:
        """Simulate the 7-day testing-mode expiry / user revoking access in their account."""
        self.revoked.update(self.refresh_tokens)

    # -- browser ------------------------------------------------------------------------------

    def browser(self, url: str) -> bool:
        parts = urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == AUTH_URI
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        self.last_auth_params = params
        assert params["client_id"] == self.client_id
        assert params["response_type"] == "code"
        assert params["code_challenge_method"] == "S256"
        redirect = params["redirect_uri"]
        assert redirect.startswith("http://127.0.0.1:")

        if self.deny:
            query = {"error": "access_denied", "state": params["state"]}
        else:
            requested = params["scope"].split()
            if params.get("include_granted_scopes") == "true":
                requested = sorted(set(requested) | self.user_grants)
            granted = (
                self.granted_scopes_override
                if self.granted_scopes_override is not None
                else requested
            )
            code = self._issue("4/FAKE")
            self.codes[code] = {
                "challenge": params["code_challenge"],
                "redirect_uri": redirect,
                "scopes": granted,
            }
            query = {"code": code, "scope": " ".join(granted), "state": params["state"]}

        def hit() -> None:
            if self.send_bad_state_first:
                bad = dict(query, state="attacker-state")
                try:
                    urllib.request.urlopen(f"{redirect}?{urlencode(bad)}", timeout=5)  # noqa: S310
                except urllib.error.HTTPError as exc:
                    if exc.code != 400:
                        raise
            with urllib.request.urlopen(f"{redirect}?{urlencode(query)}", timeout=5) as resp:  # noqa: S310
                assert resp.status == 200

        t = threading.Thread(target=hit, daemon=True)
        t.start()
        self.browser_threads.append(t)
        return True

    # -- endpoints ----------------------------------------------------------------------------

    def http(self) -> FakeGoogleHttp:
        return FakeGoogleHttp(self)

    def handle(self, uri: str, method: str, body: Any, headers: dict[str, str]) -> tuple[int, Any]:
        base = uri.split("?", 1)[0]
        self.requests.append((method, base))
        form: dict[str, str] = {}
        if body:
            text = body.decode() if isinstance(body, bytes) else str(body)
            form = {k: v[0] for k, v in parse_qs(text).items()}
        if method == "POST" and base == TOKEN_URI:
            return self._token(form)
        if method == "POST" and base == REVOKE_URI:
            assert "token" not in urlsplit(uri).query, "token must not be sent in the URL"
            if self.revoke_fails:
                return 503, {"error": "unavailable"}
            self.revoked.add(form.get("token", ""))
            return 200, {}
        if method == "GET" and base == "https://www.googleapis.com/drive/v3/about":
            auth = {k.lower(): v for k, v in headers.items()}.get("authorization", "")
            token = auth.removeprefix("Bearer ")
            if token not in self.access_tokens or token in self.revoked:
                return 401, {"error": {"code": 401, "status": "UNAUTHENTICATED"}}
            if not self.drive_api_enabled:
                return 403, {
                    "error": {
                        "code": 403,
                        "errors": [
                            {"reason": "accessNotConfigured", "message": "Drive API disabled"}
                        ],
                    }
                }
            return 200, {"user": {"emailAddress": self.email}}
        raise AssertionError(f"unexpected request {method} {base}")

    def _token(self, form: dict[str, str]) -> tuple[int, Any]:
        if (
            form.get("client_id") != self.client_id
            or form.get("client_secret") != self.client_secret
        ):
            return 401, {"error": "invalid_client"}
        grant = form.get("grant_type")
        if grant == "authorization_code":
            entry = self.codes.pop(form.get("code", ""), None)  # single use
            if entry is None or entry["redirect_uri"] != form.get("redirect_uri"):
                return 400, {"error": "invalid_grant"}
            digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
            if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != entry["challenge"]:
                return 400, {"error": "invalid_grant", "error_description": "PKCE mismatch"}
            scopes = entry["scopes"]
            self.user_grants |= set(scopes)
            refresh, access = self._issue("1//FAKE"), self._issue("ya29.FAKE")
            self.refresh_tokens[refresh] = scopes
            self.access_tokens[access] = scopes
            return 200, {
                "access_token": access,
                "refresh_token": refresh,
                "expires_in": 3599,
                "scope": " ".join(scopes),
                "token_type": "Bearer",
            }
        if grant == "refresh_token":
            refresh = form.get("refresh_token", "")
            if refresh not in self.refresh_tokens or refresh in self.revoked:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "Token has been expired or revoked.",
                }
            access = self._issue("ya29.FAKE")
            self.access_tokens[access] = self.refresh_tokens[refresh]
            return 200, {
                "access_token": access,
                "expires_in": 3599,
                "scope": " ".join(self.refresh_tokens[refresh]),
                "token_type": "Bearer",
            }
        return 400, {"error": "unsupported_grant_type"}


class FakeGoogleHttp(GuardedHttp):
    def __init__(self, google: FakeGoogle) -> None:
        super().__init__()
        self._google = google

    def _send(
        self,
        uri: str,
        method: str,
        body: Any,
        headers: dict[str, str] | None,
        redirections: int,
        connection_type: Any,
    ) -> tuple[httplib2.Response, bytes]:
        status, payload = self._google.handle(uri, method, body, headers or {})
        response = httplib2.Response({"status": str(status), "content-type": "application/json"})
        return response, json.dumps(payload).encode()
