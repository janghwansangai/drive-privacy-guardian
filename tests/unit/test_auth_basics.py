"""Client JSON validation, scopes, secret store backends, guarded HTTP transport."""

from __future__ import annotations

import json
from typing import Any

import httplib2
import pytest

from dpg.core.auth.client import parse_client_json
from dpg.core.auth.errors import ClientConfigError, InsecureSecretStore
from dpg.core.auth.scopes import (
    SCOPE_FULL,
    SCOPE_METADATA_READONLY,
    SCOPE_READONLY,
    AccessLevel,
    granted_level,
    satisfies,
)
from dpg.core.auth.secret_store import KeyringSecretStore, is_secure_backend
from dpg.core.net_guard import BlockedConnectionError
from dpg.core.net_guard.http import GuardedHttp
from tests.fakes.fake_google_auth import CLIENT_ID, make_client_json

# --- client JSON ------------------------------------------------------------------------------


def test_valid_desktop_client() -> None:
    raw = make_client_json(client_secret="GOCSPX-FAKEabcdefghijklmnop")
    cfg = parse_client_json(raw.encode("utf-8-sig"))  # BOM tolerated
    assert cfg.client_id == CLIENT_ID
    assert cfg.project_id == "dpg-test-project"
    assert "GOCSPX" not in repr(cfg)
    stored = cfg.to_stored()
    assert set(json.loads(stored)) == {"v", "client_id", "client_secret", "project_id"}


@pytest.mark.parametrize(
    ("raw", "fragment"),
    [
        (json.dumps({"web": {"client_id": CLIENT_ID}}), "웹 애플리케이션"),
        (json.dumps({"type": "service_account", "private_key": "x"}), "서비스 계정"),
        (json.dumps({"other": {}}), "데스크톱 앱"),
        ("not json", "JSON"),
        ("[1, 2]", "형식"),
        (make_client_json(client_id="evil"), "client_id"),
        (make_client_json(client_secret=""), "client_secret"),
        (make_client_json(token_uri="https://evil.example/token"), "변조"),
        (make_client_json(auth_uri="https://evil.example/auth"), "변조"),
    ],
)
def test_invalid_client_json(raw: str, fragment: str) -> None:
    with pytest.raises(ClientConfigError) as exc:
        parse_client_json(raw)
    assert fragment in exc.value.user_message


def test_client_error_messages_never_contain_secret() -> None:
    secret = "GOCSPX-FAKEsecretvaluexyz0123"
    with pytest.raises(ClientConfigError) as exc:
        parse_client_json(make_client_json(client_secret=secret, token_uri="https://evil.example"))
    assert secret not in str(exc.value)


def test_oversized_file_rejected() -> None:
    with pytest.raises(ClientConfigError):
        parse_client_json(b" " * (64 * 1024 + 1))


# --- scopes -----------------------------------------------------------------------------------


def test_scope_levels() -> None:
    assert granted_level([]) is None
    assert granted_level(["openid"]) is None
    assert granted_level([SCOPE_METADATA_READONLY]) == AccessLevel.AUDIT
    assert granted_level([SCOPE_METADATA_READONLY, SCOPE_READONLY]) == AccessLevel.DETECT
    assert granted_level([SCOPE_FULL]) == AccessLevel.MODIFY
    assert satisfies([SCOPE_READONLY], AccessLevel.AUDIT)
    assert not satisfies([SCOPE_METADATA_READONLY], AccessLevel.DETECT)


# --- secret store -----------------------------------------------------------------------------


def _backend(module: str) -> Any:
    cls = type("B", (), {"__module__": module})
    return cls()


@pytest.mark.parametrize(
    ("module", "ok"),
    [
        ("keyring.backends.macOS", True),
        ("keyring.backends.Windows", True),
        ("keyring.backends.SecretService", True),
        ("keyring.backends.fail", False),
        ("keyring.backends.null", False),
        ("keyrings.alt.file", False),  # plaintext / file-based
        ("my.custom.backend", False),
    ],
)
def test_secure_backend_detection(module: str, ok: bool) -> None:
    assert is_secure_backend(_backend(module)) is ok


def test_chainer_requires_all_members_secure() -> None:
    chainer = _backend("keyring.backends.chainer")
    chainer.backends = [_backend("keyring.backends.macOS"), _backend("keyrings.alt.file")]
    assert not is_secure_backend(chainer)
    chainer.backends = [_backend("keyring.backends.macOS")]
    assert is_secure_backend(chainer)


def test_keyring_store_refuses_insecure_backend() -> None:
    from keyring.backends.fail import Keyring as FailKeyring

    with pytest.raises(InsecureSecretStore):
        KeyringSecretStore(backend=FailKeyring())


def test_keyring_store_roundtrip_and_size_limit() -> None:
    class Mem:
        __module__ = "keyring.backends.macOS"

        def __init__(self) -> None:
            self.d: dict[tuple[str, str], str] = {}

        def get_password(self, s: str, k: str) -> str | None:
            return self.d.get((s, k))

        def set_password(self, s: str, k: str, v: str) -> None:
            self.d[(s, k)] = v

        def delete_password(self, s: str, k: str) -> None:
            from keyring.errors import PasswordDeleteError

            if (s, k) not in self.d:
                raise PasswordDeleteError(k)
            del self.d[(s, k)]

    store = KeyringSecretStore(backend=Mem())
    store.set("a", "1")
    assert store.get("a") == "1"
    store.delete("a")
    store.delete("a")  # idempotent
    assert store.get("a") is None
    with pytest.raises(ValueError, match="too large"):
        store.set("a", "x" * 1201)


# --- guarded HTTP -----------------------------------------------------------------------------


class RecordingHttp(GuardedHttp):
    def __init__(self) -> None:
        super().__init__()
        self.sent: list[str] = []

    def _send(self, uri: str, *args: Any) -> tuple[httplib2.Response, bytes]:
        self.sent.append(uri)
        return httplib2.Response({"status": "200"}), b"{}"


def test_guarded_http_blocks_before_sending() -> None:
    http = RecordingHttp()
    http.request("https://oauth2.googleapis.com/token", "POST")
    for bad in ("https://evil.example/", "http://www.googleapis.com/", "https://sentry.io/api"):
        with pytest.raises(BlockedConnectionError):
            http.request(bad)
    assert http.sent == ["https://oauth2.googleapis.com/token"]


def test_guarded_http_ignores_environment_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.evil.example:3128")
    assert GuardedHttp().proxy_info is None


def test_guarded_http_checks_redirect_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    """httplib2 follows redirects via self.request(); the redirect target must be re-checked."""
    calls: list[str] = []

    def fake_conn_request(
        self: Any, conn: Any, request_uri: str, method: str, body: Any, headers: Any
    ) -> tuple[httplib2.Response, bytes]:
        calls.append(request_uri)
        resp = httplib2.Response({"status": "302", "location": "https://evil.example/steal"})
        return resp, b""

    monkeypatch.setattr(httplib2.Http, "_conn_request", fake_conn_request)
    with pytest.raises(BlockedConnectionError):
        GuardedHttp().request("https://www.googleapis.com/drive/v3/files")
    assert len(calls) == 1  # the evil host was never contacted
