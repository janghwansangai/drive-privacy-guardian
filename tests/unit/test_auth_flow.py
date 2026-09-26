"""Loopback + PKCE login, AuthManager lifecycle and CLI — all against FakeGoogle.

These tests open a real listener on 127.0.0.1, so they opt in to sockets.
"""

from __future__ import annotations

import re
import socket
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from dpg.core.auth import AccessLevel, AuthManager, InsufficientScope, NotLoggedIn, ReauthRequired
from dpg.core.auth.client import parse_client_json
from dpg.core.auth.errors import LoginCancelled, LoginTimeout
from dpg.core.auth.loopback import LoopbackLogin, make_pkce_pair
from dpg.core.auth.scopes import SCOPE_METADATA_READONLY, SCOPE_READONLY
from dpg.core.auth.secret_store import KEY_CLIENT, KEY_TOKEN
from tests.fakes.fake_google_auth import FakeGoogle, MemorySecretStore

pytestmark = pytest.mark.enable_socket


@pytest.fixture
def google() -> FakeGoogle:
    return FakeGoogle()


@pytest.fixture
def store() -> MemorySecretStore:
    return MemorySecretStore()


@pytest.fixture
def manager(google: FakeGoogle, store: MemorySecretStore) -> AuthManager:
    m = AuthManager(store, http_factory=google.http, open_browser=google.browser)
    m.import_client(google.client_json())
    return m


def test_pkce_pair() -> None:
    verifier, challenge = make_pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert re.fullmatch(r"[A-Za-z0-9\-._~]+", verifier)
    assert re.fullmatch(r"[A-Za-z0-9\-_]{43}", challenge)
    assert make_pkce_pair()[0] != verifier


# --- loopback ---------------------------------------------------------------------------------


def _flow(google: FakeGoogle, **kw: object) -> LoopbackLogin:
    client = parse_client_json(google.client_json())
    return LoopbackLogin(
        client,
        [SCOPE_METADATA_READONLY],
        google.http,
        kw.pop("open_browser", google.browser),
        timeout=kw.pop("timeout", 10),
        **kw,
    )  # type: ignore[arg-type]


def test_loopback_login_exchanges_code(
    google: FakeGoogle, capsys: pytest.CaptureFixture[str]
) -> None:
    result = _flow(google).run()
    assert result.refresh_token in google.refresh_tokens
    assert result.scopes == (SCOPE_METADATA_READONLY,)
    p = google.last_auth_params
    assert p["prompt"] == "consent"
    assert p["include_granted_scopes"] == "true"
    assert urlsplit(p["redirect_uri"]).hostname == "127.0.0.1"
    # the request handler must not log (the query string contains the code)
    captured = capsys.readouterr()
    assert "4/FAKE" not in captured.err + captured.out


def test_loopback_listener_is_closed_after_login(google: FakeGoogle) -> None:
    ports: list[int] = []
    flow = _flow(
        google,
        on_url=lambda url: ports.append(
            int(urlsplit(parse_qs(urlsplit(url).query)["redirect_uri"][0]).port or 0)
        ),
    )
    flow.run()
    s = socket.socket()
    try:
        assert s.connect_ex(("127.0.0.1", ports[0])) != 0
    finally:
        s.close()


def test_wrong_state_is_ignored(google: FakeGoogle) -> None:
    google.send_bad_state_first = True
    assert _flow(google).run().access_token


def test_user_denies(google: FakeGoogle) -> None:
    google.deny = True
    with pytest.raises(LoginCancelled):
        _flow(google).run()


def test_timeout_and_cancel(google: FakeGoogle) -> None:
    with pytest.raises(LoginTimeout):
        _flow(google, open_browser=lambda url: False, timeout=0.3).run()
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(LoginCancelled):
        _flow(google, open_browser=lambda url: False, cancel=cancel).run()


# --- manager ----------------------------------------------------------------------------------


def test_login_status_credentials(manager: AuthManager, google: FakeGoogle) -> None:
    assert not manager.status().logged_in
    with pytest.raises(NotLoggedIn):
        manager.credentials(AccessLevel.AUDIT)
    result = manager.login(AccessLevel.AUDIT)
    assert result.account == google.email
    assert result.level == AccessLevel.AUDIT
    assert result.warning is None
    st = manager.status()
    assert (st.logged_in, st.account, st.level) == (True, google.email, AccessLevel.AUDIT)
    assert manager.credentials(AccessLevel.AUDIT).valid
    with pytest.raises(InsufficientScope):
        manager.credentials(AccessLevel.DETECT)


def test_staged_scope_upgrade(manager: AuthManager, google: FakeGoogle) -> None:
    manager.login(AccessLevel.AUDIT)
    result = manager.login(AccessLevel.DETECT)
    assert result.level == AccessLevel.DETECT
    assert google.last_auth_params["scope"] == SCOPE_READONLY
    assert manager.credentials(AccessLevel.DETECT).valid


def test_refresh_after_restart(google: FakeGoogle, store: MemorySecretStore) -> None:
    AuthManager(store, google.http, google.browser).import_client(google.client_json())
    AuthManager(store, google.http, google.browser).login(AccessLevel.AUDIT)
    fresh = AuthManager(store, google.http, google.browser)  # new process: no access token
    before = len(google.access_tokens)
    assert fresh.credentials(AccessLevel.AUDIT).valid
    assert len(google.access_tokens) == before + 1  # refreshed via refresh token
    assert fresh.verify() == google.email


def test_invalid_grant_requires_relogin(
    manager: AuthManager, google: FakeGoogle, store: MemorySecretStore
) -> None:
    manager.login(AccessLevel.AUDIT)
    google.expire_all_refresh_tokens()
    fresh = AuthManager(store, google.http, google.browser)
    with pytest.raises(ReauthRequired) as exc:
        fresh.credentials(AccessLevel.AUDIT)
    assert "다시 로그인" in exc.value.user_message
    assert KEY_TOKEN not in store.data
    assert not fresh.status().logged_in


def test_logout_revokes_and_deletes(
    manager: AuthManager, google: FakeGoogle, store: MemorySecretStore
) -> None:
    manager.login(AccessLevel.AUDIT)
    refresh = next(iter(google.refresh_tokens))
    result = manager.logout()
    assert (result.had_token, result.revoked) == (True, True)
    assert refresh in google.revoked
    assert KEY_TOKEN not in store.data
    assert KEY_CLIENT in store.data  # client stays until removed
    assert manager.logout().had_token is False


def test_logout_when_revoke_fails_still_deletes(
    manager: AuthManager, google: FakeGoogle, store: MemorySecretStore
) -> None:
    manager.login(AccessLevel.AUDIT)
    google.revoke_fails = True
    assert manager.logout().revoked is False
    assert KEY_TOKEN not in store.data


def test_replacing_client_logs_out(
    manager: AuthManager, google: FakeGoogle, store: MemorySecretStore
) -> None:
    manager.login(AccessLevel.AUDIT)
    other = FakeGoogle(
        client_id="999999999999-otherclient000000000000000000.apps.googleusercontent.com"
    )
    manager.import_client(other.client_json())
    assert KEY_TOKEN not in store.data
    assert google.revoked  # old token revoked with the old client's endpoint


def test_remove_client(manager: AuthManager, store: MemorySecretStore) -> None:
    manager.login(AccessLevel.AUDIT)
    manager.remove_client()
    assert store.data == {}


def test_drive_api_disabled_warning(manager: AuthManager, google: FakeGoogle) -> None:
    google.drive_api_enabled = False
    result = manager.login(AccessLevel.AUDIT)
    assert result.account is None
    assert result.warning is not None
    assert "Google Drive API" in result.warning


def test_unchecked_scope_warning(manager: AuthManager, google: FakeGoogle) -> None:
    google.granted_scopes_override = []  # user unticked the Drive checkbox
    result = manager.login(AccessLevel.AUDIT)
    assert result.level is None
    assert result.warning is not None
    with pytest.raises(InsufficientScope):
        manager.credentials(AccessLevel.AUDIT)


# --- CLI --------------------------------------------------------------------------------------


def test_cli_end_to_end(
    google: FakeGoogle,
    store: MemorySecretStore,
    tmp_path: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pathlib import Path

    from dpg.cli.main import main
    from dpg.core.net_guard import global_guard

    def factory() -> AuthManager:
        return AuthManager(store, http_factory=google.http, open_browser=google.browser)

    src = Path(str(tmp_path)) / "client_secret_test.json"
    src.write_text(google.client_json(), encoding="utf-8")
    try:
        assert main(["client", "import", str(src)], manager_factory=factory) == 0
        assert "원본 JSON 파일을 삭제" in capsys.readouterr().out
        assert main(["status"], manager_factory=factory) == 1
        assert main(["login", "--level", "audit"], manager_factory=factory) == 0
        out = capsys.readouterr().out
        assert google.email in out
        assert main(["status", "--check"], manager_factory=factory) == 0
        assert "연결 확인 완료" in capsys.readouterr().out
        assert main(["login", "--level", "detect"], manager_factory=factory) == 0
        assert "추가 권한" in capsys.readouterr().out
        assert main(["logout"], manager_factory=factory) == 0
        assert "철회" in capsys.readouterr().out
        google.expire_all_refresh_tokens()
        assert main(["status", "--check"], manager_factory=factory) == 1  # logged out
        assert main(["client", "remove"], manager_factory=factory) == 0
        assert main(["login"], manager_factory=factory) == 2
        assert "클라이언트가 설정되지 않았습니다" in capsys.readouterr().err
    finally:
        global_guard().uninstall()
