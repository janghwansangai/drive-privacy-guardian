"""Auth lifecycle: client import, login, staged scopes, token refresh, logout/revoke.

Secrets live only in the SecretStore (OS keyring). The access token is kept in memory only;
the keyring holds the refresh token, granted scopes, account e-mail and owning client ID.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import google.auth.exceptions
import google_auth_httplib2
import httplib2
from google.oauth2.credentials import Credentials

from dpg.core.auth.client import ClientConfig, parse_client_json
from dpg.core.auth.errors import (
    AuthError,
    InsufficientScope,
    NetworkError,
    NoClientConfigured,
    NotLoggedIn,
    ReauthRequired,
)
from dpg.core.auth.loopback import TOKEN_URI, LoopbackLogin, TokenResult, revoke_token
from dpg.core.auth.scopes import LEVEL_SCOPE, AccessLevel, granted_level, satisfies
from dpg.core.auth.secret_store import KEY_CLIENT, KEY_TOKEN, SecretStore
from dpg.core.logging import get_logger
from dpg.core.net_guard.http import GuardedHttp

log = get_logger("auth")

ABOUT_URI = "https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)"
MANUAL_REVOKE_URL = "https://myaccount.google.com/connections"


@dataclass(frozen=True)
class AuthStatus:
    client_configured: bool
    client_display_id: str | None
    logged_in: bool
    account: str | None
    level: AccessLevel | None


@dataclass(frozen=True)
class LoginResult:
    account: str | None
    level: AccessLevel | None
    requested: AccessLevel
    warning: str | None = None


@dataclass(frozen=True)
class LogoutResult:
    had_token: bool
    revoked: bool  # False if the remote revocation failed (local copy is deleted regardless)


@dataclass
class _StoredToken:
    refresh_token: str
    scopes: list[str]
    account: str | None
    client_id: str

    def dumps(self) -> str:
        return json.dumps(
            {
                "v": 1,
                "refresh_token": self.refresh_token,
                "scopes": self.scopes,
                "account": self.account,
                "client_id": self.client_id,
            },
            separators=(",", ":"),
        )

    @classmethod
    def loads(cls, raw: str) -> _StoredToken:
        d = json.loads(raw)
        return cls(d["refresh_token"], list(d["scopes"]), d.get("account"), d["client_id"])


def is_invalid_grant(exc: BaseException) -> bool:
    if not isinstance(exc, google.auth.exceptions.RefreshError):
        return False
    for arg in exc.args:
        if isinstance(arg, dict) and arg.get("error") == "invalid_grant":
            return True
    return "invalid_grant" in str(exc)


class AuthManager:
    def __init__(
        self,
        store: SecretStore,
        http_factory: Callable[[], httplib2.Http] = GuardedHttp,
        open_browser: Callable[[str], bool] = webbrowser.open,
    ) -> None:
        self._store = store
        self._http_factory = http_factory
        self._open_browser = open_browser
        self._creds: Credentials | None = None

    @property
    def secret_store(self) -> SecretStore:
        """The OS keychain wrapper (also holds the local DB encryption key)."""
        return self._store

    # -- client ---------------------------------------------------------------------------------

    def client(self) -> ClientConfig | None:
        raw = self._store.get(KEY_CLIENT)
        return ClientConfig.from_stored(raw) if raw else None

    def import_client(self, raw: bytes | str) -> ClientConfig:
        config = parse_client_json(raw)
        current = self.client()
        if current is not None and current.client_id != config.client_id:
            self.logout()  # tokens belong to the old client
        self._store.set(KEY_CLIENT, config.to_stored())
        log.info("client imported project=%s", config.project_id)
        return config

    def remove_client(self) -> LogoutResult:
        result = self.logout()
        self._store.delete(KEY_CLIENT)
        log.info("client removed")
        return result

    def _require_client(self) -> ClientConfig:
        config = self.client()
        if config is None:
            raise NoClientConfigured()
        return config

    # -- token storage --------------------------------------------------------------------------

    def _stored_token(self) -> _StoredToken | None:
        raw = self._store.get(KEY_TOKEN)
        if not raw:
            return None
        try:
            token = _StoredToken.loads(raw)
        except (ValueError, KeyError, TypeError):
            self._store.delete(KEY_TOKEN)
            return None
        config = self.client()
        if config is None or config.client_id != token.client_id:
            return None
        return token

    def status(self) -> AuthStatus:
        config = self.client()
        token = self._stored_token()
        return AuthStatus(
            client_configured=config is not None,
            client_display_id=config.display_id if config else None,
            logged_in=token is not None,
            account=token.account if token else None,
            level=granted_level(token.scopes) if token else None,
        )

    # -- login / logout -------------------------------------------------------------------------

    def login(
        self,
        level: AccessLevel,
        *,
        on_url: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
        timeout: float = 300.0,
        open_browser: Callable[[str], bool] | None = None,
    ) -> LoginResult:
        config = self._require_client()
        flow = LoopbackLogin(
            config,
            [LEVEL_SCOPE[level]],
            self._http_factory,
            open_browser or self._open_browser,
            timeout=timeout,
            on_url=on_url,
            cancel=cancel,
        )
        result = flow.run()
        previous = self._stored_token()
        refresh = result.refresh_token or (previous.refresh_token if previous else None)
        if refresh is None:
            raise AuthError("구글이 로그인 유지 정보를 보내지 않았습니다. 다시 로그인해 주세요.")

        creds = self._make_credentials(config, refresh, list(result.scopes), result)
        account, warning = self._fetch_account(creds)
        self._store.set(
            KEY_TOKEN, _StoredToken(refresh, list(result.scopes), account, config.client_id).dumps()
        )
        self._creds = creds
        got = granted_level(result.scopes)
        if got is None or got < level:
            warning = (
                "요청한 권한 중 일부가 허용되지 않았습니다. "
                "구글 로그인 화면에서 모든 항목을 체크해 주세요."
            )
        log.info("login ok level=%s", got.name if got else None)
        return LoginResult(account=account, level=got, requested=level, warning=warning)

    def logout(self) -> LogoutResult:
        """Revoke the refresh token remotely (best effort) and always delete it locally."""
        raw = self._store.get(KEY_TOKEN)
        self._creds = None
        if not raw:
            return LogoutResult(had_token=False, revoked=False)
        revoked = False
        try:
            token = _StoredToken.loads(raw)
            revoked = revoke_token(self._http_factory(), token.refresh_token)
        except (ValueError, KeyError, TypeError):
            pass
        finally:
            self._store.delete(KEY_TOKEN)
        log.info("logout revoked=%s", revoked)
        return LogoutResult(had_token=True, revoked=revoked)

    # -- credentials for API use ----------------------------------------------------------------

    def _make_credentials(
        self,
        config: ClientConfig,
        refresh: str,
        scopes: list[str],
        fresh: TokenResult | None = None,
    ) -> Credentials:
        token = expiry = None
        if fresh is not None:
            token = fresh.access_token
            # google-auth compares against naive UTC datetimes
            expiry = dt.datetime.now(dt.UTC).replace(tzinfo=None) + dt.timedelta(
                seconds=max(0, fresh.expires_in - 60)
            )
        return Credentials(
            token=token,
            refresh_token=refresh,
            token_uri=TOKEN_URI,
            client_id=config.client_id,
            client_secret=config.client_secret,
            scopes=scopes,
            expiry=expiry,
        )

    def credentials(self, required: AccessLevel) -> Credentials:
        """Valid credentials with at least `required` access, refreshing if needed.

        Raises NotLoggedIn, InsufficientScope, ReauthRequired (token expired/revoked — the
        stored token is deleted) or NetworkError.
        """
        config = self._require_client()
        token = self._stored_token()
        if token is None:
            raise NotLoggedIn()
        if not satisfies(token.scopes, required):
            raise InsufficientScope()
        creds = self._creds
        if creds is None or creds.refresh_token != token.refresh_token:
            creds = self._make_credentials(config, token.refresh_token, token.scopes)
        if not creds.valid:
            self.refresh(creds)
        self._creds = creds
        return creds

    def refresh(self, creds: Credentials) -> None:
        try:
            creds.refresh(google_auth_httplib2.Request(self._http_factory()))
        except google.auth.exceptions.RefreshError as exc:
            if is_invalid_grant(exc):
                self._store.delete(KEY_TOKEN)
                self._creds = None
                log.info("refresh rejected: invalid_grant")
                raise ReauthRequired() from None
            raise AuthError(
                "로그인 정보를 갱신하지 못했습니다. 잠시 후 다시 시도해 주세요."
            ) from None
        except google.auth.exceptions.TransportError:
            raise NetworkError() from None
        stored = self._stored_token()
        if stored and creds.refresh_token and creds.refresh_token != stored.refresh_token:
            stored.refresh_token = creds.refresh_token
            self._store.set(KEY_TOKEN, stored.dumps())

    def authorized_http(self, required: AccessLevel) -> google_auth_httplib2.AuthorizedHttp:
        return google_auth_httplib2.AuthorizedHttp(
            self.credentials(required), http=self._http_factory()
        )

    def verify(self) -> str | None:
        """Refresh the token and call the Drive API once. Returns the account e-mail."""
        creds = self.credentials(AccessLevel.AUDIT)
        self.refresh(creds)
        account, warning = self._fetch_account(creds)
        if warning:
            raise AuthError(warning)
        return account

    def _fetch_account(self, creds: Credentials) -> tuple[str | None, str | None]:
        http = google_auth_httplib2.AuthorizedHttp(creds, http=self._http_factory())
        try:
            response, content = http.request(ABOUT_URI, "GET")
        except google.auth.exceptions.RefreshError as exc:
            if is_invalid_grant(exc):
                raise ReauthRequired() from None
            raise AuthError("로그인 정보를 갱신하지 못했습니다.") from None
        except (OSError, httplib2.HttpLib2Error, google.auth.exceptions.TransportError):
            return (
                None,
                "로그인은 되었지만 구글 드라이브에 연결하지 못했습니다. "
                "인터넷 연결을 확인해 주세요.",
            )
        body: Any
        try:
            body = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = {}
        if int(response.status) == 200:
            email = body.get("user", {}).get("emailAddress") if isinstance(body, dict) else None
            return (str(email) if email else None), None
        reason = _error_reason(body)
        log.info("about.get failed status=%s reason=%s", response.status, reason)
        if reason in ("accessNotConfigured", "SERVICE_DISABLED"):
            return None, (
                "구글 클라우드 프로젝트에서 'Google Drive API'가 사용 설정되지 않았습니다. "
                "설정 안내서의 'Drive API 사용 설정' 단계를 진행한 뒤 다시 시도해 주세요."
            )
        return None, f"구글 드라이브 연결 확인에 실패했습니다 (HTTP {response.status}, {reason})."


def _error_reason(body: Any) -> str:
    if not isinstance(body, dict):
        return "unknown"
    err = body.get("error", {})
    if not isinstance(err, dict):
        return str(err)[:64]
    for item in err.get("errors", []) or []:
        if isinstance(item, dict) and item.get("reason"):
            return str(item["reason"])[:64]
    for detail in err.get("details", []) or []:
        if isinstance(detail, dict) and detail.get("reason"):
            return str(detail["reason"])[:64]
    return str(err.get("status", "unknown"))[:64]
