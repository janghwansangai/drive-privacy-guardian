"""BYO OAuth client loading, staged scopes, keyring token storage (SPEC 3.1, 5.3)."""

from dpg.core.auth.errors import AuthError, InsufficientScope, NotLoggedIn, ReauthRequired
from dpg.core.auth.manager import AuthManager, AuthStatus, LoginResult, LogoutResult
from dpg.core.auth.scopes import AccessLevel

__all__ = [
    "AccessLevel",
    "AuthError",
    "AuthManager",
    "AuthStatus",
    "InsufficientScope",
    "LoginResult",
    "LogoutResult",
    "NotLoggedIn",
    "ReauthRequired",
]
