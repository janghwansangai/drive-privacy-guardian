"""The common password of standard-ZIP archives (D-107, user decision "내가 정한 공통 비밀번호").

One password the user chooses and keeps (memorised or on paper) opens every standard ZIP the
app makes — with Windows Explorer or macOS alone, even without this app. It lives in the OS
keychain only. When it is changed, the earlier ones are kept (newest first) so archives made
before still open from the app; they are removed by 「모든 기록 삭제 (비밀번호 포함)」.
"""

from __future__ import annotations

import json

from dpg.core.auth.secret_store import SecretStore

COMMON_KEY = "vault:common-password"
COMMON_OLD_KEY = "vault:common-passwords-old"
MAX_OLD = 20


def current(secrets: SecretStore) -> str | None:
    return secrets.get(COMMON_KEY) or None


def older(secrets: SecretStore) -> list[str]:
    try:
        data = json.loads(secrets.get(COMMON_OLD_KEY) or "[]")
    except ValueError:
        return []
    return [str(p) for p in data] if isinstance(data, list) else []


def all_passwords(secrets: SecretStore) -> list[str]:
    """Current first, then the earlier ones: the order to try them in when opening."""
    now = current(secrets)
    return [p for p in [now, *older(secrets)] if p]


def set_current(secrets: SecretStore, password: str) -> None:
    previous = current(secrets)
    if previous and previous != password:
        kept = [previous, *[p for p in older(secrets) if p not in (previous, password)]]
        secrets.set(COMMON_OLD_KEY, json.dumps(kept[:MAX_OLD]))
    secrets.set(COMMON_KEY, password)


def forget(secrets: SecretStore) -> bool:
    had = bool(current(secrets) or older(secrets))
    secrets.delete(COMMON_KEY)
    secrets.delete(COMMON_OLD_KEY)
    return had
