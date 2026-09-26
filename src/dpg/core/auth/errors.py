"""Auth errors. Each carries a Korean message safe to show the user (never secrets)."""

from __future__ import annotations


class AuthError(Exception):
    user_message = "인증 중 문제가 발생했습니다."

    def __init__(self, user_message: str | None = None) -> None:
        if user_message is not None:
            self.user_message = user_message
        super().__init__(self.user_message)


class ClientConfigError(AuthError):
    user_message = "OAuth 클라이언트 파일을 확인해 주세요."


class NoClientConfigured(AuthError):
    user_message = (
        "OAuth 클라이언트가 설정되지 않았습니다. 먼저 클라이언트 JSON 파일을 불러와 주세요 "
        "(docs/SETUP_GOOGLE_KO.md 참고)."
    )


class NotLoggedIn(AuthError):
    user_message = "로그인되어 있지 않습니다. 먼저 로그인해 주세요."


class ReauthRequired(AuthError):
    """Refresh token expired or revoked (e.g. `invalid_grant`, 7-day testing expiry)."""

    user_message = "로그인이 만료되었습니다. 다시 로그인해 주세요."


class InsufficientScope(AuthError):
    user_message = (
        "이 기능에는 추가 권한이 필요합니다. 권한을 추가로 허용하려면 다시 로그인해 주세요."
    )


class LoginCancelled(AuthError):
    user_message = "로그인이 취소되었습니다."


class LoginTimeout(AuthError):
    user_message = "로그인 시간이 초과되었습니다. 다시 시도해 주세요."


class InsecureSecretStore(AuthError):
    user_message = (
        "안전한 비밀 저장소(macOS 키체인 / Windows 자격 증명 관리자)를 사용할 수 없어 "
        "로그인 정보를 저장하지 않습니다."
    )


class NetworkError(AuthError):
    user_message = "구글 서버에 연결할 수 없습니다. 인터넷 연결을 확인해 주세요."
