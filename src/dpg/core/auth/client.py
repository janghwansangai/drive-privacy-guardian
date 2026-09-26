"""BYO OAuth client JSON loading and validation (SPEC 3.1).

Only the fields we need are kept; endpoint URLs in the file are validated but never used —
the app always talks to the hard-coded Google endpoints.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from dpg.core.auth.errors import ClientConfigError

MAX_CLIENT_JSON_BYTES = 64 * 1024
_CLIENT_ID_RE = re.compile(r"^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$")
_EXPECTED_URIS = {
    "auth_uri": {
        "https://accounts.google.com/o/oauth2/auth",
        "https://accounts.google.com/o/oauth2/v2/auth",
    },
    "token_uri": {
        "https://oauth2.googleapis.com/token",
        "https://accounts.google.com/o/oauth2/token",
    },
}


@dataclass(frozen=True)
class ClientConfig:
    client_id: str
    client_secret: str
    project_id: str | None = None

    def to_stored(self) -> str:
        return json.dumps(
            {
                "v": 1,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "project_id": self.project_id,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_stored(cls, raw: str) -> ClientConfig:
        data = json.loads(raw)
        return cls(data["client_id"], data["client_secret"], data.get("project_id"))

    @property
    def display_id(self) -> str:
        """Shortened client ID for screens and logs (the full ID is not secret, just noisy)."""
        return self.client_id.split("-", 1)[0][:6] + "…" + ".apps.googleusercontent.com"

    def __repr__(self) -> str:  # never print the secret
        return f"ClientConfig(client_id={self.display_id!r}, project_id={self.project_id!r})"


def parse_client_json(raw: bytes | str) -> ClientConfig:
    if isinstance(raw, bytes):
        if len(raw) > MAX_CLIENT_JSON_BYTES:
            raise ClientConfigError(
                "파일이 너무 큽니다. 구글에서 받은 클라이언트 JSON 파일이 맞는지 확인해 주세요."
            )
        try:
            raw = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ClientConfigError("JSON 파일이 아닙니다.") from None
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError:
        raise ClientConfigError(
            "JSON 형식이 아닙니다. 구글에서 받은 파일을 그대로 선택해 주세요."
        ) from None
    if not isinstance(data, dict):
        raise ClientConfigError("클라이언트 JSON 형식이 아닙니다.")

    if data.get("type") == "service_account":
        # Principle 5: service accounts are never used. The file is a powerful key.
        raise ClientConfigError(
            "서비스 계정 키 파일입니다. 이 앱은 서비스 계정을 사용하지 않습니다. "
            "이 파일은 매우 민감하므로 안전하게 삭제하고, "
            "'OAuth 클라이언트 ID(데스크톱 앱)'를 새로 만들어 주세요."
        )
    if "web" in data:
        raise ClientConfigError(
            "'웹 애플리케이션' 유형의 클라이언트입니다. "
            "클라이언트 유형을 '데스크톱 앱'으로 다시 만들어 주세요."
        )
    installed = data.get("installed")
    if not isinstance(installed, dict):
        raise ClientConfigError(
            "'데스크톱 앱' 유형의 OAuth 클라이언트 JSON이 아닙니다 (installed 항목 없음)."
        )

    client_id = installed.get("client_id")
    client_secret = installed.get("client_secret")
    if not isinstance(client_id, str) or not _CLIENT_ID_RE.match(client_id):
        raise ClientConfigError("client_id 형식이 올바르지 않습니다.")
    if not isinstance(client_secret, str) or not client_secret.strip():
        raise ClientConfigError("client_secret 항목이 없습니다. JSON 파일을 다시 내려받아 주세요.")
    for key, allowed in _EXPECTED_URIS.items():
        value = installed.get(key)
        if value is not None and value not in allowed:
            raise ClientConfigError(
                f"{key} 값이 구글 공식 주소가 아닙니다. "
                f"변조된 파일일 수 있으니 구글 콘솔에서 다시 내려받아 주세요."
            )
    project_id = installed.get("project_id")
    return ClientConfig(
        client_id=client_id,
        client_secret=client_secret.strip(),
        project_id=project_id if isinstance(project_id, str) else None,
    )
