"""Staged OAuth scopes (SPEC 5.3)."""

from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum

SCOPE_METADATA_READONLY = "https://www.googleapis.com/auth/drive.metadata.readonly"
SCOPE_READONLY = "https://www.googleapis.com/auth/drive.readonly"
SCOPE_FULL = "https://www.googleapis.com/auth/drive"


class AccessLevel(IntEnum):
    AUDIT = 1  # 권한 감사 (R1)
    DETECT = 2  # 개인정보 탐지 (R3)
    MODIFY = 3  # 권한 변경·정리·보관 업로드 (R2, R4)


LEVEL_SCOPE = {
    AccessLevel.AUDIT: SCOPE_METADATA_READONLY,
    AccessLevel.DETECT: SCOPE_READONLY,
    AccessLevel.MODIFY: SCOPE_FULL,
}

LEVEL_LABEL_KO = {
    AccessLevel.AUDIT: "권한 감사 (파일 목록·공유 설정 읽기)",
    AccessLevel.DETECT: "개인정보 탐지 (파일 내용 읽기)",
    AccessLevel.MODIFY: "권한 변경·정리 (공유 설정 변경, 보관 파일 업로드)",
}

LEVEL_EXPLAIN_KO = {
    AccessLevel.AUDIT: (
        "드라이브 파일의 이름·공유 설정 같은 정보만 읽습니다. "
        "파일 내용은 읽지 않고, 아무것도 바꾸지 않습니다."
    ),
    AccessLevel.DETECT: (
        "개인정보를 찾기 위해 파일 내용을 읽습니다. "
        "내용은 이 컴퓨터의 메모리에서만 검사하며 저장하거나 전송하지 않습니다. "
        "아무것도 바꾸지 않습니다."
    ),
    AccessLevel.MODIFY: (
        "공유 설정을 바꾸고 암호화 보관 파일을 올릴 수 있는 권한입니다. "
        "모든 변경은 미리보기와 승인 후에만 실행됩니다."
    ),
}

# Broader scopes imply narrower ones.
_IMPLIES = {
    SCOPE_FULL: AccessLevel.MODIFY,
    SCOPE_READONLY: AccessLevel.DETECT,
    SCOPE_METADATA_READONLY: AccessLevel.AUDIT,
}


def granted_level(scopes: Iterable[str]) -> AccessLevel | None:
    levels = [_IMPLIES[s] for s in scopes if s in _IMPLIES]
    return max(levels) if levels else None


def satisfies(scopes: Iterable[str], required: AccessLevel) -> bool:
    level = granted_level(scopes)
    return level is not None and level >= required


def parse_level(name: str) -> AccessLevel:
    try:
        return AccessLevel[name.upper()]
    except KeyError:
        raise ValueError(f"unknown access level: {name}") from None
