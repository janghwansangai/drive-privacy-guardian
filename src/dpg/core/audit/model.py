"""Audit data model and Korean labels (SPEC 6.1, principle 6)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class ItemStatus(StrEnum):
    OK = "ok"  # 정상 조회
    INSUFFICIENT = "insufficient"  # 권한 부족/정보 불완전 — never shown as "safe"
    FAILED = "failed"  # 조회 실패


class Exposure(IntEnum):
    """Ordered by risk (SPEC 6.1): link+edit > link+view > external > domain > restricted."""

    RESTRICTED = 0
    DOMAIN = 1
    EXTERNAL = 2
    LINK_VIEW = 3
    LINK_EDIT = 4


class Origin(StrEnum):
    DIRECT = "direct"  # 직접 부여
    INHERITED = "inherited"  # 상속 (API가 알려줌: 공유 드라이브)
    INHERITED_LIKELY = "inherited_likely"  # 상위 폴더에서 온 권한 추정 (내 드라이브)
    UNKNOWN = "unknown"


STATUS_LABEL_KO = {
    ItemStatus.OK: "정상 조회",
    ItemStatus.INSUFFICIENT: "권한 부족/정보 불완전",
    ItemStatus.FAILED: "조회 실패",
}
EXPOSURE_LABEL_KO = {
    Exposure.RESTRICTED: "제한됨",
    Exposure.DOMAIN: "도메인 공개",
    Exposure.EXTERNAL: "외부 계정 공유",
    Exposure.LINK_VIEW: "링크 공개(보기)",
    Exposure.LINK_EDIT: "링크 공개(편집)",
}
UNKNOWN_EXPOSURE_LABEL_KO = "알 수 없음"
ORIGIN_LABEL_KO = {
    Origin.DIRECT: "직접",
    Origin.INHERITED: "상속",
    Origin.INHERITED_LIKELY: "상위 폴더에서 온 권한 추정",
    Origin.UNKNOWN: "알 수 없음",
}
ROLE_LABEL_KO = {
    "owner": "소유자",
    "organizer": "관리자",
    "fileOrganizer": "콘텐츠 관리자",
    "writer": "편집자",
    "commenter": "댓글 작성자",
    "reader": "뷰어",
}

EDIT_ROLES = frozenset({"owner", "organizer", "fileOrganizer", "writer"})
CONSUMER_DOMAINS = frozenset({"gmail.com", "googlemail.com"})


@dataclass(frozen=True)
class PermissionView:
    perm_id: str
    type: str  # user | group | domain | anyone
    role: str
    email: str | None
    domain: str | None
    discoverable: bool
    origin: Origin
    inherited_from: str | None
    metadata_only: bool  # limited-access entry: can see, cannot open (V5)
    deleted: bool
    expires: str | None


@dataclass
class FileAudit:
    file_id: str
    name: str
    mime_type: str
    is_folder: bool
    drive_id: str | None
    parent_id: str | None
    owner_email: str | None
    owned_by_me: bool | None
    modified_time: str | None
    status: ItemStatus
    exposure: Exposure | None  # None = unknown (never treated as safe)
    risk_score: int | None
    link_role: str | None = None
    link_discoverable: bool = False
    domain_shares: list[tuple[str, str]] = field(default_factory=list)  # (domain, role)
    external_accounts: list[tuple[str, str]] = field(default_factory=list)  # (email, role)
    internal_accounts: int = 0
    editor_count: int = 0
    writers_can_share: bool | None = None
    download_restricted: bool | None = None
    limited_access_folder: bool = False
    permissions: list[PermissionView] = field(default_factory=list)
    error_code: str | None = None
    notes: list[str] = field(default_factory=list)
    size: int | None = None  # bytes; None for Google Docs types
    md5: str | None = None  # md5Checksum (binary files only) — duplicate detection (SPEC 6.6)

    @property
    def origins(self) -> set[Origin]:
        return {p.origin for p in self.permissions if p.role != "owner"}
