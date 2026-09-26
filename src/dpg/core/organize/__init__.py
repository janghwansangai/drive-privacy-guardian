"""File organisation (SPEC 6.6): category suggestions, duplicate candidates, safe moves.

Pure functions over audit/detection results — no API calls. Moves are only *planned* here
and executed through `dpg.core.actions` (preview → re-check → execute → verify → undo).
"""

from __future__ import annotations

import dataclasses
import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from dpg.core.actions.model import ActionKind, Change, Op, Plan, Skip
from dpg.core.audit.model import Exposure, FileAudit, ItemStatus, Origin, PermissionView
from dpg.core.policy import DetectStatus, FileDetection

ARCHIVE_AFTER_DAYS = 180  # 업무 종료로 보는 기준 (수정 없음)
DISPOSAL_REVIEW_AFTER_DAYS = 3 * 365

_ROLE_RANK = {
    "reader": 1,
    "commenter": 2,
    "writer": 3,
    "fileOrganizer": 4,
    "organizer": 5,
    "owner": 6,
}


class Category(StrEnum):
    GENERAL = "general"
    INTERNAL = "internal"
    PROTECT = "protect"
    ARCHIVE = "archive"
    DISPOSAL = "disposal"


CATEGORY_LABEL_KO = {
    Category.GENERAL: "일반",
    Category.INTERNAL: "내부공유",
    Category.PROTECT: "개인정보보호",
    Category.ARCHIVE: "암호화보관",
    Category.DISPOSAL: "파기검토",
}


@dataclass(frozen=True)
class Suggestion:
    category: Category | None  # None = 보류 (unknown is never "일반")
    reason: str


def _age_days(modified: str | None, now: dt.datetime) -> int | None:
    if not modified:
        return None
    try:
        return (now - dt.datetime.fromisoformat(modified.replace("Z", "+00:00"))).days
    except ValueError:
        return None


def suggest(
    audit: FileAudit, det: FileDetection | None, now: dt.datetime | None = None
) -> Suggestion:
    """A suggestion only — nothing is moved without a separate, approved plan."""
    now = now or dt.datetime.now(dt.UTC)
    if audit.is_folder:
        return Suggestion(None, "폴더는 분류하지 않음")
    if audit.status is not ItemStatus.OK:
        return Suggestion(None, "공유 정보를 모두 확인하지 못해 분류 보류")
    if det is None:
        return Suggestion(None, "개인정보 탐지를 하지 않아 분류 보류")
    if det.status in (DetectStatus.UNSCANNABLE, DetectStatus.FAILED) or det.partial:
        return Suggestion(None, "내용을 모두 검사하지 못해 분류 보류 (직접 확인 필요)")
    age = _age_days(audit.modified_time, now)
    if det.status is DetectStatus.DETECTED:
        if age is not None and age >= DISPOSAL_REVIEW_AFTER_DAYS:
            return Suggestion(
                Category.DISPOSAL,
                f"개인정보 포함 · {age // 365}년 넘게 수정 없음 — 보존 기한 지났는지 확인",
            )
        if (det.high_sensitivity or "student_roster" in det.kinds) and (
            age is not None and age >= ARCHIVE_AFTER_DAYS
        ):
            return Suggestion(
                Category.ARCHIVE, f"고위험 개인정보 · {age}일 수정 없음 — 업무 종료 문서로 보임"
            )
        return Suggestion(Category.PROTECT, "개인정보 포함 — 공유 범위를 최소로 유지")
    if det.status is DetectStatus.SUSPECT:
        return Suggestion(Category.PROTECT, "개인정보 의심 — 확인 전까지 보호 대상으로 취급")
    if audit.exposure is Exposure.DOMAIN or audit.internal_accounts:
        return Suggestion(Category.INTERNAL, "학교(도메인) 안에서만 공유")
    return Suggestion(Category.GENERAL, "개인정보가 발견되지 않음(지원 범위 내)")


# -- duplicates ---------------------------------------------------------------------------------


def duplicate_groups(items: Iterable[FileAudit]) -> list[list[FileAudit]]:
    """Same size + same md5Checksum (never by name). Google Docs have no checksum: excluded.

    Only a "중복 후보" marker — nothing is deleted.
    """
    groups: dict[tuple[int, str], list[FileAudit]] = {}
    for a in items:
        if a.is_folder or a.md5 is None or a.size is None:
            continue
        groups.setdefault((a.size, a.md5), []).append(a)
    out = [sorted(g, key=lambda a: (a.modified_time or "", a.name)) for g in groups.values()]
    return sorted((g for g in out if len(g) > 1), key=lambda g: -(g[0].size or 0))


# -- moves --------------------------------------------------------------------------------------


def _principal(p: PermissionView) -> tuple[str, str] | None:
    if p.deleted or p.role == "owner":
        return None
    if p.type == "anyone":
        return ("anyone", "")
    if p.type == "domain":
        return ("domain", (p.domain or "").lower())
    return (p.type, (p.email or "").lower())


def _access(perms: Iterable[PermissionView]) -> dict[tuple[str, str], int]:
    out: dict[tuple[str, str], int] = {}
    for p in perms:
        key = _principal(p)
        if key is None:
            continue
        out[key] = max(out.get(key, 0), _ROLE_RANK.get(p.role, 0))
    return out


def widening(item: FileAudit, dest: FileAudit) -> list[str]:
    """Who would gain (or gain more) access if `item` were moved into `dest` (Korean lines).

    Everything shared on the destination folder is inherited by what goes in it.
    """
    now = _access(item.permissions)
    lines = []
    for key, rank in sorted(_access(dest.permissions).items()):
        if now.get(key, 0) >= rank:
            continue
        kind, who = key
        label = {
            "anyone": "링크가 있는 모든 사용자",
            "domain": f"도메인 {who} 전체",
        }.get(kind, "다른 계정")
        lines.append(label if key not in now else f"{label}(권한 상승)")
    return lines


def build_move_plan(
    items: Iterable[FileAudit], dest: FileAudit, all_items: Iterable[FileAudit]
) -> Plan:
    """Plan moves into `dest`, blocking any move that would widen who can see the file."""
    plan = Plan(ActionKind.MOVE)
    by_id = {a.file_id: a for a in all_items}
    for a in items:
        if dest.status is not ItemStatus.OK or dest.exposure is None:
            plan.skipped.append(Skip(a.file_id, "목적지 폴더의 공유 상태를 확인하지 못해 차단"))
            continue
        if not dest.is_folder:
            plan.skipped.append(Skip(a.file_id, "목적지가 폴더가 아님"))
            continue
        if a.status is not ItemStatus.OK:
            plan.skipped.append(Skip(a.file_id, "공유 정보를 확인하지 못해 이동하지 않음"))
            continue
        if a.drive_id is not None or dest.drive_id is not None:
            plan.skipped.append(Skip(a.file_id, "공유 드라이브 이동은 지원하지 않음"))
            continue
        if not a.owned_by_me:
            plan.skipped.append(Skip(a.file_id, "내 소유가 아니라 이동하지 않음"))
            continue
        if a.parent_id is None:
            plan.skipped.append(Skip(a.file_id, "현재 위치를 알 수 없음"))
            continue
        if a.parent_id == dest.file_id:
            plan.skipped.append(Skip(a.file_id, "이미 그 폴더에 있음"))
            continue
        if a.file_id == dest.file_id or _is_ancestor(a.file_id, dest, by_id):
            plan.skipped.append(Skip(a.file_id, "폴더를 자기 안으로 옮길 수 없음"))
            continue
        wider = widening(a, dest)
        if wider:
            plan.skipped.append(
                Skip(
                    a.file_id,
                    "⚠ 차단: 목적지 폴더가 더 넓게 공유되어 있어 옮기면 볼 수 있는 사람이 늘어남 ("
                    + ", ".join(dict.fromkeys(wider))
                    + ")",
                )
            )
            continue
        plan.changes.append(
            Change(
                a.file_id,
                Op.MOVE,
                None,
                {"parent": a.parent_id},
                {"parent": dest.file_id},
                f"'{by_id[a.parent_id].name if a.parent_id in by_id else '현재 폴더'}' → "
                f"'{dest.name}'",
            )
        )
    return plan


def _is_ancestor(folder_id: str, item: FileAudit, by_id: dict[str, FileAudit]) -> bool:
    seen: set[str] = set()
    cur = item.parent_id
    while cur is not None and cur not in seen:
        if cur == folder_id:
            return True
        seen.add(cur)
        parent = by_id.get(cur)
        cur = parent.parent_id if parent else None
    return False


def new_folder_audit(folder_id: str, name: str, parent: FileAudit) -> FileAudit:
    """Audit view of a folder just created inside `parent`: it has exactly the parent's
    sharing (inherited), so the widening check for moves into it stays correct."""
    inherited = [
        dataclasses.replace(p, origin=Origin.INHERITED_LIKELY, inherited_from=parent.file_id)
        for p in parent.permissions
        if not p.deleted
    ]
    return FileAudit(
        file_id=folder_id,
        name=name,
        mime_type="application/vnd.google-apps.folder",
        is_folder=True,
        drive_id=parent.drive_id,
        parent_id=parent.file_id,
        owner_email=parent.owner_email,
        owned_by_me=True,
        modified_time=None,
        status=ItemStatus.OK,
        exposure=parent.exposure,
        risk_score=parent.risk_score,
        link_role=parent.link_role,
        domain_shares=list(parent.domain_shares),
        external_accounts=list(parent.external_accounts),
        internal_accounts=parent.internal_accounts,
        permissions=inherited,
    )
