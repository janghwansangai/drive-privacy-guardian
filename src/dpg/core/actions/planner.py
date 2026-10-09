"""Build a change plan from audit results (SPEC 6.2 steps 1–2). Pure: no API calls.

Only permissions granted *directly* on an item are ever planned. Owner permissions, inherited
permissions, "inherited (likely)" and origin-unknown permissions, and limited-access
(`view=metadata`) entries are skipped with a Korean explanation.
"""

from __future__ import annotations

from collections.abc import Iterable

from dpg.core.actions.model import ActionKind, Change, Op, Plan, Skip
from dpg.core.audit.model import EDIT_ROLES, ROLE_LABEL_KO, FileAudit, ItemStatus, Origin
from dpg.core.audit.model import PermissionView as PV

MAX_FILES_PER_RUN = 500  # SPEC 5.6 "배치 한도"
CONFIRM_THRESHOLD = 50  # SPEC 6.2: more files than this => type a confirmation phrase
CONFIRM_PHRASE = "권한 변경 확인"

_PERM_KINDS = {
    ActionKind.REMOVE_LINK,
    ActionKind.LINK_TO_VIEW,
    ActionKind.REMOVE_EXTERNAL,
    ActionKind.REMOVE_DOMAIN,
    ActionKind.EDITORS_TO_VIEWERS,
    ActionKind.RESTRICT_ALL,
}
_REMOVALS = (ActionKind.REMOVE_LINK, ActionKind.REMOVE_DOMAIN, ActionKind.REMOVE_EXTERNAL)


def _who(p: PV) -> str:
    if p.type == "anyone":
        return "링크가 있는 모든 사용자"
    if p.type == "domain":
        return f"도메인 {p.domain}"
    return p.email or "(알 수 없는 계정)"


def _before(p: PV) -> dict[str, object]:
    out: dict[str, object] = {"id": p.perm_id, "type": p.type, "role": p.role}
    if p.email:
        out["emailAddress"] = p.email
    if p.domain:
        out["domain"] = p.domain
    if p.type in ("anyone", "domain"):
        out["allowFileDiscovery"] = p.discoverable
    if p.expires:
        out["expirationTime"] = p.expires
    return out


def _removal_text(p: PV) -> str:
    role = ROLE_LABEL_KO.get(p.role, p.role)
    if p.type in ("anyone", "domain"):
        return f"일반 액세스: {_who(p)}({role}) → 제한됨"
    return f"{_who(p)}({role}): 액세스 권한 삭제"


def _email_domain(email: str | None) -> str | None:
    return email.rsplit("@", 1)[1].lower() if email and "@" in email else None


def _targets(kind: ActionKind, a: FileAudit, me: str | None, internal: frozenset[str]) -> list[PV]:
    if kind == ActionKind.RESTRICT_ALL:
        return [p for k in _REMOVALS for p in _targets(k, a, me, internal)]
    live = [p for p in a.permissions if not p.metadata_only and not p.deleted and p.role != "owner"]
    if kind == ActionKind.REMOVE_LINK:
        return [p for p in live if p.type == "anyone"]
    if kind == ActionKind.LINK_TO_VIEW:
        return [p for p in live if p.type == "anyone" and p.role != "reader"]
    if kind == ActionKind.REMOVE_DOMAIN:
        return [p for p in live if p.type == "domain"]
    if kind == ActionKind.REMOVE_EXTERNAL:
        return [
            p
            for p in live
            if p.type in ("user", "group")
            and p.email != me
            and _email_domain(p.email) not in internal
        ]
    if kind == ActionKind.EDITORS_TO_VIEWERS:
        return [
            p
            for p in live
            if p.type in ("user", "group", "domain") and p.email != me and p.role == "writer"
        ]
    return []


def _children(all_items: Iterable[FileAudit]) -> dict[str, int]:
    by_id = {a.file_id: a for a in all_items}
    counts: dict[str, int] = {}
    for a in by_id.values():
        seen: set[str] = set()
        cur = a.parent_id
        while cur and cur in by_id and cur not in seen:
            seen.add(cur)
            counts[cur] = counts.get(cur, 0) + 1
            cur = by_id[cur].parent_id
    return counts


def build_plan(
    kind: ActionKind,
    selected: Iterable[FileAudit],
    *,
    account: str | None,
    internal_domains: frozenset[str],
    all_items: Iterable[FileAudit] = (),
) -> Plan:
    kind = ActionKind(kind)  # UI widgets may hand back the plain string value
    me = account.lower() if account else None
    plan = Plan(kind)
    children = _children(all_items)
    for a in selected:
        if a.status is not ItemStatus.OK:
            plan.skipped.append(Skip(a.file_id, "공유 설정을 볼 권한이 없어 바꿀 수 없음"))
            continue
        if a.is_folder and children.get(a.file_id):
            plan.folder_children[a.file_id] = children[a.file_id]
        if kind in _PERM_KINDS:
            _plan_permissions(kind, a, me, internal_domains, plan)
        elif kind == ActionKind.DISABLE_RESHARE:
            if a.drive_id is not None:
                plan.skipped.append(Skip(a.file_id, "공유 드라이브는 드라이브 설정에서 관리됨"))
            elif not a.owned_by_me:
                plan.skipped.append(Skip(a.file_id, "소유자만 바꿀 수 있음"))
            elif a.writers_can_share is False:
                plan.skipped.append(Skip(a.file_id, "이미 재공유 금지"))
            else:
                plan.changes.append(
                    Change(
                        a.file_id,
                        Op.UPDATE_FILE,
                        None,
                        {"writersCanShare": True},
                        {"writersCanShare": False},
                        "설정 ⚙ '편집자가 권한을 변경하고 공유할 수 있음': 켜짐 → 꺼짐",
                    )
                )
        elif kind == ActionKind.RESTRICT_DOWNLOAD:
            if a.is_folder:
                plan.skipped.append(Skip(a.file_id, "폴더에는 적용되지 않음"))
            elif a.drive_id is not None or not a.owned_by_me:
                plan.skipped.append(
                    Skip(a.file_id, "소유자(공유 드라이브는 관리자)만 바꿀 수 있음")
                )
            elif a.download_restricted:
                plan.skipped.append(Skip(a.file_id, "이미 제한됨"))
            else:
                off = {"restrictedForReaders": False, "restrictedForWriters": False}
                on = {"restrictedForReaders": True, "restrictedForWriters": False}
                plan.changes.append(
                    Change(
                        a.file_id,
                        Op.UPDATE_FILE,
                        None,
                        {"downloadRestrictions": {"itemDownloadRestriction": off}},
                        {"downloadRestrictions": {"itemDownloadRestriction": on}},
                        "설정 ⚙ '뷰어 및 댓글 작성자에게 다운로드, 인쇄, 복사 옵션 표시': 켜짐 → 꺼짐",  # noqa: E501 — user-facing Korean text
                    )
                )
    return plan


def _plan_permissions(
    kind: ActionKind, a: FileAudit, me: str | None, internal: frozenset[str], plan: Plan
) -> None:
    targets = _targets(kind, a, me, internal)
    if not targets:
        plan.skipped.append(Skip(a.file_id, "해당하는 공유가 없음"))
        return
    for p in targets:
        if p.origin is not Origin.DIRECT:
            where = (
                "상위 폴더"
                if p.origin in (Origin.INHERITED, Origin.INHERITED_LIKELY)
                else "알 수 없는 곳"
            )
            plan.skipped.append(
                Skip(
                    a.file_id,
                    f"{_who(p)} 권한은 {where}에서 온 것이라 여기서 바꾸지 않음 "
                    f"(상위 폴더에서 변경하세요)",
                    (p.inherited_from or a.parent_id) if where == "상위 폴더" else None,
                )
            )
            continue
        if kind in _REMOVALS or kind == ActionKind.RESTRICT_ALL:
            plan.changes.append(
                Change(
                    a.file_id,
                    Op.DELETE_PERM,
                    p.perm_id,
                    _before(p),
                    None,
                    _removal_text(p),
                )
            )
        else:
            new_role = "reader"
            if p.role not in EDIT_ROLES and p.role != "commenter":
                continue
            plan.changes.append(
                Change(
                    a.file_id,
                    Op.UPDATE_PERM,
                    p.perm_id,
                    _before(p),
                    {"role": new_role},
                    f"{_who(p)}: {ROLE_LABEL_KO.get(p.role, p.role)} → {ROLE_LABEL_KO[new_role]}",
                )
            )
