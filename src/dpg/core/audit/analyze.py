"""Pure analysis: raw Drive metadata -> FileAudit (SPEC 6.1). No I/O.

Inputs per item (collected by runner.py):
- `meta`: files.list resource (FILE_FIELDS)
- `perms`: authoritative permission list, or None when unavailable
- `perm_source`: "inline" (files.list `permissions`), "listed" (permissions.list),
  "derived" (shared-drive item without direct permissions: drive members + ancestors),
  "unavailable" (caller cannot see permissions), "error"
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from dpg.core.audit.model import (
    CONSUMER_DOMAINS,
    EDIT_ROLES,
    Exposure,
    FileAudit,
    ItemStatus,
    Origin,
    PermissionView,
)
from dpg.core.drive.client import FOLDER_MIME

BASE_SCORE = {
    Exposure.RESTRICTED: 0,
    Exposure.DOMAIN: 40,
    Exposure.EXTERNAL: 60,
    Exposure.LINK_VIEW: 80,
    Exposure.LINK_EDIT: 95,
}


def internal_domains_for(account: str | None, extra: Iterable[str] = ()) -> frozenset[str]:
    """The account's own domain counts as internal, except consumer domains like gmail.com
    (another gmail user is not a colleague)."""
    domains = {d.lower().strip() for d in extra if d.strip()}
    if account and "@" in account:
        own = account.rsplit("@", 1)[1].lower()
        if own not in CONSUMER_DOMAINS:
            domains.add(own)
    return frozenset(domains)


def _email_domain(email: str | None) -> str | None:
    return email.rsplit("@", 1)[1].lower() if email and "@" in email else None


def permission_view(
    raw: dict[str, Any], origin: Origin, inherited_from: str | None = None
) -> PermissionView:
    return PermissionView(
        perm_id=str(raw.get("id", "")),
        type=str(raw.get("type", "")),
        role=str(raw.get("role", "")),
        email=(str(raw["emailAddress"]).lower() if raw.get("emailAddress") else None),
        domain=(str(raw["domain"]).lower() if raw.get("domain") else None),
        discoverable=bool(raw.get("allowFileDiscovery", False)),
        origin=origin,
        inherited_from=inherited_from,
        metadata_only=raw.get("view") == "metadata",
        deleted=bool(raw.get("deleted", False)),
        expires=raw.get("expirationTime"),
    )


def origin_from_details(raw: dict[str, Any]) -> tuple[Origin, str | None]:
    """Shared drives (and possibly My Drive) report inheritance in permissionDetails (V5)."""
    details = raw.get("permissionDetails")
    if not details:
        return Origin.UNKNOWN, None
    if any(not d.get("inherited", False) for d in details):
        return Origin.DIRECT, None
    source = next((d.get("inheritedFrom") for d in details if d.get("inheritedFrom")), None)
    return Origin.INHERITED, source


def classify(
    file_id: str,
    meta: dict[str, Any],
    perms: list[PermissionView] | None,
    *,
    account: str | None,
    internal: frozenset[str],
    public_hint: str | None = None,  # "anyoneWithLink" / "anyoneCanFind" from visibility query
    status: ItemStatus = ItemStatus.OK,
    error_code: str | None = None,
) -> FileAudit:
    owners = meta.get("owners") or []
    owner_email = next((o.get("emailAddress") for o in owners if o.get("emailAddress")), None)
    dr = (
        (meta.get("downloadRestrictions") or {}).get("effectiveDownloadRestrictionWithContext")
        or (meta.get("downloadRestrictions") or {}).get("itemDownloadRestriction")
        or {}
    )
    download_restricted: bool | None = None
    if "copyRequiresWriterPermission" in meta or dr:
        download_restricted = bool(meta.get("copyRequiresWriterPermission")) or bool(
            dr.get("restrictedForReaders")
        )
    audit = FileAudit(
        file_id=file_id,
        name=str(meta.get("name", "")),
        mime_type=str(meta.get("mimeType", "")),
        is_folder=meta.get("mimeType") == FOLDER_MIME,
        drive_id=meta.get("driveId"),
        parent_id=(meta.get("parents") or [None])[0],
        owner_email=owner_email.lower() if owner_email else None,
        owned_by_me=meta.get("ownedByMe"),
        modified_time=meta.get("modifiedTime"),
        status=status,
        exposure=None,
        risk_score=None,
        writers_can_share=meta.get("writersCanShare"),
        download_restricted=download_restricted,
        limited_access_folder=bool(meta.get("inheritedPermissionsDisabled", False)),
        error_code=error_code,
        size=int(meta["size"]) if str(meta.get("size", "")).isdigit() else None,
        md5=str(meta["md5Checksum"]) if meta.get("md5Checksum") else None,
    )
    if perms is None:
        # Principle 6: unknown is not safe. Use the visibility query as a partial signal.
        if public_hint is not None:
            audit.exposure = Exposure.LINK_VIEW
            audit.link_discoverable = public_hint == "anyoneCanFind"
            audit.risk_score = _score(audit)
            audit.notes.append("링크 공개 확인됨(공개 범위 검색). 링크 권한 수준은 확인하지 못함")
        elif meta.get("shared"):
            audit.notes.append("공유된 파일이지만 공유 대상을 확인할 권한이 없음")
        return audit

    me = account.lower() if account else None
    audit.permissions = perms
    exposure = Exposure.RESTRICTED
    for p in perms:
        if p.metadata_only or p.deleted:
            continue  # limited-access entries grant no content access
        if p.role in EDIT_ROLES and p.role != "owner" and p.type != "anyone":
            audit.editor_count += 1
        if p.type == "anyone":
            level = Exposure.LINK_EDIT if p.role in EDIT_ROLES else Exposure.LINK_VIEW
            if audit.link_role is None or (p.role in EDIT_ROLES):
                audit.link_role = p.role
            audit.link_discoverable = audit.link_discoverable or p.discoverable
            exposure = max(exposure, level)
        elif p.type == "domain":
            dom = p.domain or ""
            audit.domain_shares.append((dom, p.role))
            exposure = max(exposure, Exposure.DOMAIN if dom in internal else Exposure.EXTERNAL)
        elif p.type in ("user", "group"):
            if p.email == me or p.role == "owner":
                continue
            if _email_domain(p.email) in internal:
                audit.internal_accounts += 1
            else:
                audit.external_accounts.append((p.email or "", p.role))
                exposure = max(exposure, Exposure.EXTERNAL)
    if public_hint is not None and exposure < Exposure.LINK_VIEW:
        audit.notes.append("공개 범위 검색 결과와 권한 목록이 다름 — 수동 확인 필요")
        exposure = Exposure.LINK_VIEW
    audit.exposure = exposure
    audit.risk_score = _score(audit)
    if any(p.metadata_only for p in perms):
        audit.notes.append("제한된 액세스 폴더: 일부 사용자는 이름만 볼 수 있음")
    if any(p.expires for p in perms if not p.metadata_only):
        audit.notes.append("만료일이 설정된 권한 있음")
    return audit


def _score(a: FileAudit) -> int | None:
    if a.exposure is None:
        return None
    score = BASE_SCORE[a.exposure]
    if a.link_discoverable:
        score += 5  # anyoneCanFind: discoverable on the web
    external_editors = sum(1 for _, r in a.external_accounts if r in EDIT_ROLES)
    if external_editors:
        score += 5
        if a.writers_can_share:
            score += 5  # external editors can re-share
    if a.exposure in (Exposure.EXTERNAL, Exposure.LINK_VIEW) and a.download_restricted:
        score -= 5
    return max(0, min(100, score))


def infer_my_drive_origins(
    perms: list[PermissionView], parent_perm_ids: set[str] | None
) -> list[PermissionView]:
    """My Drive: the API may not say which permissions are inherited. A permission that also
    exists on the parent folder is marked "inherited (likely)"; others are direct."""
    if parent_perm_ids is None:
        return perms
    out = []
    for p in perms:
        if p.origin is not Origin.UNKNOWN or p.role == "owner":
            out.append(p)
            continue
        origin = Origin.INHERITED_LIKELY if p.perm_id in parent_perm_ids else Origin.DIRECT
        out.append(replace(p, origin=origin))
    return out
