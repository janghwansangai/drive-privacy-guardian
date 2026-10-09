"""Read-only permission audit with checkpoints (SPEC 6.1).

Phases (the checkpoint records which one is next, so an interrupted scan resumes):
  public  -> visibility queries: which files are link-public (fast signal, also covers files
             whose permission list we cannot read)
  list    -> files.list pages (or folder-by-folder BFS); every page is saved with its token.
             A big drive (> SPLIT_ITEMS) is listed in createdTime windows instead, so an
             expired page token (long pause, lost connection) costs one window, not the drive
  perms   -> permissions.list only where files.list did not include them
  analyze -> classify every item, store plaintext status/exposure/score

Only read requests are issued (DriveClient has no write methods).
"""

from __future__ import annotations

import datetime as dt
import threading
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from itertools import pairwise
from typing import Any

from dpg.core.audit.analyze import (
    classify,
    infer_my_drive_origins,
    internal_domains_for,
    origin_from_details,
    permission_view,
)
from dpg.core.audit.model import Exposure, FileAudit, ItemStatus, Origin, PermissionView
from dpg.core.drive.client import FOLDER_MIME, VAULT_NAME_RE, DriveClient, DriveHttpError
from dpg.core.logging import get_logger
from dpg.core.store.audit_store import AuditStore, ItemRow

log = get_logger("audit")

PERM_BATCH = 50
SPLIT_ITEMS = 10_000  # past this many items, list in createdTime windows (see _windows)
TRIM_ITEMS = 200_000  # past this many items the result keeps only what needs attention (D-102)
WINDOWS_FROM = 2012  # one window for everything older, then half-years up to now


def _windows(now: dt.datetime) -> list[list[str | None]]:
    """Half-open createdTime ranges covering all time: [None, 2012-01) … [last half-year, None)."""
    edges = [
        f"{y}-{m:02d}-01T00:00:00"
        for y in range(WINDOWS_FROM, now.year + 1)
        for m in (1, 7)
        if (y, m) <= (now.year, now.month)
    ]
    middle: list[list[str | None]] = [[a, b] for a, b in pairwise(edges)]
    return [[None, edges[0]], *middle, [edges[-1], None]]


def window_label(window: list[str | None]) -> str:
    lo = window[0]
    if lo is None:
        return f"{WINDOWS_FROM}년 이전"
    half = "상반기" if lo[5:7] == "01" else "하반기"
    return f"{lo[:4]}년 {half}" + ("~" if window[1] is None else "")


def _window_query(window: list[str | None]) -> str:
    lo, hi = window
    parts = []
    if lo is not None:
        parts.append(f"createdTime >= '{lo}'")
    if hi is not None:
        parts.append(f"createdTime < '{hi}'")
    return " and ".join(parts)


class AuditCancelled(Exception):
    pass


@dataclass(frozen=True)
class AuditScope:
    kind: str  # mine | public | shared | drive | folder
    target: str | None = None

    @classmethod
    def parse(cls, text: str) -> AuditScope:
        kind, _, target = text.partition(":")
        kind = kind.strip().lower()
        if kind in ("mine", "public", "shared") and not target:
            return cls(kind)
        if kind in ("drive", "folder") and target.strip():
            return cls(kind, target.strip())
        raise ValueError(
            "범위는 mine, public, shared, drive:<공유드라이브ID>, folder:<폴더ID> "
            "중 하나여야 합니다."
        )

    @property
    def key(self) -> str:
        return self.kind if self.target is None else f"{self.kind}:{self.target}"

    @property
    def label_ko(self) -> str:
        return {
            "mine": "내 소유 파일",
            "public": "링크로 공개된 내 파일",
            "shared": "나에게 공유됨",
            "drive": "공유 드라이브",
            "folder": "특정 폴더",
        }[self.kind]


@dataclass(frozen=True)
class Progress:
    phase: str
    listed: int = 0
    perms_done: int = 0
    perms_total: int = 0
    retries: int = 0
    window: int = 0  # 1-based, when a big drive is listed in createdTime windows
    windows: int = 0
    window_label: str = ""


@dataclass
class AuditResult:
    scan_id: int
    scope: AuditScope
    items: list[FileAudit]
    resumed: bool
    incomplete_search: bool
    counts: Counter[str] = field(default_factory=Counter)
    incremental: bool = False  # built from the previous scan + Drive's change list
    changed: set[str] = field(default_factory=set)  # file ids added / changed / removed
    content_changed: set[str] = field(default_factory=set)  # need re-detection
    unchanged: bool = False  # nothing changed: `items` is empty, keep what is on screen
    changes_token: str | None = None  # where the next incremental audit starts
    total_items: int = 0  # every item checked (more than len(items) when trimmed)
    trimmed: bool = False  # big drive: `items` holds only what needs attention (D-102)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


class AuditRunner:
    def __init__(
        self,
        client: DriveClient,
        store: AuditStore,
        *,
        account: str | None,
        internal_domains: tuple[str, ...] = (),
        on_progress: Callable[[Progress], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.client = client
        self.store = store
        self.account = account
        self.internal = internal_domains_for(account, internal_domains)
        self.on_progress = on_progress
        self.cancel = cancel
        self._analysis: tuple[int, bool] = (0, False)  # (items checked, trimmed) of the last run

    # -- helpers --------------------------------------------------------------------------------

    def _check_cancel(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise AuditCancelled()

    def _progress(self, **kw: Any) -> None:
        if self.on_progress is not None:
            self.on_progress(Progress(retries=self.client.retries, **kw))

    def _scope_query(self, scope: AuditScope, extra: str | None = None) -> str:
        parts = ["trashed = false"]
        if scope.kind == "mine":
            parts.insert(0, "'me' in owners")
        elif scope.kind == "public":
            # Quick check: only what anyone with the link can open (V4: the two public values).
            parts.insert(0, "(visibility = 'anyoneWithLink' or visibility = 'anyoneCanFind')")
            parts.insert(0, "'me' in owners")
        elif scope.kind == "shared":
            parts.insert(0, "sharedWithMe")
        if extra:
            parts.append(extra)
        return " and ".join(parts)

    @staticmethod
    def _row_for(meta: dict[str, Any]) -> ItemRow:
        drive_id = meta.get("driveId")
        perms: list[dict[str, Any]] | None = None
        if drive_id is None:
            if "permissions" in meta:
                source, perms = "inline", list(meta["permissions"])
            elif (meta.get("capabilities") or {}).get("canShare"):
                source = "pending"
            else:
                source = "unavailable"
        else:
            source = "pending" if meta.get("hasAugmentedPermissions") else "derived"
        stripped = {k: v for k, v in meta.items() if k != "permissions"}
        return ItemRow(
            file_id=str(meta["id"]),
            kind="item",
            drive_id=drive_id,
            parent_id=(meta.get("parents") or [None])[0],
            perm_source=source,
            meta=stripped,
            perms=perms,
        )

    # -- main -----------------------------------------------------------------------------------

    def run(self, scope: AuditScope, *, resume: bool = True) -> AuditResult:
        existing = self.store.resumable_scan(scope.key) if resume else None
        if existing is not None:
            scan_id, cp, resumed = existing.scan_id, existing.checkpoint, True
            self.store.set_status(scan_id, "running")
            log.info("resuming scan %s at phase %s", scan_id, cp.get("phase"))
        else:
            cp = {"phase": "public"}
            scan_id, resumed = self.store.new_scan(scope.key, cp), False
            log.info("new scan %s scope=%s", scan_id, scope.kind)
        try:
            if cp["phase"] == "public":
                self._phase_public(scope, cp)
                cp["phase"] = "list"
                self.store.save_checkpoint(scan_id, cp)
            if cp["phase"] == "list":
                self._phase_list(scan_id, scope, cp)
                cp["phase"] = "perms"
                self.store.save_checkpoint(scan_id, cp)
            if cp["phase"] == "perms":
                self._check_cancel()
                self._phase_perms(scan_id)
                cp["phase"] = "analyze"
                self.store.save_checkpoint(scan_id, cp)
            self._check_cancel()
            items = self._phase_analyze(scan_id, cp)
        except (AuditCancelled, KeyboardInterrupt):
            self.store.set_status(scan_id, "cancelled")
            log.info("scan %s cancelled", scan_id)
            raise
        except DriveHttpError as exc:
            self.store.set_status(scan_id, "failed", f"{exc.status}:{exc.reason}")
            raise
        except BaseException as exc:
            self.store.set_status(scan_id, "failed", type(exc).__name__)
            raise
        self.store.set_status(scan_id, "done")
        self.store.delete_scans_before(scope.key, scan_id)
        result = AuditResult(scan_id, scope, items, resumed, bool(cp.get("incomplete")))
        result.counts = summarize(items)
        result.total_items, result.trimmed = self._analysis
        result.changes_token = cp.get("changes_token")
        log.info("scan %s done items=%s", scan_id, len(items))
        return result

    # -- incremental (Phase 7) ------------------------------------------------------------------

    @staticmethod
    def _changes_drive(scope: AuditScope) -> str | None:
        return scope.target if scope.kind == "drive" else None

    def run_incremental(
        self, scope: AuditScope, *, reuse_unchanged: bool = False
    ) -> AuditResult | None:
        """Re-check only what changed since the last finished audit of this scope.

        Returns None when an incremental audit is not possible (no previous audit, no token,
        token expired, or the "shared with me" scope) — the caller then runs a full audit.
        """
        if scope.kind in ("shared", "public"):
            # "shared with me" membership is not in a change record; the public list is quick
            # to re-read in full (and link visibility is not a file field to filter changes by)
            return None
        prev = self.store.latest_done_scan(scope.key)
        token = prev.checkpoint.get("changes_token") if prev is not None else None
        if prev is None or not token:
            return None
        self._progress(phase="changes")
        try:
            changes, new_token = self.client.list_changes(str(token), self._changes_drive(scope))
        except DriveHttpError as exc:
            if exc.status in (400, 403, 404, 410):
                log.info("changes token unusable (%s): full audit", exc.status)
                return None
            raise
        if not changes and reuse_unchanged:
            # The periodic check: nothing changed, so no copy and no re-analysis at all.
            self.store.set_changes_token(prev.scan_id, new_token)
            return AuditResult(
                prev.scan_id,
                scope,
                [],
                False,
                False,
                incremental=True,
                unchanged=True,
                changes_token=new_token,
            )
        cp = {k: v for k, v in prev.checkpoint.items() if k not in ("page_token", "queue")}
        cp.update(phase="perms", changes_token=new_token, incremental_from=prev.scan_id)
        scan_id = self.store.copy_scan(prev.scan_id, scope.key, cp)
        # Shared-drive membership is re-read every time (one request per drive).
        roots = [t.file_id for t in self.store.tree(scan_id) if t.kind == "drive_root"]
        self.store.delete_items(scan_id, roots)
        try:
            changed, content = self._apply_changes(scan_id, scope, changes)
            if changed:
                self._phase_public(scope, cp)  # refresh the visibility hints
            self.store.save_checkpoint(scan_id, cp)
            self._check_cancel()
            self._phase_perms(scan_id)
            self._check_cancel()
            items = self._phase_analyze(scan_id, cp)
        except (AuditCancelled, KeyboardInterrupt):
            self.store.set_status(scan_id, "cancelled")
            raise
        except BaseException as exc:
            self.store.set_status(scan_id, "failed", type(exc).__name__)
            raise
        self.store.set_status(scan_id, "done")
        self.store.delete_scans_before(scope.key, scan_id)
        result = AuditResult(scan_id, scope, items, False, bool(cp.get("incomplete")))
        result.counts = summarize(items)
        result.total_items, result.trimmed = self._analysis
        result.incremental, result.changed, result.content_changed = True, changed, content
        result.changes_token = new_token
        log.info("incremental scan %s changes=%s items=%s", scan_id, len(changed), len(items))
        return result

    def _in_scope(self, scope: AuditScope, meta: dict[str, Any]) -> bool:
        if scope.kind == "mine":
            return bool(meta.get("ownedByMe")) and meta.get("driveId") is None
        if scope.kind == "drive":
            return meta.get("driveId") == scope.target
        return True  # folder: decided by ancestry after applying (see _apply_changes)

    def _apply_changes(
        self, scan_id: int, scope: AuditScope, changes: list[dict[str, Any]]
    ) -> tuple[set[str], set[str]]:
        # Only the tree (plaintext parent links) for everything; full rows only for what changed.
        parent_of = {t.file_id: t.parent_id for t in self.store.tree(scan_id) if t.kind == "item"}
        changed_ids = {str(ch.get("fileId")) for ch in changes}
        old_rows = {
            r.file_id: r
            for r in self.store.get_items(scan_id, changed_ids & parent_of.keys())
            if r.kind == "item"
        }
        removed: set[str] = set()
        upserts: dict[str, ItemRow] = {}
        refresh_below: set[str] = set()  # folders whose sharing / place changed
        content: set[str] = set()
        for ch in changes:
            fid = str(ch.get("fileId"))
            meta = ch.get("file")
            if (
                ch.get("removed")
                or meta is None
                or meta.get("trashed")
                or not self._in_scope(scope, meta)
            ):
                if fid in parent_of or fid in upserts:
                    removed.add(fid)
                    upserts.pop(fid, None)
                    old = old_rows.get(fid)
                    if old is not None and old.meta.get("mimeType") == FOLDER_MIME:
                        removed |= self._descendants(fid, parent_of)
                continue
            row = self._row_for(meta)
            old = old_rows.get(fid)
            if old is None or old.meta.get("modifiedTime") != meta.get("modifiedTime"):
                content.add(fid)
            if meta.get("mimeType") == FOLDER_MIME and old is not None and _sharing_moved(old, row):
                refresh_below.add(fid)
            removed.discard(fid)
            upserts[fid] = row
        merged = {k: v for k, v in parent_of.items() if k not in removed}
        merged.update({k: r.parent_id for k, r in upserts.items()})
        # Children of a folder whose sharing or location changed are not in the change list:
        # re-read them so inherited permissions are current.
        refreshed: list[ItemRow] = []
        for folder in refresh_below:
            for child in self._descendants(folder, merged):
                if child in upserts:
                    continue
                self._check_cancel()
                try:
                    meta = self.client.get_file(child)
                except DriveHttpError as exc:
                    if exc.status == 404:
                        removed.add(child)
                        merged.pop(child, None)
                        continue
                    raise
                if meta.get("trashed"):
                    removed.add(child)
                    merged.pop(child, None)
                    continue
                row = self._row_for(meta)
                merged[child] = row.parent_id
                refreshed.append(row)
        if scope.kind == "folder" and scope.target is not None:
            outside = {fid for fid in merged if not _under(fid, scope.target, merged)}
            removed |= outside & parent_of.keys()
            for fid in outside:
                merged.pop(fid, None)
                upserts.pop(fid, None)
        refreshed = [r for r in refreshed if r.file_id in merged]
        self.store.delete_items(scan_id, removed)
        self.store.save_items(scan_id, [*upserts.values(), *refreshed])
        self.store.delete_detections(scan_id, content)
        changed = removed | set(upserts) | {r.file_id for r in refreshed}
        return changed, content & set(merged)

    @staticmethod
    def _descendants(folder: str, parent_of: dict[str, str | None]) -> set[str]:
        children: dict[str, list[str]] = {}
        for fid, parent in parent_of.items():
            if parent:
                children.setdefault(parent, []).append(fid)
        out: set[str] = set()
        stack = [folder]
        while stack:
            for c in children.get(stack.pop(), []):
                if c not in out:
                    out.add(c)
                    stack.append(c)
        return out

    # -- phases ---------------------------------------------------------------------------------

    def _phase_public(self, scope: AuditScope, cp: dict[str, Any]) -> None:
        self._progress(phase="public")
        public: dict[str, str] = {}
        if scope.kind != "folder":  # a subtree cannot be expressed in a single query
            drive_id = scope.target if scope.kind == "drive" else None
            for value in ("anyoneWithLink", "anyoneCanFind"):
                self._check_cancel()
                q = self._scope_query(scope, f"visibility = '{value}'")
                for fid in self.client.list_ids(q=q, drive_id=drive_id):
                    public[fid] = value
        cp["public"] = public
        if "changes_token" not in cp:
            # Taken before listing, so anything that changes during the scan is caught next time.
            try:
                cp["changes_token"] = self.client.start_page_token(self._changes_drive(scope))
            except DriveHttpError as exc:
                log.info("no changes token (%s): next audit will be a full one", exc.status)
        if scope.kind in ("mine", "public"):
            cp["root_id"] = self.client.get_file("root")["id"]

    def _phase_list(self, scan_id: int, scope: AuditScope, cp: dict[str, Any]) -> None:
        if scope.kind == "folder":
            self._list_folder_tree(scan_id, scope, cp)
            return
        drive_id = scope.target if scope.kind == "drive" else None
        base = self._scope_query(scope)
        listed = self.store.count_items(scan_id)
        if cp.get("windows") is None and listed >= SPLIT_ITEMS and not cp.get("page_token"):
            self._start_windows(cp)  # resuming a big drive whose listing had not started over
        while True:
            self._check_cancel()
            windows = cp.get("windows")
            if windows is not None and cp["window"] >= len(windows):
                return
            q = base if windows is None else f"{base} and {_window_query(windows[cp['window']])}"
            token = cp.get("page_token")
            try:
                page = self.client.list_files_page(q=q, page_token=token, drive_id=drive_id)
            except DriveHttpError as exc:
                if token and exc.status == 400:
                    # Page tokens expire after some hours: restart this listing (or just this
                    # window), keep the saved rows.
                    log.info("page token rejected on resume; relisting")
                    cp["page_token"] = None
                    if windows is None and listed >= SPLIT_ITEMS:
                        self._start_windows(cp)
                    continue
                raise
            rows = [self._row_for(m) for m in page.items]
            if page.incomplete:
                cp["incomplete"] = True
            listed += len(rows)
            cp["page_token"] = page.next_token
            done = False
            if windows is None:
                if page.next_token and listed >= SPLIT_ITEMS:
                    # A big drive: go on in windows so an interruption costs one window. The
                    # pages already read are saved; re-reading them only updates those rows.
                    self._start_windows(cp)
                elif not page.next_token:
                    done = True
            elif not page.next_token:
                cp["window"] += 1
            self.store.save_items(scan_id, rows, cp)
            windows = cp.get("windows")
            if windows is not None and cp["window"] < len(windows):
                self._progress(
                    phase="list",
                    listed=listed,
                    window=cp["window"] + 1,
                    windows=len(windows),
                    window_label=window_label(windows[cp["window"]]),
                )
            else:
                self._progress(phase="list", listed=listed)
            if done:
                return

    @staticmethod
    def _start_windows(cp: dict[str, Any]) -> None:
        cp["windows"] = _windows(dt.datetime.now(dt.UTC))
        cp["window"] = 0
        cp["page_token"] = None
        log.info("big drive: listing in %s createdTime windows", len(cp["windows"]))

    def _list_folder_tree(self, scan_id: int, scope: AuditScope, cp: dict[str, Any]) -> None:
        if scope.target is None:
            raise ValueError("folder scope requires a folder ID")
        if "queue" not in cp:
            root = self.client.get_file(scope.target)
            if root.get("mimeType") != FOLDER_MIME:
                raise ValueError("folder: 범위에는 폴더 ID를 지정해야 합니다.")
            cp.update(
                queue=[scope.target], visited=[], folder_drive=root.get("driveId"), page_token=None
            )
            root_row = self._row_for(root)
            if root_row.drive_id is not None:
                # Its ancestors are outside the scan, so derive nothing: ask for the full list.
                root_row.perm_source = "pending"
            self.store.save_items(scan_id, [root_row], cp)
        visited = set(cp["visited"])
        listed = self.store.count_items(scan_id)
        while cp["queue"]:
            folder = cp["queue"][0]
            while True:
                self._check_cancel()
                q = f"'{_escape(folder)}' in parents and trashed = false"
                token = cp.get("page_token")
                try:
                    page = self.client.list_files_page(
                        q=q, page_token=token, drive_id=cp.get("folder_drive")
                    )
                except DriveHttpError as exc:
                    if token and exc.status == 400:
                        cp["page_token"] = None
                        continue
                    raise
                rows = [self._row_for(m) for m in page.items]
                for m in page.items:
                    if (
                        m.get("mimeType") == FOLDER_MIME
                        and m["id"] not in visited
                        and m["id"] not in cp["queue"]
                    ):
                        cp["queue"].append(m["id"])
                cp["page_token"] = page.next_token
                if not page.next_token:
                    visited.add(folder)
                    cp["visited"] = sorted(visited)
                    cp["queue"].pop(0)
                self.store.save_items(scan_id, rows, cp)
                listed += len(rows)
                self._progress(phase="list", listed=listed)
                if not page.next_token:
                    break

    def _phase_perms(self, scan_id: int) -> None:
        tree = self.store.tree(scan_id)  # plaintext columns: no need to decrypt every item
        pending = self.store.get_items(
            scan_id, [t.file_id for t in tree if t.perm_source == "pending"]
        )
        have_roots = {t.file_id for t in tree if t.kind == "drive_root"}
        needed_roots = sorted(
            {t.drive_id for t in tree if t.kind == "item" and t.drive_id} - have_roots
        )
        del tree
        total = len(pending) + len(needed_roots)
        done = 0
        batch: list[ItemRow] = []

        def flush() -> None:
            if batch:
                self.store.save_items(scan_id, batch)
                batch.clear()

        for drive_id in needed_roots:
            self._check_cancel()
            try:
                perms: list[dict[str, Any]] | None = self.client.list_permissions(drive_id)
                source = "listed"
            except DriveHttpError as exc:
                perms, source = None, f"unavailable:{exc.status}"
            batch.append(
                ItemRow(drive_id, "drive_root", drive_id, None, source, {"id": drive_id}, perms)
            )
            done += 1
        flush()
        for row in pending:
            self._check_cancel()
            try:
                row.perms = self.client.list_permissions(row.file_id)
                row.perm_source = "listed"
            except DriveHttpError as exc:
                if exc.status in (403, 404):
                    row.perm_source = "unavailable" if exc.status == 403 else "error"
                    row.error_code = f"{exc.status}:{exc.reason}"
                else:
                    raise
            batch.append(row)
            done += 1
            if len(batch) >= PERM_BATCH:
                flush()
                self._progress(phase="perms", perms_done=done, perms_total=total)
        flush()
        self._progress(phase="perms", perms_done=done, perms_total=total)

    # -- analysis -------------------------------------------------------------------------------

    def _phase_analyze(self, scan_id: int, cp: dict[str, Any]) -> list[FileAudit]:
        """Classify every item, a batch at a time (D-102). Only the rows children inherit from
        (their parent folders, shared-drive roots) are kept in memory, so a million-item drive
        needs memory for its folders, not for every file. Past TRIM_ITEMS the result keeps only
        what needs attention (shared / unknown / encrypted archives) and the folders above it."""
        self._progress(phase="analyze")
        public: dict[str, str] = cp.get("public", {})
        root_id = cp.get("root_id")
        tree = self.store.tree(scan_id)
        parent_of = {t.file_id: t.parent_id for t in tree if t.kind == "item"}
        wanted = {p for p in parent_of.values() if p is not None} & parent_of.keys()
        wanted |= {t.file_id for t in tree if t.kind == "drive_root"}
        del tree
        loaded = self.store.get_items(scan_id, wanted)
        roots = {r.file_id: r for r in loaded if r.kind == "drive_root"}
        parents = {r.file_id: r for r in loaded if r.kind == "item"}
        del loaded
        memo: dict[str, list[PermissionView] | None] = {}

        def own_views(r: ItemRow, depth: int) -> list[PermissionView] | None:
            if r.perm_source in ("inline", "listed") and r.perms is not None:
                result = []
                for p in r.perms:
                    origin, source = origin_from_details(p)
                    result.append(permission_view(p, origin, source))
                return result
            if r.perm_source == "derived" and r.parent_id is not None:
                parent = parent_views(r.parent_id, depth + 1)
                if parent is not None:
                    inherited = [_inherit(p, r.parent_id) for p in parent]
                    if r.meta.get("inheritedPermissionsDisabled"):
                        inherited = [_limit(p) for p in inherited]
                    return inherited
            return None

        def parent_views(fid: str, depth: int = 0) -> list[PermissionView] | None:
            if fid in memo:
                return memo[fid]
            memo[fid] = None  # cycle guard
            result: list[PermissionView] | None = None
            if fid in roots:
                r = roots[fid]
                if r.perms is not None:
                    result = [permission_view(p, Origin.INHERITED, fid) for p in r.perms]
            elif fid in parents and depth < 200:
                result = own_views(parents[fid], depth)
            memo[fid] = result
            return result

        trim = len(parent_of) > TRIM_ITEMS
        audits: list[FileAudit] = []
        folder_audits: dict[str, FileAudit] = {}  # trimmed: candidates for the "위치" column
        for batch in self.store.item_batches(scan_id):
            self._check_cancel()
            results: list[tuple[str, str, int | None, int | None, str | None]] = []
            for r in batch:
                if r.kind != "item":
                    continue
                fid = r.file_id
                perms = parent_views(fid) if fid in parents else own_views(r, 0)
                if perms is not None and r.drive_id is None:
                    parent_ids: set[str] | None = None
                    if r.parent_id is not None and r.parent_id == root_id:
                        parent_ids = set()
                    elif r.parent_id is not None:
                        parent = parent_views(r.parent_id)
                        if parent is not None:
                            parent_ids = {p.perm_id for p in parent if p.role != "owner"}
                    perms = infer_my_drive_origins(perms, parent_ids)
                if perms is not None:
                    status = ItemStatus.OK
                elif r.perm_source == "error":
                    status = ItemStatus.FAILED
                else:
                    status = ItemStatus.INSUFFICIENT
                audit = classify(
                    fid,
                    r.meta,
                    perms,
                    account=self.account,
                    internal=self.internal,
                    public_hint=public.get(fid),
                    status=status,
                    error_code=r.error_code,
                )
                if r.perm_source == "derived" and perms is None:
                    audit.notes.append("상위 폴더 또는 공유 드라이브 권한을 확인하지 못함")
                results.append(
                    (
                        audit.file_id,
                        audit.status.value,
                        int(audit.exposure) if audit.exposure is not None else None,
                        audit.risk_score,
                        audit.error_code,
                    )
                )
                if not trim or _needs_attention(audit):
                    audits.append(audit)
                elif fid in parents:
                    folder_audits[fid] = audit
            self.store.update_results(scan_id, results)
        if trim:
            above: set[str] = set()
            for a in audits:
                cur, seen = a.parent_id, 0
                while cur in folder_audits and cur not in above and seen < 200:
                    above.add(cur)
                    cur, seen = parent_of.get(cur), seen + 1
            audits.extend(folder_audits[f] for f in folder_audits if f in above)
            log.info("big scan: %s of %s items kept in the result", len(audits), len(parent_of))
        self._analysis = (len(parent_of), trim)
        return audits


def _needs_attention(a: FileAudit) -> bool:
    """What a trimmed result keeps: anything shared, unknown, or an encrypted archive."""
    return (
        a.exposure is None
        or a.exposure > Exposure.RESTRICTED
        or a.status is not ItemStatus.OK
        or bool(VAULT_NAME_RE.match(a.name or ""))
    )


def _sharing_moved(old: ItemRow, new: ItemRow) -> bool:
    """Did anything that children inherit change (permissions, limited access, location)?"""

    def key(r: ItemRow) -> tuple[Any, ...]:
        perms = sorted(
            (p.get("id"), p.get("role"), p.get("type"), p.get("view")) for p in (r.perms or [])
        )
        return (
            perms,
            r.perm_source,
            r.parent_id,
            r.meta.get("inheritedPermissionsDisabled"),
            r.meta.get("hasAugmentedPermissions"),
        )

    return key(old) != key(new)


def _under(fid: str, target: str, parent_of: dict[str, str | None]) -> bool:
    seen: set[str] = set()
    cur: str | None = fid
    while cur is not None and cur not in seen:
        if cur == target:
            return True
        seen.add(cur)
        cur = parent_of.get(cur)
    return False


def _inherit(p: PermissionView, parent_id: str) -> PermissionView:
    source = p.inherited_from if p.origin is Origin.INHERITED and p.inherited_from else parent_id
    return replace(p, origin=Origin.INHERITED, inherited_from=source)


def _limit(p: PermissionView) -> PermissionView:
    if p.role in ("organizer", "owner"):
        return p
    return replace(p, role="reader", metadata_only=True)


def summarize(items: list[FileAudit]) -> Counter[str]:
    c: Counter[str] = Counter(total=len(items))
    for a in items:
        c[f"status:{a.status.value}"] += 1
        if a.exposure is None:
            c["exposure:unknown"] += 1
        else:
            c[f"exposure:{a.exposure.name.lower()}"] += 1
        if a.exposure in (Exposure.LINK_VIEW, Exposure.LINK_EDIT):
            c["link_public"] += 1
    return c
