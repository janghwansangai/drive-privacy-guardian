"""Execute / verify / undo a change plan (SPEC 6.2 steps 3–6).

For every file: re-fetch → compare with the plan (differences become CONFLICT, needing
re-approval) → apply (unless dry run) → re-fetch to verify → record the before-state
(encrypted) so the change can be undone.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from dpg.core.actions.model import Change, ChangeState, Op, Plan, RunResult
from dpg.core.actions.writer import DriveWriter
from dpg.core.drive.client import DriveClient, DriveHttpError
from dpg.core.logging import get_logger
from dpg.core.store.audit_store import AuditStore

log = get_logger("actions")


class ActionCancelled(Exception):
    pass


@dataclass(frozen=True)
class ActionProgress:
    done: int
    total: int


def _perm_matches(current: dict[str, Any] | None, before: dict[str, Any]) -> bool:
    if current is None:
        return False
    return (
        current.get("type") == before.get("type")
        and current.get("role") == before.get("role")
        and (current.get("emailAddress") or "").lower() == (before.get("emailAddress") or "")
        and (current.get("domain") or "").lower() == (before.get("domain") or "")
    )


_FILE_OPS = frozenset({Op.UPDATE_FILE, Op.MOVE, Op.TRASH})


def _file_value(meta: dict[str, Any], key: str) -> Any:
    if key == "parent":
        return (meta.get("parents") or [None])[0]
    if key == "trashed":
        return bool(meta.get("trashed"))
    if key == "downloadRestrictions":
        r = (meta.get("downloadRestrictions") or {}).get("itemDownloadRestriction") or {}
        return {
            "itemDownloadRestriction": {
                "restrictedForReaders": bool(r.get("restrictedForReaders")),
                "restrictedForWriters": bool(r.get("restrictedForWriters")),
            }
        }
    return meta.get(key)


def _file_matches(meta: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(_file_value(meta, k) == v for k, v in expected.items())


class ActionExecutor:
    def __init__(
        self,
        client: DriveClient,
        store: AuditStore,
        *,
        on_progress: Callable[[ActionProgress], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.client = client
        self.writer = DriveWriter(client)
        self.store = store
        self.on_progress = on_progress
        self.cancel = cancel

    # -- state fetch ----------------------------------------------------------------------------

    def _current_perms(self, file_id: str) -> dict[str, dict[str, Any]]:
        return {p["id"]: p for p in self.client.list_permissions(file_id)}

    def _still_as_planned(
        self, change: Change, perms: dict[str, dict[str, Any]] | None, meta: dict[str, Any] | None
    ) -> bool:
        if change.op in _FILE_OPS:
            return meta is not None and _file_matches(meta, change.before)
        return perms is not None and _perm_matches(perms.get(change.perm_id or ""), change.before)

    def _verified(
        self, change: Change, perms: dict[str, dict[str, Any]] | None, meta: dict[str, Any] | None
    ) -> bool:
        if change.op in _FILE_OPS:
            return (
                meta is not None and change.after is not None and _file_matches(meta, change.after)
            )
        current = (perms or {}).get(change.perm_id or "")
        if change.op is Op.DELETE_PERM:
            return current is None
        return (
            current is not None
            and change.after is not None
            and current.get("role") == change.after.get("role")
        )

    def _fetch(
        self, changes: list[Change]
    ) -> tuple[dict[str, dict[str, Any]] | None, dict[str, Any] | None]:
        file_id = changes[0].file_id
        perms = (
            self._current_perms(file_id) if any(c.op not in _FILE_OPS for c in changes) else None
        )
        meta = self.client.get_file(file_id) if any(c.op in _FILE_OPS for c in changes) else None
        return perms, meta

    def _apply(self, change: Change) -> None:
        if change.op is Op.DELETE_PERM:
            self.writer.delete_permission(change.file_id, change.perm_id or "")
        elif change.op is Op.UPDATE_PERM:
            self.writer.update_permission_role(
                change.file_id, change.perm_id or "", str((change.after or {})["role"])
            )
        elif change.op is Op.MOVE:
            self.writer.move_file(
                change.file_id, str((change.after or {})["parent"]), str(change.before["parent"])
            )
        elif change.op is Op.TRASH:
            self.writer.set_trashed(change.file_id, True)
        else:
            self.writer.update_file(change.file_id, change.after or {})

    # -- execute --------------------------------------------------------------------------------

    def execute(self, plan: Plan, *, dry_run: bool = False) -> RunResult:
        run_id = self.store.new_action_run(plan.action.value, dry_run)
        self.store.save_changes(run_id, plan.changes)
        by_file: dict[str, list[Change]] = {}
        for c in plan.changes:
            by_file.setdefault(c.file_id, []).append(c)
        done = 0
        try:
            for file_id, changes in by_file.items():
                if self.cancel is not None and self.cancel.is_set():
                    raise ActionCancelled()
                self._execute_file(changes, dry_run)
                self.store.save_changes(run_id, plan.changes)
                done += 1
                if self.on_progress is not None:
                    self.on_progress(ActionProgress(done, len(by_file)))
                log.info("action file done run=%s file=%s", run_id, file_id)
        except (ActionCancelled, KeyboardInterrupt):
            for c in plan.changes:
                if c.state is ChangeState.PLANNED:
                    c.state = ChangeState.CANCELLED
            self.store.save_changes(run_id, plan.changes)
            self.store.finish_action_run(run_id, "cancelled")
            raise
        self.store.finish_action_run(run_id, "done")
        return RunResult(run_id, dry_run, plan.changes)

    def _execute_file(self, changes: list[Change], dry_run: bool) -> None:
        try:
            perms, meta = self._fetch(changes)  # step 4: re-fetch right before executing
        except DriveHttpError as exc:
            for c in changes:
                c.state, c.error = ChangeState.FAILED, f"{exc.status}:{exc.reason}"
            return
        runnable = []
        for c in changes:
            if self._still_as_planned(c, perms, meta):
                runnable.append(c)
            else:
                c.state = ChangeState.CONFLICT
        if dry_run:
            for c in runnable:
                c.state = ChangeState.DRY_RUN_OK
            return
        for c in runnable:
            try:
                self._apply(c)
            except DriveHttpError as exc:
                c.state, c.error = ChangeState.FAILED, f"{exc.status}:{exc.reason}"
        attempted = [c for c in runnable if c.state is ChangeState.PLANNED]
        if not attempted:
            return
        try:
            perms, meta = self._fetch(attempted)  # step 5: verify
        except DriveHttpError as exc:
            for c in attempted:
                c.state, c.error = ChangeState.FAILED, f"verify {exc.status}:{exc.reason}"
            return
        for c in attempted:
            if self._verified(c, perms, meta):
                c.state = ChangeState.DONE
            else:
                c.state, c.error = ChangeState.FAILED, "변경 후 확인 결과가 다름"

    # -- undo -----------------------------------------------------------------------------------

    def undo(self, run_id: int) -> RunResult:
        changes = self.store.load_changes(run_id)
        undo_id = self.store.new_action_run(f"undo:{run_id}", False)
        targets = [c for c in reversed(changes) if c.state is ChangeState.DONE]
        by_file: dict[str, list[Change]] = {}
        for c in targets:
            by_file.setdefault(c.file_id, []).append(c)
        for changes_for_file in by_file.values():
            self._undo_file(changes_for_file)
            self.store.save_changes(run_id, changes)
        self.store.finish_action_run(undo_id, "done")
        return RunResult(run_id, False, changes)

    def _undo_file(self, changes: list[Change]) -> None:
        try:
            perms, meta = self._fetch(changes)
        except DriveHttpError as exc:
            for c in changes:
                c.state, c.error = ChangeState.UNDO_FAILED, f"{exc.status}:{exc.reason}"
            return
        for c in changes:
            try:
                if c.op is Op.DELETE_PERM:
                    if perms is not None and c.perm_id in perms:
                        c.state = ChangeState.UNDONE  # someone already restored it
                        continue
                    self.writer.create_permission(c.file_id, c.before)
                elif c.op is Op.UPDATE_PERM:
                    current = (perms or {}).get(c.perm_id or "")
                    if current is None or current.get("role") != (c.after or {}).get("role"):
                        c.state, c.error = ChangeState.NOT_UNDOABLE, "그 사이 다시 바뀜"
                        continue
                    self.writer.update_permission_role(
                        c.file_id, c.perm_id or "", str(c.before["role"])
                    )
                else:
                    if meta is None or not _file_matches(meta, c.after or {}):
                        c.state, c.error = ChangeState.NOT_UNDOABLE, "그 사이 다시 바뀜"
                        continue
                    if c.op is Op.MOVE:
                        self.writer.move_file(
                            c.file_id, str(c.before["parent"]), str((c.after or {})["parent"])
                        )
                    elif c.op is Op.TRASH:
                        self.writer.set_trashed(c.file_id, False)
                    else:
                        self.writer.update_file(c.file_id, c.before)
                c.state = ChangeState.UNDONE
            except DriveHttpError as exc:
                c.state, c.error = ChangeState.UNDO_FAILED, f"{exc.status}:{exc.reason}"
