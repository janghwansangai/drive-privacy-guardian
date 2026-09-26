"""Phase 5 gate (SPEC 7): normal / partial failure / cancel / conflict / undo on fake_drive,
and zero attempts to change owner or inherited permissions."""

from __future__ import annotations

import ast
import os
import threading
from pathlib import Path

import pytest

from dpg.core.actions.executor import ActionCancelled, ActionExecutor
from dpg.core.actions.model import ActionKind, ChangeState
from dpg.core.actions.planner import build_plan
from dpg.core.audit.analyze import internal_domains_for
from dpg.core.audit.model import Exposure
from dpg.core.audit.runner import AuditRunner, AuditScope
from dpg.core.drive.client import DriveClient
from dpg.core.store.audit_store import AuditStore
from dpg.core.store.crypto import ColumnCipher
from tests.fakes.fake_drive import FakeDrive

ME = "teacher@school.example"
INTERNAL = internal_domains_for(ME)
SRC = Path(__file__).resolve().parents[2] / "src" / "dpg"


@pytest.fixture
def store(tmp_path: Path) -> AuditStore:
    s = AuditStore(tmp_path / "a.db", ColumnCipher(os.urandom(32)))
    yield s  # type: ignore[misc]
    s.close()


def _drive() -> tuple[FakeDrive, dict[str, str]]:
    f = FakeDrive(me=ME, read_only=False)
    ids = {"link": f.add_file("공지.pdf")}
    f.share(ids["link"], "anyone", "writer")
    ids["ext"] = f.add_file("명단.xlsx")
    f.share(ids["ext"], "user", "writer", email="parent@gmail.example")
    f.share(ids["ext"], "user", "reader", email="colleague@school.example")
    ids["folder"] = f.add_folder("공유 폴더")
    f.share(ids["folder"], "anyone", "reader")
    ids["child"] = f.add_file("child.txt", parent=ids["folder"])  # link inherited from folder
    ids["domain"] = f.add_file("도메인.txt")
    f.share(ids["domain"], "domain", "reader", domain="school.example")
    ids["other"] = f.add_file("남의 파일", owner="other@school.example")
    f.share(ids["other"], "user", "writer", email=ME)
    f.share(ids["other"], "anyone", "reader")
    return f, ids


def _audit(fake: FakeDrive, store: AuditStore) -> dict[str, object]:
    result = AuditRunner(DriveClient(fake.service()), store, account=ME).run(
        AuditScope.parse("mine")
    )
    shared = AuditRunner(DriveClient(fake.service()), store, account=ME).run(
        AuditScope.parse("shared")
    )
    return {a.file_id: a for a in [*result.items, *shared.items]}


def _plan(kind: ActionKind, audits: dict[str, object], ids: list[str]) -> object:
    return build_plan(
        kind,
        [audits[i] for i in ids],
        account=ME,  # type: ignore[misc]
        internal_domains=INTERNAL,
        all_items=list(audits.values()),
    )  # type: ignore[arg-type]


def _write_targets(fake: FakeDrive) -> list[tuple[str, str | None]]:
    return [(n, kw.get("permissionId")) for n, kw in fake.write_calls]


def test_plan_skips_owner_inherited_and_unknown(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    plan = _plan(ActionKind.REMOVE_LINK, audits, list(ids.values()))
    planned = {(c.file_id, c.perm_id) for c in plan.changes}  # type: ignore[attr-defined]
    assert (ids["link"], "anyoneWithLink") in planned
    assert (ids["folder"], "anyoneWithLink") in planned
    assert all(fid != ids["child"] for fid, _ in planned)  # inherited: change the folder instead
    reasons = {s.file_id: s.reason for s in plan.skipped}  # type: ignore[attr-defined]
    assert "상위 폴더" in reasons[ids["child"]]
    assert plan.folder_children == {ids["folder"]: 1}  # type: ignore[attr-defined]
    # external removal never targets the owner or me or an internal colleague
    ext = _plan(ActionKind.REMOVE_EXTERNAL, audits, [ids["ext"]])
    assert [c.before["emailAddress"] for c in ext.changes] == ["parent@gmail.example"]  # type: ignore[attr-defined]


def test_normal_run_and_undo(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    client = DriveClient(fake.service())
    plan = _plan(ActionKind.REMOVE_LINK, audits, [ids["link"], ids["folder"]])
    result = ActionExecutor(client, store).execute(plan)  # type: ignore[arg-type]
    assert result.count(ChangeState.DONE) == 2
    assert fake.visibility(fake.items[ids["link"]]) == "limited"
    assert fake.visibility(fake.items[ids["child"]]) == "limited"  # inherited link gone too
    assert fake.notifications == []

    undo = ActionExecutor(client, store).undo(result.run_id)
    assert undo.count(ChangeState.UNDONE) == 2
    assert fake.visibility(fake.items[ids["link"]]) == "anyoneWithLink"
    assert fake.items[ids["link"]].permissions[0].role == "writer"  # role restored exactly
    assert fake.notifications == []  # re-creating never e-mails anyone (V9)
    # owner / inherited permissions were never touched
    assert all(pid in ("anyoneWithLink", None) for _n, pid in _write_targets(fake))


def test_role_updates_and_file_settings_with_undo(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    client = DriveClient(fake.service())
    ex = ActionExecutor(client, store)
    r1 = ex.execute(_plan(ActionKind.LINK_TO_VIEW, audits, [ids["link"]]))  # type: ignore[arg-type]
    r2 = ex.execute(_plan(ActionKind.EDITORS_TO_VIEWERS, audits, [ids["ext"]]))  # type: ignore[arg-type]
    r3 = ex.execute(_plan(ActionKind.DISABLE_RESHARE, audits, [ids["ext"]]))  # type: ignore[arg-type]
    r4 = ex.execute(_plan(ActionKind.RESTRICT_DOWNLOAD, audits, [ids["ext"]]))  # type: ignore[arg-type]
    r5 = ex.execute(_plan(ActionKind.REMOVE_DOMAIN, audits, [ids["domain"]]))  # type: ignore[arg-type]
    for r in (r1, r2, r3, r4, r5):
        assert r.count(ChangeState.DONE) == 1, r.changes
    ext = fake.items[ids["ext"]]
    assert {p.email: p.role for p in ext.permissions}["parent@gmail.example"] == "reader"
    assert ext.writers_can_share is False
    assert ext.download_restricted_for_readers is True
    for r in (r5, r4, r3, r2, r1):
        assert ex.undo(r.run_id).count(ChangeState.UNDONE) == 1
    assert ext.writers_can_share is True
    assert ext.download_restricted_for_readers is False
    assert {p.email: p.role for p in ext.permissions}["parent@gmail.example"] == "writer"
    assert fake.visibility(fake.items[ids["domain"]]) is None  # domain share restored


def test_dry_run_writes_nothing(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    plan = _plan(ActionKind.REMOVE_LINK, audits, [ids["link"]])
    result = ActionExecutor(DriveClient(fake.service()), store).execute(plan, dry_run=True)  # type: ignore[arg-type]
    assert result.count(ChangeState.DRY_RUN_OK) == 1
    assert fake.write_calls == []


def test_conflict_when_changed_after_planning(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    plan = _plan(ActionKind.REMOVE_EXTERNAL, audits, [ids["ext"]])
    # someone else changes the permission between planning and execution
    for p in fake.items[ids["ext"]].permissions:
        if p.email == "parent@gmail.example":
            p.role = "reader"
    result = ActionExecutor(DriveClient(fake.service()), store).execute(plan)  # type: ignore[arg-type]
    assert result.count(ChangeState.CONFLICT) == 1
    assert fake.write_calls == []  # conflicts are not executed; they need re-approval


def test_partial_failure(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    plan = _plan(ActionKind.REMOVE_LINK, audits, [ids["link"], ids["folder"]])
    fake.inject_error(
        "permissions.delete", 500, times=None, when=lambda kw: kw["fileId"] == ids["folder"]
    )
    client = DriveClient(fake.service(), sleep=lambda s: None, max_retries=1)
    result = ActionExecutor(client, store).execute(plan)  # type: ignore[arg-type]
    states = {c.file_id: c.state for c in result.changes}
    assert states == {ids["link"]: ChangeState.DONE, ids["folder"]: ChangeState.FAILED}
    assert fake.visibility(fake.items[ids["folder"]]) == "anyoneWithLink"
    # undo restores only what was actually changed
    fake._injections.clear()
    undo = ActionExecutor(client, store).undo(result.run_id)
    assert {c.file_id: c.state for c in undo.changes} == {
        ids["link"]: ChangeState.UNDONE,
        ids["folder"]: ChangeState.FAILED,
    }


def test_cancel_mid_run(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    plan = _plan(ActionKind.REMOVE_LINK, audits, [ids["link"], ids["folder"]])
    cancel = threading.Event()
    ex = ActionExecutor(
        DriveClient(fake.service()), store, on_progress=lambda p: cancel.set(), cancel=cancel
    )
    with pytest.raises(ActionCancelled):
        ex.execute(plan)  # type: ignore[arg-type]
    states = [c.state for c in plan.changes]  # type: ignore[attr-defined]
    assert states == [ChangeState.DONE, ChangeState.CANCELLED]
    run_id = store.action_runs()[0][0]
    assert store.action_runs()[0][3] == "cancelled"
    assert (
        ActionExecutor(DriveClient(fake.service()), store).undo(run_id).count(ChangeState.UNDONE)
        == 1
    )


def test_before_states_are_encrypted(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    ActionExecutor(DriveClient(fake.service()), store).execute(
        _plan(ActionKind.REMOVE_EXTERNAL, audits, [ids["ext"]])
    )  # type: ignore[arg-type]
    store.close()
    raw = store.path.read_bytes()
    assert b"parent@gmail.example" not in raw


def test_not_owner_cannot_change_file_settings(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    plan = _plan(ActionKind.DISABLE_RESHARE, audits, [ids["other"]])
    assert plan.changes == []  # type: ignore[attr-defined]
    assert "소유자" in plan.skipped[0].reason  # type: ignore[attr-defined]
    # A file shared with me: its parent folder is not visible, so the link's origin is unknown.
    # It is skipped (it might be inherited — SPEC 7: zero inherited-permission attempts).
    link = _plan(ActionKind.REMOVE_LINK, audits, [ids["other"]])
    assert audits[ids["other"]].exposure == Exposure.LINK_VIEW  # type: ignore[attr-defined]
    assert link.changes == []  # type: ignore[attr-defined]
    assert "알 수 없는 곳" in link.skipped[0].reason  # type: ignore[attr-defined]


WRITE_CALLS = {"delete", "update", "create", "emptyTrash", "copy", "trash"}


def test_only_the_writer_module_issues_write_requests() -> None:
    """Every `.permissions().X(` / `.files().X(` write call lives in actions/writer.py."""
    offenders = []
    for path in SRC.rglob("*.py"):
        if path.name == "writer.py" and path.parent.name == "actions":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in WRITE_CALLS
                and isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Attribute)
                and node.func.value.func.attr in ("permissions", "files", "drives")
            ):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert offenders == []
