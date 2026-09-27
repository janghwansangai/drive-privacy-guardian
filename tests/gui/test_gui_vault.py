"""Phase 6 GUI: archive flow (restrict → password → archive → verified → trash → undo),
moves blocked when they would widen access, suggestions, and opening an archive."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialogButtonBox, QFileDialog, QInputDialog

from dpg.core.actions.model import ActionKind
from dpg.core.auth.scopes import AccessLevel
from dpg.core.drive.client import VAULT_NAME_RE
from dpg.core.vault import archive
from dpg.core.vault.archive import ArchiveFormat
from dpg.gui.actions_ui import ActionDialog, HistoryDialog, ResultDialog
from dpg.gui.main_window import MainWindow
from dpg.gui.vault_ui import (
    ArchiveDialog,
    ArchiveResultDialog,
    MoveDialog,
    OrganizeDialog,
    PasswordDialog,
    recovery_card_html,
)
from tests.gui.test_gui import Env, _audit, _login, _select_file

pytestmark = pytest.mark.enable_socket


def _window(qtbot: Any, env: Env) -> MainWindow:
    assert env.ctx is not None
    _login(env)
    env.ctx.manager.login(AccessLevel.MODIFY)
    env.fake.read_only = False
    window = MainWindow(env.ctx)
    qtbot.addWidget(window)
    return window


def test_archive_flow_end_to_end(qtbot: Any, env: Env) -> None:
    assert env.ctx is not None
    fid = env.fake.add_file("가상명단.csv", content=b"name,phone\nA,010\n")
    env.fake.share(fid, "anyone", "reader")
    vault_dir = env.fake.add_folder("비공개 보관함")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    seen: dict[str, Any] = {}

    def show(dialog: Any) -> int:
        if isinstance(dialog, ArchiveDialog):
            assert "영구 삭제" in dialog.findChildren(type(dialog.fmt_warning))[0].text()
            dialog.fmt.setCurrentIndex(1)
            assert "파일 이름" in dialog.fmt_warning.text()  # AES-ZIP trade-off shown
            dialog.fmt.setCurrentIndex(0)
            assert "원래 있던 자리" in dialog.dest.itemText(0)  # in place is the default
            assert dialog.replace.isChecked()
            dialog.select_destination(vault_dir)
            return 1
        if isinstance(dialog, ActionDialog):
            assert dialog.plan.action is ActionKind.RESTRICT_ALL
            assert not dialog.dry_run.isEnabled()
            return 1
        if isinstance(dialog, PasswordDialog):
            assert dialog.save_keychain.isChecked()  # keychain by default
            assert "키체인 접근" in dialog.findChildren(type(dialog.note))[1].text()
            dialog.save_keychain.setChecked(False)
            assert not dialog.ok.isEnabled()  # then it must have been written down
            dialog.recorded.setChecked(True)
            assert dialog.ok.isEnabled()
            dialog.save_keychain.setChecked(True)
            seen["password"] = dialog.field.text()
            return 1
        if isinstance(dialog, ArchiveResultDialog):
            assert dialog.finish_btn.text().startswith("✓ 암호화 완료")
            dialog._finish()
            seen["archive_done"] = True
            return 1
        if isinstance(dialog, ResultDialog):
            seen.setdefault("results", []).append(dialog)
            close = dialog.findChild(QDialogButtonBox).buttons()
            seen.setdefault("buttons", []).extend(b.text() for b in close)
            return 0
        return 0

    env.ctx.show_dialog = show
    _select_file(window, "가상명단.csv")
    window.archive_selected()
    qtbot.waitUntil(lambda: env.fake.items[fid].trashed, timeout=20000)
    qtbot.waitUntil(lambda: window.task is None, timeout=20000)
    assert env.fake.visibility(env.fake.items[fid]) == "limited"  # step 1 happened
    assert "✓ 암호화 완료" in seen["buttons"]  # the final dialog says "done", not "close"
    assert fid not in window.model.checked  # user report: the processed file stayed checked
    uploaded = [
        it
        for it in env.fake.items.values()
        if VAULT_NAME_RE.match(it.name) and it.name.endswith(".7z")
    ]
    assert len(uploaded) == 1
    assert uploaded[0].parent == vault_dir
    pw = seen["password"]
    assert archive.open_archive(uploaded[0].content or b"", pw) == {
        "가상명단.csv": b"name,phone\nA,010\n"
    }
    assert env.store.get(f"vault:{uploaded[0].name}") == pw  # opted-in keychain copy
    assert env.fake.call_count("files.delete") == 0

    # the trash step is in the history and can be undone
    def show_history(dialog: Any) -> int:
        if isinstance(dialog, HistoryDialog):
            labels = [dialog.table.item(r, 2).text() for r in range(dialog.table.rowCount())]
            row = labels.index("원본 휴지통 이동 (보관 후)")
            dialog.table.selectRow(row)
            dialog._undo()
            return 1
        return 0

    env.ctx.show_dialog = show_history
    window.open_history()
    qtbot.waitUntil(lambda: not env.fake.items[fid].trashed, timeout=15000)
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)


def test_archive_cancel_at_password_changes_nothing_more(qtbot: Any, env: Env) -> None:
    assert env.ctx is not None
    fid = env.fake.add_file("가상.txt", content=b"x")  # nothing to restrict
    window = _window(qtbot, env)
    _audit(qtbot, window)

    def show(dialog: Any) -> int:
        return 1 if isinstance(dialog, ArchiveDialog) else 0

    env.ctx.show_dialog = show
    _select_file(window, "가상.txt")
    window.archive_selected()
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)
    assert env.fake.call_count("files.create") == 0
    assert not env.fake.items[fid].trashed


def test_move_dialog_blocks_widening(qtbot: Any, env: Env) -> None:
    assert env.ctx is not None
    fid = env.fake.add_file("가상 상담.txt", content=b"x")
    public = env.fake.add_folder("공개 폴더")
    env.fake.share(public, "anyone", "reader")
    private = env.fake.add_folder("개인 폴더")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    captured: list[MoveDialog] = []

    def show(dialog: Any) -> int:
        if isinstance(dialog, MoveDialog):
            captured.append(dialog)
            dialog.select(public)
            ok = dialog.buttons.buttons()[0]
            assert dialog.plan is not None
            assert dialog.plan.changes == []
            assert "차단" in dialog.plan.skipped[0].reason
            assert not ok.isEnabled()
            dialog.select(private)
            assert len(dialog.plan.changes) == 1
            return 1
        return 0

    env.ctx.show_dialog = show
    _select_file(window, "가상 상담.txt")
    window.move_selected()
    qtbot.waitUntil(lambda: env.fake.items[fid].parent == private, timeout=15000)
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)


def test_organize_dialog_lists_duplicates(qtbot: Any, env: Env) -> None:
    assert env.ctx is not None
    env.fake.add_file("a.txt", content=b"same")
    env.fake.add_file("b.txt", content=b"same")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    captured: list[OrganizeDialog] = []
    env.ctx.show_dialog = lambda d: captured.append(d) or 0  # type: ignore[func-returns-value]
    window.show_organize()
    dialog = captured[0]
    assert dialog.dup_table.rowCount() == 2
    # without detection every file is "보류", never "일반"
    col = [dialog.suggest_table.item(r, 1).text() for r in range(dialog.suggest_table.rowCount())]
    assert set(col) == {"보류"}


def test_open_archive_from_menu(
    qtbot: Any, env: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert env.ctx is not None
    window = MainWindow(env.ctx)
    qtbot.addWidget(window)
    src = tmp_path / "보관.zip"
    src.write_bytes(archive.create({"가상.txt": b"hi"}, "Aa1-pw", ArchiveFormat.AES_ZIP))
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(src), ""))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(out))
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("wrong", True))
    window.open_archive_file()
    assert "비밀번호가 틀렸" in env.notices[-1][1]
    assert not list(out.iterdir())
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("Aa1-pw", True))
    window.open_archive_file()
    assert (out / "가상.txt").read_bytes() == b"hi"


def test_recovery_card_contains_password_only_on_paper() -> None:
    html = recovery_card_html("Abcd-1234")
    assert "Abcd-1234" in html
    assert "7-Zip" in html


def test_trash_needs_verified_result(qtbot: Any) -> None:
    from dpg.core.vault.job import ArchiveResult

    unverified = ArchiveResult("보관.7z", ArchiveFormat.SEVEN_ZIP, members={"f1": "a.txt"})
    unverified.verified = True  # uploaded copy not verified
    dialog = ArchiveResultDialog(unverified, {"f1": "a.txt"})
    qtbot.addWidget(dialog)
    assert not dialog._checks[0].isEnabled()
    assert not dialog._checks[0].isChecked()
    assert "원본 그대로" in dialog.finish_btn.text()
    dialog._finish()
    assert dialog.approved == []  # nothing is trashed without both verifications


def test_archive_result_defaults_to_trashing_originals(qtbot: Any) -> None:
    from dpg.core.vault.job import ArchiveResult

    ok = ArchiveResult("보관.7z", ArchiveFormat.SEVEN_ZIP, members={"f1": "a.txt", "f2": "b.txt"})
    ok.verified = ok.upload_verified = True
    dialog = ArchiveResultDialog(ok, {"f1": "a.txt", "f2": "b.txt"})
    qtbot.addWidget(dialog)
    assert all(b.isChecked() for b in dialog._checks)  # default: originals go to the trash
    assert dialog.finish_btn.text() == "✓ 암호화 완료 (원본 2개 휴지통으로)"
    dialog.check("f2", False)
    assert dialog.finish_btn.text() == "✓ 암호화 완료 (원본 1개 휴지통으로)"
    dialog._finish()
    assert dialog.approved == ["f1"]


def test_action_buttons_follow_checkboxes(qtbot: Any, env: Env) -> None:
    from PySide6.QtCore import Qt

    from dpg.gui.results_model import COL_CHECK

    env.fake.add_file("가상.txt", content=b"x")
    window = _window(qtbot, env)
    assert not window.archive_btn.isEnabled()
    assert window.unpack_btn.isEnabled()  # works without an audit (local file)
    _audit(qtbot, window)
    assert not window.change_btn.isEnabled()  # nothing chosen yet
    assert "체크박스" in window.selection_label.text()
    idx = window.proxy.index(0, COL_CHECK)
    window.proxy.setData(idx, Qt.CheckState.Checked.value, Qt.ItemDataRole.CheckStateRole)
    for b in (window.change_btn, window.archive_btn, window.move_btn, window.organize_btn):
        assert b.isEnabled()
    assert "1개" in window.selection_label.text()
    assert len(window.selected_items()) == 1
    window.uncheck_all()
    assert not window.change_btn.isEnabled()
    # header checkbox: all rows shown in this view, then none
    assert window._visible_check_state() == Qt.CheckState.Unchecked
    window.check_header.click_checkbox()
    assert len(window.selected_items()) == window.proxy.rowCount()
    assert window._visible_check_state() == Qt.CheckState.Checked
    window.check_header.click_checkbox()
    assert window.selected_items() == []


def test_unpack_to_this_computer_without_saving_the_archive(
    qtbot: Any, env: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dpg.gui.vault_ui import UnpackDialog

    assert env.ctx is not None
    blob = archive.create({"가상명단.csv": b"a,b\n"}, "Aa1-pw", ArchiveFormat.SEVEN_ZIP)
    arc = env.fake.add_file(
        "보관_2026-09-26_ab12.7z", content=blob, mime_type="application/x-7z-compressed"
    )
    window = _window(qtbot, env)
    _audit(qtbot, window)
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(out))
    opened: list[bool] = []
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: opened.append(True))

    def show(dialog: Any) -> int:
        if isinstance(dialog, UnpackDialog):
            assert dialog.to_drive.isChecked()  # default: in place on Drive
            assert not dialog.ok.isEnabled()
            dialog.to_local.setChecked(True)
            dialog.password.setText("Aa1-pw")
            dialog.done(1)
            return 1
        return 0

    env.ctx.show_dialog = show
    _select_file(window, "보관_2026-09-26_ab12.7z")
    window.unpack_btn.click()
    qtbot.waitUntil(lambda: (out / "가상명단.csv").exists(), timeout=15000)
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)
    assert (out / "가상명단.csv").read_bytes() == b"a,b\n"
    assert opened == []  # no local file picker
    assert not list(tmp_path.rglob("*.7z"))  # the archive itself never touched the disk
    assert not env.fake.items[arc].trashed  # local mode keeps the Drive archive


def test_change_dialog_uses_google_wording_and_sections(qtbot: Any) -> None:
    from dpg.core.actions.model import PERMISSION_ACTIONS, Plan

    dialog = ActionDialog(lambda k: Plan(k), {}, ActionKind.REMOVE_LINK, False)
    qtbot.addWidget(dialog)
    texts = [dialog.kind.itemText(i) for i in range(dialog.kind.count())]
    assert "── 일반 액세스 ──" in texts
    assert "── 액세스 권한이 있는 사용자 ──" in texts
    assert "── 설정 ⚙ ──" in texts
    assert any("'제한됨'" in t for t in texts)
    assert any("액세스 권한 삭제" in t for t in texts)
    assert any("편집자가 권한을 변경하고 공유할 수 있음" in t for t in texts)
    assert "공유 → 일반 액세스" in dialog.hint.text()
    for kind in PERMISSION_ACTIONS:
        dialog.kind.setCurrentIndex(dialog.kind.findData(kind))
        assert dialog.plan.action is kind
        assert dialog.hint.text()
    # section headers cannot be chosen
    model = dialog.kind.model()
    header = model.index(texts.index("── 설정 ⚙ ──"), 0)
    assert not (model.flags(header) & mw_flags().ItemIsEnabled)


def mw_flags() -> Any:
    from PySide6.QtCore import Qt

    return Qt.ItemFlag


def test_vault_filter_and_unpack_in_place_with_saved_password(qtbot: Any, env: Env) -> None:
    from dpg.gui.results_model import COL_NAME, COL_NOTES
    from dpg.gui.vault_ui import UnpackDialog

    assert env.ctx is not None
    folder = env.fake.add_folder("비공개 보관함")
    blob = archive.create({"가상.txt": b"hello"}, "Saved-Pw-1", ArchiveFormat.SEVEN_ZIP)
    arc = env.fake.add_file(
        "보관_2026-09-26_beef.7z", folder, content=blob, mime_type="application/x-7z-compressed"
    )
    env.fake.add_file("다른.zip", content=b"PK", mime_type="application/zip")
    window = _window(qtbot, env)
    env.store.set("vault:보관_2026-09-26_beef.7z", "Saved-Pw-1")
    _audit(qtbot, window)
    assert window.dash_buttons["vault"].text().endswith("1")
    window.vault_btn.click()  # the vault is a view of the same file list
    assert window.proxy.rowCount() == 1
    assert window.proxy.index(0, COL_NAME).data() == "보관_2026-09-26_beef.7z"
    assert "키체인에 저장됨" in window.proxy.index(0, COL_NOTES).data()

    def show(dialog: Any) -> int:
        if isinstance(dialog, UnpackDialog):
            assert dialog.uses_saved
            assert dialog.ok.isEnabled()
            dialog.done(1)
            return 1
        return 0  # ResultDialog of the trash step

    env.ctx.show_dialog = show
    window.table.selectRow(0)
    window.unpack_btn.click()
    qtbot.waitUntil(lambda: env.fake.items[arc].trashed, timeout=15000)
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)
    restored = [it for it in env.fake.items.values() if it.name == "가상.txt"]
    assert len(restored) == 1
    assert restored[0].parent == folder
    assert restored[0].content == b"hello"
    assert env.fake.call_count("files.delete") == 0
    # after the automatic re-check the vault view no longer lists the trashed archive
    qtbot.waitUntil(lambda: window.proxy.rowCount() == 0, timeout=15000)


def test_default_sort_is_folders_then_their_files(qtbot: Any, env: Env) -> None:
    from dpg.gui.results_model import COL_LOCATION, COL_NAME

    env.fake.add_file("z-맨위파일.txt", content=b"x")
    folder = env.fake.add_folder("가-폴더")
    env.fake.add_file("나-안쪽파일.txt", folder, content=b"x")
    env.fake.add_folder("다-폴더")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    names = [window.proxy.index(r, COL_NAME).data() for r in range(window.proxy.rowCount())]
    assert names == ["📁 가-폴더 /", "나-안쪽파일.txt", "📁 다-폴더 /", "z-맨위파일.txt"]
    locs = [window.proxy.index(r, COL_LOCATION).data() for r in range(window.proxy.rowCount())]
    assert locs[1] == "내 드라이브 › 가-폴더"
    window.sort_combo.setCurrentIndex(2)  # 이름 순
    names = [window.proxy.index(r, COL_NAME).data() for r in range(window.proxy.rowCount())]
    assert names == sorted(names)


def test_exclusion_list_and_restore_rescans(qtbot: Any, env: Env) -> None:
    from dpg.core.policy import DetectStatus
    from dpg.gui.vault_ui import ExclusionsDialog

    assert env.ctx is not None
    fid = env.fake.add_file("가상 메모.txt", content="연락처 010-1234-5678".encode())
    window = _window(qtbot, env)
    window.detect_check.setChecked(True)
    _audit(qtbot, window)
    assert window.detections is not None
    before = window.detections[fid].status
    _select_file(window, "가상 메모.txt")
    window.exclude_selected()
    assert window.detections[fid].status is DetectStatus.EXCLUDED
    assert window.dash_buttons["excluded"].text().endswith("1")  # shown in 결과 요약
    window.set_filter("excluded")
    assert window.proxy.rowCount() == 1  # the excluded list can be viewed in the table
    window.set_filter("all")

    def show(dialog: Any) -> int:
        if isinstance(dialog, ExclusionsDialog):
            assert dialog.table.item(0, 1).text() == "가상 메모.txt"
            assert not dialog.restore_btn.isEnabled()
            dialog.check(0)
            dialog._restore()
            return 1
        return 0

    env.ctx.show_dialog = show
    window.exclusions_btn.click()
    qtbot.waitUntil(lambda: window.detections[fid].status is before, timeout=15000)
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)


def test_checks_in_other_views_are_reported_and_cleared(qtbot: Any, env: Env) -> None:
    link = env.fake.add_file("공지.txt", content=b"x")
    env.fake.share(link, "anyone", "reader")
    env.fake.add_file("개인.txt", content=b"y")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    window.set_filter("link")
    window.check_header.click_checkbox()  # check the link file only
    window.set_filter("restricted")
    assert window._visible_check_state() == Qt.CheckState.Unchecked
    assert "다른 보기" in window.selection_label.text()  # hidden check is not silent
    window.check_header.click_checkbox()
    assert len(window.model.checked) == 2
    window.uncheck_all()  # clears the hidden one too
    assert window.model.checked == set()


def test_exclude_button_turns_into_restore(qtbot: Any, env: Env) -> None:
    from dpg.core.policy import DetectStatus

    assert env.ctx is not None
    fid = env.fake.add_file("가상 메모.txt", content="연락처 010-1234-5678".encode())
    window = _window(qtbot, env)
    window.detect_check.setChecked(True)
    _audit(qtbot, window)
    before = window.detections[fid].status  # type: ignore[index]
    _select_file(window, "가상 메모.txt")
    assert "제외" in window.exclude_btn.text()
    window.exclude_selected()
    window.set_filter("excluded")
    window.check_header.click_checkbox()
    assert window.exclude_btn.text().startswith("↩")
    window.exclude_btn.click()
    qtbot.waitUntil(
        lambda: window.detections[fid].status is before,  # type: ignore[index]
        timeout=15000,
    )
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)
    assert window.detections[fid].status is not DetectStatus.EXCLUDED  # type: ignore[index]


def test_move_into_a_new_folder_and_to_top_level(
    qtbot: Any, env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dpg.gui.results_model import COL_NAME

    assert env.ctx is not None
    team = env.fake.add_folder("학년 폴더")
    env.fake.share(team, "user", "writer", email="colleague@school.example")
    fid = env.fake.add_file("가상 기록.txt", team, content=b"x")
    private = env.fake.add_folder("개인 폴더")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    # folders look different from files
    row = next(
        r
        for r in range(window.proxy.rowCount())
        if window.proxy.index(r, COL_NAME).data() == "📁 개인 폴더 /"
    )
    assert window.proxy.index(row, COL_NAME).data(Qt.ItemDataRole.FontRole).bold()
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("2026 보관", True))

    def show(dialog: Any) -> int:
        if isinstance(dialog, MoveDialog):
            assert dialog.dest.itemText(0) == "🏠 내 드라이브 (최상위)"
            dialog.select(private)
            dialog.new_btn.click()  # new folder inside the private folder
            assert dialog.dest.currentText().startswith("🆕")
            assert dialog.plan is not None
            assert len(dialog.plan.changes) == 1
            return 1
        return 0

    env.ctx.show_dialog = show
    _select_file(window, "가상 기록.txt")
    window.move_selected()
    made = [it for it in env.fake.items.values() if it.name == "2026 보관"]
    assert len(made) == 1
    assert made[0].parent == private
    qtbot.waitUntil(lambda: env.fake.items[fid].parent == made[0].id, timeout=15000)
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)


def test_new_folder_inside_a_shared_folder_is_treated_as_shared() -> None:
    from dpg.core.audit.model import Exposure, ItemStatus, Origin, PermissionView
    from dpg.core.audit.model import FileAudit as FA
    from dpg.core.organize import build_move_plan, new_folder_audit

    def perm(email: str, role: str) -> PermissionView:
        return PermissionView(
            email, "user", role, email, None, False, Origin.DIRECT, None, False, False, None
        )

    shared = FA(
        "s", "공유", "application/vnd.google-apps.folder", True, None, "r", "me@x", True, None,
        ItemStatus.OK, Exposure.RESTRICTED, 0, internal_accounts=1,
        permissions=[perm("me@x", "owner"), perm("friend@x", "writer")],
    )  # fmt: skip
    new = new_folder_audit("n", "새 폴더", shared)
    private_file = FA(
        "f", "a.txt", "text/plain", False, None, "r", "me@x", True, None, ItemStatus.OK,
        Exposure.RESTRICTED, 0, permissions=[perm("me@x", "owner")],
    )  # fmt: skip
    plan = build_move_plan([private_file], new, [shared, new, private_file])
    assert plan.changes == []
    assert "차단" in plan.skipped[0].reason


def test_second_audit_only_rechecks_changes_and_live_refresh(qtbot: Any, env: Env) -> None:
    from dpg.gui.results_model import COL_NAME

    env.fake.add_file("처음.txt", content=b"x")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    assert "감사 완료" in window.progress_label.text()
    lists = env.fake.call_count("files.list")
    _audit(qtbot, window)  # nothing changed: incremental, no file listing at all
    assert "바뀐 부분만" in window.progress_label.text()
    assert env.fake.call_count("files.list") == lists

    # live check: no change -> no audit is started
    window._live_tick()
    qtbot.waitUntil(lambda: window._live_check is None, timeout=10000)
    assert window.task is None
    assert "마지막 확인" in window.live_label.text()

    # a folder is created on Drive (e.g. in the browser) -> shows up by itself
    env.fake.add_folder("새로 만든 폴더")
    window._live_tick()
    qtbot.waitUntil(
        lambda: any(
            window.proxy.index(r, COL_NAME).data() == "📁 새로 만든 폴더 /"
            for r in range(window.proxy.rowCount())
        ),
        timeout=15000,
    )
    qtbot.waitUntil(lambda: window.task is None, timeout=15000)
    assert "드라이브 변경 반영" in window.progress_label.text()
    assert env.fake.write_calls == []


def test_live_refresh_can_be_turned_off(qtbot: Any, env: Env) -> None:
    assert env.ctx is not None
    window = _window(qtbot, env)
    assert window.live_timer.isActive()
    env.ctx.prefs.live_refresh = False
    window._apply_live_setting()
    assert not window.live_timer.isActive()
    assert "꺼짐" in window.live_label.text()


def test_settings_wipe_all_records(qtbot: Any, env: Env, isolated_app_home: Path) -> None:
    from dpg.gui.main_window import SettingsDialog, WipeDialog

    assert env.ctx is not None
    env.fake.add_file("가상.txt", content=b"x")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    assert list((isolated_app_home / "data").glob("*.db"))

    def show(dialog: Any) -> int:
        if isinstance(dialog, SettingsDialog):
            dialog._wipe()
            return 1
        if isinstance(dialog, WipeDialog):
            assert not dialog.ok.isEnabled()
            dialog.confirm.setText("삭제")
            assert dialog.ok.isEnabled()
            return 1
        return 0

    env.ctx.show_dialog = show
    window.open_settings()
    assert not list((isolated_app_home / "data").glob("*.db"))
    assert window.result is None
    assert window.model.rowCount() == 0
    assert "지웠습니다" in env.notices[-1][1]
    assert env.ctx.manager.status().logged_in  # login kept unless asked


def test_checklist_is_local_and_remembered(qtbot: Any, env: Env) -> None:
    from dpg.core.checklist import all_keys
    from dpg.gui.checklist_ui import ChecklistDialog

    assert env.ctx is not None
    window = MainWindow(env.ctx)
    qtbot.addWidget(window)

    def show(dialog: Any) -> int:
        if isinstance(dialog, ChecklistDialog):
            assert len(dialog.boxes) == len(all_keys()) >= 20
            dialog.boxes["g-2sv"].setChecked(True)
            dialog.boxes["n-321"].setChecked(True)
            return 0
        return 0

    env.ctx.show_dialog = show
    window.show_checklist()
    assert env.ctx.prefs.checklist_done == ["g-2sv", "n-321"]
    assert env.fake.calls == []  # no Drive / network use


def test_wipe_keeps_archive_passwords_unless_explicitly_confirmed(qtbot: Any, env: Env) -> None:
    from dpg.core.store.wipe import remember_vault_password
    from dpg.gui.main_window import SettingsDialog, WipeDialog

    assert env.ctx is not None
    window = _window(qtbot, env)
    remember_vault_password(env.store, "보관_2026-09-26_ab12.7z", "Pw-1")
    seen: dict[str, Any] = {}

    def show(dialog: Any) -> int:
        if isinstance(dialog, SettingsDialog):
            dialog._wipe()
            return 1
        if isinstance(dialog, WipeDialog):
            texts = " ".join(lbl.text() for lbl in dialog.findChildren(type(dialog.vault_warn)))
            assert "1개는 지우지 않고 그대로" in texts
            assert not dialog.vault.isChecked()
            dialog.vault.setChecked(True)
            dialog.confirm.setText("삭제")
            assert not dialog.ok.isEnabled()  # a stronger phrase is needed for passwords
            dialog.confirm.setText("비밀번호까지 삭제")
            assert dialog.ok.isEnabled()
            dialog.vault.setChecked(False)  # changed their mind: back to the plain phrase
            assert not dialog.ok.isEnabled()
            dialog.confirm.setText("삭제")
            seen["ok"] = dialog.ok.isEnabled()
            return 1
        return 0

    env.ctx.show_dialog = show
    window.open_settings()
    assert seen["ok"]
    assert env.store.get("vault:보관_2026-09-26_ab12.7z") == "Pw-1"  # archive stays openable


def test_checklist_says_ticking_is_not_protection(qtbot: Any) -> None:
    from PySide6.QtWidgets import QLabel

    from dpg.gui.checklist_ui import ChecklistDialog

    dialog = ChecklistDialog(set(), lambda _u: None)
    qtbot.addWidget(dialog)
    labels = " ".join(w.text() for w in dialog.findChildren(QLabel))
    assert "스스로 점검" in labels
    assert "보안이 강화되지는 않습니다" in labels


def test_login_steps_tell_to_press_continue(qtbot: Any, env: Env) -> None:
    from dpg.gui.wizard import LOGIN_STEPS_HTML, SetupWizard

    assert env.ctx is not None
    assert LOGIN_STEPS_HTML.count("「계속」") >= 3
    assert "Google에서 확인하지 않은 앱" in LOGIN_STEPS_HTML
    wizard = SetupWizard(env.ctx)
    qtbot.addWidget(wizard)
    assert "계속" in wizard.login_page.steps.text()


def test_logout_then_log_in_again(qtbot: Any, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    assert env.ctx is not None
    env.fake.add_file("가상.txt", content=b"x")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    assert window.logout_btn.text() == "로그아웃"
    window.logout_btn.click()  # ctx.confirm answers yes
    assert not env.ctx.manager.status().logged_in
    assert window.logout_btn.text() == "🔑 로그인"
    assert window.logout_btn.isEnabled()
    assert window.model.rowCount() == 0  # previous account's results are cleared
    assert not window.start_btn.isEnabled()

    def fake_setup(level: AccessLevel = AccessLevel.AUDIT) -> bool:
        env.ctx.manager.login(level)  # type: ignore[union-attr]
        window.refresh_account()
        return True

    monkeypatch.setattr(window, "run_setup", fake_setup)
    window.logout_btn.click()
    assert env.ctx.manager.status().logged_in
    assert window.logout_btn.text() == "로그아웃"
    assert window.start_btn.isEnabled()


def test_recovery_key_opens_archive_after_losing_every_password(
    qtbot: Any, env: Env, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from dpg.core.store.wipe import wipe_local_records
    from dpg.core.vault.recovery import RECOVERY_KEY_NAME
    from dpg.gui.vault_ui import RecoveryKeyDialog, UnpackDialog

    assert env.ctx is not None
    fid = env.fake.add_file("가상 상담.txt", content=b"secret-ish")
    window = _window(qtbot, env)
    _audit(qtbot, window)
    paper: dict[str, str] = {}

    def show(dialog: Any) -> int:
        if isinstance(dialog, ArchiveDialog):
            return 1
        if isinstance(dialog, RecoveryKeyDialog):
            assert not dialog.ok.isEnabled()  # must confirm a paper copy exists
            paper["key"] = dialog.field.text()
            dialog.kept.setChecked(True)
            return 1
        if isinstance(dialog, PasswordDialog):
            assert dialog.recoverable
            dialog.save_keychain.setChecked(False)  # not even the per-archive copy
            assert dialog.ok.isEnabled()  # recoverable: no need to write it down
            return 1
        if isinstance(dialog, ArchiveResultDialog):
            dialog._trash()
            return 1
        return 0

    env.ctx.show_dialog = show
    _select_file(window, "가상 상담.txt")
    window.archive_selected()
    qtbot.waitUntil(lambda: env.fake.items[fid].trashed, timeout=20000)
    qtbot.waitUntil(lambda: window.task is None, timeout=20000)
    assert env.ctx.prefs.recovery_fingerprint
    arc = next(it for it in env.fake.items.values() if VAULT_NAME_RE.match(it.name))
    assert arc.name.startswith("가상 상담.txt (암호화 ")  # D-087: the name shows what is inside

    # everything in the keychain is gone (wiped with "비밀번호까지 삭제")
    wipe_local_records(env.store, include_vault_passwords=True)
    assert env.store.get(RECOVERY_KEY_NAME) is None
    window.uncheck_all()
    _audit(qtbot, window)

    def show_unpack(dialog: Any) -> int:
        if isinstance(dialog, UnpackDialog):
            assert not dialog.uses_saved  # nothing saved any more
            assert "복구 키" in dialog.recover_hint.text()
            dialog.password.setText(paper["key"].lower().replace("-", " "))  # typed from paper
            dialog.done(1)
            return 1
        return 0

    env.ctx.show_dialog = show_unpack
    _select_file(window, arc.name)
    window.unpack_btn.click()
    qtbot.waitUntil(lambda: env.fake.items[arc.id].trashed, timeout=20000)
    qtbot.waitUntil(lambda: window.task is None, timeout=20000)
    restored = [
        it for it in env.fake.items.values() if it.name == "가상 상담.txt" and not it.trashed
    ]
    assert len(restored) == 1
    assert restored[0].content == b"secret-ish"


def test_recovery_key_is_never_replaced_and_reentry_checks_fingerprint(
    qtbot: Any, env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dpg.core.vault.recovery import RECOVERY_KEY_NAME, new_recovery_key
    from dpg.gui.vault_ui import RecoveryKeyDialog

    assert env.ctx is not None
    window = MainWindow(env.ctx)
    qtbot.addWidget(window)

    def accept_new(dialog: Any) -> int:
        if isinstance(dialog, RecoveryKeyDialog):
            dialog.kept.setChecked(True)
            return 1
        return 0

    env.ctx.show_dialog = accept_new
    window.create_recovery_key()
    first = env.store.get(RECOVERY_KEY_NAME)
    assert first
    window.create_recovery_key()  # a second key would orphan archives made with the first
    assert env.store.get(RECOVERY_KEY_NAME) == first

    env.store.delete(RECOVERY_KEY_NAME)
    other = new_recovery_key()
    asked: list[str] = []
    env.ctx.confirm = lambda _p, _t, text, *a: asked.append(text) or False  # type: ignore[func-returns-value]
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: (other, True))
    assert window.enter_recovery_key() is False  # different fingerprint -> asked, declined
    assert "다른 키" in asked[0]
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: (first, True))
    assert window.enter_recovery_key() is True
    assert env.store.get(RECOVERY_KEY_NAME) == first


def test_check_update_only_opens_the_browser(
    qtbot: Any, env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dpg

    assert env.ctx is not None
    window = MainWindow(env.ctx)
    qtbot.addWidget(window)
    monkeypatch.setattr(dpg, "REPOSITORY_URL", "")
    window.check_update()
    assert "저장소 주소" in env.notices[-1][1]
    monkeypatch.setattr(dpg, "REPOSITORY_URL", "https://github.com/example/dpg/")
    window.check_update()
    assert env.opened[-1] == "https://github.com/example/dpg/releases"
    assert env.fake.calls == []
