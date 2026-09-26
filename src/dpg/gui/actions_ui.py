"""Dialogs for permission changes (SPEC 6.2): choose → preview → confirm → result → undo."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtGui import QStandardItemModel
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dpg.core.actions.model import (
    ACTION_GOOGLE_HINT_KO,
    ACTION_LABEL_KO,
    ACTION_SECTIONS_KO,
    PERMISSION_ACTIONS,
    STATE_LABEL_KO,
    ActionKind,
    ChangeState,
    Plan,
    RunResult,
)
from dpg.core.actions.planner import CONFIRM_PHRASE, CONFIRM_THRESHOLD, MAX_FILES_PER_RUN

PlanBuilder = Callable[[ActionKind], Plan]


def _table(headers: list[str], rows: list[list[str]]) -> QTableWidget:
    table = QTableWidget(len(rows), len(headers))
    table.setHorizontalHeaderLabels(headers)
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            table.setItem(r, c, QTableWidgetItem(value))
    table.horizontalHeader().setStretchLastSection(True)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.resizeColumnsToContents()
    return table


class ActionDialog(QDialog):
    """Pick an action and see exactly what will change before anything is written."""

    def __init__(
        self,
        build: PlanBuilder,
        names: dict[str, str],
        default: ActionKind,
        dry_run_default: bool,
        parent: QWidget | None = None,
        kinds: tuple[ActionKind, ...] = PERMISSION_ACTIONS,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("권한 변경 — 미리보기")
        self.resize(900, 600)
        self.build = build
        self.names = names
        self.plan: Plan = build(default)
        self.kind = QComboBox()
        # Grouped like Google's share dialog: 일반 액세스 / 액세스 권한이 있는 사용자 / 설정 ⚙
        model = self.kind.model()
        for section, members in ACTION_SECTIONS_KO:
            shown = [k for k in members if k in kinds]
            if not shown:
                continue
            if len(kinds) > 1:
                self.kind.addItem(f"── {section} ──")
                if isinstance(model, QStandardItemModel):
                    header = model.item(self.kind.count() - 1)
                    header.setEnabled(False)
                    header.setSelectable(False)
            for kind in shown:
                self.kind.addItem("   " + ACTION_LABEL_KO[kind], kind)
        self.kind.setCurrentIndex(self.kind.findData(default))
        self.hint = QLabel(ACTION_GOOGLE_HINT_KO.get(default, ""))
        self.hint.setWordWrap(True)
        self.hint.setStyleSheet("color: #5f6368;")
        self.kind.currentIndexChanged.connect(self._rebuild)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.preview_box = QVBoxLayout()
        self.dry_run = QCheckBox("드라이런 (실제로 바꾸지 않고 실행 직전 확인까지만)")
        self.dry_run.setChecked(dry_run_default)
        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText(f"계속하려면 '{CONFIRM_PHRASE}'를 입력하세요")
        self.confirm.textChanged.connect(self._update_buttons)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.dry_run.toggled.connect(self._update_buttons)
        top = QHBoxLayout()
        top.addWidget(QLabel("조치:"))
        top.addWidget(self.kind, 1)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.hint)
        layout.addWidget(self.summary)
        layout.addLayout(self.preview_box, 1)
        layout.addWidget(self.dry_run)
        layout.addWidget(self.confirm)
        layout.addWidget(self.buttons)
        self._render()

    @property
    def needs_phrase(self) -> bool:
        return len(self.plan.file_ids) > CONFIRM_THRESHOLD

    def _rebuild(self) -> None:
        data = self.kind.currentData()
        if data is None:  # a section header
            return
        kind = ActionKind(data)
        self.hint.setText(ACTION_GOOGLE_HINT_KO.get(kind, ""))
        self.plan = self.build(kind)
        self._render()

    def _render(self) -> None:
        while self.preview_box.count():
            item = self.preview_box.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()
        plan = self.plan
        lines = [
            f"바뀌는 파일 {len(plan.file_ids):,}개 · 변경 {len(plan.changes):,}건 · "
            f"영향받는 대상 {plan.affected_accounts:,}"
        ]
        for folder, n in plan.folder_children.items():
            if any(c.file_id == folder for c in plan.changes):
                lines.append(
                    f"⚠ 폴더 '{self.names.get(folder, folder)}'을(를) 바꾸면 "
                    f"하위 항목 {n:,}개에도 적용됩니다."
                )
        if len(plan.file_ids) > MAX_FILES_PER_RUN:
            lines.append(
                f"✗ 한 번에 최대 {MAX_FILES_PER_RUN:,}개 파일까지 바꿀 수 있습니다. "
                "선택을 줄여 주세요."
            )
        lines.append(
            "알림 메일은 보내지 않습니다. 실행 직전에 각 파일을 다시 확인하고, "
            "그 사이 바뀐 항목은 '충돌'로 분리합니다. 실행 후 되돌릴 수 있습니다."
        )
        self.summary.setText("\n".join(lines))
        rows = [[self.names.get(c.file_id, c.file_id), c.description] for c in plan.changes]
        self.preview_box.addWidget(QLabel("변경될 내용"))
        self.preview_box.addWidget(_table(["파일", "변경 전 → 후"], rows), 3)
        if plan.skipped:
            skipped = [[self.names.get(s.file_id, s.file_id), s.reason] for s in plan.skipped]
            self.preview_box.addWidget(QLabel(f"제외된 항목 {len(skipped):,}개 (바꾸지 않음)"))
            self.preview_box.addWidget(_table(["파일", "이유"], skipped), 2)
        self.confirm.setVisible(self.needs_phrase and not self.dry_run.isChecked())
        self._update_buttons()

    def _update_buttons(self) -> None:
        ok = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok.setText("드라이런 실행" if self.dry_run.isChecked() else "변경 실행")
        allowed = bool(self.plan.changes) and len(self.plan.file_ids) <= MAX_FILES_PER_RUN
        if self.needs_phrase and not self.dry_run.isChecked():
            self.confirm.setVisible(True)
            allowed = allowed and self.confirm.text().strip() == CONFIRM_PHRASE
        ok.setEnabled(allowed)


class ResultDialog(QDialog):
    def __init__(
        self,
        result: RunResult,
        names: dict[str, str],
        parent: QWidget | None = None,
        labels: tuple[str, str] | None = None,  # (window title, close button) for a workflow
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(
            labels[0] if labels else ("권한 변경 결과" if not result.dry_run else "드라이런 결과")
        )
        self.resize(900, 520)
        self.undo_requested = False
        counts = " / ".join(
            f"{STATE_LABEL_KO[s]} {result.count(s):,}" for s in ChangeState if result.count(s)
        )
        info = QLabel(counts)
        info.setWordWrap(True)
        rows = [
            [names.get(c.file_id, c.file_id), c.description, STATE_LABEL_KO[c.state], c.error or ""]
            for c in result.changes
        ]
        layout = QVBoxLayout(self)
        layout.addWidget(info)
        if result.count(ChangeState.CONFLICT):
            layout.addWidget(
                QLabel("충돌 항목은 실행하지 않았습니다. 다시 감사한 뒤 새로 계획해 주세요.")
            )
        layout.addWidget(_table(["파일", "변경", "결과", "오류"], rows), 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText(
            labels[1] if labels else "닫기"
        )
        buttons.rejected.connect(self.reject)
        if result.count(ChangeState.DONE):
            undo = QPushButton("이 변경 되돌리기")
            undo.clicked.connect(self._undo)
            buttons.addButton(undo, QDialogButtonBox.ButtonRole.ActionRole)
        layout.addWidget(buttons)

    def _undo(self) -> None:
        self.undo_requested = True
        self.accept()


class HistoryDialog(QDialog):
    def __init__(
        self, runs: list[tuple[int, str, bool, str, str]], parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("변경 기록 (최근 30일)")
        self.resize(640, 400)
        self.selected_run: int | None = None
        self.runs = [r for r in runs if not r[1].startswith("undo:")]
        rows = []
        for run_id, action, dry, status, created in self.runs:
            label = (
                ACTION_LABEL_KO.get(ActionKind(action), action)
                if action in {k.value for k in ActionKind}
                else action
            )
            rows.append(
                [
                    str(run_id),
                    created.replace("T", " ").rstrip("Z"),
                    label,
                    "드라이런" if dry else "실행",
                    status,
                ]
            )
        self.table = _table(["번호", "시각(UTC)", "조치", "종류", "상태"], rows)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        undo = QPushButton("선택한 변경 되돌리기")
        undo.clicked.connect(self._undo)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("닫기")
        buttons.rejected.connect(self.reject)
        buttons.addButton(undo, QDialogButtonBox.ButtonRole.ActionRole)
        layout = QVBoxLayout(self)
        layout.addWidget(self.table, 1)
        layout.addWidget(buttons)

    def _undo(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows and not self.runs[rows[0].row()][2]:  # dry runs changed nothing
            self.selected_run = self.runs[rows[0].row()][0]
            self.accept()
