"""Dialogs for encrypted archiving and file organisation (SPEC 6.5, 6.6)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtGui import QFont, QTextDocument
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from dpg.core.actions.model import Plan
from dpg.core.audit.model import FileAudit
from dpg.core.organize import CATEGORY_LABEL_KO, Suggestion
from dpg.core.vault.archive import AES_ZIP_WARNING_KO, ArchiveFormat
from dpg.core.vault.job import ArchiveResult

ROOT_ID = "root"


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


KEYCHAIN_WHERE_KO = (
    "이 Mac의 키체인(암호 보관함)에 저장됩니다. 확인 방법: 「키체인 접근」 앱 → "
    "검색창에 drive-privacy-guardian → 계정이 'vault:보관 파일 이름'인 항목. "
    "Windows는 「자격 증명 관리자」 → Windows 자격 증명. "
    "이 컴퓨터에만 있고 인터넷으로 보내지 않습니다."
)


@dataclass(frozen=True)
class Destination:
    folder_id: str
    label: str
    warning: str = ""  # shown when the folder is shared with others


class ArchiveDialog(QDialog):
    """Step overview + choices (format, where the archive goes) before anything happens."""

    def __init__(
        self,
        items: list[FileAudit],
        destinations: list[Destination],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("암호화 보관")
        self.resize(780, 560)
        files = [a for a in items if not a.is_folder]
        self.destinations = destinations
        intro = QLabel(
            f"고른 파일 {len(files):,}개를 비밀번호가 걸린 보관 파일 하나로 만듭니다.\n"
            "원본의 공유를 먼저 해제하고, 암호화한 파일을 다시 풀어 원본과 똑같은지 확인한 뒤 "
            "드라이브에 올립니다. 영구 삭제는 하지 않습니다(휴지통은 30일 안에 복원 가능).\n"
            "계속 함께 편집할 문서는 보관하지 말고 공유 설정만 바꾸세요."
        )
        intro.setWordWrap(True)
        self.fmt = QComboBox()
        self.fmt.addItem("7z (권장: 파일 이름까지 암호화)", ArchiveFormat.SEVEN_ZIP)
        self.fmt.addItem("AES-ZIP (호환용)", ArchiveFormat.AES_ZIP)
        self.fmt_warning = QLabel("")
        self.fmt_warning.setWordWrap(True)
        self.fmt.currentIndexChanged.connect(self._fmt_changed)
        self.dest = QComboBox()
        for d in destinations:
            self.dest.addItem(d.label, d.folder_id)
        self.dest_warning = QLabel("")
        self.dest_warning.setWordWrap(True)
        self.dest_warning.setStyleSheet("color: #b06000;")
        self.dest.currentIndexChanged.connect(self._dest_changed)
        self.replace = QCheckBox(
            "원본 삭제 (기본) — 확인이 끝나면 원본은 휴지통으로, 그 자리에 암호 파일만 남김 "
            "(영구 삭제 아님, 30일 안에 복원 가능)"
        )
        self.replace.setChecked(True)
        names = _table(["보관할 파일"], [[a.name] for a in files])
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("다음")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(files))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("형식:"))
        row1.addWidget(self.fmt, 1)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("암호 파일을 둘 곳:"))
        row2.addWidget(self.dest, 1)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(names, 1)
        layout.addLayout(row1)
        layout.addWidget(self.fmt_warning)
        layout.addLayout(row2)
        layout.addWidget(self.dest_warning)
        layout.addWidget(self.replace)
        layout.addWidget(buttons)
        self._dest_changed()

    def _fmt_changed(self) -> None:
        is_zip = self.fmt.currentData() == ArchiveFormat.AES_ZIP
        self.fmt_warning.setText(f"⚠ {AES_ZIP_WARNING_KO}" if is_zip else "")

    def _dest_changed(self) -> None:
        i = self.dest.currentIndex()
        warn = self.destinations[i].warning if 0 <= i < len(self.destinations) else ""
        self.dest_warning.setText(f"⚠ {warn}" if warn else "")

    def select_destination(self, folder_id: str) -> None:
        self.dest.setCurrentIndex(self.dest.findData(folder_id))

    @property
    def chosen_format(self) -> ArchiveFormat:
        return ArchiveFormat(self.fmt.currentData())

    @property
    def upload_parent(self) -> str:
        return str(self.dest.currentData())


class PasswordDialog(QDialog):
    """Shows the generated password once and says exactly where (if anywhere) it is kept."""

    def __init__(
        self,
        password: str,
        print_card: Callable[[str], None] | None = None,
        parent: QWidget | None = None,
        recoverable: bool = False,
    ) -> None:
        super().__init__(parent)
        self.recoverable = recoverable
        self.setWindowTitle("보관 파일 비밀번호")
        self.resize(640, 360)
        self._password = password
        warn = QLabel(
            "이 비밀번호가 있어야 보관 파일을 풀 수 있습니다. 앱은 비밀번호를 드라이브나 "
            "인터넷 어디에도 보내지 않으며, 잃어버리면 누구도(개발자 포함) 열 수 없습니다."
        )
        warn.setWordWrap(True)
        self.field = QLineEdit(password)
        self.field.setReadOnly(True)
        font = QFont("Menlo")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(18)
        self.field.setFont(font)
        self.save_keychain = QCheckBox(
            "🔑 이 컴퓨터의 키체인에 저장 (권장 — 풀 때 자동으로 채워짐)"
        )
        self.save_keychain.setChecked(True)
        where = QLabel(KEYCHAIN_WHERE_KO)
        where.setWordWrap(True)
        where.setStyleSheet("color: #5f6368;")
        self.recorded = QCheckBox("비밀번호를 종이 등 다른 곳에도 적어 두었습니다")
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.ok = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok.setText("보관 시작")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        self.note = QLabel("")
        self.note.setWordWrap(True)
        self.note.setStyleSheet("color: #b06000;")
        self.save_keychain.toggled.connect(self._update)
        self.recorded.toggled.connect(self._update)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(warn)
        layout.addWidget(self.field)
        if recoverable:
            rec = QLabel("🛟 이 비밀번호는 복구 키로 언제든 다시 만들 수 있습니다.")
            rec.setStyleSheet("color: #188038; font-weight: bold;")
            layout.addWidget(rec)
        layout.addWidget(self.save_keychain)
        layout.addWidget(where)
        if print_card is not None:
            card = QPushButton("🖨 복구 카드 인쇄…")
            card.clicked.connect(lambda: print_card(self._password))
            layout.addWidget(card)
        layout.addWidget(self.recorded)
        layout.addWidget(self.note)
        layout.addWidget(self.buttons)
        self._update()

    def _update(self) -> None:
        keep, wrote = self.save_keychain.isChecked(), self.recorded.isChecked()
        self.ok.setEnabled(keep or wrote or self.recoverable)
        if self.recoverable:
            self.note.setText("")
        elif not keep and not wrote:
            self.note.setText("키체인에 저장하지 않으려면 비밀번호를 적어 두었다고 체크해 주세요.")
        elif keep and not wrote:
            self.note.setText(
                "키체인은 이 컴퓨터에만 있습니다. 컴퓨터를 바꾸거나 잃어버리면 열 수 없으니 "
                "적어 두는 것도 권장합니다."
            )
        else:
            self.note.setText("")

    def done(self, result: int) -> None:
        self.field.clear()
        super().done(result)


class UnpackDialog(QDialog):
    """Where to unpack + the password (or the one saved in the keychain)."""

    def __init__(
        self,
        name: str,
        folder_label: str,
        has_saved: bool,
        parent: QWidget | None = None,
        saved_label: str = "🔑 키체인에 저장된 비밀번호 사용",
        recoverable: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("보관 파일 풀기")
        self.resize(620, 320)
        title = QLabel(f"🔓 {name}")
        title.setStyleSheet("font-size: 15px; font-weight: bold;")
        self.to_drive = QRadioButton(
            f"드라이브의 같은 폴더({folder_label})에 풀기 — 푼 파일을 확인한 뒤 "
            "암호 파일은 휴지통으로 (권장)"
        )
        self.to_local = QRadioButton("이 컴퓨터의 폴더에 저장 — 드라이브의 암호 파일은 그대로 둠")
        self.to_drive.setChecked(True)
        self.use_saved = QCheckBox(saved_label)
        self.use_saved.setVisible(has_saved)
        self.use_saved.setChecked(has_saved)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText(
            "비밀번호 또는 복구 키(35자)" if recoverable else "비밀번호"
        )
        self.recover_hint = QLabel(
            "비밀번호를 모르면 종이에 적어 둔 복구 키(35자)를 입력해도 됩니다."
            if recoverable
            else "이 파일은 복구 키가 생기기 전에 만든 것이라 보관할 때의 비밀번호가 필요합니다."
        )
        self.recover_hint.setWordWrap(True)
        self.recover_hint.setStyleSheet("color: #5f6368;")
        self.use_saved.toggled.connect(self._update)
        self.password.textChanged.connect(self._update)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.ok = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok.setText("풀기")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(self.to_drive)
        layout.addWidget(self.to_local)
        layout.addSpacing(8)
        layout.addWidget(self.use_saved)
        layout.addWidget(self.password)
        layout.addWidget(self.recover_hint)
        layout.addWidget(self.buttons)
        self._update()

    def _update(self) -> None:
        saved = self.uses_saved  # isHidden(): isVisible() is False until the dialog is shown
        self.password.setEnabled(not saved)
        self.ok.setEnabled(saved or bool(self.password.text()))

    @property
    def uses_saved(self) -> bool:
        return not self.use_saved.isHidden() and self.use_saved.isChecked()

    def done(self, result: int) -> None:
        self._typed = self.password.text() if result else ""
        self.password.clear()
        super().done(result)

    @property
    def typed_password(self) -> str:
        return getattr(self, "_typed", "")


def recovery_card_html(password: str, today: dt.date | None = None) -> str:
    today = today or dt.date.today()
    return (
        "<h2>Drive Privacy Guardian — 보관 파일 복구 카드</h2>"
        f"<p>작성일: {today.isoformat()}</p>"
        f"<p style='font-family:monospace;font-size:20pt'>{password}</p>"
        "<p>보관 파일 이름: ______________________</p>"
        "<p>이 카드를 가진 사람은 보관 파일을 열 수 있습니다. 잠금 보관하세요.</p>"
        "<p>여는 방법: Drive Privacy Guardian → 파일 → 보관 파일 풀기, "
        "또는 7-Zip·반디집·Keka</p>"
    )


def print_recovery_card(password: str, parent: QWidget | None = None) -> None:
    from PySide6.QtPrintSupport import QPrintDialog, QPrinter

    printer = QPrinter()
    if QPrintDialog(printer, parent).exec() == QDialog.DialogCode.Accepted:
        doc = QTextDocument()
        doc.setHtml(recovery_card_html(password))
        doc.print_(printer)
        doc.clear()


class ArchiveResultDialog(QDialog):
    """Verification results. When everything verified, the originals are checked for the trash
    by default and one press of 「암호화 완료」 finishes the job (uncheck to keep a file)."""

    def __init__(
        self,
        result: ArchiveResult,
        names: dict[str, str],
        parent: QWidget | None = None,
        precheck: bool = True,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("암호화 보관 결과")
        self.resize(800, 520)
        self.approved: list[str] = []
        self.safe = result.safe_to_trash
        info = QLabel(
            f"보관 파일: {result.name} ({result.size:,} 바이트)\n"
            f"{'✓' if result.verified else '✗'} 풀어서 원본과 비교(SHA-256)\n"
            f"{'✓' if result.upload_verified else '✗'} 드라이브에 올린 파일 다시 확인\n\n"
            + (
                "✓ 모든 확인을 통과했습니다. 체크된 원본은 「암호화 완료」를 누르면 휴지통으로 "
                "옮겨집니다(영구 삭제 아님 — 30일 안에 복원, 변경 기록에서 되돌리기 가능). "
                "원본을 남기려면 체크를 해제하세요."
                if self.safe
                else "✗ 확인을 통과하지 못해 원본은 그대로 두었습니다."
            )
        )
        info.setWordWrap(True)
        self.table = QTableWidget(len(result.members), 2)
        self.table.setHorizontalHeaderLabels(["휴지통으로", "원본 파일"])
        self._ids = list(result.members)
        self._checks: list[QCheckBox] = []
        for r, fid in enumerate(self._ids):
            box = QCheckBox()
            box.setEnabled(self.safe)
            box.setChecked(precheck and self.safe)
            box.toggled.connect(self._update)
            self._checks.append(box)
            self.table.setCellWidget(r, 0, box)
            self.table.setItem(r, 1, QTableWidgetItem(names.get(fid, fid)))
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout = QVBoxLayout(self)
        layout.addWidget(info)
        layout.addWidget(self.table, 1)
        if result.skipped:
            layout.addWidget(QLabel(f"보관하지 않은 파일 {len(result.skipped):,}개"))
            layout.addWidget(
                _table(
                    ["파일", "이유"],
                    [[names.get(s.file_id, s.file_id), s.reason] for s in result.skipped],
                )
            )
        buttons = QDialogButtonBox()
        self.finish_btn = QPushButton()
        self.finish_btn.setDefault(True)
        self.finish_btn.clicked.connect(self._finish)
        buttons.addButton(self.finish_btn, QDialogButtonBox.ButtonRole.AcceptRole)
        self.trash_btn = self.finish_btn  # kept name for callers/tests
        layout.addWidget(buttons)
        self._update()

    def _update(self) -> None:
        n = sum(b.isChecked() for b in self._checks)
        if not self.safe:
            self.finish_btn.setText("확인 (원본 그대로)")
        elif n:
            self.finish_btn.setText(f"✓ 암호화 완료 (원본 {n}개 휴지통으로)")
        else:
            self.finish_btn.setText("✓ 암호화 완료 (원본 남김)")

    def check(self, file_id: str, on: bool = True) -> None:
        self._checks[self._ids.index(file_id)].setChecked(on)

    def _finish(self) -> None:
        self.approved = (
            [fid for fid, b in zip(self._ids, self._checks, strict=True) if b.isChecked()]
            if self.safe
            else []
        )
        self.accept()

    _trash = _finish  # backwards-compatible alias


class MoveDialog(QDialog):
    """Pick a destination (or make a new folder); moves that would widen access are blocked."""

    def __init__(
        self,
        build: Callable[[FileAudit], Plan],
        folders: list[FileAudit],
        names: dict[str, str],
        parent: QWidget | None = None,
        create_folder: Callable[[str, FileAudit], FileAudit | None] | None = None,
        labels: dict[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("폴더로 옮기기 — 미리보기")
        self.resize(880, 560)
        self.build = build
        self.names = names
        self.folders = list(folders)
        self.labels = labels or {}
        self.create_folder = create_folder
        self.plan: Plan | None = None
        self.dest = QComboBox()
        for f in self.folders:
            self.dest.addItem(self._label(f), f.file_id)
        self.dest.currentIndexChanged.connect(self._rebuild)
        self.new_btn = QPushButton("➕ 이 폴더 안에 새 폴더 만들기…")
        self.new_btn.setToolTip("고른 목적지 안에 새 폴더를 만들고 그 폴더로 옮깁니다")
        self.new_btn.clicked.connect(self._new_folder)
        self.new_btn.setVisible(create_folder is not None)
        self.box = QVBoxLayout()
        note = QLabel(
            "옮긴 파일은 목적지 폴더의 공유 설정을 물려받습니다. "
            "옮긴 뒤 볼 수 있는 사람이 늘어나는 경우는 차단합니다. 실행 후 되돌릴 수 있습니다."
        )
        note.setWordWrap(True)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("옮기기 실행")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        top = QHBoxLayout()
        top.addWidget(QLabel("목적지:"))
        top.addWidget(self.dest, 1)
        top.addWidget(self.new_btn)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(note)
        layout.addLayout(self.box, 1)
        layout.addWidget(self.buttons)
        self._rebuild()

    def _label(self, f: FileAudit) -> str:
        return self.labels.get(f.file_id) or f"📁 {f.name}"

    def select(self, folder_id: str) -> None:
        self.dest.setCurrentIndex(self.dest.findData(folder_id))

    def _new_folder(self) -> None:
        idx = self.dest.currentIndex()
        if self.create_folder is None or idx < 0:
            return
        where = self.folders[idx]
        name, ok = QInputDialog.getText(
            self, "새 폴더", f"'{where.name}' 안에 만들 새 폴더 이름:", QLineEdit.EchoMode.Normal
        )
        name = name.strip()
        if not ok or not name:
            return
        made = self.create_folder(name, where)
        if made is None:
            return
        self.folders.append(made)
        self.labels[made.file_id] = f"🆕 {self._label(where).removeprefix('📁 ')} › {made.name}"
        self.dest.addItem(self.labels[made.file_id], made.file_id)
        self.select(made.file_id)

    def _rebuild(self) -> None:
        while self.box.count():
            item = self.box.takeAt(0)
            w = item.widget() if item is not None else None
            if w is not None:
                w.deleteLater()
        idx = self.dest.currentIndex()
        self.plan = self.build(self.folders[idx]) if idx >= 0 else None
        plan = self.plan
        ok = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok.setEnabled(bool(plan and plan.changes))
        if plan is None:
            self.box.addWidget(QLabel("옮길 수 있는 폴더가 없습니다."))
            return
        rows = [[self.names.get(c.file_id, c.file_id), c.description] for c in plan.changes]
        self.box.addWidget(QLabel(f"옮길 항목 {len(rows):,}개"))
        self.box.addWidget(_table(["파일/폴더", "이동"], rows), 2)
        if plan.skipped:
            skipped = [[self.names.get(s.file_id, s.file_id), s.reason] for s in plan.skipped]
            self.box.addWidget(QLabel(f"옮기지 않는 항목 {len(skipped):,}개"))
            self.box.addWidget(_table(["파일/폴더", "이유"], skipped), 2)


class OrganizeDialog(QDialog):
    """Suggestions and duplicate candidates. Read-only: nothing is moved or deleted here."""

    def __init__(
        self,
        suggestions: list[tuple[FileAudit, Suggestion]],
        duplicates: list[list[FileAudit]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("정리 제안 · 중복 후보")
        self.resize(900, 560)
        note = QLabel(
            "제안만 보여 줍니다. 이동·보관·권한 변경은 표에서 파일을 골라 따로 실행하세요. "
            "'보류'는 확인이 덜 된 파일로, 안전하다는 뜻이 아닙니다."
        )
        note.setWordWrap(True)
        tabs = QTabWidget()
        rows = [
            [
                a.name,
                CATEGORY_LABEL_KO[s.category] if s.category else "보류",
                s.reason,
            ]
            for a, s in suggestions
        ]
        self.suggest_table = _table(["파일", "제안 분류", "이유"], rows)
        tabs.addTab(self.suggest_table, f"분류 제안 ({len(rows):,})")
        dup_rows = []
        for n, group in enumerate(duplicates, 1):
            for a in group:
                dup_rows.append([str(n), a.name, f"{a.size or 0:,}", (a.modified_time or "")[:10]])
        self.dup_table = _table(["묶음", "파일", "크기(바이트)", "수정일"], dup_rows)
        tabs.addTab(self.dup_table, f"중복 후보 ({len(duplicates):,}묶음)")
        dup_note = QLabel(
            "중복 후보는 이름이 아니라 크기와 내용 지문(MD5)이 같은 파일입니다. "
            "구글 문서·시트는 지문이 없어 제외됩니다. 삭제하지 않고 표시만 합니다."
        )
        dup_note.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("닫기")
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(note)
        layout.addWidget(tabs, 1)
        layout.addWidget(dup_note)
        layout.addWidget(buttons)


class ExclusionsDialog(QDialog):
    """Files/rules excluded from detection, with one-click restore."""

    def __init__(
        self, rows: list[tuple[str, str, str | None]], parent: QWidget | None = None
    ) -> None:
        from dpg.core.detect.rules import KIND_LABEL_KO

        super().__init__(parent)
        self.setWindowTitle("탐지에서 제외한 파일")
        self.resize(720, 420)
        self.rows = rows
        self.restored: list[tuple[str, str]] = []
        info = QLabel(
            f"제외한 항목 {len(rows):,}개. 되돌릴 항목을 체크하고 「제외 해제」를 누르면 "
            "바로 다시 검사합니다."
            if rows
            else "탐지에서 제외한 파일이 없습니다."
        )
        info.setWordWrap(True)
        self.table = QTableWidget(len(rows), 3)
        self.table.setHorizontalHeaderLabels(["되돌리기", "파일", "제외 범위"])
        self._checks: list[QCheckBox] = []
        for r, (fid, rule, name) in enumerate(rows):
            box = QCheckBox()
            box.toggled.connect(self._update)
            self._checks.append(box)
            self.table.setCellWidget(r, 0, box)
            label = name or f"(이번 결과에 없는 파일: {fid[:8]}…)"
            self.table.setItem(r, 1, QTableWidgetItem(label))
            scope = "파일 전체" if rule == "*" else f"이 규칙만: {KIND_LABEL_KO.get(rule, rule)}"
            self.table.setItem(r, 2, QTableWidgetItem(scope))
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.resizeColumnsToContents()
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("닫기")
        buttons.rejected.connect(self.reject)
        self.restore_btn = QPushButton("↩ 체크한 항목 제외 해제")
        self.restore_btn.setEnabled(False)
        self.restore_btn.clicked.connect(self._restore)
        buttons.addButton(self.restore_btn, QDialogButtonBox.ButtonRole.ActionRole)
        layout = QVBoxLayout(self)
        layout.addWidget(info)
        layout.addWidget(self.table, 1)
        layout.addWidget(buttons)

    def _update(self) -> None:
        self.restore_btn.setEnabled(any(b.isChecked() for b in self._checks))

    def check(self, row: int, on: bool = True) -> None:
        self._checks[row].setChecked(on)

    def _restore(self) -> None:
        self.restored = [
            (fid, rule)
            for (fid, rule, _n), b in zip(self.rows, self._checks, strict=True)
            if b.isChecked()
        ]
        self.accept()


def recovery_key_html(key: str, fp: str, today: dt.date | None = None) -> str:
    today = today or dt.date.today()
    return (
        "<h2>Drive Privacy Guardian — 복구 키</h2>"
        f"<p>작성일: {today.isoformat()} · 지문: {fp}</p>"
        f"<p style='font-family:monospace;font-size:20pt'>{key}</p>"
        "<p>이 키가 있으면 이 키로 만든 <b>모든</b> 암호화 보관 파일을 열 수 있습니다. "
        "금고나 잠긴 서랍에 보관하고, 사진을 찍어 휴대폰·메일에 두지 마세요.</p>"
        "<p>사용법: 보관 파일을 풀 때 비밀번호 칸에 이 키(35자)를 입력하거나, "
        "설정 → 복구 키 입력.</p>"
    )


def print_recovery_key(key: str, fp: str, parent: QWidget | None = None) -> None:
    from PySide6.QtPrintSupport import QPrintDialog, QPrinter

    printer = QPrinter()
    if QPrintDialog(printer, parent).exec() == QDialog.DialogCode.Accepted:
        doc = QTextDocument()
        doc.setHtml(recovery_key_html(key, fp))
        doc.print_(printer)
        doc.clear()


class RecoveryKeyDialog(QDialog):
    """Shows the recovery key (new, or again from the keychain). New keys need confirmation
    that a paper copy exists."""

    def __init__(
        self,
        key: str,
        fp: str,
        *,
        new: bool,
        print_key: Callable[[str, str], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("복구 키 만들기" if new else "복구 키")
        self.resize(660, 420)
        intro = QLabel(
            "복구 키를 만들었습니다. 앞으로 암호화하는 파일의 비밀번호는 이 키로 다시 "
            "만들 수 있어서, 비밀번호와 키체인을 모두 잃어도 이 키만 있으면 열 수 있습니다."
            if new
            else "키체인에 저장된 복구 키입니다. 종이 사본을 잃어버렸다면 다시 적어 두세요."
        )
        intro.setWordWrap(True)
        self.field = QLineEdit(key)
        self.field.setReadOnly(True)
        font = QFont("Menlo")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(17)
        self.field.setFont(font)
        warn = QLabel(
            "⚠ 이 키가 있으면 이 키로 만든 모든 보관 파일이 열립니다. 종이에 적거나 인쇄해 "
            "금고처럼 안전한 곳에 두고, 사진·메일·메신저에 남기지 마세요. "
            "메일로 초기화하는 기능은 없습니다(누구도 대신 열 수 없게 하기 위해서입니다)."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet("color: #b06000; font-weight: bold;")
        self.kept = QCheckBox("복구 키를 종이에 적거나 인쇄해 안전한 곳에 보관했습니다")
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | (
                QDialogButtonBox.StandardButton.Cancel
                if new
                else QDialogButtonBox.StandardButton.NoButton
            )
        )
        self.ok = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok.setText("복구 키 사용 시작" if new else "닫기")
        if new:
            self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("만들지 않음")
            self.ok.setEnabled(False)
            self.kept.toggled.connect(self.ok.setEnabled)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self.field)
        layout.addWidget(QLabel(f"지문(키를 구별하는 번호, 비밀 아님): {fp}"))
        if print_key is not None:
            btn = QPushButton("🖨 복구 키 인쇄…")
            btn.clicked.connect(lambda: print_key(key, fp))
            layout.addWidget(btn)
        layout.addWidget(warn)
        if new:
            layout.addWidget(self.kept)
        layout.addWidget(self.buttons)

    def done(self, result: int) -> None:
        self.field.clear()
        super().done(result)
