"""Main window: account bar, scope selection, progress, dashboard, results, export, settings."""

from __future__ import annotations

import datetime as dt
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QProgressBar,
    QPushButton,
    QSystemTrayIcon,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dpg import __version__
from dpg.core.actions.executor import ActionExecutor, ActionProgress
from dpg.core.actions.model import ActionKind, ChangeState, Plan, RunResult
from dpg.core.actions.planner import build_plan
from dpg.core.actions.writer import DriveWriter
from dpg.core.audit.analyze import internal_domains_for
from dpg.core.audit.model import Exposure, FileAudit, ItemStatus
from dpg.core.audit.report import EXPORT_WARNING_KO, write_report
from dpg.core.audit.runner import AuditResult, AuditRunner, AuditScope, Progress
from dpg.core.auth import AccessLevel, AuthError, NotLoggedIn, ReauthRequired
from dpg.core.auth.scopes import LEVEL_EXPLAIN_KO, LEVEL_LABEL_KO
from dpg.core.detect.rules import KIND_LABEL_KO
from dpg.core.detect.runner import DetectProgress, DetectRunner, review
from dpg.core.drive.client import VAULT_NAME_RE, DriveClient, DriveHttpError
from dpg.core.extract import UNSCANNABLE_LABEL_KO, Unscannable
from dpg.core.logging import get_logger
from dpg.core.organize import build_move_plan, duplicate_groups, new_folder_audit, suggest
from dpg.core.policy import DetectStatus, FileDetection
from dpg.core.schedule import Schedule
from dpg.core.store.audit_store import AuditStore
from dpg.core.store.wipe import remember_vault_password, vault_names, wipe_local_records
from dpg.core.vault import archive
from dpg.core.vault.job import (
    ArchiveJob,
    ArchiveProgress,
    ArchiveResult,
    RestoreJob,
    RestoreResult,
    archive_trash_plan,
    member_name,
    trash_plan,
)
from dpg.core.vault.recovery import (
    RECOVERY_KEY_NAME,
    InvalidRecoveryKey,
    derive_password,
    fingerprint,
    new_recovery_key,
    parse_recovery_key,
    tag_from_name,
)
from dpg.gui.actions_ui import ActionDialog, HistoryDialog, ResultDialog
from dpg.gui.checklist_ui import ChecklistDialog
from dpg.gui.context import RETENTION_CHOICES, AppContext
from dpg.gui.keepawake import KeepAwake
from dpg.gui.results_model import (
    COL_ADVICE,
    COL_CHECK,
    COL_EXPOSURE,
    COL_LOCATION,
    COL_NAME,
    COL_PRIVACY,
    COL_RISK,
    FILTERS,
    SORTS,
    CheckHeader,
    ResultsFilter,
    ResultsModel,
    matches_filter,
)
from dpg.gui.schedule_ui import ScheduleDialog, badge_icon
from dpg.gui.tasks import Task, user_message_for
from dpg.gui.vault_ui import (
    ROOT_ID,
    ArchiveDialog,
    ArchiveResultDialog,
    Destination,
    ExclusionsDialog,
    MoveDialog,
    OrganizeDialog,
    PasswordDialog,
    RecoveryKeyDialog,
    UnpackDialog,
    print_recovery_card,
    print_recovery_key,
)
from dpg.gui.wizard import SetupWizard

log = get_logger("gui")

PHASE_KO = {
    "changes": "지난 검사 이후 바뀐 파일 확인 중…",
    "public": "공개 링크 파일 확인 중…",
    "list": "파일 목록 수집 중…",
    "perms": "공유 설정 확인 중…",
    "analyze": "분석 중…",
}

# Past this many files, the every-minute refresh would re-copy and re-analyse the whole drive
# whenever anything changes (it is used elsewhere all day): pause it, check on demand instead.
LIVE_MAX_ITEMS = 50_000
OFFLINE_WAIT_LIMIT = 60 * 60  # seconds a scan waits for the connection to come back
OFFLINE_STEP = 20
SCHEDULE_TICK_MS = 30_000
SCHEDULE_RETRY = dt.timedelta(minutes=10)  # after a failed scheduled run, inside its window
DETECT_GUIDE_MIN_ITEMS = 5_000  # explain first when the drive is big (or not audited yet)

DETECT_GUIDE_KO = (
    "개인정보 찾기는 문서(한글·워드·엑셀·PDF·텍스트 등)를 하나씩 내려받아 이 컴퓨터의 "
    "메모리에서 읽습니다. 내용은 저장하지 않습니다.\n\n"
    "• 걸리는 시간: 문서 크기와 인터넷 속도에 따라 문서 1개에 1초~수 초입니다. "
    "문서가 수만 개면 몇 시간에서 하루 이상 걸릴 수 있습니다. 진행 중에 남은 시간을 보여 줍니다.\n"
    "• 처음에는 「공유된 파일만」을 체크하거나 「특정 폴더」로 시작하는 것을 권합니다"
    "(「취소」를 누르고 바꾸세요).\n"
    "• 중단해도 검사한 파일은 기억합니다. 다시 시작하면 나머지만 이어서 합니다.\n"
    "• 전원을 연결해 두세요. 검사 중에는 컴퓨터가 저절로 잠들지 않게 합니다"
    "(노트북 덮개를 닫으면 잠듭니다). 인터넷이 끊기면 최대 60분 기다렸다가 이어서 합니다.\n"
    "• 권장: 메모리 8GB 이상. 50MB가 넘는 파일은 건너뜁니다."
)


@dataclass(frozen=True)
class OfflineWait:
    waited: int  # seconds without a connection so far


def _duration_ko(seconds: float) -> str:
    minutes = max(1, round(seconds / 60))
    if minutes < 60:
        return f"{minutes}분"
    hours, rest = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}시간 {rest}분" if rest else f"{hours}시간"
    return f"{hours // 24}일 {hours % 24}시간"


OPEN_MAX = 10


def drive_link(a: FileAudit) -> str:
    """The item's own page in Google Drive (opened in the user's browser, never fetched here)."""
    fid = quote(a.file_id, safe="")
    if a.is_folder:
        return f"https://drive.google.com/drive/folders/{fid}"
    return f"https://drive.google.com/open?id={fid}"


SCOPE_CHOICES = [
    ("mine", "내 소유 파일"),
    ("public", "링크로 공개된 내 파일만 (빠름)"),
    ("shared", "나에게 공유된 파일"),
    ("drive", "공유 드라이브"),
    ("folder", "특정 폴더 (폴더 ID 또는 주소)"),
]

DASHBOARD = [
    ("all", "전체"),
    ("urgent", "긴급·높음 조치"),
    ("detected", "개인정보 탐지"),
    ("link", "링크 공개"),
    ("external", "외부 계정 공유"),
    ("domain", "도메인 공개"),
    ("review", "확인 필요"),
    ("excluded", "🙈 탐지 제외"),
    ("vault", "🔐 암호화된 파일"),
]

# ①–④ section colours (Google palette) — number badge + left bar
_SECTION_COLORS = {1: "#1a73e8", 2: "#188038", 3: "#9334e6", 4: "#e8710a"}


def _section(number: int, title: str, hint: str) -> tuple[QFrame, QVBoxLayout]:
    """A card with a big coloured step number, so ① → ④ reads at a glance."""
    color = _SECTION_COLORS[number]
    frame = QFrame()
    frame.setObjectName(f"section{number}")
    frame.setStyleSheet(
        f"QFrame#section{number} {{ border: 1px solid #dadce0; border-left: 6px solid {color};"
        " border-radius: 8px; }"
    )
    col = QVBoxLayout(frame)
    col.setContentsMargins(12, 8, 12, 10)
    head = QHBoxLayout()
    badge = QLabel(str(number))
    badge.setFixedSize(30, 30)
    badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
    badge.setStyleSheet(
        f"background: {color}; color: white; border-radius: 15px;"
        " font-size: 17px; font-weight: bold;"
    )
    label = QLabel(title)
    label.setStyleSheet(f"color: {color}; font-size: 17px; font-weight: bold;")
    sub = QLabel(hint)
    sub.setStyleSheet("color: #5f6368;")
    head.addWidget(badge)
    head.addWidget(label)
    head.addSpacing(8)
    head.addWidget(sub, 1)
    col.addLayout(head)
    return frame, col


def folder_id_from(text: str) -> str:
    """Accept a raw folder ID or a Drive folder URL."""
    text = text.strip()
    if "/folders/" in text:
        text = text.split("/folders/", 1)[1]
    return text.split("?", 1)[0].split("/", 1)[0].strip()


ABOUT_TEXT = (
    f"개인정보 보안관 (Drive Privacy Guardian) {__version__}\n\n"
    "구글 드라이브 공유 권한과 개인정보 포함 파일을 "
    "이 컴퓨터 안에서만 점검하는 무료 프로그램입니다. "
    "구글 외 어떤 서버와도 통신하지 않습니다.\n\n"
    "본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다.\n\n"
    "라이선스: MIT. Qt/PySide6는 LGPL-3.0으로 사용하며 교체할 수 있습니다(NOTICE_KO.txt). "
    "그 밖의 오픈소스 라이선스는 THIRD_PARTY_LICENSES.txt에 있습니다.\n\n"
    "Google Drive는 Google LLC의 상표입니다. 이 프로그램은 Google과 제휴하거나 "
    "Google의 보증을 받은 제품이 아닙니다."
)


class ReviewDialog(QDialog):
    """Masked, in-memory preview of where personal data was found (never stored)."""

    def __init__(
        self,
        name: str,
        lines: list[Any],
        parent: QWidget | None = None,
        open_drive: Any = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"검토 — {name}")
        self.resize(760, 480)
        info = QLabel(
            "값은 가려서 보여 주며, 이 창을 닫으면 메모리에서 지워집니다. "
            "파일이나 기록에 저장하지 않습니다."
        )
        info.setWordWrap(True)
        table = QTableWidget(len(lines), 3)
        table.setHorizontalHeaderLabels(["유형", "위치", "내용(가림)"])
        for r, line in enumerate(lines):
            for c, value in enumerate(
                (KIND_LABEL_KO.get(line.kind, line.kind), line.location, line.snippet)
            ):
                table.setItem(r, c, QTableWidgetItem(value))
        table.horizontalHeader().setStretchLastSection(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("닫기")
        buttons.rejected.connect(self.reject)
        if open_drive is not None:
            go = buttons.addButton("↗ 드라이브에서 열기", QDialogButtonBox.ButtonRole.ActionRole)
            go.setToolTip("원본 파일을 브라우저의 구글 드라이브에서 열어 직접 확인합니다")
            go.clicked.connect(open_drive)
        layout = QVBoxLayout(self)
        layout.addWidget(info)
        if not lines:
            layout.addWidget(
                QLabel("표시할 탐지 위치가 없습니다(파일명에서만 탐지되었거나 제외됨).")
            )
        layout.addWidget(table, 1)
        layout.addWidget(buttons)


class ExportDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("보고서 저장")
        self.mask_check = QCheckBox("파일명·이메일 가리기 (권장)")
        self.mask_check.setChecked(True)
        self.fmt = QComboBox()
        self.fmt.addItem("엑셀 (XLSX)", ".xlsx")
        self.fmt.addItem("CSV", ".csv")
        warning = QLabel(f"⚠ {EXPORT_WARNING_KO}\n탐지된 개인정보 값은 보고서에 포함되지 않습니다.")
        warning.setWordWrap(True)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("저장할 위치 선택…")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form = QFormLayout()
        form.addRow("형식", self.fmt)
        form.addRow("", self.mask_check)
        layout = QVBoxLayout(self)
        layout.addWidget(warning)
        layout.addLayout(form)
        layout.addWidget(buttons)


class WipeDialog(QDialog):
    """What "모든 기록 삭제" removes — and, above all, what it keeps (archive passwords)."""

    PHRASE = "삭제"
    VAULT_PHRASE = "비밀번호까지 삭제"

    def __init__(self, vault_count: int = 0, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("모든 기록 삭제")
        self.resize(620, 420)
        info = QLabel(
            "이 컴퓨터에서 다음을 지웁니다. 구글 드라이브의 파일과 공유 설정은 바뀌지 않습니다.\n\n"
            "• 검사 결과·개인정보 탐지 결과·변경 기록(되돌리기 정보 포함)\n"
            "• 위 기록을 여는 열쇠(검사 기록 전용 암호화 키)\n"
            "• 앱 로그\n\n"
            "지운 뒤에는 되돌리기와 이어서 검사를 할 수 없고, 다음 검사는 처음부터 합니다."
        )
        info.setWordWrap(True)
        keep = QLabel(
            "🔐 암호화된 파일은 안전합니다: 보관 파일은 검사 기록 키가 아니라 "
            "보관할 때 만든 **각자의 비밀번호**로 잠겨 있습니다. "
            + (
                f"키체인에 저장된 보관 파일 비밀번호 {vault_count:,}개는 지우지 않고 그대로 둡니다."
                if vault_count
                else "키체인에 저장된 보관 파일 비밀번호는 지우지 않고 그대로 둡니다."
            )
        )
        keep.setWordWrap(True)
        keep.setTextFormat(Qt.TextFormat.MarkdownText)
        keep.setStyleSheet("color: #188038;")
        self.vault = QCheckBox("보관 파일 비밀번호도 지우기 (권장하지 않음)")
        self.vault_warn = QLabel(
            "⚠ 키체인의 보관 파일 비밀번호와 복구 키가 모두 지워집니다. 종이에 적어 둔 "
            "비밀번호나 복구 키가 없다면, 드라이브의 암호화된 파일을 누구도(개발자 포함) "
            "영영 열 수 없게 됩니다. 계속하려면 아래에 "
            f"'{self.VAULT_PHRASE}'를 입력하세요."
        )
        self.vault_warn.setWordWrap(True)
        self.vault_warn.setStyleSheet("color: #c5221f; font-weight: bold;")
        self.vault_warn.setVisible(False)
        self.logout = QCheckBox("로그인 정보와 OAuth 클라이언트 설정도 지우기 (앱 권한 철회)")
        self.confirm = QLineEdit()
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok.setText("지우기")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        self.confirm.textChanged.connect(self._update)
        self.vault.toggled.connect(self._update)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(info)
        layout.addWidget(keep)
        layout.addSpacing(6)
        layout.addWidget(self.vault)
        layout.addWidget(self.vault_warn)
        layout.addWidget(self.logout)
        layout.addWidget(self.confirm)
        layout.addWidget(buttons)
        self._update()

    @property
    def required_phrase(self) -> str:
        return self.VAULT_PHRASE if self.vault.isChecked() else self.PHRASE

    def _update(self) -> None:
        self.vault_warn.setVisible(self.vault.isChecked())
        self.confirm.setPlaceholderText(f"계속하려면 '{self.required_phrase}'를 입력하세요")
        self.ok.setEnabled(self.confirm.text().strip() == self.required_phrase)


class SettingsDialog(QDialog):
    def __init__(
        self,
        ctx: AppContext,
        parent: QWidget | None = None,
        recovery: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.recovery = recovery or {}
        self.setWindowTitle("설정")
        self.auto_logout = QCheckBox("앱을 닫을 때 자동으로 로그아웃 (공용 PC 권장)")
        self.auto_logout.setChecked(ctx.prefs.auto_logout_on_exit)
        self.dry_run = QCheckBox(
            "권한 변경 드라이런 모드 (실제로 바꾸지 않고 실행 직전 확인까지만)"
        )
        self.dry_run.setChecked(ctx.prefs.dry_run_mode)
        self.live = QCheckBox("드라이브 변경 자동 반영 (앱이 열려 있는 동안 1분마다 확인)")
        self.live.setChecked(ctx.prefs.live_refresh)
        self.live.setToolTip(
            "구글 드라이브의 '변경 목록'만 확인합니다. 바뀐 것이 없으면 작은 요청 하나로 끝나며, "
            "바뀐 파일만 다시 검사합니다."
        )
        self.retention = QComboBox()
        for days in RETENTION_CHOICES:
            self.retention.addItem(f"{days}일", days)
        idx = self.retention.findData(ctx.prefs.retention_days)
        self.retention.setCurrentIndex(idx if idx >= 0 else 1)
        wipe_btn = QPushButton("🗑 모든 기록 삭제…")
        wipe_btn.setToolTip(
            "이 컴퓨터에 남은 검사 결과·변경 기록·로그를 지웁니다 (드라이브는 그대로)"
        )
        wipe_btn.clicked.connect(self._wipe)
        self.wiped = False
        self.domains = QLineEdit(", ".join(ctx.prefs.internal_domains))
        self.domains.setPlaceholderText("예: school.go.kr, sen.go.kr")
        hint = QLabel(
            "내부 도메인: 이 도메인 계정과의 공유는 '외부'로 보지 않습니다. "
            "로그인한 계정의 도메인은 자동 포함됩니다(gmail.com 등 개인 계정 제외)."
        )
        hint.setWordWrap(True)
        client = ctx.manager.client()
        self.client_label = QLabel(client.display_id if client else "설정 안 됨")
        replace_btn = QPushButton("클라이언트 교체/삭제…")
        replace_btn.clicked.connect(self._client_menu)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("저장")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        form = QFormLayout()
        form.addRow("", self.auto_logout)
        form.addRow("", self.dry_run)
        form.addRow("", self.live)
        form.addRow("검사 기록 보관 기간", self.retention)
        form.addRow("", QLabel("기간이 지난 검사 결과와 변경 기록은 앱을 열 때 자동으로 지웁니다."))
        form.addRow("내 컴퓨터의 기록", wipe_btn)
        if self.recovery:
            has_key = bool(ctx.manager.secret_store.get(RECOVERY_KEY_NAME))
            fp = ctx.prefs.recovery_fingerprint
            status = (
                f"있음 (지문 {fp})"
                if has_key
                else ("이 컴퓨터에 없음 — 종이의 복구 키를 입력하세요" if fp else "아직 없음")
            )
            rec_row = QHBoxLayout()
            self.recovery_label = QLabel(status)
            rec_row.addWidget(self.recovery_label, 1)
            for text, key, show in (
                ("만들기…", "create", not has_key and not fp),
                ("보기·인쇄…", "show", has_key),
                ("입력…", "enter", not has_key),
            ):
                if show:
                    btn = QPushButton(text)
                    btn.clicked.connect(lambda _=False, k=key: self._recovery(k))
                    rec_row.addWidget(btn)
            form.addRow("🛟 복구 키", rec_row)
        form.addRow("내부 도메인", self.domains)
        form.addRow("", hint)
        client_row = QHBoxLayout()
        client_row.addWidget(self.client_label)
        client_row.addWidget(replace_btn)
        form.addRow("OAuth 클라이언트", client_row)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.removed_client = False

    def _client_menu(self) -> None:
        if self.ctx.confirm(
            self,
            "클라이언트 삭제",
            "클라이언트와 로그인 정보를 삭제할까요?\n"
            "구글에 저장된 앱 권한도 철회합니다. 삭제 후 설정 마법사가 열립니다.",
            "삭제",
            "취소",
        ):
            self.ctx.manager.remove_client()
            self.removed_client = True
            self.accept()

    def _recovery(self, action: str) -> None:
        self.recovery[action]()
        has_key = bool(self.ctx.manager.secret_store.get(RECOVERY_KEY_NAME))
        fp = self.ctx.prefs.recovery_fingerprint
        self.recovery_label.setText(f"있음 (지문 {fp})" if has_key else "아직 없음")

    def _wipe(self) -> None:
        dialog = WipeDialog(len(vault_names(self.ctx.manager.secret_store)), self)
        if not self.ctx.show_dialog(dialog):
            return
        report = wipe_local_records(
            self.ctx.manager.secret_store,
            include_vault_passwords=dialog.vault.isChecked(),
        )
        if dialog.logout.isChecked():
            self.ctx.manager.remove_client()
            self.removed_client = True
        # Leave nothing that starts by itself: scheduled scans and the login item go too.
        if self.ctx.prefs.schedule.get("enabled"):
            self.ctx.prefs.schedule = {**self.ctx.prefs.schedule, "enabled": False}
            self.ctx.prefs.save()
        try:
            self.ctx.autostart.disable()
        except OSError:
            log.info("could not remove the login item")
        self.wiped = True
        self.ctx.notify(
            self,
            "모든 기록 삭제",
            f"검사 기록 {report.databases:,}개와 암호화 키, 로그 {report.logs:,}개를 지웠습니다."
            + (
                f"\n키체인의 보관 파일 비밀번호 {report.vault_passwords:,}개"
                + (" 와 복구 키" if report.recovery_key else "")
                + "도 지웠습니다. 종이에 적어 둔 복구 키로는 계속 열 수 있습니다."
                if dialog.vault.isChecked()
                else ""
            )
            + (
                "\n로그인 정보와 클라이언트 설정도 지웠습니다." if dialog.logout.isChecked() else ""
            ),
        )
        self.accept()

    def _save(self) -> None:
        self.ctx.prefs.live_refresh = self.live.isChecked()
        self.ctx.prefs.retention_days = int(self.retention.currentData())
        self.ctx.prefs.auto_logout_on_exit = self.auto_logout.isChecked()
        self.ctx.prefs.dry_run_mode = self.dry_run.isChecked()
        self.ctx.prefs.internal_domains = [
            d.strip().lower() for d in self.domains.text().replace(";", ",").split(",") if d.strip()
        ][:20]
        self.ctx.prefs.save()
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.task: Task | None = None
        self.cancel_event = threading.Event()
        self.keep_awake = KeepAwake()
        self._rate: tuple[str, float, int] | None = None
        self.result: AuditResult | None = None
        self.detections: dict[str, FileDetection] | None = None
        self._tasks: set[Task] = set()
        self._keep_detections: dict[str, FileDetection] | None = None
        self._pending_undo: tuple[int, dict[str, str]] | None = None
        self._pending_refresh = False
        self._pending_next: Any = None
        self._archive_precheck = False
        self._auto_run = False
        self._live_token: str | None = None
        self._live_check: Task | None = None  # a callable to start once the current task is done
        self.setWindowTitle(f"개인정보 보안관 {__version__}")
        self.resize(1200, 760)
        self._build_menu()
        self._build_ui()
        self.live_timer = QTimer(self)
        self.live_timer.setInterval(60_000)
        self.live_timer.timeout.connect(self._live_tick)
        self._apply_live_setting()
        # Scheduled scans (D-099)
        self.now: Any = dt.datetime.now  # injectable clock (tests)
        self.sched_awake = KeepAwake()
        self._sched_run = False  # the running task was started by the schedule
        self._sched_stopping = False  # … and is being stopped because its window ended
        self._sched_done_for: dt.datetime | None = None  # window (start) already finished
        self._sched_retry_at: dt.datetime | None = None
        self._sched_notified_for: dt.datetime | None = None
        self._quitting = False
        self._tray_hint_shown = False
        self.tray: QSystemTrayIcon | None = None
        self._setup_tray()
        self.schedule_timer = QTimer(self)
        self.schedule_timer.setInterval(SCHEDULE_TICK_MS)
        self.schedule_timer.timeout.connect(self._schedule_tick)
        self.schedule_timer.start()
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)
        self._last_counts: Counter[str] = Counter()
        self._sched_no_detect_permission = False
        self._apply_schedule()
        self.refresh_account()

    # -- construction ---------------------------------------------------------------------------

    def _build_menu(self) -> None:
        menu = self.menuBar().addMenu("파일")
        settings = QAction("설정…", self)
        settings.triggered.connect(self.open_settings)
        menu.addAction(settings)
        export = QAction("보고서 저장…", self)
        export.triggered.connect(self.export_report)
        menu.addAction(export)
        history = QAction("변경 기록…", self)
        history.triggered.connect(self.open_history)
        menu.addAction(history)
        menu.addSeparator()
        unpack = QAction("보관 파일 풀기…", self)
        unpack.triggered.connect(self.unpack_clicked)
        menu.addAction(unpack)
        vault = QAction("암호화된 파일 보기", self)
        vault.triggered.connect(lambda: self.set_filter("vault"))
        menu.addAction(vault)
        menu.addSeparator()
        schedule = QAction("예약 검사…", self)
        schedule.triggered.connect(self.open_schedule)
        menu.addAction(schedule)
        quit_action = QAction("종료", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.setMenuRole(QAction.MenuRole.QuitRole)
        quit_action.triggered.connect(self.quit_app)
        menu.addAction(quit_action)
        tools = self.menuBar().addMenu("정리")
        self.archive_action = QAction("선택 파일 암호화 보관…", self)
        self.archive_action.triggered.connect(self.archive_selected)
        self.move_action = QAction("선택 파일 폴더로 이동…", self)
        self.move_action.triggered.connect(self.move_selected)
        self.organize_action = QAction("정리 제안 · 중복 후보…", self)
        self.organize_action.triggered.connect(self.show_organize)
        for act in (self.archive_action, self.move_action, self.organize_action):
            act.setEnabled(False)
            tools.addAction(act)
        help_menu = self.menuBar().addMenu("도움말")
        update = QAction("새 버전 확인…", self)
        update.triggered.connect(self.check_update)
        help_menu.addAction(update)
        checklist = QAction("보안 점검표…", self)
        checklist.triggered.connect(self.show_checklist)
        help_menu.addAction(checklist)
        about = QAction("정보…", self)
        about.triggered.connect(self.show_about)
        help_menu.addAction(about)

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setSpacing(8)

        # account bar
        account_row = QHBoxLayout()
        self.account_label = QLabel()
        self.logout_btn = QPushButton("로그아웃")
        self.logout_btn.clicked.connect(self._account_clicked)
        self.switch_btn = QPushButton("🔁 계정·열쇠 바꾸기")
        self.switch_btn.setToolTip(
            "다른 구글 계정이나 새 로그인 열쇠(클라이언트 JSON)로 바꿉니다. "
            "로그인 화면에 '액세스 차단됨'이나 다른 앱 이름이 나올 때 누르세요."
        )
        self.switch_btn.clicked.connect(self.switch_client)
        account_row.addWidget(self.account_label, 1)
        account_row.addWidget(self.switch_btn)
        account_row.addWidget(self.logout_btn)
        layout.addLayout(account_row)

        # ① 검사
        scope_box, scope_col = _section(1, "검사하기", "읽기 전용 — 드라이브를 바꾸지 않습니다")
        scope_row = QHBoxLayout()
        self.scope_combo = QComboBox()
        for key, label in SCOPE_CHOICES:
            self.scope_combo.addItem(label, key)
        self.scope_combo.currentIndexChanged.connect(self._scope_changed)
        self.drive_combo = QComboBox()
        self.drive_combo.setVisible(False)
        self.folder_edit = QLineEdit()
        self.folder_edit.setPlaceholderText("폴더 주소 또는 ID (drive.google.com/drive/folders/…)")
        self.folder_edit.setVisible(False)
        self.detect_check = QCheckBox("개인정보도 찾기")
        self.detect_check.setToolTip(
            "파일 내용을 이 컴퓨터의 메모리에서만 읽어 주민번호·연락처 등을 찾습니다. "
            "처음 사용할 때 '파일 내용 읽기' 권한을 추가로 요청합니다."
        )
        self.detect_shared_check = QCheckBox("공유된 파일만")
        self.detect_shared_check.setEnabled(False)
        self.detect_shared_check.setToolTip(
            "링크·외부 계정·도메인으로 공유된 파일만 내용을 읽습니다. 밖으로 나갈 수 있는 "
            "파일부터 빠르게 확인할 수 있습니다. 끄면 모든 문서를 읽습니다(오래 걸림)."
        )
        self.detect_check.toggled.connect(self.detect_shared_check.setEnabled)
        self.restart_check = QCheckBox("처음부터 다시")
        self.restart_check.setToolTip("체크하지 않으면 중단된 감사를 이어서 진행합니다.")
        self.start_btn = QPushButton("▶ 검사 시작")
        self.start_btn.setDefault(True)
        self.start_btn.setMinimumWidth(120)
        self.start_btn.clicked.connect(self.start_audit)
        self.cancel_btn = QPushButton("■ 중단")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_audit)
        scope_row.addWidget(QLabel("어디를:"))
        scope_row.addWidget(self.scope_combo)
        scope_row.addWidget(self.drive_combo, 1)
        scope_row.addWidget(self.folder_edit, 1)
        scope_row.addStretch()
        scope_row.addWidget(self.detect_check)
        scope_row.addWidget(self.detect_shared_check)
        scope_row.addWidget(self.restart_check)
        scope_row.addWidget(self.start_btn)
        scope_row.addWidget(self.cancel_btn)
        scope_col.addLayout(scope_row)
        progress_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setMaximumHeight(8)
        self.progress_label = QLabel("「검사 시작」을 누르면 진행 상황이 여기에 표시됩니다.")
        self.live_label = QLabel("")
        self.live_label.setStyleSheet("color: #188038;")
        self.live_label.setToolTip(
            "앱이 열려 있는 동안 1분마다 구글 드라이브의 '변경 목록'만 확인합니다. "
            "바뀐 것이 없으면 아주 작은 요청 하나로 끝나고, 바뀐 파일만 다시 검사합니다."
        )
        self.live_btn = QPushButton("끄기")
        self.live_btn.setToolTip(
            "드라이브 변경 자동 반영을 끄거나 켭니다 (설정에서도 바꿀 수 있음)"
        )
        self.live_btn.clicked.connect(self.toggle_live)
        progress_row.addWidget(self.progress_bar, 1)
        progress_row.addWidget(self.progress_label, 2)
        self.schedule_btn = QPushButton("⏰ 예약")
        self.schedule_btn.clicked.connect(self.open_schedule)
        progress_row.addWidget(self.live_label)
        progress_row.addWidget(self.live_btn)
        progress_row.addWidget(self.schedule_btn)
        scope_col.addLayout(progress_row)
        layout.addWidget(scope_box)

        # ② 결과 요약
        summary_box, summary_col = _section(
            2, "결과 요약", "칸을 누르면 그 파일만 아래 목록에 보입니다"
        )
        dash = QGridLayout()
        summary_col.addLayout(dash)
        self.dash_buttons: dict[str, QPushButton] = {}
        for col, (key, label) in enumerate(DASHBOARD):
            btn = QPushButton(f"{label}\n–")
            btn.setMinimumHeight(52)
            btn.setCheckable(True)
            btn.clicked.connect(lambda _=False, k=key: self.set_filter(k))
            self.dash_buttons[key] = btn
            dash.addWidget(btn, 0, col)
        self.vault_btn = self.dash_buttons["vault"]
        self.vault_btn.setToolTip("이 앱으로 암호화한 보관 파일만 아래 목록에 보여 줍니다")
        self.dash_buttons["excluded"].setToolTip("개인정보 탐지에서 제외한 파일")
        self.notice_label = QLabel("")
        self.notice_label.setWordWrap(True)
        self.notice_label.setStyleSheet("color: #9a6700;")
        self.notice_label.setVisible(False)
        dash.addWidget(self.notice_label, 1, 0, 1, len(DASHBOARD))
        layout.addWidget(summary_box)

        # ③ 파일 목록
        list_box, list_col = _section(3, "파일 목록", "왼쪽 체크박스로 파일을 고르세요")
        filter_row = QHBoxLayout()
        self.filter_combo = QComboBox()
        for key, label in FILTERS.items():
            self.filter_combo.addItem(label, key)
        self.filter_combo.currentIndexChanged.connect(
            lambda _i: self.set_filter(self.filter_combo.currentData())
        )
        self.sort_combo = QComboBox()
        for label, _col, _desc in SORTS:
            self.sort_combo.addItem(label)
        self.sort_combo.currentIndexChanged.connect(self.apply_sort)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔎 파일 이름 검색")
        self.search_edit.textChanged.connect(self._search_changed)
        self.count_label = QLabel("")
        filter_row.addWidget(QLabel("보기:"))
        filter_row.addWidget(self.filter_combo)
        filter_row.addWidget(QLabel("정렬:"))
        filter_row.addWidget(self.sort_combo)
        filter_row.addWidget(self.search_edit, 1)
        filter_row.addWidget(self.count_label)
        # list-wide tools (no selection needed)
        self.export_btn = QPushButton("📄 보고서 저장")
        self.export_btn.setToolTip(
            "지금 결과를 엑셀/CSV로 저장합니다 (이름·이메일은 기본으로 가림)"
        )
        self.export_btn.clicked.connect(self.export_report)
        self.organize_btn = QPushButton("🧹 정리 제안·중복")
        self.organize_btn.setToolTip("분류 제안과 내용이 같은 파일을 보여 줍니다 (보기만 함)")
        self.organize_btn.clicked.connect(self.show_organize)
        self.exclusions_btn = QPushButton("🙈 제외 목록")
        self.exclusions_btn.setToolTip("개인정보 탐지에서 제외한 파일을 보고, 되돌립니다")
        self.exclusions_btn.clicked.connect(self.show_exclusions)
        self.history_btn = QPushButton("🕘 변경 기록")
        self.history_btn.setToolTip("이 앱으로 바꾼 내용을 보고 되돌립니다")
        self.history_btn.clicked.connect(self.open_history)
        for b in (self.export_btn, self.organize_btn):
            b.setEnabled(False)
        for b in (self.export_btn, self.organize_btn, self.exclusions_btn, self.history_btn):
            filter_row.addWidget(b)
        list_col.addLayout(filter_row)

        self.model = ResultsModel()
        self.proxy = ResultsFilter()
        self.proxy.setSourceModel(self.model)
        self.proxy.rowsInserted.connect(self._update_count)
        self.proxy.modelReset.connect(self._update_count)
        self.proxy.layoutChanged.connect(self._update_count)
        self.model.dataChanged.connect(lambda *_a: self._update_actions())
        self.model.modelReset.connect(self._update_actions)
        self.table = QTableView()
        self.check_header = CheckHeader(self._visible_check_state)
        self.check_header.toggled_all.connect(self.check_visible)
        self.table.setHorizontalHeader(self.check_header)
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(COL_CHECK, 34)
        self.table.setColumnWidth(COL_RISK, 50)
        self.table.setColumnWidth(COL_ADVICE, 200)
        self.table.setColumnWidth(COL_PRIVACY, 220)
        self.table.setColumnWidth(COL_EXPOSURE, 120)
        self.table.setColumnWidth(COL_NAME, 260)
        self.table.setColumnWidth(COL_LOCATION, 200)
        self.table.doubleClicked.connect(lambda _i: self.review_selected())
        self.table.selectionModel().selectionChanged.connect(lambda *_a: self._update_actions())
        list_col.addWidget(self.table, 1)

        # ④ selection action bar
        action_box, action_col = _section(4, "고른 파일로 할 일", "버튼은 파일을 고르면 켜집니다")
        pick_row = QHBoxLayout()
        self.selection_label = QLabel("고른 파일 없음")
        self.select_none_btn = QPushButton("모든 체크 해제 (다른 보기 포함)")
        self.select_none_btn.setToolTip(
            "지금 안 보이는 다른 보기(칸)에서 체크한 파일까지 모두 해제합니다"
        )
        self.select_none_btn.clicked.connect(self.uncheck_all)
        pick_row.addWidget(self.selection_label, 1)
        pick_row.addWidget(self.select_none_btn)
        action_col.addLayout(pick_row)
        buttons_row = QHBoxLayout()
        self.change_btn = QPushButton("🔗 공유 설정 바꾸기")
        self.change_btn.setToolTip(
            "링크 공개 해제, 외부 사용자 삭제 등. "
            "미리보기와 승인 후에만 바뀌고, 되돌릴 수 있습니다."
        )
        self.change_btn.clicked.connect(self.change_selected)
        self.archive_btn = QPushButton("🔒 암호화 보관")
        self.archive_btn.setToolTip("끝난 문서를 비밀번호로 잠가 드라이브에 보관합니다")
        self.archive_btn.clicked.connect(self.archive_selected)
        self.move_btn = QPushButton("📁 폴더로 옮기기")
        self.move_btn.setToolTip("더 넓게 공유된 폴더로는 옮기지 않습니다")
        self.move_btn.clicked.connect(self.move_selected)
        self.detect_btn = QPushButton("🔎 개인정보 검사")
        self.detect_btn.setToolTip(
            "고른 파일만 내용을 읽어 주민번호·연락처 등을 찾습니다 (예: 「링크 공개」 칸에서 "
            "걸러 본 파일). 이미 검사한 파일은 다시 읽지 않고, 중단해도 이어서 합니다."
        )
        self.detect_btn.clicked.connect(self.detect_selected)
        self.open_btn = QPushButton("↗ 드라이브에서 열기")
        self.open_btn.setToolTip(
            "고른 파일을 브라우저의 구글 드라이브에서 엽니다 (직접 열어 확인). 한 번에 10개까지"
        )
        self.open_btn.clicked.connect(self.open_selected_in_drive)
        self.review_btn = QPushButton("🔍 내용 확인")
        self.review_btn.setToolTip(
            "파일 1개를 다시 읽어 개인정보 위치를 가린 채로 보여 줍니다 (저장 안 함)"
        )
        self.review_btn.clicked.connect(self.review_selected)
        self.exclude_btn = QPushButton("🙈 탐지에서 제외")
        self.exclude_btn.setToolTip("개인정보가 아닌데 잘못 찾은 파일을 다음 탐지부터 뺍니다")
        self.exclude_btn.clicked.connect(self.exclude_selected)
        self.unpack_btn = QPushButton("🔓 보관 파일 풀기")
        self.unpack_btn.setToolTip(
            "고른 보관 파일(.7z/.zip)을 드라이브에서 바로 풉니다. "
            "고르지 않으면 이 컴퓨터의 파일을 고릅니다."
        )
        self.unpack_btn.clicked.connect(self.unpack_clicked)
        for b in (
            self.change_btn,
            self.archive_btn,
            self.move_btn,
            self.detect_btn,
            self.open_btn,
            self.review_btn,
            self.exclude_btn,
            self.unpack_btn,
        ):
            b.setMinimumHeight(34)
            buttons_row.addWidget(b)
        action_col.addLayout(buttons_row)
        layout.addWidget(list_box, 1)
        layout.addWidget(action_box)
        self.setCentralWidget(root)
        self.apply_sort(0)
        self._update_actions()

    # -- account --------------------------------------------------------------------------------

    def refresh_account(self) -> None:
        st = self.ctx.manager.status()
        client = self.ctx.manager.client()
        key = f"  ·  열쇠: {client.project_id}" if client and client.project_id else ""
        if st.logged_in:
            level = LEVEL_LABEL_KO[st.level] if st.level else "권한 없음"
            self.account_label.setText(
                f"로그인: {st.account or '(계정 미확인)'}  ·  권한: {level}{key}"
            )
        else:
            self.account_label.setText(f"로그인되어 있지 않습니다.{key}")
        self.logout_btn.setText("로그아웃" if st.logged_in else "🔑 로그인")
        self.logout_btn.setToolTip(
            "로그아웃하고 구글에 저장된 앱 권한을 철회합니다"
            if st.logged_in
            else "구글 계정으로 다시 로그인합니다"
        )
        self.logout_btn.setEnabled(True)
        self.start_btn.setEnabled(st.logged_in and self.task is None)

    def run_setup(self, level: AccessLevel = AccessLevel.AUDIT) -> bool:
        wizard = SetupWizard(self.ctx, self, level)
        ok = bool(wizard.exec())
        self.refresh_account()
        st = self.ctx.manager.status()
        return ok and st.logged_in and st.level is not None and st.level >= level

    def ensure_detect_permission(self) -> bool:
        """SPEC 5.3: explain, then ask Google for the extra scope only when first needed."""
        st = self.ctx.manager.status()
        if st.level is not None and st.level >= AccessLevel.DETECT:
            return True
        if not self.ctx.confirm(
            self,
            "권한 추가",
            "개인정보 탐지는 파일 내용을 읽는 권한이 추가로 필요합니다.\n\n"
            f"{LEVEL_EXPLAIN_KO[AccessLevel.DETECT]}\n\n구글 로그인 화면에서 권한을 추가할까요?",
            "권한 추가",
            "취소",
        ):
            return False
        return self.run_setup(AccessLevel.DETECT)

    def _account_clicked(self) -> None:
        if self.ctx.manager.status().logged_in:
            self.logout()
        else:
            self.login()

    def login(self) -> None:
        """Log in again after logging out (the saved OAuth client is reused)."""
        if self.run_setup(AccessLevel.AUDIT):
            self.progress_label.setText("✓ 로그인했습니다. 「▶ 검사 시작」을 눌러 주세요.")

    def logout(self) -> None:
        if not self.ctx.confirm(
            self, "로그아웃", "로그아웃하고 구글에 저장된 앱 권한을 철회할까요?", "로그아웃", "취소"
        ):
            return
        result = self.ctx.manager.logout()
        if result.had_token and not result.revoked:
            self.ctx.notify(
                self,
                "로그아웃",
                "이 컴퓨터의 로그인 정보는 삭제했지만 구글 쪽 권한 철회는 "
                "확인하지 못했습니다.\nhttps://myaccount.google.com/connections 에서 "
                "앱 연결을 직접 해제해 주세요.",
            )
        self._clear_session()
        self.progress_label.setText(
            "로그아웃했습니다. 다시 쓰려면 오른쪽 위 「🔑 로그인」을 누르세요."
        )
        self.refresh_account()

    def _clear_session(self) -> None:
        """Stop running work and don't leave one account's results for whoever logs in next."""
        self.cancel_event.set()
        self.wait_for_tasks()
        self.result, self.detections, self._live_token = None, None, None
        self.model.set_items([])
        self._update_dashboard([])

    def switch_client(self) -> None:
        """Another account or a new OAuth client: drop the saved one and rerun the wizard."""
        if not self.ctx.confirm(
            self,
            "계정·열쇠 바꾸기",
            "이 컴퓨터의 로그인 정보와 로그인 열쇠(클라이언트)를 지우고 설정 마법사를 엽니다.\n"
            "새 클라이언트 JSON 파일을 고른 뒤 바꿀 계정으로 로그인하면 됩니다.\n\n"
            "구글 드라이브의 파일, 암호화된 파일, 복구 키는 그대로입니다.\n"
            "진행 중인 검사는 멈춥니다(다음에 같은 계정으로 이어서 할 수 있습니다).",
            "바꾸기",
            "취소",
        ):
            return
        self._clear_session()
        self.ctx.manager.remove_client()
        self.progress_label.setText("로그인 열쇠를 지웠습니다. 설정 마법사에서 새 열쇠를 고르세요.")
        if self.run_setup():
            self.progress_label.setText(
                "✓ 바꾼 계정으로 로그인했습니다. 「▶ 검사 시작」을 눌러 주세요."
            )
        self.refresh_account()

    def open_settings(self) -> None:
        dialog = SettingsDialog(
            self.ctx,
            self,
            recovery={
                "create": self.create_recovery_key,
                "show": self.show_recovery_key,
                "enter": self.enter_recovery_key,
            },
        )
        self.ctx.show_dialog(dialog)
        if dialog.wiped:
            self.result, self.detections, self._live_token = None, None, None
            self.model.set_items([])
            self._update_dashboard([])
            self.progress_label.setText(
                "✓ 이 컴퓨터의 기록을 지웠습니다. 다음 검사는 처음부터 합니다."
            )
        self._apply_live_setting()
        self._apply_schedule()
        if dialog.removed_client:
            self.run_setup()
        self.refresh_account()

    # -- scope ----------------------------------------------------------------------------------

    def _scope_changed(self) -> None:
        key = self.scope_combo.currentData()
        self.drive_combo.setVisible(key == "drive")
        self.folder_edit.setVisible(key == "folder")
        if key == "drive" and self.drive_combo.count() == 0:
            self._load_drives()

    def _load_drives(self) -> None:
        self.drive_combo.addItem("불러오는 중…", None)
        manager, factory = self.ctx.manager, self.ctx.service_factory

        def work(_progress: Any) -> Any:
            return list(DriveClient(factory(manager)).list_shared_drives())

        task = Task(work)
        task.succeeded.connect(self._drives_loaded)
        task.failed.connect(self._drives_failed)
        self._start(task)

    def _drives_failed(self, exc: object) -> None:
        self.drive_combo.clear()
        self.drive_combo.addItem("불러오지 못함", None)
        if isinstance(exc, BaseException):
            self.ctx.notify(self, "공유 드라이브", user_message_for(exc), True)

    def _drives_loaded(self, drives: list[dict[str, Any]]) -> None:
        self.drive_combo.clear()
        if not drives:
            self.drive_combo.addItem("접근 가능한 공유 드라이브가 없습니다", None)
        for d in drives:
            self.drive_combo.addItem(str(d.get("name", d["id"])), d["id"])

    def current_scope(self) -> AuditScope | None:
        key = self.scope_combo.currentData()
        if key in ("mine", "public", "shared"):
            return AuditScope(key)
        if key == "drive":
            drive_id = self.drive_combo.currentData()
            return AuditScope("drive", drive_id) if drive_id else None
        folder = folder_id_from(self.folder_edit.text())
        return AuditScope("folder", folder) if folder else None

    # -- audit ----------------------------------------------------------------------------------

    def _open_store(self, account: str) -> AuditStore:
        return AuditStore.open_for(
            account, self.ctx.manager.secret_store, self.ctx.prefs.retention_days
        )

    def start_audit(self, *, auto: bool = False, scheduled: Schedule | None = None) -> None:
        """Run an audit. After the first full audit this only re-checks what changed
        (Drive's change list); '처음부터 다시' forces a full audit. A scheduled run asks
        nothing (no dialogs at 3 a.m.) and never starts over."""
        if scheduled is not None:
            self._start_scheduled(scheduled)
            return
        scope = self.current_scope() if not auto or self.result is None else self.result.scope
        if scope is None:
            self.ctx.notify(
                self, "감사 범위", "공유 드라이브를 고르거나 폴더 주소를 입력해 주세요."
            )
            return
        if auto:
            level = self.ctx.manager.status().level
            detect = (
                self.detections is not None and level is not None and level >= AccessLevel.DETECT
            )
        else:
            detect = self.detect_check.isChecked()
            big = self.result is None or len(self.result.items) > DETECT_GUIDE_MIN_ITEMS
            if (
                detect
                and big
                and not self.detect_shared_check.isChecked()
                and scope.kind != "folder"
                and not self.ctx.confirm(
                    self, "개인정보 찾기 안내", DETECT_GUIDE_KO, "그대로 시작", "취소"
                )
            ):
                return
            if detect and not self.ensure_detect_permission():
                return
        shared_only = detect and self.detect_shared_check.isChecked()
        self._auto_run = auto
        restart = self.restart_check.isChecked() and not auto
        self.progress_label.setText("🔄 드라이브 변경 반영 중…" if auto else "구글 계정 확인 중…")
        self._run_audit(scope, detect=detect, shared_only=shared_only, restart=restart)

    def _start_scheduled(self, sched: Schedule) -> None:
        try:
            scope = AuditScope.parse(sched.scope)
        except ValueError:
            scope = AuditScope("mine")
        level = self.ctx.manager.status().level
        detect = sched.detect and level is not None and level >= AccessLevel.DETECT
        self._sched_no_detect_permission = sched.detect and not detect
        self._sched_run = True
        self._sched_stopping = False
        self._auto_run = False
        self.progress_label.setText(f"⏰ 예약 검사 시작 — {sched.summary_ko()}")
        self._run_audit(
            scope, detect=detect, shared_only=detect and sched.detect_shared_only, restart=False
        )

    def _run_audit(
        self, scope: AuditScope, *, detect: bool, shared_only: bool, restart: bool
    ) -> None:
        self.cancel_event.clear()
        self._set_running(True)
        manager, factory, prefs = self.ctx.manager, self.ctx.service_factory, self.ctx.prefs
        cancel = self.cancel_event

        def work(progress: Any) -> Any:
            def offline(waited: float) -> bool:
                """Connection lost mid-scan: wait (up to an hour), go on where it stopped."""
                if waited >= OFFLINE_WAIT_LIMIT or cancel.is_set():
                    return False
                progress(OfflineWait(int(waited)))
                return not cancel.wait(OFFLINE_STEP)

            account = manager.verify()
            if account is None:
                raise NotLoggedIn("계정을 확인하지 못했습니다. 다시 로그인해 주세요.")
            store = self._open_store(account)
            try:
                client = DriveClient(factory(manager), on_offline=offline)
                runner = AuditRunner(
                    client,
                    store,
                    account=account,
                    internal_domains=tuple(prefs.internal_domains),
                    on_progress=progress,
                    cancel=cancel,
                )
                result = None
                if not restart and store.resumable_scan(scope.key) is None:
                    result = runner.run_incremental(scope)
                if result is None:
                    result = runner.run(scope, resume=not restart)
                detections = None
                if detect:
                    # files unchanged since the last detection keep their result (copied)
                    targets = result.items
                    if shared_only:
                        targets = [
                            a
                            for a in result.items
                            if a.exposure is None or a.exposure > Exposure.RESTRICTED
                        ]
                    detections = DetectRunner(
                        client, store, on_progress=progress, cancel=cancel
                    ).run(result.scan_id, targets)
                return result, detections
            finally:
                store.close()

        self.task = Task(work)
        self.task.progress.connect(self._on_progress)
        self.task.succeeded.connect(self._on_done)
        self.task.failed.connect(self._on_failed)
        self.task.finished.connect(self._task_finished)
        self._start(self.task)

    # -- live refresh (Phase 7) -----------------------------------------------------------------

    def _live_tick(self) -> None:
        """Every minute: ask Drive whether anything changed (one small read request, no DB).
        Only if something did, re-check just those files."""
        if (
            not self.ctx.prefs.live_refresh
            or self.result is None
            or not self._live_token
            or self._live_check is not None
            or not self.ctx.manager.status().logged_in
        ):
            return
        if self.task is not None:
            return
        total = max(self.result.total_items, len(self.result.items))
        if total > LIVE_MAX_ITEMS:
            self.live_label.setText(
                f"🔄 자동 반영 쉼 — 파일이 많아({total:,}개) 자동으로 확인하지 "
                "않습니다. 필요할 때 「검사 시작」"
            )
            return
        token = self._live_token
        drive = self.result.scope.target if self.result.scope.kind == "drive" else None
        manager, factory = self.ctx.manager, self.ctx.service_factory

        def work(_progress: Any) -> Any:
            return DriveClient(factory(manager)).list_changes(token, drive)

        check = Task(work)
        self._live_check = check
        check.succeeded.connect(self._on_live_checked)
        check.failed.connect(lambda _e: self._live_done(None))
        check.finished.connect(lambda: setattr(self, "_live_check", None))
        self._start(check)

    def _on_live_checked(self, payload: object) -> None:
        if not isinstance(payload, tuple):
            return
        changes, token = payload
        if not changes:
            self._live_token = str(token)
            self._live_done(0)
            return
        # Something changed: an incremental audit from the saved token picks it all up.
        if self.task is None:
            self.start_audit(auto=True)
        else:
            self._pending_refresh = True

    def _live_done(self, changed: int | None) -> None:
        now = dt.datetime.now().strftime("%H:%M")
        if changed is None:
            self.live_label.setText(f"🔄 자동 반영: 확인 실패 ({now}) — 다음에 다시 시도")
        else:
            self.live_label.setText(f"🔄 자동 반영 켜짐 · 마지막 확인 {now}")

    def _apply_live_setting(self) -> None:
        on = self.ctx.prefs.live_refresh
        if on:
            self.live_timer.start()
        else:
            self.live_timer.stop()
        self.live_label.setText(
            "🔄 자동 반영 켜짐 (1분마다 바뀐 파일 확인)" if on else "자동 반영 꺼짐"
        )
        self.live_btn.setText("끄기" if on else "켜기")

    def toggle_live(self) -> None:
        self.ctx.prefs.live_refresh = not self.ctx.prefs.live_refresh
        self.ctx.prefs.save()
        self._apply_live_setting()

    # -- scheduled scans (D-099) -----------------------------------------------------------------

    def schedule(self) -> Schedule:
        return Schedule.from_json(self.ctx.prefs.schedule)

    def open_schedule(self) -> None:
        dialog = ScheduleDialog(self.ctx, self, current_scope=self.current_scope(), now=self.now())
        if self.ctx.show_dialog(dialog):
            self._sched_done_for = None
            self._sched_retry_at = None
            self._apply_schedule()
            self._schedule_tick()

    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        tray = QSystemTrayIcon(badge_icon(), self)
        menu = QMenu(self)
        show = menu.addAction("열기")
        show.triggered.connect(self.show_window)
        run_now = menu.addAction("지금 검사 (이어서)")
        run_now.triggered.connect(self._run_schedule_now)
        menu.addSeparator()
        quit_action = menu.addAction("종료")
        quit_action.triggered.connect(self.quit_app)
        tray.setContextMenu(menu)
        tray.activated.connect(
            lambda reason: (
                self.show_window() if reason == QSystemTrayIcon.ActivationReason.Trigger else None
            )
        )
        self._tray_menu = menu
        self.tray = tray

    def _apply_schedule(self) -> None:
        sched = self.schedule()
        now = self.now()
        if not sched.enabled:
            self.schedule_btn.setText("⏰ 예약")
            self.schedule_btn.setToolTip("정해진 시간에 알아서 검사합니다 (예약 꺼짐)")
            self.sched_awake.stop()
        else:
            nxt = sched.next_start(now)
            active = sched.window_at(now) is not None
            self.schedule_btn.setText("⏰ 예약 중" if active else f"⏰ {sched.start} 예약")
            self.schedule_btn.setToolTip(
                f"{sched.summary_ko()}\n"
                + (
                    "지금 예약 시간입니다"
                    if active
                    else f"다음: {nxt:%m월 %d일 %H:%M}"
                    if nxt
                    else ""
                )
            )
        if self.tray is not None:
            self.tray.setToolTip(f"개인정보 보안관 · {sched.summary_ko()}")
            self.tray.setVisible(sched.enabled)

    def show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def quit_app(self) -> None:
        self._quitting = True
        self.close()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.Type.Quit:  # Dock → Quit, Cmd+Q from the system menu
            self._quitting = True
        return super().eventFilter(watched, event)

    def _tray_message(self, title: str, text: str) -> None:
        if self.tray is not None and self.tray.isVisible() and self.schedule().notify:
            self.tray.showMessage(title, text)

    def _run_schedule_now(self) -> None:
        if self.task is None and self.ctx.manager.status().logged_in:
            self.start_audit(scheduled=self.schedule())

    def _schedule_tick(self) -> None:
        """Every 30 s: inside a window start (or go on with) the scan, at its end stop it."""
        sched = self.schedule()
        now = self.now()
        window = sched.window_at(now)
        self._apply_schedule()
        if window is None:
            self.sched_awake.stop()
            if self.task is not None and self._sched_run and not self.cancel_event.is_set():
                self._sched_stopping = True
                self.cancel_audit()
            return
        begin, _finish = window
        if self._sched_done_for == begin:
            self.sched_awake.stop()
            return
        self.sched_awake.start()  # the whole window, also between retries
        if self.task is not None or self._live_check is not None:
            return  # a manual scan (or the live check) is running: go on afterwards
        if self._sched_retry_at is not None and now < self._sched_retry_at:
            return
        if not self.ctx.manager.status().logged_in:
            if self._sched_notified_for != begin:
                self._sched_notified_for = begin
                self.progress_label.setText("⏰ 로그인되어 있지 않아 예약 검사를 하지 못했습니다.")
                self._tray_message(
                    "예약 검사를 못 했습니다", "로그인이 필요합니다. 앱을 열어 로그인해 주세요."
                )
            return
        self.start_audit(scheduled=sched)

    def _scheduled_done(self, result: AuditResult, detections: Any) -> None:
        window = self.schedule().window_at(self.now())
        self._sched_done_for = window[0] if window else None
        self._sched_retry_at = None
        self.sched_awake.stop()
        c = self._last_counts
        parts = [f"{result.scope.label_ko} {max(result.total_items, len(result.items)):,}개"]
        parts.append(f"긴급·높음 {c['urgent']:,}")
        parts.append(f"링크 공개 {c['link']:,}")
        parts.append(f"외부 공유 {c['external']:,}")
        if detections is not None:
            parts.append(f"개인정보 {c['detected']:,}")
        elif self._sched_no_detect_permission:
            parts.append("개인정보는 권한이 없어 건너뜀")
        text = " · ".join(parts)
        self.progress_label.setText(f"⏰ 예약 검사 완료 ({self.now():%H:%M}) — {text}")
        self._tray_message("예약 검사 완료", text)

    def _scheduled_failed(self, exc: BaseException) -> None:
        if self._sched_stopping:
            self.progress_label.setText(
                "⏰ 예약 시간이 끝나 멈췄습니다. 다음 예약 때 그 자리부터 이어서 합니다."
            )
            return
        if isinstance(exc, (ReauthRequired, NotLoggedIn)):
            window = self.schedule().window_at(self.now())
            self._sched_done_for = window[0] if window else None
            self.refresh_account()
            self._tray_message(
                "예약 검사를 못 했습니다",
                "로그인이 만료되었습니다. 앱을 열어 다시 로그인해 주세요.",
            )
            return
        self._sched_retry_at = self.now() + SCHEDULE_RETRY
        self.progress_label.setText(
            f"⏰ 예약 검사 중 문제가 생겼습니다: {user_message_for(exc)} — "
            f"{self._sched_retry_at:%H:%M}에 다시 시도합니다."
        )

    def cancel_audit(self) -> None:
        self.cancel_event.set()
        self.progress_label.setText("중단하는 중… (현재 요청이 끝나면 멈춥니다)")
        self.cancel_btn.setEnabled(False)

    def _set_running(self, running: bool) -> None:
        if running:
            self.keep_awake.start()
            self._rate = None
        else:
            self.keep_awake.stop()
        self.start_btn.setEnabled(not running)
        self.cancel_btn.setEnabled(running)
        self.scope_combo.setEnabled(not running)
        self.logout_btn.setEnabled(not running)
        self.switch_btn.setEnabled(not running)
        self.progress_bar.setRange(0, 0 if running else 1)
        self.progress_bar.setValue(0 if running else 1)

    def _speed(self, kind: str, count: int) -> float | None:
        """Items per minute for the current phase (None until there is enough to measure)."""
        now = time.monotonic()
        if self._rate is None or self._rate[0] != kind or count < self._rate[2]:
            self._rate = (kind, now, count)
            return None
        _kind, t0, c0 = self._rate
        if now - t0 < 30 or count <= c0:
            return None
        return (count - c0) / (now - t0) * 60

    def _on_progress(self, p: object) -> None:
        if isinstance(p, OfflineWait):
            self.progress_label.setText(
                f"📡 인터넷 연결이 끊겼습니다 — 연결되면 그 자리부터 자동으로 이어서 합니다 "
                f"(기다린 시간 {p.waited // 60}분, 최대 {OFFLINE_WAIT_LIMIT // 60}분)"
            )
            return
        if isinstance(p, DetectProgress):
            self.progress_bar.setRange(0, max(p.total, 1))
            self.progress_bar.setValue(p.done)
            retry = f"  (구글 요청 제한으로 재시도 {p.retries}회)" if p.retries else ""
            per_min = self._speed("detect", p.done)
            eta = ""
            if per_min:
                eta = f" · 남은 시간 약 {_duration_ko((p.total - p.done) / per_min * 60)}"
            self.progress_label.setText(
                f"개인정보 탐지 중… {p.done:,}/{p.total:,}{eta} (파일 내용은 저장하지 않습니다)"
                f"{retry}"
            )
            return
        if not isinstance(p, Progress):
            return
        text = PHASE_KO.get(p.phase, p.phase)
        if p.phase == "list":
            text += f" {p.listed:,}개"
            if p.windows:
                text += f" · 구간 {p.window}/{p.windows} ({p.window_label})"
            per_min = self._speed("list", p.listed)
            if per_min:
                text += f" · 1분에 약 {per_min:,.0f}개"
        elif p.phase == "perms" and p.perms_total:
            self.progress_bar.setRange(0, p.perms_total)
            self.progress_bar.setValue(p.perms_done)
            text += f" {p.perms_done:,}/{p.perms_total:,}"
        if p.retries:
            text += f"  (구글 요청 제한으로 재시도 {p.retries}회)"
        self.progress_label.setText(text)

    def _on_done(self, payload: object) -> None:
        if not isinstance(payload, tuple):
            return
        result, detections = payload
        if not isinstance(result, AuditResult):
            return
        self.result = result
        self.detections = detections
        self.model.set_items(result.items, detections)
        self._update_dashboard(result.items)
        self.export_btn.setEnabled(bool(result.items))
        self.organize_btn.setEnabled(bool(result.items))
        for act in (self.archive_action, self.move_action, self.organize_action):
            act.setEnabled(bool(result.items))
        if detections is None and self._keep_detections is not None:
            detections = self._keep_detections  # permission changes do not change contents
            self.detections = detections
            self.model.set_items(result.items, detections)
            self._update_dashboard(result.items)
        self._keep_detections = None
        self._update_actions()
        self._refresh_vault_keys()
        self._live_token = result.changes_token
        now = dt.datetime.now().strftime("%H:%M")
        if self._auto_run:
            self.progress_label.setText(
                f"✓ 드라이브 변경 반영: 바뀐 항목 {len(result.changed):,}개 ({now})"
            )
            self._live_done(len(result.changed))
        elif result.incremental:
            self.progress_label.setText(
                f"✓ 바뀐 부분만 다시 검사: 변경 {len(result.changed):,}개 · "
                f"{result.scope.label_ko} {len(result.items):,}개 (처음부터 하려면 '처음부터 다시')"
            )
        else:
            note = " (중단된 감사를 이어서 완료)" if result.resumed else ""
            total = max(result.total_items, len(result.items))
            self.progress_label.setText(f"✓ 감사 완료: {result.scope.label_ko} {total:,}개{note}")
        self._auto_run = False
        notices = []
        if detections is not None:
            unscannable = sum(
                1
                for d in detections.values()
                if d.status in (DetectStatus.UNSCANNABLE, DetectStatus.FAILED) or d.partial
            )
            if unscannable:
                notices.append(
                    f"검사 불가 {unscannable:,}개: 암호·스캔·크기 초과 등으로 "
                    "내용을 읽지 못한 파일입니다. "
                    "안전하다는 뜻이 아닙니다."
                )
        if any(a.exposure is None for a in result.items):
            notices.append(
                "'확인 필요' 항목은 공유 설정을 확인할 권한이 없는 파일입니다. "
                "안전하다는 뜻이 아니므로 소유자에게 확인해 주세요."
            )
        if result.trimmed:
            notices.append(
                f"파일이 아주 많아(전체 {result.total_items:,}개) 메모리를 아끼려고 "
                "목록에는 공유되었거나 확인이 필요한 항목과 그 상위 폴더 "
                f"{len(result.items):,}개만 보여 줍니다. "
                "나머지는 공유되지 않은(제한됨) 파일입니다."
                + (" 개인정보 찾기도 이 항목들만 했습니다." if detections is not None else "")
            )
        if result.incomplete_search:
            notices.append(
                "⚠ 구글이 일부 검색 결과를 생략했다고 알려 왔습니다. "
                "범위를 좁혀 다시 감사해 주세요."
            )
        self.notice_label.setText("\n".join(notices))
        self.notice_label.setVisible(bool(notices))
        if self._sched_run:
            self._scheduled_done(result, detections)

    def _on_failed(self, exc: object) -> None:
        self._auto_run = False
        if not isinstance(exc, BaseException):
            return
        self.progress_label.setText(f"✗ {user_message_for(exc)}")
        if self._sched_run:
            self._scheduled_failed(exc)
            return
        if isinstance(exc, (ReauthRequired, NotLoggedIn)):
            self.ctx.notify(self, "다시 로그인", user_message_for(exc))
            self.refresh_account()
            self.run_setup()

    def _task_finished(self) -> None:
        self.task = None
        self._sched_run = False
        self._sched_stopping = False
        self._set_running(False)
        self._update_actions()
        self.refresh_account()
        self._after_task()

    # -- dashboard / filter ---------------------------------------------------------------------

    def _update_dashboard(self, items: list[FileAudit]) -> None:
        counts: Counter[str] = Counter()
        for a in items:
            det = self.model.detections.get(a.file_id)
            recs = self.model.recs.get(a.file_id)
            for key, _label in DASHBOARD:
                if matches_filter(a, key, det, recs):
                    counts[key] += 1
        for key, label in DASHBOARD:
            self.dash_buttons[key].setText(f"{label}\n{counts[key]:,}")
        self._last_counts = counts

    def set_filter(self, key: str) -> None:
        self.proxy.set_key(key)
        self._update_actions()
        for k, btn in self.dash_buttons.items():
            btn.setChecked(k == key)
        index = self.filter_combo.findData(key)
        if index >= 0 and index != self.filter_combo.currentIndex():
            self.filter_combo.setCurrentIndex(index)
        self._update_count()

    def _search_changed(self, text: str) -> None:
        self.proxy.set_text(text)

    def _update_count(self, *_args: object) -> None:
        self.count_label.setText(f"{self.proxy.rowCount():,} / {self.model.rowCount():,}개")

    # -- export ---------------------------------------------------------------------------------

    def export_report(self) -> None:
        if self.result is None or not self.result.items:
            self.ctx.notify(self, "보고서 저장", "먼저 감사를 실행해 주세요.")
            return
        dialog = ExportDialog(self)
        if not dialog.exec():
            return
        suffix = dialog.fmt.currentData()
        default = str(Path.home() / f"dpg_감사보고서{suffix}")
        path_str, _ = QFileDialog.getSaveFileName(self, "보고서 저장", default, f"*{suffix}")
        if not path_str:
            return
        path = Path(path_str)
        if path.suffix.lower() != suffix:
            path = path.with_suffix(suffix)
        try:
            n = write_report(
                path,
                self.result.items,
                mask=dialog.mask_check.isChecked(),
                detections=self.detections,
            )
        except OSError:
            self.ctx.notify(
                self,
                "보고서 저장",
                "보고서를 저장하지 못했습니다. 다른 폴더를 선택해 주세요.\n"
                "(macOS: 시스템 설정 → 개인정보 보호 및 보안 → 파일 및 폴더에서 허용이 "
                "필요할 수 있습니다)",
                True,
            )
            return
        self.ctx.notify(self, "보고서 저장", f"저장했습니다 ({n:,}행):\n{path}")

    # -- review / exclude (Phase 4) ------------------------------------------------------------

    def selected_item(self) -> FileAudit | None:
        items = self.selected_items()
        return items[0] if len(items) == 1 else (items[0] if items else None)

    def open_selected_in_drive(self) -> None:
        """Open the chosen files in the browser's Google Drive to look at them directly."""
        items = self.selected_items() if self.result is not None else []
        if not items:
            return
        if len(items) > OPEN_MAX:
            self.ctx.notify(
                self,
                "드라이브에서 열기",
                f"한 번에 {OPEN_MAX}개까지 엽니다. 앞의 {OPEN_MAX}개를 엽니다.",
            )
        for a in items[:OPEN_MAX]:
            self.ctx.open_url(drive_link(a))

    def detect_selected(self) -> None:
        """Personal-data check of the chosen files only (e.g. the link-public ones)."""
        items = self.selected_items() if self.result is not None else []
        if not items or self.result is None or self.task is not None:
            return
        if not self.ensure_detect_permission():
            return
        result = self.result
        manager, factory, cancel = self.ctx.manager, self.ctx.service_factory, self.cancel_event
        self.cancel_event.clear()
        self._set_running(True)
        self.progress_label.setText(f"고른 파일 {len(items):,}개의 개인정보를 찾는 중…")

        def work(progress: Any) -> Any:
            account = manager.verify()
            if account is None:
                raise NotLoggedIn("계정을 확인하지 못했습니다. 다시 로그인해 주세요.")
            store = self._open_store(account)
            try:
                client = DriveClient(factory(manager))
                runner = DetectRunner(client, store, on_progress=progress, cancel=cancel)
                return runner.run(result.scan_id, items)
            finally:
                store.close()

        def done(found: object) -> None:
            if not isinstance(found, dict) or self.result is not result:
                return
            self.detections = {**(self.detections or {}), **found}
            self.model.set_items(result.items, self.detections)
            self._update_dashboard(result.items)
            hits = sum(
                1
                for a in items
                if (d := self.detections.get(a.file_id)) is not None
                and d.status is DetectStatus.DETECTED
            )
            self.progress_label.setText(
                f"✓ 고른 파일 {len(items):,}개 검사 — 개인정보 있음 {hits:,}개 "
                "(「개인정보 탐지」 칸에서 모아 보기)"
            )
            self._update_actions()

        self.task = Task(work)
        self.task.progress.connect(self._on_progress)
        self.task.succeeded.connect(done)
        self.task.failed.connect(self._on_failed)
        self.task.finished.connect(self._task_finished)
        self._start(self.task)

    def review_selected(self) -> None:
        item = self.selected_item()
        if item is None or self.detections is None:
            return
        if item.is_folder:
            self.ctx.notify(self, "검토", "폴더는 이름만 검사합니다.")
            return
        manager, factory = self.ctx.manager, self.ctx.service_factory

        def work(_progress: Any) -> Any:
            return review(DriveClient(factory(manager)), item)

        task = Task(work)
        task.succeeded.connect(lambda lines: self._show_review(item, lines))
        task.failed.connect(
            lambda exc: self.ctx.notify(
                self,
                "검토",
                user_message_for(exc)
                if not isinstance(exc, Unscannable)
                else f"검사 불가: {UNSCANNABLE_LABEL_KO[exc.reason]}",
                True,
            )
        )
        self._start(task)

    def _show_review(self, item: FileAudit, lines: object) -> None:
        if not isinstance(lines, list):
            return
        dialog = ReviewDialog(
            item.name, lines, self, open_drive=lambda: self.ctx.open_url(drive_link(item))
        )
        self.ctx.show_dialog(dialog)

    def _all_excluded(self, items: list[FileAudit]) -> bool:
        dets = self.detections or {}
        return bool(items) and all(
            (d := dets.get(a.file_id)) is not None and d.status is DetectStatus.EXCLUDED
            for a in items
        )

    def exclude_selected(self) -> None:
        items = self.selected_items()
        if not items or self.detections is None:
            return
        if self._all_excluded(items):
            self._restore_exclusions([(a.file_id, "*") for a in items])
            return
        what = f"'{items[0].name}'" if len(items) == 1 else f"파일 {len(items):,}개"
        if not self.ctx.confirm(
            self,
            "탐지에서 제외",
            f"{what}을(를) 개인정보 탐지에서 제외할까요?\n"
            "(다음 탐지부터 읽지 않습니다. 설정은 이 컴퓨터에만 저장됩니다.\n"
            "잘못 제외했다면 「🙈 제외 목록」에서 바로 되돌릴 수 있습니다.)",
            "제외",
            "취소",
        ):
            return
        account = self.ctx.manager.status().account
        if account is None:
            return
        store = self._open_store(account)
        try:
            for item in items:
                store.add_exclusion(item.file_id)
        finally:
            store.close()
        for item in items:
            det = FileDetection(item.file_id, DetectStatus.EXCLUDED)
            self.detections[item.file_id] = det
            self.model.update_detection(det)
        self.model.set_checked([a.file_id for a in items], False)
        if self.result is not None:
            self._update_dashboard(self.result.items)
        self.progress_label.setText(
            f"✓ {what} 제외함 — 되돌리려면 「🙈 제외 목록」 (보기: '탐지에서 제외한 파일')"
        )

    def show_exclusions(self) -> None:
        account = self.ctx.manager.status().account
        if account is None:
            self.ctx.notify(self, "제외 목록", "먼저 구글 계정으로 로그인해 주세요.")
            return
        store = self._open_store(account)
        try:
            rules = sorted(store.exclusions())
        finally:
            store.close()
        by_id = {a.file_id: a for a in self.result.items} if self.result else {}
        dialog = ExclusionsDialog(
            [(fid, rule, by_id[fid].name if fid in by_id else None) for fid, rule in rules], self
        )
        self.ctx.show_dialog(dialog)
        if dialog.restored:
            self._restore_exclusions(dialog.restored)

    def _restore_exclusions(self, pairs: list[tuple[str, str]]) -> None:
        """Undo exclusions and re-check those files right away."""
        account = self.ctx.manager.status().account
        if account is None:
            return
        store = self._open_store(account)
        try:
            for fid, rule in pairs:
                store.remove_exclusion(fid, rule)
        finally:
            store.close()
        by_id = {a.file_id: a for a in self.result.items} if self.result else {}
        again = [by_id[fid] for fid, _r in pairs if fid in by_id]
        if again and self.detections is not None:
            self._rescan(again)
        else:
            self.progress_label.setText("✓ 제외를 해제했습니다. 다음 탐지부터 다시 검사합니다.")

    def _rescan(self, items: list[FileAudit]) -> None:
        """Re-detect just these files right away (e.g. after removing an exclusion)."""
        if self.task is not None:
            self._pending_next = lambda: self._rescan(items)
            return
        manager, factory = self.ctx.manager, self.ctx.service_factory
        account = manager.status().account

        def work(_progress: Any) -> Any:
            if account is None:
                raise NotLoggedIn()
            store = self._open_store(account)
            try:
                runner = DetectRunner(DriveClient(factory(manager)), store)
                return [runner.scan_one(a, set()) for a in items]
            finally:
                store.close()

        def done(dets: object) -> None:
            if not isinstance(dets, list):
                return
            for det in dets:
                if self.detections is not None:
                    self.detections[det.file_id] = det
                self.model.update_detection(det)
            if self.result is not None:
                self._update_dashboard(self.result.items)
            self.progress_label.setText(f"✓ 제외 해제 후 다시 검사함: {len(dets):,}개")

        self._set_running(True)
        self.progress_label.setText("제외를 해제한 파일을 다시 검사하는 중…")
        self.task = Task(work)
        self.task.succeeded.connect(done)
        self.task.failed.connect(self._on_failed)
        self.task.finished.connect(self._task_finished)
        self._start(self.task)

    # -- permission changes (Phase 5) ---------------------------------------------------------

    def selected_items(self) -> list[FileAudit]:
        """Checked rows (checkbox column); if none are checked, the highlighted rows."""
        checked = self.model.checked_items()
        if checked:
            return checked
        rows = self.table.selectionModel().selectedRows()
        return [self.model.items[self.proxy.mapToSource(r).row()] for r in rows]

    def _visible_ids(self) -> list[str]:
        return [
            self.model.items[self.proxy.mapToSource(self.proxy.index(r, 0)).row()].file_id
            for r in range(self.proxy.rowCount())
        ]

    def _visible_check_state(self) -> Qt.CheckState:
        ids = self._visible_ids()
        n = sum(1 for i in ids if i in self.model.checked)
        if ids and n == len(ids):
            return Qt.CheckState.Checked
        return Qt.CheckState.PartiallyChecked if n else Qt.CheckState.Unchecked

    def check_visible(self, on: bool) -> None:
        """Header checkbox: check / uncheck every row shown in the current view."""
        self.model.set_checked(self._visible_ids(), on)
        self._update_actions()

    def uncheck_all(self) -> None:
        """Also clears rows checked in other views (filters) that are hidden right now."""
        self.model.set_checked(list(self.model.checked), False)
        self.table.clearSelection()
        self._update_actions()

    def apply_sort(self, index: int) -> None:
        _label, col, desc = SORTS[index]
        order = Qt.SortOrder.DescendingOrder if desc else Qt.SortOrder.AscendingOrder
        self.table.sortByColumn(col, order)

    def _update_actions(self) -> None:
        """Enable the ④ buttons according to what is chosen (and explain the count)."""
        if not hasattr(self, "unpack_btn"):
            return
        items = self.selected_items() if self.result is not None else []
        n = len(items)
        checked = len(self.model.checked)
        visible = set(self._visible_ids())
        hidden = sum(1 for i in self.model.checked if i not in visible)
        if not n:
            text = "고른 파일 없음 — 표 왼쪽 체크박스를 누르세요 (맨 위 칸은 모두 고르기)"
        else:
            text = f"✔ 고른 파일 {n:,}개"
            if hidden:
                text += f"  ⚠ 그중 {hidden:,}개는 다른 보기에서 고른 파일(지금 안 보임)"
            elif not checked:
                text += " (줄 선택)"
        self.selection_label.setText(text)
        self.check_header.viewport().update()
        has = self.result is not None and n > 0
        for b in (self.change_btn, self.archive_btn, self.move_btn):
            b.setEnabled(has)
        self.detect_btn.setEnabled(has and self.task is None)
        self.open_btn.setEnabled(has)
        detected = self.detections is not None
        self.review_btn.setEnabled(has and n == 1 and detected)
        self.exclude_btn.setEnabled(has and detected)
        self.exclude_btn.setText(
            "↩ 탐지 제외 해제"
            if has and detected and self._all_excluded(items)
            else "🙈 탐지에서 제외"
        )
        self.unpack_btn.setEnabled(True)
        self.select_none_btn.setEnabled(bool(checked) or n > 0)

    def ensure_modify_permission(self) -> bool:
        st = self.ctx.manager.status()
        if st.level is not None and st.level >= AccessLevel.MODIFY:
            return True
        if not self.ctx.confirm(
            self,
            "권한 추가",
            "공유 설정을 바꾸려면 권한이 추가로 필요합니다.\n\n"
            f"{LEVEL_EXPLAIN_KO[AccessLevel.MODIFY]}\n\n구글 로그인 화면에서 권한을 추가할까요?",
            "권한 추가",
            "취소",
        ):
            return False
        return self.run_setup(AccessLevel.MODIFY)

    def change_selected(self, items: list[FileAudit] | None = None) -> None:
        items = items if items is not None else self.selected_items()
        if not items or self.result is None:
            self.ctx.notify(self, "권한 변경", "표에서 바꿀 파일을 먼저 선택해 주세요.")
            return
        if self.task is not None:
            return
        if not self.ensure_modify_permission():
            return
        account = self.ctx.manager.status().account
        internal = internal_domains_for(account, self.ctx.prefs.internal_domains)
        all_items = self.result.items
        names = {a.file_id: a.name for a in all_items}
        default = ActionKind.REMOVE_LINK
        for a in items:
            recs = self.model.recs.get(a.file_id) or []
            keys = {k.value for k in ActionKind}
            if recs and recs[0].action in keys:
                default = ActionKind(recs[0].action)
                break

        def build(kind: ActionKind) -> Plan:
            return build_plan(
                kind, items, account=account, internal_domains=internal, all_items=all_items
            )

        dialog = ActionDialog(build, names, default, self.ctx.prefs.dry_run_mode, self)
        if not self.ctx.show_dialog(dialog):
            if dialog.go_to_folders:  # the link comes from a parent folder: change it there
                by_id = {a.file_id: a for a in all_items}
                folders = [by_id[f] for f in dialog.go_to_folders if f in by_id]
                if folders:
                    self.change_selected(folders)
                else:
                    self.ctx.notify(
                        self,
                        "권한 변경",
                        "상위 폴더가 이번 검사 범위 밖에 있습니다. 「내 소유 파일」로 검사한 뒤 "
                        "다시 해 주세요.",
                    )
            return
        self.run_plan(dialog.plan, dry_run=dialog.dry_run.isChecked(), names=names)

    def _executor_task(
        self,
        fn: Any,
        names: dict[str, str],
        refresh: bool,
        then: Any = None,
        labels: tuple[str, str] | None = None,
    ) -> None:
        manager, factory = self.ctx.manager, self.ctx.service_factory
        account = manager.status().account
        cancel = self.cancel_event
        cancel.clear()

        def work(progress: Any) -> Any:
            if account is None:
                raise NotLoggedIn()
            store = self._open_store(account)
            try:
                executor = ActionExecutor(
                    DriveClient(factory(manager)), store, on_progress=progress, cancel=cancel
                )
                return fn(executor)
            finally:
                store.close()

        self._set_running(True)
        self.progress_label.setText("권한 변경 중… (파일마다 실행 직전에 다시 확인합니다)")
        self.task = Task(work)
        self.task.progress.connect(self._on_action_progress)
        self.task.succeeded.connect(lambda r: self._on_action_done(r, names, refresh, then, labels))
        self.task.failed.connect(self._on_failed)
        self.task.finished.connect(self._task_finished)
        self._start(self.task)

    def run_plan(
        self,
        plan: Plan,
        *,
        dry_run: bool,
        names: dict[str, str],
        then: Any = None,
        labels: tuple[str, str] | None = None,
    ) -> None:
        self._executor_task(
            lambda ex: ex.execute(plan, dry_run=dry_run),
            names,
            refresh=not dry_run,
            then=then,
            labels=labels,
        )

    def run_undo(self, run_id: int, names: dict[str, str]) -> None:
        self._executor_task(lambda ex: ex.undo(run_id), names, refresh=True)

    def _on_action_progress(self, p: object) -> None:
        if isinstance(p, ActionProgress):
            self.progress_bar.setRange(0, max(p.total, 1))
            self.progress_bar.setValue(p.done)
            self.progress_label.setText(f"권한 변경 중… {p.done:,}/{p.total:,}")

    def _on_action_done(
        self,
        result: object,
        names: dict[str, str],
        refresh: bool,
        then: Any = None,
        labels: tuple[str, str] | None = None,
    ) -> None:
        if not isinstance(result, RunResult):
            return
        done = result.count(ChangeState.DONE) + result.count(ChangeState.UNDONE)
        self.progress_label.setText(
            "✓ 드라이런 완료" if result.dry_run else f"✓ 권한 변경 처리 완료 ({done:,}건)"
        )
        dialog = ResultDialog(result, names, self, labels=labels)
        self.ctx.show_dialog(dialog)
        if dialog.undo_requested:
            self._pending_undo = (result.run_id, names)
        elif then is not None:
            self._pending_next = lambda: then(result)
        if refresh:
            self._pending_refresh = True

    def _after_task(self) -> None:
        """Follow-ups that must start after the current task has fully finished."""
        pending_next = self._pending_next
        self._pending_next = None
        if pending_next is not None:
            pending_next()
            return
        pending_undo = self._pending_undo
        self._pending_undo = None
        if pending_undo is not None:
            self.run_undo(*pending_undo)
            return
        if self._pending_refresh:
            self._pending_refresh = False
            self.refresh_audit()

    def refresh_audit(self) -> None:
        """After a change made here (or seen by the live check): re-check only what changed.
        Detection results of unchanged files are kept; new or edited files are re-read."""
        if self.result is None:
            return
        self._keep_detections = self.detections
        self.start_audit(auto=True)

    def open_history(self) -> None:
        account = self.ctx.manager.status().account
        if account is None:
            return
        store = self._open_store(account)
        try:
            runs = store.action_runs()
        finally:
            store.close()
        dialog = HistoryDialog(runs, self)
        self.ctx.show_dialog(dialog)
        if dialog.selected_run is not None and self.ensure_modify_permission():
            names = {a.file_id: a.name for a in self.result.items} if self.result else {}
            self.run_undo(dialog.selected_run, names)

    # -- encrypted archive / organise (Phase 6) ------------------------------------------------

    def _names(self) -> dict[str, str]:
        return {a.file_id: a.name for a in self.result.items} if self.result else {}

    def archive_selected(self) -> None:
        items = [a for a in self.selected_items() if not a.is_folder]
        if not items or self.result is None:
            self.ctx.notify(self, "암호화 보관", "표에서 보관할 파일을 먼저 선택해 주세요.")
            return
        if self.task is not None or not self.ensure_modify_permission():
            return
        choose = ArchiveDialog(items, self._archive_destinations(items), self)
        if not self.ctx.show_dialog(choose):
            return
        fmt, parent_id = choose.chosen_format, choose.upload_parent
        self._archive_precheck = choose.replace.isChecked()  # default: originals to the trash
        account = self.ctx.manager.status().account
        internal = internal_domains_for(account, self.ctx.prefs.internal_domains)
        names = self._names()
        restrict = build_plan(
            ActionKind.RESTRICT_ALL,
            items,
            account=account,
            internal_domains=internal,
            all_items=self.result.items,
        )
        if not restrict.changes:
            self._ask_password_and_archive(items, fmt, parent_id)
            return
        dialog = ActionDialog(
            lambda kind: restrict,
            names,
            ActionKind.RESTRICT_ALL,
            False,
            self,
            kinds=(ActionKind.RESTRICT_ALL,),
        )
        dialog.dry_run.setChecked(False)
        dialog.dry_run.setEnabled(False)  # step 1 must really happen before archiving
        if not self.ctx.show_dialog(dialog):
            return

        def after_restrict(result: RunResult) -> None:
            if result.count(ChangeState.FAILED) or result.count(ChangeState.CONFLICT):
                self.ctx.notify(
                    self,
                    "암호화 보관 중단",
                    "원본 공유 해제가 모두 끝나지 않아 보관을 시작하지 않았습니다. "
                    "다시 감사한 뒤 시도해 주세요.",
                )
                self._pending_refresh = True
                self._after_task()
                return
            self._ask_password_and_archive(items, fmt, parent_id)

        self.run_plan(
            dialog.plan,
            dry_run=False,
            names=names,
            then=after_restrict,
            labels=("① 원본 공유 해제 결과", "다음: 암호화 진행 →"),
        )

    def _archive_destinations(self, items: list[FileAudit]) -> list[Destination]:
        """Where the archive may go: the originals' own folder first, then my folders."""
        all_items = self.result.items if self.result is not None else []
        by_id = {a.file_id: a for a in all_items}

        def warning(folder_id: str) -> str:
            f = by_id.get(folder_id)
            if f is None:
                return ""
            if f.exposure is None or f.status is not ItemStatus.OK:
                return "공유 상태를 확인하지 못한 폴더입니다."
            if f.exposure is not Exposure.RESTRICTED or f.internal_accounts:
                return (
                    "이 폴더는 다른 사람과 공유되어 있어 암호 파일이 그 사람들에게도 보입니다 "
                    "(비밀번호 없이는 열 수 없음)."
                )
            return ""

        out: list[Destination] = []
        parents = {a.parent_id for a in items}
        here = next(iter(parents)) if len(parents) == 1 else None
        if here:
            label = self.model.paths.get(items[0].file_id, "원래 폴더")
            out.append(Destination(here, f"📍 원래 있던 자리 — {label}", warning(here)))
        if here is None or here in by_id:
            out.append(Destination(ROOT_ID, "내 드라이브 (최상위)"))
        for f in sorted(
            (a for a in all_items if a.is_folder and a.owned_by_me and a.drive_id is None),
            key=lambda a: self.model.tree_keys.get(a.file_id, a.name),
        ):
            if f.file_id != here:
                path = self.model.paths.get(f.file_id, "내 드라이브")
                out.append(Destination(f.file_id, f"📁 {path} › {f.name}", warning(f.file_id)))
        return out

    # -- recovery key (D-074) -------------------------------------------------------------------

    def _recovery_key(self) -> bytes | None:
        text = self.ctx.manager.secret_store.get(RECOVERY_KEY_NAME)
        if not text:
            return None
        try:
            return parse_recovery_key(text)
        except InvalidRecoveryKey:
            return None

    def _recovery_key_for_new_archive(self) -> bytes | None:
        """Use the recovery key if there is one; otherwise offer to make (or re-enter) one."""
        raw = self._recovery_key()
        if raw is not None:
            return raw
        if self.ctx.prefs.recovery_fingerprint:
            if self.ctx.confirm(
                self,
                "복구 키",
                "예전에 만든 복구 키가 이 컴퓨터의 키체인에 없습니다(모든 기록 삭제 또는 새 "
                "컴퓨터). 종이에 적어 둔 복구 키를 입력하면 이어서 쓸 수 있습니다.",
                "복구 키 입력",
                "이번엔 복구 키 없이 진행",
            ):
                self.enter_recovery_key()
            return self._recovery_key()
        if self.ctx.confirm(
            self,
            "복구 키 만들기 (권장)",
            "비밀번호와 키체인을 모두 잃어도 암호화한 파일을 열 수 있도록 '복구 키'를 "
            "만들까요?\n\n복구 키는 한 번 만들어 종이에 보관합니다. 메일·서버로 보내지 않습니다.",
            "복구 키 만들기",
            "만들지 않고 진행",
        ):
            self.create_recovery_key()
        return self._recovery_key()

    def create_recovery_key(self) -> None:
        if self._recovery_key() is not None:
            return  # never replace: archives made with the old key would lose their recovery
        key = new_recovery_key()
        raw = parse_recovery_key(key)
        fp = fingerprint(raw)
        dialog = RecoveryKeyDialog(
            key, fp, new=True, print_key=lambda k, f: print_recovery_key(k, f, self), parent=self
        )
        if not self.ctx.show_dialog(dialog):
            return
        self.ctx.manager.secret_store.set(RECOVERY_KEY_NAME, key)
        self.ctx.prefs.recovery_fingerprint = fp
        self.ctx.prefs.save()

    def show_recovery_key(self) -> None:
        text = self.ctx.manager.secret_store.get(RECOVERY_KEY_NAME)
        raw = self._recovery_key()
        if text is None or raw is None:
            self.ctx.notify(self, "복구 키", "이 컴퓨터에 저장된 복구 키가 없습니다.")
            return
        self.ctx.show_dialog(
            RecoveryKeyDialog(
                text,
                fingerprint(raw),
                new=False,
                print_key=lambda k, f: print_recovery_key(k, f, self),
                parent=self,
            )
        )

    def enter_recovery_key(self) -> bool:
        text, ok = QInputDialog.getText(
            self, "복구 키 입력", "종이에 적어 둔 복구 키(35자):", QLineEdit.EchoMode.Normal
        )
        if not ok or not text.strip():
            return False
        try:
            raw = parse_recovery_key(text)
        except InvalidRecoveryKey as exc:
            self.ctx.notify(self, "복구 키", str(exc), True)
            return False
        fp = fingerprint(raw)
        known = self.ctx.prefs.recovery_fingerprint
        if (
            known
            and known != fp
            and not self.ctx.confirm(
                self,
                "복구 키",
                f"이 컴퓨터에서 쓰던 복구 키(지문 {known})와 다른 키(지문 {fp})입니다. "
                "그래도 이 키를 저장할까요?",
                "저장",
                "취소",
            )
        ):
            return False
        self.ctx.manager.secret_store.set(RECOVERY_KEY_NAME, text.strip().upper())
        self.ctx.prefs.recovery_fingerprint = fp
        self.ctx.prefs.save()
        self.ctx.notify(
            self, "복구 키", f"복구 키를 이 컴퓨터의 키체인에 저장했습니다 (지문 {fp})."
        )
        return True

    def _password_for(self, archive_name: str, typed: str) -> str:
        """A typed recovery key (35 chars) turns into that archive's derived password."""
        tag = tag_from_name(archive_name)
        if tag is None:
            return typed
        try:
            raw = parse_recovery_key(typed)
        except InvalidRecoveryKey:
            return typed
        return derive_password(raw, tag)

    def _ask_password_and_archive(
        self, items: list[FileAudit], fmt: archive.ArchiveFormat, parent_id: str
    ) -> None:
        raw = self._recovery_key_for_new_archive()
        name = archive.archive_name(fmt, names=[member_name(i) for i in items])
        tag = tag_from_name(name)
        if raw is not None and tag is not None:
            password = derive_password(raw, tag)
        else:
            password = archive.generate_password()
        pw_dialog = PasswordDialog(
            password,
            lambda pw: print_recovery_card(pw, self),
            self,
            recoverable=raw is not None,
        )
        if not self.ctx.show_dialog(pw_dialog):
            self._pending_refresh = True
            self._after_task()
            return
        keep = pw_dialog.save_keychain.isChecked()
        manager, factory = self.ctx.manager, self.ctx.service_factory
        cancel = self.cancel_event
        cancel.clear()

        def work(progress: Any) -> Any:
            job = ArchiveJob(DriveClient(factory(manager)), on_progress=progress, cancel=cancel)
            result = job.run(items, password, fmt, parent_id, name=name)
            if keep and result.uploaded_id:
                remember_vault_password(manager.secret_store, result.name, password)
            return result

        self._set_running(True)
        self.progress_label.setText("암호화 보관 중…")
        self.task = Task(work)
        self.task.progress.connect(self._on_archive_progress)
        self.task.succeeded.connect(self._on_archive_done)
        self.task.failed.connect(self._on_failed)
        self.task.finished.connect(self._task_finished)
        self._start(self.task)

    def _on_archive_progress(self, p: object) -> None:
        if isinstance(p, ArchiveProgress):
            self.progress_bar.setRange(0, max(p.total, 1))
            self.progress_bar.setValue(p.done)
            self.progress_label.setText(f"암호화 보관: {p.step}… {p.done:,}/{p.total:,}")

    def _on_archive_done(self, result: object) -> None:
        if not isinstance(result, ArchiveResult):
            return
        self.progress_label.setText(
            f"✓ 보관 파일 {result.name} 업로드 완료"
            if result.safe_to_trash
            else "⚠ 보관 파일 확인 실패 — 원본은 그대로입니다"
        )
        # the job is over: its files are no longer "chosen" (user report: checks stayed on)
        self.model.set_checked(list(result.members) + [s.file_id for s in result.skipped], False)
        names = self._names()
        dialog = ArchiveResultDialog(result, names, self, precheck=self._archive_precheck)
        self.ctx.show_dialog(dialog)
        self._pending_refresh = True
        if dialog.approved and self.result is not None:
            by_id = {a.file_id: a for a in self.result.items}
            plan = trash_plan(result, dialog.approved, by_id)
            self._pending_next = lambda: self.run_plan(
                plan,
                dry_run=False,
                names=names,
                labels=("암호화 보관 완료", "✓ 암호화 완료"),
            )

    def move_selected(self) -> None:
        items = self.selected_items()
        if not items or self.result is None:
            self.ctx.notify(self, "폴더로 이동", "표에서 옮길 파일을 먼저 선택해 주세요.")
            return
        if self.task is not None or not self.ensure_modify_permission():
            return
        all_items = list(self.result.items)
        folders = sorted(
            (a for a in all_items if a.is_folder and a.drive_id is None),
            key=lambda a: self.model.tree_keys.get(a.file_id, a.name),
        )
        labels = {
            f.file_id: f"📁 {self.model.paths.get(f.file_id, '내 드라이브')} › {f.name}"
            for f in folders
        }
        root = self._my_drive_root(all_items)
        if root is not None:
            folders.insert(0, root)
            labels[root.file_id] = "🏠 내 드라이브 (최상위)"
        if not folders:
            self.ctx.notify(self, "폴더로 옮기기", "옮길 수 있는 폴더가 없습니다.")
            return
        manager, factory = self.ctx.manager, self.ctx.service_factory

        def create_folder(name: str, where: FileAudit) -> FileAudit | None:
            try:
                meta = DriveWriter(DriveClient(factory(manager))).create_folder(name, where.file_id)
            except (DriveHttpError, ValueError, AuthError) as exc:
                self.ctx.notify(self, "새 폴더", f"폴더를 만들지 못했습니다: {exc}", True)
                return None
            log.info("folder created for move")
            made = new_folder_audit(str(meta["id"]), name.strip(), where)
            all_items.append(made)
            self._pending_refresh = True
            return made

        dialog = MoveDialog(
            lambda dest: build_move_plan(items, dest, all_items),
            folders,
            self._names(),
            self,
            create_folder=create_folder,
            labels=labels,
        )
        if not self.ctx.show_dialog(dialog) or dialog.plan is None:
            if self._pending_refresh:
                self._after_task()  # show a folder that was created even if nothing moved
            return
        self.run_plan(dialog.plan, dry_run=False, names=self._names())

    @staticmethod
    def _my_drive_root(items: list[FileAudit]) -> FileAudit | None:
        """My Drive's root as a move destination (its id is the parent of my top items)."""
        ids = {a.file_id for a in items}
        roots = {
            a.parent_id
            for a in items
            if a.owned_by_me and a.drive_id is None and a.parent_id and a.parent_id not in ids
        }
        if len(roots) != 1:
            return None
        return FileAudit(
            file_id=str(next(iter(roots))),
            name="내 드라이브",
            mime_type="application/vnd.google-apps.folder",
            is_folder=True,
            drive_id=None,
            parent_id=None,
            owner_email=None,
            owned_by_me=True,
            modified_time=None,
            status=ItemStatus.OK,
            exposure=Exposure.RESTRICTED,
            risk_score=0,
        )

    def show_organize(self) -> None:
        if self.result is None:
            return
        dets = self.detections or {}
        files = [a for a in self.result.items if not a.is_folder]
        suggestions = [(a, suggest(a, dets.get(a.file_id))) for a in files]
        self.ctx.show_dialog(OrganizeDialog(suggestions, duplicate_groups(self.result.items), self))

    def unpack_clicked(self) -> None:
        """Selected archive → unpack from Drive (in place, or to this computer); else local file."""
        chosen = [
            a
            for a in (self.selected_items() if self.result is not None else [])
            if not a.is_folder and a.name.lower().endswith((".7z", ".zip"))
        ]
        if not chosen:
            self.open_archive_file()
            return
        item = chosen[0]
        store = self.ctx.manager.secret_store
        saved = store.get(f"vault:{item.name}")
        label = "🔑 키체인에 저장된 비밀번호 사용"
        tag = tag_from_name(item.name)
        raw = self._recovery_key()
        if saved is None and raw is not None and tag is not None:
            saved, label = derive_password(raw, tag), "🛟 복구 키로 만든 비밀번호 사용"
        folder_label = self.model.paths.get(item.file_id, "원래 폴더")
        dialog = UnpackDialog(
            item.name,
            folder_label,
            bool(saved),
            self,
            saved_label=label,
            recoverable=tag is not None,
        )
        if not self.ctx.show_dialog(dialog):
            return
        password = (
            saved
            if (dialog.uses_saved and saved)
            else self._password_for(item.name, dialog.typed_password)
        )
        if not password:
            return
        if dialog.to_local.isChecked():
            self._download_and_unpack(item.file_id, item.name, password)
        else:
            self._restore_on_drive(item, password)

    def _restore_on_drive(self, item: FileAudit, password: str) -> None:
        if self.task is not None or item.parent_id is None:
            return
        by_id = {a.file_id: a for a in self.result.items} if self.result else {}
        folder = by_id.get(item.parent_id)
        shared = folder is not None and (
            folder.exposure is not Exposure.RESTRICTED or bool(folder.internal_accounts)
        )
        if (
            shared
            and folder is not None
            and not self.ctx.confirm(
                self,
                "보관 파일 풀기",
                f"'{folder.name}' 폴더는 다른 사람과 공유되어 있거나 공유 상태를 알 수 없습니다.\n"
                "여기에 풀면 개인정보가 든 파일을 그 사람들도 볼 수 있습니다. 계속할까요?",
                "계속",
                "취소",
            )
        ):
            return
        if not self.ensure_modify_permission():
            return
        manager, factory = self.ctx.manager, self.ctx.service_factory
        cancel = self.cancel_event
        cancel.clear()
        parent_id = item.parent_id

        def work(progress: Any) -> Any:
            job = RestoreJob(DriveClient(factory(manager)), on_progress=progress, cancel=cancel)
            return job.run(item.file_id, item.name, password, parent_id)

        self._set_running(True)
        self.progress_label.setText(f"드라이브에서 푸는 중… {item.name}")
        self.task = Task(work)
        self.task.progress.connect(self._on_archive_progress)
        self.task.succeeded.connect(self._on_restored)
        self.task.failed.connect(self._on_failed)
        self.task.finished.connect(self._task_finished)
        self._start(self.task)

    def _on_restored(self, result: object) -> None:
        if not isinstance(result, RestoreResult):
            return
        self._pending_refresh = True
        renamed = (
            "\n같은 이름 파일이 있어 이름을 바꾼 파일: "
            + ", ".join(f"{a} → {b}" for a, b in result.renamed.items())
            if result.renamed
            else ""
        )
        if not result.safe_to_trash_archive:
            self.progress_label.setText("⚠ 푼 파일 확인 실패 — 암호 파일은 그대로 두었습니다")
            self.ctx.notify(
                self,
                "보관 파일 풀기",
                "파일을 올렸지만 확인(SHA-256)이 맞지 않아 암호 파일을 그대로 두었습니다."
                + renamed,
                True,
            )
            return
        self.progress_label.setText(
            f"✓ 파일 {len(result.uploaded):,}개를 원래 폴더에 풀었습니다 — 암호 파일을 휴지통으로"
        )
        if renamed:
            self.ctx.notify(self, "보관 파일 풀기", renamed.strip())
        self.model.set_checked([result.archive_id], False)
        plan = archive_trash_plan(result)
        names = {result.archive_id: result.archive_name}
        self._pending_next = lambda: self.run_plan(
            plan, dry_run=False, names=names, labels=("보관 파일 풀기 완료", "✓ 풀기 완료")
        )

    def _refresh_vault_keys(self) -> None:
        """Mark which archives have their password in the keychain (shown in 비고)."""
        if self.result is None:
            return
        store = self.ctx.manager.secret_store
        self.model.vault_saved = {
            a.name
            for a in self.result.items
            if VAULT_NAME_RE.match(a.name) and store.get(f"vault:{a.name}")
        }
        self.model.layoutChanged.emit()

    def open_archive_from_drive(self, item: FileAudit) -> None:
        self._download_and_unpack(item.file_id, item.name)

    def _download_and_unpack(self, file_id: str, name: str, password: str | None = None) -> None:
        """Download into memory only (the .7z is never written to disk), then decrypt."""
        if self.task is not None:
            return
        if not self.ensure_detect_permission():
            return
        manager, factory = self.ctx.manager, self.ctx.service_factory

        def work(_progress: Any) -> Any:
            return DriveClient(factory(manager)).download(file_id, archive.MAX_ARCHIVE_BYTES)

        self._set_running(True)
        self.progress_label.setText(f"보관 파일 받는 중(메모리에만)… {name}")
        self.task = Task(work)
        self.task.succeeded.connect(lambda data: self._unpack_bytes(data, name, password))
        self.task.failed.connect(self._on_failed)
        self.task.finished.connect(self._task_finished)
        self._start(self.task)

    def _unpack_bytes(self, data: object, label: str, password: str | None = None) -> None:
        if not isinstance(data, bytes):
            return
        self.progress_label.setText(f"✓ 받기 완료: {label}")
        self._decrypt_and_save(data, password)

    def open_archive_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "보관 파일 선택", str(Path.home()), "보관 파일 (*.7z *.zip)"
        )
        if not path:
            return
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            self.ctx.notify(self, "보관 파일 풀기", f"열 수 없습니다: {exc}", True)
            return
        name = Path(path).name
        saved = self.ctx.manager.secret_store.get(f"vault:{name}")
        raw, tag = self._recovery_key(), tag_from_name(name)
        for candidate in (saved, derive_password(raw, tag) if raw and tag else None):
            if candidate:
                try:
                    archive.open_archive(data, candidate)
                except (archive.WrongPassword, archive.ArchiveError):
                    continue
                self._decrypt_and_save(data, candidate)
                return
        self._decrypt_and_save(data, archive_name=name)

    def _decrypt_and_save(
        self, data: bytes, password: str | None = None, archive_name: str = ""
    ) -> None:
        if password is None:
            typed, ok = QInputDialog.getText(
                self,
                "보관 파일 풀기",
                "비밀번호 (모르면 종이에 적어 둔 복구 키 35자):",
                QLineEdit.EchoMode.Password,
            )
            if not ok:
                return
            password = self._password_for(archive_name, typed)
        try:
            files = archive.open_archive(data, password)
        except archive.WrongPassword:
            self.ctx.notify(
                self, "보관 파일 풀기", "비밀번호가 틀렸거나 파일이 손상되었습니다.", True
            )
            return
        except archive.ArchiveError as exc:
            self.ctx.notify(self, "보관 파일 풀기", f"열 수 없습니다: {exc}", True)
            return
        finally:
            del password
        out = QFileDialog.getExistingDirectory(self, "풀어 놓을 폴더 선택", str(Path.home()))
        if not out:
            return
        written = archive.extract_to(files, Path(out))
        self.ctx.notify(
            self,
            "보관 파일 풀기",
            f"파일 {len(written):,}개를 풀었습니다.\n\n"
            "이 파일들에는 개인정보가 들어 있을 수 있습니다. "
            "쓰고 나면 지워 주세요.",
        )

    def check_update(self) -> None:
        """Opens the Releases page in the browser; the app never contacts it itself."""
        from dpg import REPOSITORY_URL

        if not REPOSITORY_URL:
            self.ctx.notify(
                self,
                "새 버전 확인",
                f"현재 버전: {__version__}\n배포 저장소 주소가 아직 설정되지 않았습니다.",
            )
            return
        self.ctx.open_url(REPOSITORY_URL.rstrip("/") + "/releases")

    def show_checklist(self) -> None:
        dialog = ChecklistDialog(set(self.ctx.prefs.checklist_done), self.ctx.open_url, self)
        self.ctx.show_dialog(dialog)
        self.ctx.prefs.checklist_done = sorted(dialog.ticked)
        self.ctx.prefs.save()

    def show_about(self) -> None:
        self.ctx.notify(self, "개인정보 보안관 정보", ABOUT_TEXT)

    # -- lifecycle ------------------------------------------------------------------------------

    def _start(self, task: Task) -> None:
        """Keep a reference to every background thread until it finishes, so a QThread is never
        destroyed while running (that crashes Qt)."""
        self._tasks.add(task)
        task.finished.connect(lambda t=task: self._tasks.discard(t))
        task.start()

    def wait_for_tasks(self, timeout_ms: int = 10000) -> None:
        for task in list(self._tasks):
            task.wait(timeout_ms)

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self._quitting and self.tray is not None and self.tray.isVisible():
            # Scheduled scans need the app running: closing the window only hides it.
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.showMessage(
                    "개인정보 보안관",
                    "예약 검사를 위해 계속 실행됩니다. 끝내려면 메뉴 막대 아이콘 → 종료.",
                )
            return
        self.cancel_event.set()
        self.wait_for_tasks()
        self.keep_awake.stop()
        self.sched_awake.stop()
        if self.tray is not None:
            self.tray.hide()
        if self.ctx.prefs.auto_logout_on_exit and self.ctx.manager.status().logged_in:
            self.ctx.manager.logout()
            log.info("auto logout on exit")
        event.accept()
