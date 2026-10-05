"""First-run wizard (SPEC 3.1): mode → (setup guide) → client JSON → login."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from PySide6.QtCore import QFile, Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

from dpg.core.auth import AccessLevel, AuthError
from dpg.core.auth.client import MAX_CLIENT_JSON_BYTES
from dpg.core.auth.scopes import LEVEL_EXPLAIN_KO, LEVEL_LABEL_KO
from dpg.gui.context import AppContext
from dpg.gui.tasks import Task, user_message_for

PAGE_MODE, PAGE_GUIDE, PAGE_CLIENT, PAGE_LOGIN = range(4)

# In-app setup guide (docs/SETUP_GOOGLE_KO.md, condensed). Links open in the user's browser.
GUIDE_STEPS: list[tuple[str, str, str | None]] = [
    (
        "1. 구글 클라우드 콘솔 열기",
        "테스트/사용할 구글 계정으로 로그인합니다. 처음이면 약관에 동의합니다.",
        "https://console.cloud.google.com/",
    ),
    (
        "2. 새 프로젝트 만들기",
        "위쪽 '프로젝트 선택' → '새 프로젝트' → 이름 입력 → 만들기.",
        "https://console.cloud.google.com/projectcreate",
    ),
    (
        "3. Google Drive API 사용",
        "열린 페이지에서 '사용' 버튼을 누릅니다.",
        "https://console.cloud.google.com/apis/library/drive.googleapis.com",
    ),
    (
        "4. 앱 정보(브랜딩)",
        "'시작하기' → 앱 이름·지원 이메일 입력 → 대상 '외부' → 만들기.",
        "https://console.cloud.google.com/auth/branding",
    ),
    (
        "5. 테스트 사용자 추가",
        "'대상' → 테스트 사용자 'Add users' → 본인 이메일 추가 → 저장.",
        "https://console.cloud.google.com/auth/audience",
    ),
    (
        "6. 클라이언트 만들기",
        "'클라이언트 만들기' → 유형 '데스크톱 앱' → 만들기 → 'JSON 다운로드'.",
        "https://console.cloud.google.com/auth/clients",
    ),
]


def _wrap(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class ModePage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("시작하기")
        self.setSubTitle("구글 로그인에 쓸 'OAuth 클라이언트' 파일을 준비합니다.")
        self.personal = QRadioButton(
            "개인 설정 — 내 구글 클라우드 프로젝트에서 직접 만들기 (약 10~15분)"
        )
        self.school = QRadioButton("학교에서 받은 클라이언트 파일(JSON)이 있음")
        self.personal.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self.personal)
        group.addButton(self.school)
        layout = QVBoxLayout(self)
        layout.addWidget(
            _wrap(
                "이 앱은 여러분의 파일과 로그인 정보를 이 컴퓨터와 구글 사이에서만 주고받습니다. "
                "앱 개발자를 포함해 누구에게도 전달되지 않습니다."
            )
        )
        layout.addSpacing(12)
        layout.addWidget(self.personal)
        layout.addWidget(self.school)
        layout.addStretch()

    def nextId(self) -> int:
        return PAGE_GUIDE if self.personal.isChecked() else PAGE_CLIENT


class GuidePage(QWizardPage):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.setTitle("구글 클라우드 설정 안내")
        self.setSubTitle(
            "각 단계의 '열기'를 누르면 해당 페이지가 브라우저에서 열립니다. 끝나면 체크하세요."
        )
        self.checks: list[QCheckBox] = []
        grid = QGridLayout()
        grid.setColumnStretch(0, 1)
        for row, (title, desc, url) in enumerate(GUIDE_STEPS):
            check = QCheckBox(title)
            check.toggled.connect(self.completeChanged)
            self.checks.append(check)
            grid.addWidget(check, row * 2, 0)
            if url:
                btn = QPushButton("열기")
                btn.setFixedWidth(88)
                btn.clicked.connect(lambda _=False, u=url: ctx.open_url(u))
                grid.addWidget(btn, row * 2, 1)
            desc_label = _wrap(desc)
            desc_label.setIndent(24)
            grid.addWidget(desc_label, row * 2 + 1, 0, 1, 2)
        layout = QVBoxLayout(self)
        layout.addLayout(grid)
        layout.addWidget(
            _wrap(
                "학교 계정에서 프로젝트를 만들 수 없거나 '관리자가 차단' 메시지가 나오면, "
                "학교 관리자에게 조직용 클라이언트 파일(B 방식)을 요청하세요."
            )
        )
        layout.addStretch()

    def isComplete(self) -> bool:
        return all(c.isChecked() for c in self.checks)


class ClientPage(QWizardPage):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.setTitle("클라이언트 파일 불러오기")
        self.setSubTitle("내려받은 client_secret_….json 파일을 선택하세요.")
        self.source: Path | None = None
        self.pick = QPushButton("JSON 파일 선택…")
        self.pick.clicked.connect(self.choose)
        self.status = _wrap("")
        self.trash = QPushButton("원본 파일을 휴지통으로 이동")
        self.trash.setVisible(False)
        self.trash.clicked.connect(self.move_source_to_trash)
        layout = QVBoxLayout(self)
        layout.addWidget(self.pick, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.status)
        layout.addWidget(self.trash, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addStretch()

    def initializePage(self) -> None:
        client = self.ctx.manager.client()
        if client is not None and self.source is None:
            self.status.setText(
                f"✓ 이미 설정된 클라이언트: {client.display_id}\n"
                "다른 파일로 바꾸려면 다시 선택하세요."
            )

    def choose(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self, "클라이언트 JSON 선택", str(Path.home()), "JSON (*.json)"
        )
        if path_str:
            self.import_file(Path(path_str))

    def import_file(self, path: Path) -> None:
        try:
            if path.stat().st_size > MAX_CLIENT_JSON_BYTES:
                raise AuthError(
                    "파일이 너무 큽니다. 구글에서 받은 클라이언트 JSON 파일인지 확인해 주세요."
                )
            config = self.ctx.manager.import_client(path.read_bytes())
        except AuthError as exc:
            self.status.setText(f"✗ {exc.user_message}")
            self.completeChanged.emit()
            return
        except OSError:
            self.status.setText("✗ 파일을 읽을 수 없습니다.")
            return
        self.source = path
        self.status.setText(
            f"✓ 키체인에 안전하게 저장했습니다: {config.display_id}\n\n"
            "⚠ 보안을 위해 원본 JSON 파일을 삭제해 주세요. 앱은 이제 원본이 필요 없습니다."
        )
        self.trash.setVisible(True)
        self.completeChanged.emit()

    def move_source_to_trash(self) -> None:
        if self.source is not None and QFile.moveToTrash(str(self.source)):
            self.status.setText(
                self.status.text().split("\n")[0]
                + "\n\n✓ 원본 파일을 휴지통으로 옮겼습니다. 휴지통도 비워 주세요."
            )
            self.trash.setVisible(False)
        else:
            self.status.setText(
                self.status.text() + "\n✗ 휴지통으로 옮기지 못했습니다. 직접 삭제해 주세요."
            )

    def isComplete(self) -> bool:
        return self.ctx.manager.client() is not None


LOGIN_STEPS_HTML = (
    "<b style='font-size:15px'>브라우저에서 이렇게 진행하세요</b>"
    "<ol style='margin-top:6px'>"
    "<li>로그인할 <b>구글 계정</b>을 고릅니다.</li>"
    "<li><b>'Google에서 확인하지 않은 앱'</b> 화면이 나오면 → "
    "<b style='color:#1a73e8'>「계속」</b>을 누릅니다.<br>"
    "<span style='color:#5f6368'>「계속」이 안 보이면 「고급」 → '(앱 이름)(으)로 이동'. "
    "직접 만든 앱이라 구글 심사를 받지 않았을 뿐, 위험하다는 뜻이 아닙니다.</span></li>"
    "<li>권한 화면에서 <b>모든 항목을 체크</b>(또는 「모두 선택」)하고 → "
    "<b style='color:#1a73e8'>「계속」</b>을 누릅니다.<br>"
    "<span style='color:#5f6368'>체크를 빼면 일부 기능을 쓸 수 없습니다.</span></li>"
    "<li><b>'로그인 완료'</b> 페이지가 보이면 브라우저 탭을 닫고 이 창으로 돌아옵니다.</li>"
    "</ol>"
    "<span style='color:#b06000'>"
    "「계속」을 누르지 않고 창을 닫으면 로그인이 끝나지 않습니다.</span>"
)


class LoginPage(QWizardPage):
    def __init__(self, ctx: AppContext, level: AccessLevel = AccessLevel.AUDIT) -> None:
        super().__init__()
        self.ctx = ctx
        self.level = level
        self.setTitle("구글 로그인" if level == AccessLevel.AUDIT else "권한 추가")
        self.setSubTitle(f"요청 권한: {LEVEL_LABEL_KO[level]}")
        self.task: Task | None = None
        self.cancel_event = threading.Event()
        self.done = False
        self.login_btn = QPushButton("구글 로그인")
        self.login_btn.clicked.connect(self.start_login)
        self.cancel_btn = QPushButton("로그인 취소")
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self.cancel_event.set)
        self.status = _wrap("")
        self.url_label = _wrap("")
        self.key_label = _wrap("")
        self.switch_btn = QPushButton("다른 열쇠로 바꾸기")
        self.switch_btn.setToolTip(
            "브라우저에 '액세스 차단됨'이나 내 것이 아닌 앱 이름이 나오면 "
            "예전 열쇠가 남아 있는 것입니다. 새 클라이언트 JSON을 고르세요."
        )
        self.switch_btn.clicked.connect(self.switch_client)
        buttons = QHBoxLayout()
        buttons.addWidget(self.login_btn)
        buttons.addWidget(self.cancel_btn)
        buttons.addStretch()
        buttons.addWidget(self.switch_btn)
        layout = QVBoxLayout(self)
        layout.addWidget(_wrap(LEVEL_EXPLAIN_KO[level]))
        self.steps = QLabel(LOGIN_STEPS_HTML)
        self.steps.setTextFormat(Qt.TextFormat.RichText)
        self.steps.setWordWrap(True)
        self.steps.setStyleSheet(
            "QLabel { border: 2px solid #1a73e8; border-radius: 8px; padding: 10px; }"
        )
        layout.addWidget(self.steps)
        layout.addSpacing(8)
        layout.addLayout(buttons)
        layout.addWidget(self.status)
        layout.addWidget(self.url_label)
        layout.addStretch()
        layout.addWidget(self.key_label)

    def initializePage(self) -> None:
        client = self.ctx.manager.client()
        self.key_label.setText(
            f"사용 중인 열쇠: {client.project_id or client.display_id} 프로젝트 — "
            "브라우저에 '액세스 차단됨'이 나오면 「다른 열쇠로 바꾸기」"
            if client
            else ""
        )
        st = self.ctx.manager.status()
        if st.logged_in and st.level is not None and st.level >= self.level:
            self.done = True
            self.status.setText(f"✓ 이미 로그인됨: {st.account or ''}")
            self.completeChanged.emit()

    def start_login(self) -> None:
        self.cancel_event.clear()
        self.login_btn.setEnabled(False)
        self.cancel_btn.setVisible(True)
        self.status.setText(
            "브라우저에서 위 순서대로 진행해 주세요 — 두 번의 「계속」을 꼭 눌러야 합니다. "
            "(이 창은 그대로 두세요)"
        )
        manager = self.ctx.manager

        def work(progress: Any) -> Any:
            return manager.login(
                self.level,
                on_url=progress,
                cancel=self.cancel_event,
                timeout=600,
                open_browser=self.ctx.open_url,
            )

        self.task = Task(work)
        self.task.progress.connect(self._show_url)
        self.task.succeeded.connect(self._ok)
        self.task.failed.connect(self._fail)
        self.task.start()

    def _show_url(self, url: object) -> None:
        self.url_label.setText(
            "브라우저가 열리지 않으면 아래 주소를 복사해 브라우저에 붙여 넣으세요:\n" + str(url)
        )

    def _ok(self, result: Any) -> None:
        self.cancel_btn.setVisible(False)
        self.url_label.setText("")
        self.done = result.level is not None and result.level >= self.level
        text = f"✓ 로그인됨: {result.account or '(계정 확인 실패)'}"
        if result.warning:
            text += f"\n⚠ {result.warning}"
        self.status.setText(text)
        self.login_btn.setEnabled(not self.done)
        self.completeChanged.emit()

    def _fail(self, exc: BaseException) -> None:
        self.cancel_btn.setVisible(False)
        self.login_btn.setEnabled(True)
        self.url_label.setText("")
        self.status.setText(f"✗ {user_message_for(exc)}")

    def isComplete(self) -> bool:
        return self.done

    def switch_client(self) -> None:
        if not self.ctx.confirm(
            self,
            "다른 열쇠로 바꾸기",
            "이 컴퓨터에 저장된 로그인 열쇠와 로그인 정보를 지우고 처음 화면으로 돌아갑니다.\n"
            "구글 드라이브의 파일, 암호화된 파일, 복구 키는 그대로입니다.",
            "바꾸기",
            "취소",
        ):
            return
        self.cleanup()
        self.ctx.manager.remove_client()
        self.done = False
        self.status.setText("")
        wizard = self.wizard()
        wizard.setStartId(PAGE_MODE)
        wizard.restart()

    def cleanup(self) -> None:
        self.cancel_event.set()
        if self.task is not None:
            self.task.wait(3000)


class SetupWizard(QWizard):
    def __init__(
        self, ctx: AppContext, parent: QWidget | None = None, level: AccessLevel = AccessLevel.AUDIT
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("개인정보 보안관 — 설정")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(640, 520)
        self.setButtonText(QWizard.WizardButton.NextButton, "다음")
        self.setButtonText(QWizard.WizardButton.BackButton, "이전")
        self.setButtonText(QWizard.WizardButton.FinishButton, "시작")
        self.setButtonText(QWizard.WizardButton.CancelButton, "닫기")
        self.mode_page = ModePage()
        self.guide_page = GuidePage(ctx)
        self.client_page = ClientPage(ctx)
        self.login_page = LoginPage(ctx, level)
        self.setPage(PAGE_MODE, self.mode_page)
        self.setPage(PAGE_GUIDE, self.guide_page)
        self.setPage(PAGE_CLIENT, self.client_page)
        self.setPage(PAGE_LOGIN, self.login_page)
        self.setStartId(PAGE_LOGIN if ctx.manager.client() is not None else PAGE_MODE)
        self.finished.connect(lambda _code: self.login_page.cleanup())
