"""「업데이트」 (D-110): what changed, then the installer for this computer in the browser, and
the few steps to put it in place. The app never downloads or runs code itself."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from dpg.core.update import ASSETS, Release

STEPS_KO = {
    "Darwin": (
        "1. 「받기」를 누르면 브라우저가 설치 파일(dmg)을 받습니다.\n"
        "2. 「앱 끝내기」로 이 앱을 닫습니다.\n"
        "3. 받은 dmg를 열고 앱을 「응용 프로그램」 위로 끌어 놓은 뒤 「대치」를 누릅니다.\n"
        "4. 다시 열면 끝입니다. 설정·검사 기록·비밀번호는 그대로입니다."
    ),
    "Windows": (
        "1. 「받기」를 누르면 브라우저가 압축 파일(zip)을 받습니다.\n"
        "2. 「앱 끝내기」로 이 앱을 닫습니다.\n"
        "3. 받은 zip을 오른쪽 클릭 → 「모두 압축 풀기」 하고, 예전 폴더를 새 폴더로 바꿉니다.\n"
        "4. 새 폴더의 「Drive Privacy Guardian.exe」를 실행하면 끝입니다. "
        "설정·검사 기록·비밀번호는 그대로입니다."
    ),
}


class UpdateDialog(QDialog):
    def __init__(
        self,
        release: Release,
        current: str,
        system: str,
        open_url: Callable[[str], object],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.release = release
        self.system = system
        self.open_url = open_url
        self.quit_requested = False
        self.setWindowTitle("새 버전이 나왔습니다")
        self.resize(560, 520)
        head = QLabel(f"지금 v{current}  →  새 버전 v{release.version}")
        head.setStyleSheet("font-size: 17px; font-weight: 700;")
        notes = QTextBrowser()
        notes.setOpenLinks(False)  # shown as text; nothing opens from the notes
        if release.notes.strip():
            notes.setMarkdown(release.notes)
        else:
            notes.setPlainText("바뀐 내용은 「바뀐 내용 보기」에서 볼 수 있습니다.")
        self.steps = QLabel(
            STEPS_KO.get(
                system,
                "「받기」를 누르면 최신 버전 페이지가 열립니다. 이 컴퓨터에 맞는 파일을 받으세요.",
            )
        )
        self.steps.setWordWrap(True)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #1F7A4D; font-weight: 600;")
        buttons = QDialogButtonBox()
        self.download_btn = QPushButton("받기")
        self.download_btn.setDefault(True)
        self.download_btn.clicked.connect(self.download)
        self.page_btn = QPushButton("바뀐 내용 보기")
        self.page_btn.clicked.connect(lambda: self.open_url(self.release.page))
        self.quit_btn = QPushButton("앱 끝내기")
        self.quit_btn.setEnabled(False)
        self.quit_btn.clicked.connect(self.request_quit)
        later = QPushButton("나중에")
        later.clicked.connect(self.reject)
        for btn, role in (
            (self.download_btn, QDialogButtonBox.ButtonRole.AcceptRole),
            (self.quit_btn, QDialogButtonBox.ButtonRole.ActionRole),
            (self.page_btn, QDialogButtonBox.ButtonRole.HelpRole),
            (later, QDialogButtonBox.ButtonRole.RejectRole),
        ):
            buttons.addButton(btn, role)
        layout = QVBoxLayout(self)
        layout.addWidget(head)
        layout.addWidget(QLabel("바뀐 내용"))
        layout.addWidget(notes, 1)
        layout.addWidget(self.steps)
        layout.addWidget(self.status)
        layout.addWidget(buttons)

    def download(self) -> None:
        url = self.release.download_for(self.system)
        self.open_url(url)
        name = ASSETS.get(self.system)
        self.status.setText(
            f"✓ 브라우저에서 「{name}」을 받고 있습니다. "
            "다 받았으면 「앱 끝내기」를 누르고 설치하세요."
            if name and url != self.release.page
            else "✓ 최신 버전 페이지를 열었습니다. 이 컴퓨터에 맞는 파일을 받으세요."
        )
        self.download_btn.setText("다시 받기")
        self.quit_btn.setEnabled(True)

    def request_quit(self) -> None:
        self.quit_requested = True
        self.accept()
