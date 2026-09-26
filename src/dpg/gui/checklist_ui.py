"""Security checklist screen (SPEC 6.7). Static data, no network calls; ticks stay local."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from dpg.core.checklist import CHECKLIST, all_keys


class ChecklistDialog(QDialog):
    def __init__(
        self,
        done: set[str],
        open_url: Callable[[str], object],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("보안 점검표")
        self.resize(760, 600)
        self.ticked = set(done) & all_keys()
        self.boxes: dict[str, QCheckBox] = {}
        intro = QLabel(
            "스스로 점검해 보는 표입니다. 각 항목의 설정은 구글 계정·NAS·호스팅 관리 화면에서 "
            "직접 바꿔야 하며, 이 앱은 그 설정을 확인하거나 바꾸지 않습니다."
        )
        intro.setWordWrap(True)
        warn = QLabel(
            "⚠ 여기에 체크한다고 보안이 강화되지는 않습니다. 체크는 '내가 확인했음'을 "
            "기억해 두는 메모일 뿐이며, 이 컴퓨터에만 저장됩니다(인터넷으로 보내지 않음). "
            "자세한 설명은 docs/SERVER_SECURITY_KO.md에 있습니다."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet("color: #b06000; font-weight: bold;")
        intro.setWordWrap(True)
        self.progress = QProgressBar()
        self.progress.setRange(0, len(all_keys()))
        self.progress.setFormat("%v / %m 항목 확인했다고 표시함")
        tabs = QTabWidget()
        for section in CHECKLIST:
            page = QWidget()
            col = QVBoxLayout(page)
            for item in section.items:
                box = QCheckBox(item.title)
                box.setStyleSheet("font-weight: bold;")
                box.setChecked(item.key in self.ticked)
                box.toggled.connect(lambda on, k=item.key: self._toggle(k, on))
                self.boxes[item.key] = box
                how = QLabel(item.how)
                how.setWordWrap(True)
                how.setStyleSheet("color: #5f6368; margin-left: 24px;")
                row = QHBoxLayout()
                row.addWidget(box, 1)
                if item.link:
                    link = QPushButton("열기 ↗")
                    link.setToolTip(item.link)
                    link.clicked.connect(lambda _=False, u=item.link: open_url(u))
                    row.addWidget(link)
                col.addLayout(row)
                col.addWidget(how)
            col.addStretch(1)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(page)
            n = sum(1 for i in section.items if i.key in self.ticked)
            tabs.addTab(scroll, f"{section.title} ({n}/{len(section.items)})")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("닫기")
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(warn)
        layout.addWidget(self.progress)
        layout.addWidget(tabs, 1)
        layout.addWidget(buttons)
        self._update()

    def _toggle(self, key: str, on: bool) -> None:
        if on:
            self.ticked.add(key)
        else:
            self.ticked.discard(key)
        self._update()

    def _update(self) -> None:
        self.progress.setValue(len(self.ticked))
