"""「예약 검사」 dialog and the small badge icon used for the menu-bar / tray icon (D-099)."""

from __future__ import annotations

import datetime as dt

from PySide6.QtCore import QRectF, Qt, QTime
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)

from dpg.core.audit.runner import AuditScope
from dpg.core.schedule import WEEKDAYS_KO, Schedule
from dpg.gui.autostart import AutostartError
from dpg.gui.context import AppContext

SCHEDULE_SCOPES = [
    ("mine", "내 소유 파일"),
    ("public", "링크로 공개된 내 파일만 (빠름)"),
    ("shared", "나에게 공유된 파일"),
]

SCHEDULE_HELP_KO = (
    "• 정한 시간이 되면 알아서 검사를 시작(또는 이어서)하고, 끝 시간이 되면 멈춥니다. "
    "다음 예약 때 그 자리부터 이어서 합니다.\n"
    "• 앱이 켜져 있어야 합니다. 창을 닫아도 메뉴 막대(윈도: 작업 표시줄 오른쪽) 아이콘으로 "
    "계속 실행됩니다. 아래 「자동으로 켜기」를 쓰면 컴퓨터에 로그인할 때 저절로 켜집니다.\n"
    "• 전원을 연결하고 노트북 덮개를 열어 두세요. 예약 시간 동안은 잠자기를 막지만, "
    "잠든 컴퓨터를 깨우지는 못합니다.\n"
    "• 다 끝나면 알림으로 결과를 알려 드립니다(알림은 이 컴퓨터 안에서만)."
)


def badge_icon() -> QIcon:
    """The gold ★ badge, drawn so no image file is needed."""
    pix = QPixmap(64, 64)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor("#F2C94C"))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(2, 2, 60, 60), 14, 14)
    p.setPen(QColor("#1B2230"))
    font = QFont()
    font.setPixelSize(40)
    font.setBold(True)
    p.setFont(font)
    p.drawText(QRectF(0, 0, 64, 64), int(Qt.AlignmentFlag.AlignCenter), "★")
    p.end()
    return QIcon(pix)


def _when_ko(moment: dt.datetime | None, now: dt.datetime) -> str:
    if moment is None:
        return "없음"
    day = (
        "오늘"
        if moment.date() == now.date()
        else "내일"
        if moment.date() == now.date() + dt.timedelta(days=1)
        else f"{moment.month}월 {moment.day}일({WEEKDAYS_KO[moment.weekday()]})"
    )
    return f"{day} {moment:%H:%M}"


class ScheduleDialog(QDialog):
    def __init__(
        self,
        ctx: AppContext,
        parent: QWidget | None = None,
        *,
        current_scope: AuditScope | None = None,
        now: dt.datetime | None = None,
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.now = now or dt.datetime.now()
        self.setWindowTitle("예약 검사")
        sched = Schedule.from_json(ctx.prefs.schedule)
        self.enabled = QCheckBox("예약 검사 켜기")
        self.enabled.setChecked(sched.enabled)
        self.days = [QCheckBox(name) for name in WEEKDAYS_KO]
        days_row = QHBoxLayout()
        for i, box in enumerate(self.days):
            box.setChecked(i in sched.days)
            days_row.addWidget(box)
        days_row.addStretch()
        self.start = QTimeEdit(QTime.fromString(sched.start, "HH:mm"))
        self.end = QTimeEdit(QTime.fromString(sched.end, "HH:mm"))
        for edit in (self.start, self.end):
            edit.setDisplayFormat("HH:mm")
        self.next_day = QLabel("")
        time_row = QHBoxLayout()
        time_row.addWidget(self.start)
        time_row.addWidget(QLabel("부터"))
        time_row.addWidget(self.end)
        time_row.addWidget(QLabel("까지"))
        time_row.addWidget(self.next_day)
        time_row.addStretch()
        self.scope = QComboBox()
        for key, label in SCHEDULE_SCOPES:
            self.scope.addItem(label, key)
        extra = (
            [current_scope] if current_scope and current_scope.kind in ("drive", "folder") else []
        )
        if sched.scope.startswith(("drive:", "folder:")):
            extra.append(AuditScope.parse(sched.scope))
        for sc in extra:
            if self.scope.findData(sc.key) < 0:
                self.scope.addItem(f"{sc.label_ko} ({sc.target})", sc.key)
        idx = self.scope.findData(sched.scope)
        self.scope.setCurrentIndex(max(idx, 0))
        self.detect = QCheckBox("개인정보도 찾기")
        self.detect.setChecked(sched.detect)
        self.shared_only = QCheckBox("공유된 파일만")
        self.shared_only.setChecked(sched.detect_shared_only)
        self.shared_only.setEnabled(sched.detect)
        self.detect.toggled.connect(self.shared_only.setEnabled)
        detect_row = QHBoxLayout()
        detect_row.addWidget(self.detect)
        detect_row.addWidget(self.shared_only)
        detect_row.addStretch()
        self.notify = QCheckBox("끝나면 알림으로 결과 알려 주기")
        self.notify.setChecked(sched.notify)
        self.autostart = QCheckBox("컴퓨터에 로그인하면 자동으로 켜기 (창 없이 메뉴 막대에서 대기)")
        auto = ctx.autostart
        self.autostart.setEnabled(bool(auto.supported()))
        self.autostart_was = bool(auto.supported() and auto.is_enabled())
        self.autostart.setChecked(self.autostart_was)
        self.preview = QLabel("")
        self.preview.setStyleSheet("color: #1a73e8;")
        self.warning = QLabel("")
        self.warning.setWordWrap(True)
        self.warning.setStyleSheet("color: #b06000;")
        help_label = QLabel(SCHEDULE_HELP_KO)
        help_label.setWordWrap(True)
        help_label.setStyleSheet("color: #5f6368;")

        form = QFormLayout()
        form.addRow("", self.enabled)
        form.addRow("요일", days_row)
        form.addRow("시간", time_row)
        form.addRow("범위", self.scope)
        form.addRow("", detect_row)
        form.addRow("", self.notify)
        form.addRow("", self.autostart)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("저장")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.preview)
        layout.addWidget(self.warning)
        layout.addWidget(help_label)
        layout.addWidget(buttons)
        for box in (self.enabled, *self.days, self.detect, self.shared_only):
            box.toggled.connect(self._refresh)
        self.start.timeChanged.connect(self._refresh)
        self.end.timeChanged.connect(self._refresh)
        self._refresh()

    def schedule(self) -> Schedule:
        return Schedule(
            enabled=self.enabled.isChecked(),
            days=tuple(i for i, box in enumerate(self.days) if box.isChecked()),
            start=self.start.time().toString("HH:mm"),
            end=self.end.time().toString("HH:mm"),
            scope=str(self.scope.currentData()),
            detect=self.detect.isChecked(),
            detect_shared_only=self.shared_only.isChecked(),
            notify=self.notify.isChecked(),
        )

    def _refresh(self) -> None:
        sched = self.schedule()
        self.next_day.setText("(다음 날)" if sched.end <= sched.start else "")
        if not sched.enabled:
            self.preview.setText("예약 꺼짐")
        elif not sched.days:
            self.preview.setText("요일을 하나 이상 골라 주세요")
        elif sched.window_at(self.now) is not None:
            self.preview.setText(
                f"지금 예약 시간입니다 — 저장하면 곧 시작합니다 · {sched.summary_ko()}"
            )
        else:
            nxt = _when_ko(sched.next_start(self.now), self.now)
            self.preview.setText(f"다음 예약: {nxt} · {sched.summary_ko()}")
        warnings = []
        if sched.enabled and self.ctx.prefs.auto_logout_on_exit:
            warnings.append(
                "「앱을 닫을 때 자동으로 로그아웃」이 켜져 있으면 앱을 다시 켰을 때 로그인이 "
                "없어 예약 검사를 못 합니다. 설정에서 끄는 것을 권합니다."
            )
        if sched.enabled and sched.detect and not sched.detect_shared_only:
            warnings.append(
                "모든 문서의 개인정보 찾기는 며칠에 걸쳐 나눠 진행될 수 있습니다(매번 이어서 함)."
            )
        self.warning.setText("\n".join(warnings))
        self.warning.setVisible(bool(warnings))

    def _save(self) -> None:
        sched = self.schedule()
        if sched.enabled and not sched.days:
            self.ctx.notify(self, "예약 검사", "요일을 하나 이상 골라 주세요.")
            return
        want = self.autostart.isChecked() and sched.enabled
        auto = self.ctx.autostart
        if want != self.autostart_was:
            try:
                if want:
                    auto.enable()
                else:
                    auto.disable()
            except (AutostartError, OSError) as exc:
                message = (
                    str(exc)
                    if isinstance(exc, AutostartError)
                    else "자동으로 켜기를 바꾸지 못했습니다. 예약은 앱이 켜져 있을 때 동작합니다."
                )
                self.ctx.notify(self, "자동으로 켜기", message, True)
                if want:
                    return
        self.ctx.prefs.schedule = sched.to_json()
        self.ctx.prefs.save()
        self.accept()
