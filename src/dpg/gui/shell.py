"""The main window's look (2026-10 redesign, user choice "B + A의 첫 화면"): a left menu with the
three jobs, a 1→2→3 step guide on every page, summary tiles that filter the list, and a dark
action bar that shows only what can be done with the chosen files.

Colours follow the extension (one design language for both). Light and dark sets; the window
picks one from the OS setting. Rules are scoped to this window's own object names so dialogs
keep the native look. Icons are inline SVG line drawings rendered with QtSvg (no image files).
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QByteArray, QRectF, QSize, Qt
from PySide6.QtGui import QGuiApplication, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

LIGHT = {
    "ink": "#1B2230", "ground": "#EEF0EC", "surf": "#FFFFFF", "muted": "#4A5261",
    "line": "#DDE1DA", "head": "#F6F7F4", "sel": "#E9F0FF", "alt": "#FAFBF9",
    "blue": "#2458D6", "blue_t": "#E4ECFD", "amber": "#A35200", "amber_t": "#FDF0DC",
    "green": "#1F7A4D", "green_t": "#DDF2E6", "red": "#B42318", "red_t": "#FDE7E4",
    "gray_t": "#ECEEEA", "bar": "#1B2230", "bar_ink": "#FFFFFF", "bar_soft": "#C9D0DC",
    "primary": "#1B2230", "on_primary": "#FFFFFF", "gold": "#F2C94C",
}  # fmt: skip
DARK = {
    "ink": "#E8EAED", "ground": "#14171C", "surf": "#1E2229", "muted": "#A9B0BC",
    "line": "#323844", "head": "#252A32", "sel": "#22304D", "alt": "#21252D",
    "blue": "#8AB0FF", "blue_t": "#1F2C4A", "amber": "#F0B66B", "amber_t": "#3A2A14",
    "green": "#6FCF97", "green_t": "#183526", "red": "#FF8A80", "red_t": "#42201D",
    "gray_t": "#2A2F37", "bar": "#0B0D10", "bar_ink": "#FFFFFF", "bar_soft": "#AEB6C4",
    "primary": "#E8EAED", "on_primary": "#14171C", "gold": "#F2C94C",
}  # fmt: skip


def is_dark() -> bool:
    hints = QGuiApplication.styleHints()
    return hints is not None and hints.colorScheme() == Qt.ColorScheme.Dark


def tokens() -> dict[str, str]:
    return DARK if is_dark() else LIGHT


# -- icons ------------------------------------------------------------------------------------

_PATHS = {
    "home": '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    "share": '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/>'
    '<circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/>',
    "scan": '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/>'
    '<path d="M6 16c.8-1.5 2-2 3-2s2.2.5 3 2M15 10h3M15 13h3"/>',
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    "unlock": '<rect x="4" y="11" width="16" height="10" rx="2"/>'
    '<path d="M8 11V8a4 4 0 0 1 7.5-2"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "undo": '<path d="M9 14L4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/>',
    "gear": '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7'
    'l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>',
    "help": '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1'
    ' 1.5V14M12 17.5h.01"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "play": '<path d="M7 5l12 7-12 7z"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    "file": '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>'
    '<path d="M14 3v6h6"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/>'
    '<circle cx="12" cy="12" r="3"/>',
    "external": '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7'
    'a1 1 0 0 1 1-1h5"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5'
    'a2 2 0 0 1-2-2z"/>',
    "more": '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/>'
    '<circle cx="19" cy="12" r="1"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3"/>',
    "hide": '<path d="M3 3l18 18M10.6 6.1A10 10 0 0 1 12 6c6.4 0 10 6 10 6a17 17 0 0 1-3.3 3.9'
    'M6.6 6.6A17 17 0 0 0 2 12s3.6 6 10 6a9.6 9.6 0 0 0 4.4-1"/>',
    "report": '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>'
    '<path d="M8 13h8M8 17h5"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>',
    "shield": '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/>',
    "next": '<path d="M9 18l6-6-6-6"/>',
    "zip": '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>'
    '<path d="M10 3v2h2v2h-2v2h2v2h-2v2"/>',
}


def icon_pixmap(name: str, color: str, size: int = 20, ratio: float = 2.0) -> QPixmap:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'
        f"{_PATHS[name]}</svg>"
    )
    px = int(size * ratio)
    pix = QPixmap(px, px)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    QSvgRenderer(QByteArray(svg.encode())).render(painter, QRectF(0, 0, px, px))
    painter.end()
    pix.setDevicePixelRatio(ratio)
    return pix


def make_icon(name: str, color: str, on_color: str | None = None) -> QIcon:
    icon = QIcon()
    icon.addPixmap(icon_pixmap(name, color), QIcon.Mode.Normal, QIcon.State.Off)
    icon.addPixmap(icon_pixmap(name, on_color or color), QIcon.Mode.Normal, QIcon.State.On)
    return icon


def repolish(widget: QWidget) -> None:
    """Re-apply style rules after a dynamic property changed (on the widget and inside it)."""
    for w in [widget, *widget.findChildren(QWidget)]:
        style = w.style()
        style.unpolish(w)
        style.polish(w)
        w.update()


# -- widgets ----------------------------------------------------------------------------------


class NavButton(QPushButton):
    """A left-menu entry: icon, name and an optional count badge on the right."""

    def __init__(self, text: str, icon: str, tone: str = "blue", checkable: bool = True) -> None:
        super().__init__(text)
        self.setObjectName("navBtn")
        self.setProperty("tone", tone)
        self.icon_name = icon
        self.setCheckable(checkable)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setIconSize(QSize(20, 20))
        self.badge = QLabel("", self)
        self.badge.setObjectName("navBadge")
        self.badge.setProperty("tone", "gray")
        self.badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.badge.setVisible(False)
        self.badge.setFixedHeight(18)
        self.badge.setMinimumWidth(22)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 10, 0)
        lay.addStretch(1)
        lay.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_badge(self, count: int | None, tone: str = "gray") -> None:
        self.badge.setVisible(bool(count))
        self.badge.setText(f"{count:,}" if count else "")
        if self.badge.property("tone") != tone:
            self.badge.setProperty("tone", tone)
            repolish(self.badge)

    def apply_icon(self, t: dict[str, str]) -> None:
        tone = str(self.property("tone"))
        self.setIcon(make_icon(self.icon_name, t["muted"], t.get(tone, t["ink"])))


class StatTile(QPushButton):
    """A summary tile that filters the list: a big count over a short caption.

    `text()` stays "caption\\ncount" (what the window and its tests read)."""

    def __init__(self, caption: str, tone: str) -> None:
        super().__init__()
        self.setObjectName("tile")
        self.setProperty("tone", tone)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(66)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.count = QLabel("–")
        self.count.setObjectName("tileCount")
        self.caption = QLabel(caption)
        self.caption.setObjectName("tileCaption")
        self.caption.setWordWrap(True)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 8, 14, 8)
        lay.setSpacing(0)
        for label in (self.count, self.caption):
            label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            lay.addWidget(label)
        self._text = f"{caption}\n–"

    def setText(self, text: str) -> None:
        self._text = text
        caption, _, count = text.rpartition("\n")
        self.caption.setText(caption or text)
        self.count.setText(count)
        self.setAccessibleName(text.replace("\n", " "))

    def text(self) -> str:
        return self._text


class StepGuide(QWidget):
    """① → ② → ③ with the current step highlighted, the done ones ticked, and a hint."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("steps")
        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(8)
        self.chips: list[tuple[QFrame, QLabel, QLabel]] = []
        for i in range(3):
            if i:
                arrow = QLabel("→")
                arrow.setObjectName("stepArrow")
                self._lay.addWidget(arrow)
            chip = QFrame()
            chip.setObjectName("step")
            chip.setProperty("state", "todo")
            row = QHBoxLayout(chip)
            row.setContentsMargins(5, 4, 12, 4)
            row.setSpacing(7)
            dot = QLabel(str(i + 1))
            dot.setObjectName("stepDot")
            dot.setFixedSize(24, 24)
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
            text = QLabel("")
            text.setObjectName("stepText")
            row.addWidget(dot)
            row.addWidget(text)
            self._lay.addWidget(chip)
            self.chips.append((chip, dot, text))
        self.hint = QLabel("")
        self.hint.setObjectName("stepHint")
        self.hint.setWordWrap(True)
        self._lay.addSpacing(6)
        self._lay.addWidget(self.hint, 1)
        self.current = 0

    def set_steps(self, labels: tuple[str, str, str]) -> None:
        for (_chip, _dot, text), label in zip(self.chips, labels, strict=True):
            text.setText(label)

    def set_current(self, index: int, hint: str = "") -> None:
        self.current = index
        self.hint.setText(hint)
        for i, (chip, dot, _text) in enumerate(self.chips):
            state = "done" if i < index else "now" if i == index else "todo"
            dot.setText("✓" if state == "done" else str(i + 1))
            if chip.property("state") != state:
                chip.setProperty("state", state)
                repolish(chip)

    def states(self) -> list[str]:
        return [str(chip.property("state")) for chip, _d, _t in self.chips]


@dataclass(frozen=True)
class PageSpec:
    key: str
    title: str
    subtitle: str
    tone: str
    icon: str
    steps: tuple[str, str, str]
    hints: tuple[str, str, str]  # what to do now, for each current step
    tiles: tuple[str, ...]  # dashboard keys shown on this page
    default_filter: str
    actions: tuple[str, ...]  # action-bar buttons shown; the rest go under 「더보기」
    detect: bool = False  # this page's scan reads contents (개인정보도 찾기)


PAGES: dict[str, PageSpec] = {
    "share": PageSpec(
        key="share",
        title="공유 점검",
        subtitle="누가 내 파일을 볼 수 있는지 확인하고, 필요 없는 공유를 끕니다.",
        tone="blue",
        icon="share",
        steps=("검사하기", "고칠 파일 고르기", "미리 보고 바꾸기"),
        hints=(
            "「검사 시작」을 누르세요 — 읽기만 하고 드라이브는 바꾸지 않아요.",
            "빨간 칸부터 눌러 보고, 고칠 파일의 왼쪽 칸을 체크하세요.",
            "아래 「공유 설정 바꾸기」 → 미리 보고 승인해야 바뀌어요. 언제든 되돌릴 수 있어요.",
        ),
        tiles=("all", "urgent", "link", "external", "domain", "review"),
        default_filter="all",
        actions=("change", "archive", "open", "review"),
    ),
    "privacy": PageSpec(
        key="privacy",
        title="개인정보 점검",
        subtitle="주민번호·연락처 등이 든 파일을 찾습니다. 내용은 이 컴퓨터 메모리에서만 읽어요.",
        tone="amber",
        icon="scan",
        steps=("개인정보 찾기", "파일 확인하기", "공유 끄기·암호화"),
        hints=(
            "「검사 시작」을 누르세요 — 처음에는 「공유된 파일만」으로 빠르게 해 보세요.",
            "파일을 하나 고르고 「내용 확인」으로 어디에 있는지 보세요.",
            "공유를 끄거나 암호화하세요. 개인정보가 아니면 「탐지에서 제외」.",
        ),
        tiles=("detected", "urgent", "excluded", "all"),
        default_filter="detected",
        actions=("review", "open", "change", "archive", "exclude"),
        detect=True,
    ),
    "vault": PageSpec(
        key="vault",
        title="암호화 관리",
        subtitle="끝난 문서를 비밀번호로 잠가 드라이브에 보관하고, 필요할 때 풉니다.",
        tone="green",
        icon="lock",
        steps=("파일 고르기", "방식 정하기", "확인하고 올리기"),
        hints=(
            "「전체」 칸에서 잠글 파일을 체크하세요. "
            "암호화된 파일은 「암호화된 파일」 칸에 있어요.",
            "「암호화 보관」을 누르면 기본 ZIP(추천) 또는 높은 보안 7z를 고릅니다.",
            "풀어서 비교 확인이 끝나야 원본이 휴지통으로 가요 (30일 안에 되살리기).",
        ),
        tiles=("vault", "detected", "all"),
        default_filter="vault",
        actions=("archive", "unpack", "convert", "move"),
    ),
}


def stylesheet(t: dict[str, str]) -> str:
    """Rules for this window only (object names), so dialogs keep the native look."""
    return f"""
QWidget#shell {{ background: {t["ground"]}; }}
QFrame#nav {{ background: {t["surf"]}; border: 0; border-right: 1px solid {t["line"]}; }}
QFrame#nav QLabel {{ color: {t["ink"]}; }}
QLabel#brand {{ font-size: 15px; font-weight: 700; }}
QLabel#logo {{ background: #1B2230; border-radius: 9px; }}
QPushButton#navBtn {{ text-align: left; padding: 9px 10px; border: 0; border-radius: 11px;
  color: {t["muted"]}; font-weight: 600; font-size: 14px; background: transparent; }}
QPushButton#navBtn:hover {{ background: {t["gray_t"]}; }}
QPushButton#navBtn:checked[tone="blue"] {{ background: {t["blue_t"]}; color: {t["blue"]}; }}
QPushButton#navBtn:checked[tone="amber"] {{ background: {t["amber_t"]}; color: {t["amber"]}; }}
QPushButton#navBtn:checked[tone="green"] {{ background: {t["green_t"]}; color: {t["green"]}; }}
QPushButton#navBtn:checked[tone="ink"] {{ background: {t["gray_t"]}; color: {t["ink"]}; }}
QLabel#navBadge {{ border-radius: 9px; padding: 0 7px; font-size: 11px; font-weight: 700;
  background: {t["gray_t"]}; color: {t["muted"]}; }}
QLabel#navBadge[tone="red"] {{ background: {t["red_t"]}; color: {t["red"]}; }}
QFrame#navSep {{ background: {t["line"]}; max-height: 1px; border: 0; }}
QFrame#acct {{ border-top: 1px solid {t["line"]}; }}
QLabel#acctText {{ color: {t["muted"]}; font-size: 12px; }}
QPushButton#acctBtn {{ border: 0; color: {t["blue"]}; font-size: 12px; font-weight: 600;
  text-align: left; padding: 2px 0; background: transparent; }}

QLabel#pageTitle {{ color: {t["ink"]}; font-size: 22px; font-weight: 700; }}
QLabel#pageSub {{ color: {t["muted"]}; font-size: 13px; }}
QLabel#liveLabel {{ color: {t["green"]}; }}
QFrame#step {{ background: {t["surf"]}; border-radius: 16px; border: 2px solid transparent; }}
QFrame#step[state="now"] {{ border-color: {t["ink"]}; }}
QLabel#stepDot {{ border-radius: 12px; background: {t["gray_t"]}; color: {t["muted"]};
  font-weight: 700; font-size: 12px; }}
QFrame#step[state="done"] QLabel#stepDot {{ background: {t["green"]}; color: {t["surf"]}; }}
QFrame#step[state="now"] QLabel#stepDot {{ background: {t["ink"]}; color: {t["surf"]}; }}
QLabel#stepText {{ color: {t["muted"]}; font-weight: 600; }}
QFrame#step[state="now"] QLabel#stepText {{ color: {t["ink"]}; }}
QLabel#stepArrow {{ color: {t["muted"]}; }}
QLabel#stepHint {{ color: {t["muted"]}; }}

QFrame#card {{ background: {t["surf"]}; border-radius: 16px; border: 0; }}
QFrame#card QLabel {{ color: {t["ink"]}; }}
QFrame#card QLabel#muted, QLabel#muted {{ color: {t["muted"]}; }}
QFrame#card QCheckBox {{ color: {t["ink"]}; }}
QLabel#notice {{ background: {t["amber_t"]}; color: {t["amber"]}; border-radius: 10px;
  padding: 8px 12px; }}
QLabel#keyLine {{ background: {t["green_t"]}; color: {t["green"]}; border-radius: 10px;
  padding: 8px 12px; font-weight: 600; }}
QPushButton#primary {{ background: {t["primary"]}; color: {t["on_primary"]}; border: 0;
  border-radius: 11px; padding: 9px 16px; font-weight: 700; }}
QPushButton#primary:disabled {{ background: {t["gray_t"]}; color: {t["muted"]}; }}
QPushButton#soft {{ background: {t["surf"]}; color: {t["ink"]}; border: 1.5px solid {t["line"]};
  border-radius: 11px; padding: 8px 14px; font-weight: 600; }}
QPushButton#soft:disabled {{ color: {t["muted"]}; }}
QPushButton#link {{ background: transparent; border: 0; color: {t["blue"]}; font-weight: 600;
  padding: 4px 2px; }}

QPushButton#tile {{ border-radius: 14px; border: 2px solid transparent; text-align: left; }}
QPushButton#tile[tone="red"] {{ background: {t["red_t"]}; }}
QPushButton#tile[tone="amber"] {{ background: {t["amber_t"]}; }}
QPushButton#tile[tone="green"] {{ background: {t["green_t"]}; }}
QPushButton#tile[tone="blue"] {{ background: {t["blue_t"]}; }}
QPushButton#tile[tone="gray"] {{ background: {t["gray_t"]}; }}
QPushButton#tile:checked {{ border-color: {t["ink"]}; }}
QLabel#tileCount {{ font-size: 24px; font-weight: 800; }}
QPushButton#tile[tone="red"] QLabel#tileCount {{ color: {t["red"]}; }}
QPushButton#tile[tone="amber"] QLabel#tileCount {{ color: {t["amber"]}; }}
QPushButton#tile[tone="green"] QLabel#tileCount {{ color: {t["green"]}; }}
QPushButton#tile[tone="blue"] QLabel#tileCount {{ color: {t["blue"]}; }}
QPushButton#tile[tone="gray"] QLabel#tileCount {{ color: {t["ink"]}; }}
QLabel#tileCaption {{ color: {t["muted"]}; font-size: 12px; font-weight: 600; }}

QTableView#results {{ background: {t["surf"]}; alternate-background-color: {t["alt"]};
  color: {t["ink"]}; border: 0; border-radius: 0; gridline-color: {t["line"]};
  selection-background-color: {t["sel"]}; selection-color: {t["ink"]}; }}
QTableView#results QHeaderView::section {{ background: {t["head"]}; color: {t["muted"]};
  border: 0; border-bottom: 1px solid {t["line"]}; padding: 6px 6px; font-weight: 700; }}

QFrame#actionBar {{ background: {t["bar"]}; border-radius: 16px; }}
QFrame#actionBar QLabel {{ color: {t["bar_ink"]}; font-weight: 700; }}
QFrame#actionBar QLabel#barHint {{ color: {t["bar_soft"]}; font-weight: 500; }}
QFrame#actionBar QPushButton {{ background: rgba(255,255,255,0.13); color: {t["bar_ink"]};
  border: 0; border-radius: 10px; padding: 8px 13px; font-weight: 700; }}
QFrame#actionBar QPushButton:hover {{ background: rgba(255,255,255,0.22); }}
QFrame#actionBar QPushButton:disabled {{ color: rgba(255,255,255,0.38);
  background: rgba(255,255,255,0.06); }}
QFrame#actionBar QPushButton#barMain {{ background: #FFFFFF; color: #1B2230; }}
QFrame#actionBar QPushButton#barMain:disabled {{ background: rgba(255,255,255,0.35);
  color: #1B2230; }}
QFrame#actionBar QPushButton#barLink {{ background: transparent; color: {t["bar_soft"]};
  font-weight: 600; padding: 4px 6px; }}

QLabel#homeTitle {{ color: {t["ink"]}; font-size: 28px; font-weight: 800; }}
QFrame#homeCard {{ background: {t["surf"]}; border-radius: 20px; border: 2px solid transparent; }}
QFrame#homeCard[rec="true"] {{ border-color: {t["blue"]}; }}
QFrame#homeCard QLabel {{ color: {t["ink"]}; }}
QFrame#homeCard QLabel#muted {{ color: {t["muted"]}; }}
QLabel#homeNum {{ color: {t["muted"]}; font-size: 12px; font-weight: 700; }}
QLabel#homeName {{ font-size: 20px; font-weight: 800; }}
QLabel#recTag {{ background: {t["blue"]}; color: {t["surf"]}; border-radius: 10px;
  padding: 2px 10px; font-size: 11px; font-weight: 700; min-height: 16px; }}
QLabel#homeIcon {{ border-radius: 14px; }}
QLabel#homeIcon[tone="blue"] {{ background: {t["blue_t"]}; }}
QLabel#homeIcon[tone="amber"] {{ background: {t["amber_t"]}; }}
QLabel#homeIcon[tone="green"] {{ background: {t["green_t"]}; }}
QLabel#homeState {{ border-radius: 10px; padding: 8px 10px; font-weight: 600; font-size: 13px; }}
QLabel#homeState[tone="red"] {{ background: {t["red_t"]}; color: {t["red"]}; }}
QLabel#homeState[tone="gray"] {{ background: {t["gray_t"]}; color: {t["muted"]}; }}
QLabel#homeState[tone="green"] {{ background: {t["green_t"]}; color: {t["green"]}; }}
QPushButton#homeGo {{ border: 0; border-radius: 12px; padding: 11px 16px; font-weight: 700;
  color: #FFFFFF; }}
QPushButton#homeGo[tone="blue"] {{ background: {t["blue"]}; color: {t["surf"]}; }}
QPushButton#homeGo[tone="amber"] {{ background: {t["amber"]}; color: {t["surf"]}; }}
QPushButton#homeGo[tone="green"] {{ background: {t["green"]}; color: {t["surf"]}; }}
QPushButton#homeLink {{ background: transparent; border: 0; color: {t["muted"]}; font-weight: 600;
  padding: 6px 8px; }}
QPushButton#homeLink:hover {{ color: {t["ink"]}; }}
"""
