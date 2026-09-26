"""Audit (+ detection) results table: model + filter proxy."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QRect,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QColor, QFont, QMouseEvent, QPainter
from PySide6.QtWidgets import QHeaderView, QStyle, QStyleOptionButton, QWidget

from dpg.core.audit.model import (
    EXPOSURE_LABEL_KO,
    ORIGIN_LABEL_KO,
    STATUS_LABEL_KO,
    UNKNOWN_EXPOSURE_LABEL_KO,
    Exposure,
    FileAudit,
    ItemStatus,
)
from dpg.core.detect.rules import KIND_LABEL_KO, Confidence
from dpg.core.drive.client import VAULT_NAME_RE
from dpg.core.extract.base import UNSCANNABLE_LABEL_KO
from dpg.core.policy import (
    DETECT_STATUS_LABEL_KO,
    LEVEL_LABEL_KO,
    DetectStatus,
    FileDetection,
    Level,
    Recommendation,
    recommend,
)

COLUMNS = [
    "",  # checkbox
    "위험",
    "권장 조치",
    "개인정보",
    "노출도",
    "파일명",
    "위치",
    "소유자",
    "외부 계정",
    "편집자",
    "권한 출처",
    "조회 상태",
    "마지막 수정",
    "비고",
]
(
    COL_CHECK,
    COL_RISK,
    COL_ADVICE,
    COL_PRIVACY,
    COL_EXPOSURE,
    COL_NAME,
    COL_LOCATION,
    COL_OWNER,
    COL_EXTERNAL,
    COL_EDITORS,
    COL_ORIGIN,
    COL_STATUS,
    COL_MODIFIED,
    COL_NOTES,
) = range(14)

# Sort choices (label -> column, descending). Default: folders and their files, like Drive.
SORTS: list[tuple[str, int, bool]] = [
    ("폴더·파일 순", COL_LOCATION, False),
    ("위험도 높은 순", COL_RISK, True),
    ("이름 순", COL_NAME, False),
    ("최근 수정 순", COL_MODIFIED, True),
]

# Filter keys shared with the dashboard buttons
FILTERS: dict[str, str] = {
    "all": "전체",
    "urgent": "긴급·높음 조치",
    "detected": "개인정보 탐지",
    "link": "링크 공개",
    "external": "외부 계정 공유",
    "domain": "도메인 공개",
    "restricted": "제한됨",
    "excluded": "탐지에서 제외한 파일",
    "vault": "🔐 암호화된 파일 (이 앱으로 암호화한 보관 파일)",
    "review": "확인 필요 (권한 부족·검사 불가·알 수 없음)",
}

_EXPOSURE_COLOR = {
    Exposure.LINK_EDIT: QColor("#c62828"),
    Exposure.LINK_VIEW: QColor("#e65100"),
    Exposure.EXTERNAL: QColor("#9a6700"),
    Exposure.DOMAIN: QColor("#1565c0"),
}
_FOLDER_FG = QColor("#1a73e8")
_FOLDER_BG = QColor(26, 115, 232, 26)  # light blue tint, readable in light and dark mode
_LEVEL_COLOR = {
    Level.URGENT: QColor("#c62828"),
    Level.HIGH: QColor("#e65100"),
    Level.REVIEW: QColor("#9a6700"),
}

Index = QModelIndex | QPersistentModelIndex


def matches_filter(
    a: FileAudit,
    key: str,
    det: FileDetection | None = None,
    recs: list[Recommendation] | None = None,
) -> bool:
    if key == "all":
        return True
    if key == "urgent":
        return bool(recs) and recs is not None and recs[0].level >= Level.HIGH
    if key == "detected":
        return det is not None and det.status in (DetectStatus.DETECTED, DetectStatus.SUSPECT)
    if key == "link":
        return a.exposure in (Exposure.LINK_VIEW, Exposure.LINK_EDIT)
    if key == "external":
        return a.exposure == Exposure.EXTERNAL
    if key == "domain":
        return a.exposure == Exposure.DOMAIN
    if key == "restricted":
        return a.exposure == Exposure.RESTRICTED and a.status is ItemStatus.OK
    if key == "vault":
        return not a.is_folder and bool(VAULT_NAME_RE.match(a.name))
    if key == "excluded":
        return det is not None and det.status is DetectStatus.EXCLUDED
    if key == "review":
        return (
            a.exposure is None
            or a.status is not ItemStatus.OK
            or (
                det is not None
                and (det.status in (DetectStatus.UNSCANNABLE, DetectStatus.FAILED) or det.partial)
            )
        )
    raise KeyError(key)


def privacy_text(det: FileDetection | None) -> str:
    if det is None:
        return ""
    partial = " (일부 검사 불가)" if det.partial else ""
    if det.status is DetectStatus.UNSCANNABLE and det.reason is not None:
        return f"검사 불가: {UNSCANNABLE_LABEL_KO[det.reason]}"
    if det.status in (DetectStatus.DETECTED, DetectStatus.SUSPECT):
        top = sorted(det.kinds.items(), key=lambda kv: (-kv[1].confidence, -kv[1].count))
        text = ", ".join(f"{KIND_LABEL_KO.get(k, k)} {v.count}" for k, v in top[:3])
        if len(top) > 3:
            text += " …"
        prefix = "의심: " if det.status is DetectStatus.SUSPECT else ""
        return prefix + text + partial
    return DETECT_STATUS_LABEL_KO[det.status] + partial


class ResultsModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self.items: list[FileAudit] = []
        self.detections: dict[str, FileDetection] = {}
        self.recs: dict[str, list[Recommendation]] = {}
        self.checked: set[str] = set()
        self.paths: dict[str, str] = {}  # file id -> "내 드라이브 › 폴더 › …" (parent path)
        self.tree_keys: dict[str, str] = {}  # file id -> sort key: folder, then its files
        self.vault_saved: set[str] = set()  # archive names whose password is in the keychain

    def set_items(
        self, items: list[FileAudit], detections: dict[str, FileDetection] | None = None
    ) -> None:
        self.beginResetModel()
        self.items = list(items)
        self.detections = dict(detections or {})
        self.recs = {a.file_id: recommend(a, self.detections.get(a.file_id)) for a in self.items}
        ids = {a.file_id for a in self.items}
        self.checked &= ids
        self._build_paths()
        self.endResetModel()

    def _build_paths(self) -> None:
        by_id = {a.file_id: a for a in self.items}

        def chain(a: FileAudit) -> list[FileAudit]:
            out: list[FileAudit] = []
            seen: set[str] = set()
            cur = a.parent_id
            while cur in by_id and cur not in seen:
                seen.add(cur)
                out.append(by_id[cur])
                cur = by_id[cur].parent_id
            return list(reversed(out))

        self.paths, self.tree_keys = {}, {}
        for a in self.items:
            parents = chain(a)
            if a.drive_id:
                top = "공유 드라이브"
            elif a.owned_by_me is False and not parents:
                top = "나에게 공유됨"
            else:
                top = "내 드라이브"
            self.paths[a.file_id] = " › ".join([top, *(p.name for p in parents)])
            parts = [top, *("0" + p.name.lower() for p in parents)]
            parts.append(("0" if a.is_folder else "1") + a.name.lower())
            self.tree_keys[a.file_id] = "\x01".join(parts)

    # -- checkboxes -----------------------------------------------------------------------------

    def checked_items(self) -> list[FileAudit]:
        return [a for a in self.items if a.file_id in self.checked]

    def set_checked(self, file_ids: list[str], on: bool) -> None:
        if on:
            self.checked.update(file_ids)
        else:
            self.checked.difference_update(file_ids)
        if self.items:
            self.dataChanged.emit(
                self.index(0, COL_CHECK),
                self.index(len(self.items) - 1, COL_CHECK),
                [Qt.ItemDataRole.CheckStateRole],
            )

    def flags(self, index: Index) -> Qt.ItemFlag:
        base = super().flags(index)
        if index.isValid() and index.column() == COL_CHECK:
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def setData(self, index: Index, value: Any, role: int = Qt.ItemDataRole.EditRole) -> bool:
        if (
            index.isValid()
            and index.column() == COL_CHECK
            and role == Qt.ItemDataRole.CheckStateRole
        ):
            on = (
                Qt.CheckState(value) == Qt.CheckState.Checked
                if not isinstance(value, bool)
                else value
            )
            self.set_checked([self.items[index.row()].file_id], bool(on))
            return True
        return False

    def update_detection(self, det: FileDetection) -> None:
        self.detections[det.file_id] = det
        for row, a in enumerate(self.items):
            if a.file_id == det.file_id:
                self.recs[a.file_id] = recommend(a, det)
                self.dataChanged.emit(self.index(row, 0), self.index(row, len(COLUMNS) - 1))

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.items)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        a = self.items[index.row()]
        det = self.detections.get(a.file_id)
        recs = self.recs.get(a.file_id, [])
        col = index.column()
        if col == COL_CHECK:
            if role == Qt.ItemDataRole.CheckStateRole:
                return (
                    Qt.CheckState.Checked if a.file_id in self.checked else Qt.CheckState.Unchecked
                )
            if role == Qt.ItemDataRole.UserRole:
                return 0 if a.file_id in self.checked else 1
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            if col == COL_LOCATION:
                return self.paths.get(a.file_id, "")
            if col == COL_NOTES and VAULT_NAME_RE.match(a.name):
                key = (
                    "🔑 비밀번호: 키체인에 저장됨"
                    if a.name in self.vault_saved
                    else "🔑 비밀번호: 키체인에 없음 (적어 둔 곳 확인)"
                )
                return " / ".join([key, *a.notes])
            return self._text(a, det, recs, col)
        if role == Qt.ItemDataRole.UserRole:  # sort key
            if col == COL_LOCATION:
                return self.tree_keys.get(a.file_id, "")
            if col == COL_RISK:
                return -1 if a.risk_score is None else a.risk_score
            if col == COL_ADVICE:
                return int(recs[0].level) if recs else -1
            return self._text(a, det, recs, col)
        if a.is_folder and role == Qt.ItemDataRole.BackgroundRole:
            return _FOLDER_BG
        if a.is_folder and role == Qt.ItemDataRole.FontRole and col == COL_NAME:
            font = QFont()
            font.setBold(True)
            return font
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == COL_NAME and a.is_folder:
                return _FOLDER_FG
            if col in (COL_RISK, COL_EXPOSURE) and a.exposure is not None:
                return _EXPOSURE_COLOR.get(a.exposure)
            if col == COL_ADVICE and recs:
                return _LEVEL_COLOR.get(recs[0].level)
            if col == COL_ADVICE:
                return QColor("#80868b")
            if (
                col == COL_PRIVACY
                and det is not None
                and any(v.confidence == Confidence.HIGH for v in det.kinds.values())
            ):
                return QColor("#c62828")
        if role == Qt.ItemDataRole.ToolTipRole:
            if col == COL_NAME and a.is_folder:
                n = sum(1 for x in self.items if x.parent_id == a.file_id)
                return f"폴더 — 바로 안에 있는 항목 {n:,}개 (옮기면 안의 파일도 함께 옮겨짐)"
            if col == COL_NAME:
                return a.file_id
            if col == COL_ADVICE and not recs:
                return (
                    "개인정보 탐지를 함께 실행하면 표시됩니다."
                    if det is None
                    else "개인정보가 발견되지 않아 할 일이 없습니다(지원 범위 내)."
                )
            if col == COL_ADVICE and recs:
                return "\n".join(f"[{LEVEL_LABEL_KO[r.level] or '참고'}] {r.text}" for r in recs)
            if col == COL_PRIVACY and det is not None and det.kinds:
                return "\n".join(
                    f"{KIND_LABEL_KO.get(k, k)} {v.count}건 — {', '.join(v.locations)}"
                    for k, v in det.kinds.items()
                )
        return None

    @staticmethod
    def _text(a: FileAudit, det: FileDetection | None, recs: list[Recommendation], col: int) -> str:
        if col == COL_RISK:
            return "?" if a.risk_score is None else str(a.risk_score)
        if col == COL_ADVICE:
            if not recs:
                return "필요 없음" if det is not None else "—"
            label = LEVEL_LABEL_KO[recs[0].level]
            return (f"[{label}] " if label else "") + recs[0].text
        if col == COL_PRIVACY:
            return privacy_text(det)
        if col == COL_EXPOSURE:
            return (
                EXPOSURE_LABEL_KO[a.exposure]
                if a.exposure is not None
                else UNKNOWN_EXPOSURE_LABEL_KO
            )
        if col == COL_NAME:
            return f"📁 {a.name} /" if a.is_folder else a.name
        if col == COL_LOCATION:
            return "공유 드라이브" if a.drive_id else "내 드라이브"
        if col == COL_OWNER:
            return a.owner_email or ("공유 드라이브" if a.drive_id else "")
        if col == COL_EXTERNAL:
            return str(len(a.external_accounts)) if a.external_accounts else ""
        if col == COL_EDITORS:
            return str(a.editor_count) if a.editor_count else ""
        if col == COL_ORIGIN:
            return ", ".join(sorted(ORIGIN_LABEL_KO[o] for o in a.origins))
        if col == COL_STATUS:
            return STATUS_LABEL_KO[a.status]
        if col == COL_MODIFIED:
            return (a.modified_time or "")[:10]
        return " / ".join(a.notes)


class ResultsFilter(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self.key = "all"
        self.text = ""
        self.setSortRole(Qt.ItemDataRole.UserRole)

    def set_key(self, key: str) -> None:
        self.beginFilterChange()
        self.key = key
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_text(self, text: str) -> None:
        self.beginFilterChange()
        self.text = text.strip().lower()
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(self, row: int, parent: Index) -> bool:
        model = self.sourceModel()
        if not isinstance(model, ResultsModel):
            return True
        a = model.items[row]
        if not matches_filter(
            a, self.key, model.detections.get(a.file_id), model.recs.get(a.file_id)
        ):
            return False
        return not self.text or self.text in a.name.lower() or self.text in a.file_id.lower()


class CheckHeader(QHeaderView):
    """Header with a tri-state checkbox above the checkbox column: all / none of the rows
    currently shown. Clicking it does not sort."""

    def __init__(self, state: Callable[[], Qt.CheckState], parent: QWidget | None = None) -> None:
        super().__init__(Qt.Orientation.Horizontal, parent)
        self._state = state
        self.toggled_all = _Signal()
        self.setSectionsClickable(True)

    def paintSection(self, painter: QPainter, rect: QRect, logicalIndex: int) -> None:
        painter.save()
        super().paintSection(painter, rect, logicalIndex)
        painter.restore()
        if logicalIndex != COL_CHECK:
            return
        opt = QStyleOptionButton()
        size = 16
        opt.rect = QRect(
            rect.x() + (rect.width() - size) // 2,
            rect.y() + (rect.height() - size) // 2,
            size,
            size,
        )
        state = self._state()
        opt.state = QStyle.StateFlag.State_Enabled | (
            QStyle.StateFlag.State_On
            if state == Qt.CheckState.Checked
            else QStyle.StateFlag.State_NoChange
            if state == Qt.CheckState.PartiallyChecked
            else QStyle.StateFlag.State_Off
        )
        self.style().drawPrimitive(QStyle.PrimitiveElement.PE_IndicatorCheckBox, opt, painter)

    def mousePressEvent(self, e: QMouseEvent) -> None:
        if self.logicalIndexAt(e.position().toPoint()) == COL_CHECK:
            e.accept()
            return
        super().mousePressEvent(e)

    def mouseReleaseEvent(self, e: QMouseEvent) -> None:
        if self.logicalIndexAt(e.position().toPoint()) == COL_CHECK:
            self.click_checkbox()
            e.accept()
            return
        super().mouseReleaseEvent(e)

    def click_checkbox(self) -> None:
        self.toggled_all.emit(self._state() != Qt.CheckState.Checked)
        self.viewport().update()


class _Signal:
    """Tiny callback list (avoids a QObject subclass just for one signal)."""

    def __init__(self) -> None:
        self._slots: list[Callable[[bool], None]] = []

    def connect(self, slot: Callable[[bool], None]) -> None:
        self._slots.append(slot)

    def emit(self, value: bool) -> None:
        for slot in self._slots:
            slot(value)
