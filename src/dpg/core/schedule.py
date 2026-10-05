"""Scheduled scans (D-099): which days, from when to when, what to check.

Pure time arithmetic so it can be tested without a clock. A window opens on a chosen weekday
at `start` and closes at `end` the same day, or the next day when `end` is not after `start`
(e.g. 22:00 → 06:00). Inside a window the app starts (or continues) the scan; at the end it
stops and the next window goes on from there.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any

WEEKDAYS_KO = ("월", "화", "수", "목", "금", "토", "일")
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_SCOPE = re.compile(r"^(mine|public|shared|drive:[\w-]{1,200}|folder:[\w-]{1,200})$")


def _hhmm(value: object, default: str) -> str:
    text = str(value)
    return text if _HHMM.match(text) else default


@dataclass(frozen=True)
class Schedule:
    enabled: bool = False
    days: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6)  # Monday = 0
    start: str = "22:00"
    end: str = "06:00"
    scope: str = "mine"  # an AuditScope key
    detect: bool = False
    detect_shared_only: bool = True
    notify: bool = True

    # -- (de)serialisation (prefs.json is user-editable: validate everything) -------------------

    @classmethod
    def from_json(cls, data: object) -> Schedule:
        if not isinstance(data, dict):
            return cls()
        raw_days = data.get("days", list(range(7)))
        days = tuple(
            sorted({d for d in raw_days if isinstance(d, int) and 0 <= d <= 6})
            if isinstance(raw_days, list)
            else range(7)
        )
        scope = str(data.get("scope", "mine"))
        return cls(
            enabled=bool(data.get("enabled", False)),
            days=days or (0, 1, 2, 3, 4, 5, 6),
            start=_hhmm(data.get("start"), "22:00"),
            end=_hhmm(data.get("end"), "06:00"),
            scope=scope if _SCOPE.match(scope) else "mine",
            detect=bool(data.get("detect", False)),
            detect_shared_only=bool(data.get("detect_shared_only", True)),
            notify=bool(data.get("notify", True)),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "days": list(self.days),
            "start": self.start,
            "end": self.end,
            "scope": self.scope,
            "detect": self.detect,
            "detect_shared_only": self.detect_shared_only,
            "notify": self.notify,
        }

    # -- time ------------------------------------------------------------------------------------

    def _times(self) -> tuple[dt.time, dt.time]:
        sh, sm = (int(x) for x in self.start.split(":"))
        eh, em = (int(x) for x in self.end.split(":"))
        return dt.time(sh, sm), dt.time(eh, em)

    def _window_from(self, day: dt.date) -> tuple[dt.datetime, dt.datetime]:
        start, end = self._times()
        begin = dt.datetime.combine(day, start)
        finish = dt.datetime.combine(day, end)
        if finish <= begin:
            finish += dt.timedelta(days=1)  # crosses midnight (or start == end: a full day)
        return begin, finish

    def window_at(self, now: dt.datetime) -> tuple[dt.datetime, dt.datetime] | None:
        """The window that contains `now` (local, naive), or None."""
        if not self.enabled:
            return None
        for back in (0, 1):  # a window that opened yesterday may still be open
            day = now.date() - dt.timedelta(days=back)
            if day.weekday() not in self.days:
                continue
            begin, finish = self._window_from(day)
            if begin <= now < finish:
                return begin, finish
        return None

    def next_start(self, now: dt.datetime) -> dt.datetime | None:
        if not self.enabled:
            return None
        for ahead in range(8):
            day = now.date() + dt.timedelta(days=ahead)
            if day.weekday() not in self.days:
                continue
            begin, _finish = self._window_from(day)
            if begin > now:
                return begin
        return None

    def summary_ko(self) -> str:
        if not self.enabled:
            return "예약 꺼짐"
        days = (
            "매일"
            if len(self.days) == 7
            else "평일"
            if self.days == (0, 1, 2, 3, 4)
            else "·".join(WEEKDAYS_KO[d] for d in self.days)
        )
        what = "공유 상태" + (
            " + 개인정보(공유된 파일만)"
            if self.detect and self.detect_shared_only
            else " + 개인정보"
            if self.detect
            else ""
        )
        return f"{days} {self.start}~{self.end} · {what}"
