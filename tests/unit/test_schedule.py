"""Scheduled scan windows (D-099)."""

from __future__ import annotations

import datetime as dt

from dpg.core.schedule import Schedule

MON = dt.datetime(2026, 10, 5)  # a Monday


def at(day: int, hh: int, mm: int = 0) -> dt.datetime:
    return MON + dt.timedelta(days=day, hours=hh, minutes=mm)


def test_overnight_window_belongs_to_the_day_it_starts() -> None:
    s = Schedule(enabled=True, days=(0,), start="22:00", end="06:00")  # Monday night only
    assert s.window_at(at(0, 21, 59)) is None
    assert s.window_at(at(0, 22)) == (at(0, 22), at(1, 6))
    assert s.window_at(at(1, 5, 59)) == (at(0, 22), at(1, 6))  # Tuesday early morning
    assert s.window_at(at(1, 6)) is None
    assert s.window_at(at(1, 22)) is None  # Tuesday is not chosen


def test_same_day_window_and_full_day() -> None:
    s = Schedule(enabled=True, days=(0, 1, 2, 3, 4), start="12:30", end="13:30")
    assert s.window_at(at(2, 13)) is not None
    assert s.window_at(at(5, 13)) is None  # Saturday
    full = Schedule(enabled=True, days=(6,), start="00:00", end="00:00")
    assert full.window_at(at(6, 0)) == (at(6, 0), at(7, 0))


def test_disabled_never_runs() -> None:
    s = Schedule(enabled=False, start="00:00", end="00:00")
    assert s.window_at(at(0, 3)) is None
    assert s.next_start(at(0, 3)) is None


def test_next_start() -> None:
    s = Schedule(enabled=True, days=(2,), start="22:00", end="06:00")  # Wednesday
    assert s.next_start(at(0, 9)) == at(2, 22)
    assert s.next_start(at(2, 23)) == at(9, 22)  # inside this week's window → next week's


def test_prefs_values_are_validated() -> None:
    s = Schedule.from_json(
        {
            "enabled": 1,
            "days": [0, 9, "x", 3, 3],
            "start": "25:00",
            "end": "7:5",
            "scope": "folder:../../etc",
            "detect": "yes",
        }
    )
    assert s.enabled is True
    assert s.days == (0, 3)
    assert (s.start, s.end) == ("22:00", "06:00")
    assert s.scope == "mine"
    assert Schedule.from_json("nonsense") == Schedule()
    assert Schedule.from_json({"scope": "folder:1AbC_d-9"}).scope == "folder:1AbC_d-9"
    round_trip = Schedule(enabled=True, days=(1, 4), start="20:15", end="23:45", detect=True)
    assert Schedule.from_json(round_trip.to_json()) == round_trip


def test_summary_wording() -> None:
    assert Schedule().summary_ko() == "예약 꺼짐"
    s = Schedule(enabled=True, days=(0, 1, 2, 3, 4), detect=True, detect_shared_only=True)
    assert s.summary_ko() == "평일 22:00~06:00 · 공유 상태 + 개인정보(공유된 파일만)"
    assert Schedule(enabled=True, days=(5, 6)).summary_ko().startswith("토·일 ")
