from __future__ import annotations

import datetime as dt

import pytest

from dpg.core.detect.validators import (
    luhn_check_digit,
    luhn_ok,
    rrn_birth_date,
    rrn_checksum,
    rrn_checksum_ok,
)

# Test vectors use future birth dates (20xx with 7th digit 3/4 -> 2050+) or checksum-invalid
# values, so none can be a real person's number.


def test_rrn_checksum_known_vector() -> None:
    # 750101312345: weighted sum 128 -> (11 - 128 % 11) % 10 = 4
    assert rrn_checksum("750101312345") == 4
    assert rrn_checksum_ok("750101-3123454")
    assert not rrn_checksum_ok("750101-3123455")


def test_rrn_checksum_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="12 digits"):
        rrn_checksum("123")
    assert not rrn_checksum_ok("12345")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("900101-1000000", dt.date(1990, 1, 1)),  # checksum-invalid, date parsing only
        ("750101-3123454", dt.date(2075, 1, 1)),  # future date is still a calendar date
        ("550315-8000000", dt.date(2055, 3, 15)),  # foreigner digit 8
        ("991332-1234567", None),  # month 13
        ("900230-1234567", None),  # Feb 30
        ("900101-X234567", None),
    ],
)
def test_rrn_birth_date(value: str, expected: dt.date | None) -> None:
    assert rrn_birth_date(value) == expected


def test_luhn() -> None:
    assert luhn_ok("4111 1111 1111 1111")  # public test card number
    assert not luhn_ok("4111 1111 1111 1112")
    payload = "999912345678901"
    assert luhn_ok(payload + str(luhn_check_digit(payload)))
    assert not luhn_ok("1234")
