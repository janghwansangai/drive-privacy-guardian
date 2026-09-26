"""Checksum / format validators for Korean personal identifiers.

Pure functions, no I/O. They receive a value and return a bool; they never store or log it.
"""

from __future__ import annotations

import datetime as _dt

_RRN_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)

# 7th digit of a resident/foreigner registration number -> century of birth.
_CENTURY_BY_GENDER_DIGIT = {
    "9": 1800,
    "0": 1800,
    "1": 1900,
    "2": 1900,
    "5": 1900,
    "6": 1900,
    "3": 2000,
    "4": 2000,
    "7": 2000,
    "8": 2000,
}


def digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def rrn_birth_date(value: str) -> _dt.date | None:
    """Return the birth date encoded in a 13-digit RRN, or None if it is not a real calendar date.

    Future dates are *not* rejected here: the synthetic generator deliberately uses them so that
    test values can never belong to a living person (see DECISIONS.md D-012).
    """
    d = digits_only(value)
    if len(d) != 13:
        return None
    century = _CENTURY_BY_GENDER_DIGIT.get(d[6])
    if century is None:
        return None
    try:
        return _dt.date(century + int(d[0:2]), int(d[2:4]), int(d[4:6]))
    except ValueError:
        return None


def rrn_checksum(first12: str) -> int:
    """Check digit of the pre-2020-10 resident registration number scheme."""
    if len(first12) != 12 or not first12.isdigit():
        raise ValueError("expected 12 digits")
    total = sum(int(c) * w for c, w in zip(first12, _RRN_WEIGHTS, strict=True))
    return (11 - total % 11) % 10


def rrn_checksum_ok(value: str) -> bool:
    d = digits_only(value)
    if len(d) != 13:
        return False
    return rrn_checksum(d[:12]) == int(d[12])


def luhn_ok(value: str) -> bool:
    d = digits_only(value)
    if not 12 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_check_digit(payload: str) -> int:
    """Digit to append to `payload` so that the result passes the Luhn check."""
    for check in range(10):
        if luhn_ok(payload + str(check)):
            return check
    raise AssertionError("unreachable")  # pragma: no cover
