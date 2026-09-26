"""Display masking for the in-memory review preview (SPEC 5.1: `901012-1******`).

Masked previews are shown on screen only; they are never stored, logged or exported.
"""

from __future__ import annotations

import re

from dpg.core.detect.patterns import mask_text


def _keep_digits(value: str, head: int, tail: int) -> str:
    """Mask every digit except the first `head` and last `tail` digits, keeping separators."""
    total = sum(c.isdigit() for c in value)
    out, seen = [], 0
    for c in value:
        if c.isdigit():
            seen += 1
            out.append(c if seen <= head or seen > total - tail else "*")
        else:
            out.append(c)
    return "".join(out)


def mask_value(kind: str, value: str) -> str:
    if kind in ("rrn", "rrn_suspect"):
        return _keep_digits(value, 7, 0)  # 901012-1******
    if kind in ("mobile", "landline"):
        return _keep_digits(value, 3, 4)
    if kind in ("card", "account", "driver_license"):
        return _keep_digits(value, 0, 3)
    if kind == "passport":
        if len(value) <= 3:
            return "*" * len(value)
        return value[0] + "*" * (len(value) - 3) + value[-2:]
    if kind == "email":
        local, _, domain = value.partition("@")
        return f"{local[:2]}{'*' * max(1, len(local) - 2)}@{domain}"
    if kind == "address":
        parts = value.split()
        return " ".join([*parts[:2], "***"]) if len(parts) > 2 else "***"
    return re.sub(r"\S", "*", value)


def masked_snippet(text: str, span: tuple[int, int] | None, kind: str, radius: int = 18) -> str:
    """Context around a match with the match masked for its kind and every other broad
    personal-data pattern in the context masked too."""
    if span is None:
        return mask_text(text[: radius * 3]) + ("…" if len(text) > radius * 3 else "")
    s, e = span
    before = mask_text(text[max(0, s - radius) : s])
    after = mask_text(text[e : e + radius])
    return (
        ("…" if s > radius else "")
        + before
        + mask_value(kind, text[s:e])
        + after
        + ("…" if e + radius < len(text) else "")
    )
