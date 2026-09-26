"""Fail if any installed distribution is GPL/AGPL-licensed (SPEC 3.3). LGPL is allowed.

Reads package metadata directly (no network, no extra dependency).

Usage: uv run python tools/check_licenses.py
"""

from __future__ import annotations

import argparse
import re
import sys
from importlib import metadata

# Packages allowed despite a GPL-family string, with the reason (recorded in DECISIONS.md).
ALLOWLIST: dict[str, str] = {
    "pyinstaller": "GPL-2.0 with bootloader exception — build tool only, output is unrestricted",
    "pyinstaller-hooks-contrib": "build tool only",
    # Dual-licensed "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only": we use it under LGPL-3.0,
    # dynamically linked (PyInstaller onedir), with the licence notice shipped (SPEC 3.3, V13).
    "pyside6-essentials": "used under the LGPL-3.0 option",
    "shiboken6": "used under the LGPL-3.0 option (PySide6 runtime)",
}

_STRONG_COPYLEFT = re.compile(
    r"\bAGPL|Affero|(?<![L])GPL(?:v?[23]|-[23])?\b|GNU General Public License", re.IGNORECASE
)
_LESSER = re.compile(r"LGPL|Lesser General Public|Library General Public", re.IGNORECASE)


def license_strings(dist: metadata.Distribution) -> list[str]:
    md = dist.metadata
    out = [md.get("License-Expression") or "", md.get("License") or ""]
    out += [c for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
    return [s.splitlines()[0][:200] if s else s for s in out if s]


def is_strong_copyleft(text: str) -> bool:
    for part in re.split(r"\s+(?:OR|AND)\s+|;|::", text):
        if _STRONG_COPYLEFT.search(part) and not _LESSER.search(part):
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args(argv)
    offenders: list[str] = []
    for dist in sorted(metadata.distributions(), key=lambda d: d.metadata["Name"].lower()):
        name = dist.metadata["Name"].lower().replace("_", "-")
        if name in ALLOWLIST:
            continue
        hits = [s for s in license_strings(dist) if is_strong_copyleft(s)]
        if hits:
            offenders.append(f"{name}: {hits}")
    for line in offenders:
        print(f"FORBIDDEN LICENSE: {line}", file=sys.stderr)
    print(f"license check: {len(offenders)} forbidden")
    return 1 if offenders else 0


if __name__ == "__main__":
    sys.exit(main())
