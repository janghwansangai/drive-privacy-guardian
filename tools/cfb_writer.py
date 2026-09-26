"""Minimal Compound File Binary (OLE2, v3) writer — test fixtures only.

olefile (used by the app) can read but not create compound files, so synthetic .hwp fixtures are
built with this writer. Supports storages, streams, the mini stream (< 4096 bytes) and a single
DIFAT header (up to 109 FAT sectors ≈ 6.8 MB), which is plenty for fixtures.
"""

from __future__ import annotations

import itertools
import struct
from dataclasses import dataclass, field

SECTOR = 512
MINI_SECTOR = 64
MINI_CUTOFF = 4096
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


@dataclass
class _Entry:
    name: str
    kind: int  # 1 storage, 2 stream, 5 root
    data: bytes = b""
    children: list[_Entry] = field(default_factory=list)
    sid: int = 0
    start: int = ENDOFCHAIN
    left: int = NOSTREAM
    right: int = NOSTREAM
    child: int = NOSTREAM


def _sort_key(e: _Entry) -> tuple[int, str]:
    return (len(e.name), e.name.upper())


def build_cfb(streams: dict[str, bytes]) -> bytes:
    """`streams` maps "Storage/Stream" paths to bytes."""
    root = _Entry("Root Entry", 5)
    for path, data in streams.items():
        parts = path.split("/")
        node = root
        for part in parts[:-1]:
            nxt = next((c for c in node.children if c.name == part and c.kind == 1), None)
            if nxt is None:
                nxt = _Entry(part, 1)
                node.children.append(nxt)
            node = nxt
        node.children.append(_Entry(parts[-1], 2, data))

    entries: list[_Entry] = []

    def number(e: _Entry) -> None:
        e.sid = len(entries)
        entries.append(e)
        for c in sorted(e.children, key=_sort_key):
            number(c)

    number(root)
    for e in entries:
        kids = sorted(e.children, key=_sort_key)
        if kids:
            # Degenerate but valid tree: first child, each linked to the next via right sibling.
            e.child = kids[0].sid
            for a, b in itertools.pairwise(kids):
                a.right = b.sid

    # mini stream
    mini = bytearray()
    minifat: list[int] = []
    for e in entries:
        if e.kind == 2 and len(e.data) < MINI_CUTOFF and e.data:
            e.start = len(minifat)
            n = -(-len(e.data) // MINI_SECTOR)
            minifat += [len(minifat) + i + 1 for i in range(n - 1)] + [ENDOFCHAIN]
            mini += e.data + b"\0" * (n * MINI_SECTOR - len(e.data))

    big = [e for e in entries if e.kind == 2 and len(e.data) >= MINI_CUTOFF]
    n_dir = -(-len(entries) * 128 // SECTOR)
    n_minifat = -(-len(minifat) * 4 // SECTOR) if minifat else 0
    n_mini = -(-len(mini) // SECTOR) if mini else 0
    n_big = sum(-(-len(e.data) // SECTOR) for e in big)
    body = n_dir + n_minifat + n_mini + n_big
    n_fat = 1
    while (body + n_fat) > n_fat * (SECTOR // 4):
        n_fat += 1
    if n_fat > 109:
        raise ValueError("fixture too large for single-DIFAT writer")

    fat = [FATSECT] * n_fat
    next_sector = n_fat

    def chain(count: int) -> int:
        nonlocal next_sector
        start = next_sector
        for i in range(count):
            fat.append(start + i + 1 if i < count - 1 else ENDOFCHAIN)
        next_sector += count
        return start

    dir_start = chain(n_dir)
    minifat_start = chain(n_minifat) if n_minifat else ENDOFCHAIN
    root.start = chain(n_mini) if n_mini else ENDOFCHAIN
    root.data = bytes(mini)
    for e in big:
        e.start = chain(-(-len(e.data) // SECTOR))
    fat += [FREESECT] * (n_fat * (SECTOR // 4) - len(fat))

    header = bytearray(SECTOR)
    struct.pack_into(
        "<8s16sHHHHHH",
        header,
        0,
        bytes.fromhex("D0CF11E0A1B11AE1"),
        b"\0" * 16,
        0x003E,
        0x0003,
        0xFFFE,
        9,
        6,
        0,
    )
    struct.pack_into(
        "<IIIIIIIIII",
        header,
        40,
        0,
        n_fat,
        dir_start,
        0,
        MINI_CUTOFF,
        minifat_start,
        n_minifat,
        ENDOFCHAIN,
        0,
        0,
    )
    difat = list(range(n_fat)) + [FREESECT] * (109 - n_fat)
    struct.pack_into("<109I", header, 76, *difat)

    def dir_entry(e: _Entry) -> bytes:
        name = e.name.encode("utf-16-le") + b"\0\0"
        size = len(root.data) if e.kind == 5 else len(e.data)
        start = e.start if (e.kind != 1) else 0
        return struct.pack(
            "<64sHBBIII16sIQQIII",
            name,
            len(name),
            e.kind,
            1,
            e.left,
            e.right,
            e.child,
            b"\0" * 16,
            0,
            0,
            0,
            start,
            size,
            0,
        )

    dirs = b"".join(dir_entry(e) for e in entries)
    dirs += (
        b"\0" * 64 + struct.pack("<HBBIII", 0, 0, 0, NOSTREAM, NOSTREAM, NOSTREAM) + b"\0" * 48
    ) * (n_dir * 4 - len(entries))

    out = bytearray(header)
    out += struct.pack(f"<{len(fat)}I", *fat)
    out += dirs
    if n_minifat:
        mf = minifat + [FREESECT] * (n_minifat * (SECTOR // 4) - len(minifat))
        out += struct.pack(f"<{len(mf)}I", *mf)
    if n_mini:
        out += bytes(mini) + b"\0" * (n_mini * SECTOR - len(mini))
    for e in big:
        out += e.data + b"\0" * (-(-len(e.data) // SECTOR) * SECTOR - len(e.data))
    return bytes(out)
