"""HWP 5.0 (.hwp) text extractor — own implementation on olefile + zlib (SPEC 3.3).

본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다.
(Required notice when developing from the published format, V11 — also shown in the UI,
the manual and the help text.)

Format facts used (Hancom "글 문서 파일 구조 5.0", rev 1.3):
- Compound file with streams FileHeader, DocInfo, BodyText/SectionN.
- FileHeader: 32-byte signature "HWP Document File", DWORD version, DWORD flags
  (bit0 compressed, bit1 password, bit2 distribution document, bit4 DRM).
- Section streams are zlib-compressed (raw deflate) when bit0 is set and hold records:
  32-bit header = TagID (10 bits) | Level (10 bits) | Size (12 bits, 0xFFF => DWORD follows).
- HWPTAG_BEGIN = 0x010; PARA_TEXT = +51, CTRL_HEADER = +55, LIST_HEADER = +56, TABLE = +61.
- PARA_TEXT is UTF-16LE; codes 0–31 are controls: "char" controls take 1 WCHAR, "inline" and
  "extended" controls take 8 WCHARs.
- TABLE: UINT32 flags, UINT16 RowCount, UINT16 nCols. Each cell is a LIST_HEADER followed by
  26 bytes of cell attributes starting with UINT16 column, UINT16 row.
"""

from __future__ import annotations

import io
import struct
import zlib
from dataclasses import dataclass, field

from dpg.core.extract.base import (
    MAX_TEXT_CHARS,
    Extracted,
    Table,
    Unscannable,
    UnscannableReason,
    check_size,
)

SIGNATURE = b"HWP Document File"
FLAG_COMPRESSED = 1 << 0
FLAG_PASSWORD = 1 << 1
FLAG_DISTRIBUTION = 1 << 2
FLAG_DRM = 1 << 4

HWPTAG_BEGIN = 0x010
TAG_PARA_HEADER = HWPTAG_BEGIN + 50
TAG_PARA_TEXT = HWPTAG_BEGIN + 51
TAG_CTRL_HEADER = HWPTAG_BEGIN + 55
TAG_LIST_HEADER = HWPTAG_BEGIN + 56
TAG_TABLE = HWPTAG_BEGIN + 61

# Control codes (spec table 6). Everything not listed as "char" occupies 8 WCHARs.
CHAR_CONTROLS = frozenset({0, 10, 13, 24, 25, 26, 27, 28, 29, 30, 31})
MAX_DECOMPRESSED = 200 * 1024 * 1024


@dataclass
class Record:
    tag: int
    level: int
    data: bytes


def parse_records(stream: bytes) -> list[Record]:
    records: list[Record] = []
    pos, n = 0, len(stream)
    while pos + 4 <= n:
        (header,) = struct.unpack_from("<I", stream, pos)
        pos += 4
        tag = header & 0x3FF
        level = (header >> 10) & 0x3FF
        size = (header >> 20) & 0xFFF
        if size == 0xFFF:
            if pos + 4 > n:
                raise Unscannable(UnscannableReason.CORRUPT)
            (size,) = struct.unpack_from("<I", stream, pos)
            pos += 4
        if pos + size > n:
            raise Unscannable(UnscannableReason.CORRUPT)
        records.append(Record(tag, level, stream[pos : pos + size]))
        pos += size
    return records


def para_text(data: bytes) -> str:
    """Decode HWPTAG_PARA_TEXT, skipping control payloads."""
    out: list[str] = []
    count = len(data) // 2
    i = 0
    while i < count:
        (code,) = struct.unpack_from("<H", data, i * 2)
        if code >= 32:
            out.append(chr(code))
            i += 1
            continue
        if code in CHAR_CONTROLS:
            if code in (10, 13):
                out.append("\n")
            elif code in (30, 31):
                out.append(" ")
            i += 1
        else:
            if code == 9:
                out.append("\t")
            i += 8  # inline / extended control: code + 6 WCHAR info + code
    return "".join(out).replace("\x00", "")


def decompress(raw: bytes) -> bytes:
    for wbits in (-15, 15):
        try:
            d = zlib.decompressobj(wbits)
            data = d.decompress(raw, MAX_DECOMPRESSED)
            if d.unconsumed_tail:
                raise Unscannable(UnscannableReason.TOO_LARGE)
            return data
        except zlib.error:
            continue
    raise Unscannable(UnscannableReason.CORRUPT)


@dataclass
class _TableCtx:
    level: int
    rows: int
    cols: int
    cells: list[tuple[bytes, list[str]]] = field(default_factory=list)  # (list header, texts)


def _cell_address(header: bytes, offset: int) -> tuple[int, int] | None:
    if len(header) < offset + 4:
        return None
    col, row = struct.unpack_from("<HH", header, offset)
    return col, row


def _build_table(ctx: _TableCtx) -> list[list[str]]:
    """Place cells by their stored address. The spec lists a 6-byte list header, while files
    written by Hangul are commonly observed with 8 bytes; accept whichever offset yields valid,
    unique addresses. Fall back to row-major order with nCols."""
    for offset in (8, 6):
        addrs = [_cell_address(h, offset) for h, _ in ctx.cells]
        if all(a is not None and a[0] < ctx.cols and a[1] < ctx.rows for a in addrs) and len(
            set(addrs)
        ) == len(addrs):
            grid = [["" for _ in range(ctx.cols)] for _ in range(ctx.rows)]
            for (col, row), (_h, texts) in zip(addrs, ctx.cells, strict=True):  # type: ignore[misc]
                grid[row][col] = " ".join(t for t in texts if t).strip()
            return grid
    cols = max(ctx.cols, 1)
    flat = [" ".join(t for t in texts if t).strip() for _h, texts in ctx.cells]
    return [flat[i : i + cols] for i in range(0, len(flat), cols)]


def extract_section(records: list[Record], out: Extracted, counters: dict[str, int]) -> None:
    stack: list[_TableCtx] = []

    def close_tables(level: int) -> None:
        while stack and level < stack[-1].level:
            ctx = stack.pop()
            counters["tbl"] += 1
            rows = _build_table(ctx)
            out.tables.append(Table(f"표 {counters['tbl']}", rows))
            if stack and stack[-1].cells:  # nested table: its text also belongs to the cell
                stack[-1].cells[-1][1].extend(c for r in rows for c in r)

    for rec in records:
        close_tables(rec.level)
        if rec.tag == TAG_TABLE and len(rec.data) >= 8:
            _flags, rows, cols = struct.unpack_from("<IHH", rec.data, 0)
            stack.append(_TableCtx(rec.level, rows, cols))
        elif rec.tag == TAG_LIST_HEADER and stack and rec.level == stack[-1].level:
            stack[-1].cells.append((rec.data, []))
        elif rec.tag == TAG_PARA_TEXT:
            text = para_text(rec.data).strip()
            if not text:
                continue
            if stack and stack[-1].cells:
                stack[-1].cells[-1][1].append(text)
            else:
                counters["p"] += 1
                for line in text.splitlines():
                    out.add_text(line, f"문단 {counters['p']}")
            if counters["chars"] > MAX_TEXT_CHARS:
                out.truncated = True
                return
            counters["chars"] += len(text)
    close_tables(-1)


def extract_hwp(data: bytes) -> Extracted:
    check_size(data)
    import olefile

    if not olefile.isOleFile(io.BytesIO(data)):
        raise Unscannable(UnscannableReason.CORRUPT)
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except (OSError, ValueError, struct.error):
        raise Unscannable(UnscannableReason.CORRUPT) from None
    try:
        if not ole.exists("FileHeader"):
            raise Unscannable(UnscannableReason.CORRUPT)
        header = ole.openstream("FileHeader").read()
        if not header.startswith(SIGNATURE) or len(header) < 40:
            raise Unscannable(UnscannableReason.CORRUPT)
        _version, flags = struct.unpack_from("<II", header, 32)
        if flags & FLAG_PASSWORD:
            raise Unscannable(UnscannableReason.ENCRYPTED)
        if flags & (FLAG_DISTRIBUTION | FLAG_DRM):
            raise Unscannable(UnscannableReason.DISTRIBUTION)
        sections = sorted(
            (int(e[1][len("Section") :]), e)
            for e in ole.listdir()
            if len(e) == 2
            and e[0] == "BodyText"
            and e[1].startswith("Section")
            and e[1][len("Section") :].isdigit()
        )
        if not sections:
            raise Unscannable(UnscannableReason.CORRUPT)
        out = Extracted()
        counters = {"p": 0, "tbl": 0, "chars": 0}
        for _n, entry in sections:
            raw = ole.openstream(entry).read()
            stream = decompress(raw) if flags & FLAG_COMPRESSED else raw
            extract_section(parse_records(stream), out, counters)
            if out.truncated:
                break
        return out
    except Unscannable:
        raise
    except (OSError, ValueError, struct.error, IndexError):
        raise Unscannable(UnscannableReason.CORRUPT) from None
    finally:
        ole.close()
