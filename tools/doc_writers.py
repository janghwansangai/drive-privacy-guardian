"""Synthetic HWP / HWPX / PDF writers for test fixtures (not used by the app).

- HWP 5.0: compound file (tools/cfb_writer.py) with FileHeader, DocInfo, BodyText/Section0,
  records laid out per Hancom's published format (see src/dpg/core/extract/hwp.py).
- HWPX: OWPML zip with Contents/section0.xml.
- PDF: text drawn with an Identity-H font and a ToUnicode map, so text extraction works
  (the glyphs themselves are not meant to be viewed).
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from xml.sax.saxutils import escape

from tools.cfb_writer import build_cfb

# --- HWP 5.0 ------------------------------------------------------------------------------------

HWPTAG_BEGIN = 0x010
TAG_DOCUMENT_PROPERTIES = HWPTAG_BEGIN
TAG_CHAR_SHAPE = HWPTAG_BEGIN + 5
TAG_PARA_SHAPE = HWPTAG_BEGIN + 9
TAG_PARA_CHAR_SHAPE = HWPTAG_BEGIN + 52
TAG_PARA_HEADER = HWPTAG_BEGIN + 50
TAG_PARA_TEXT = HWPTAG_BEGIN + 51
TAG_CTRL_HEADER = HWPTAG_BEGIN + 55
TAG_LIST_HEADER = HWPTAG_BEGIN + 56
TAG_TABLE = HWPTAG_BEGIN + 61


def _record(tag: int, level: int, data: bytes) -> bytes:
    if len(data) < 0xFFF:
        return struct.pack("<I", tag | (level << 10) | (len(data) << 20)) + data
    return struct.pack("<II", tag | (level << 10) | (0xFFF << 20), len(data)) + data


def _para(level: int, text: str) -> bytes:
    body = text.encode("utf-16-le") + struct.pack("<H", 13)
    nchars = len(body) // 2
    header = struct.pack("<IIHBBHHHIH", nchars, 0, 0, 0, 0, 1, 0, 1, 0, 0)
    return _record(TAG_PARA_HEADER, level, header) + _record(TAG_PARA_TEXT, level + 1, body)


def _table(level: int, rows: list[list[str]], list_header_bytes: int = 8) -> bytes:
    """A paragraph holding one table control, then the table records."""
    n_rows, n_cols = len(rows), max(len(r) for r in rows)
    ctrl_id = struct.pack("<I", (ord("t") << 24) | (ord("b") << 16) | (ord("l") << 8) | ord(" "))
    ext = struct.pack("<H", 11) + ctrl_id + b"\0" * 8 + struct.pack("<H", 11)  # 8 WCHARs
    body = ext + struct.pack("<H", 13)
    out = _record(
        TAG_PARA_HEADER,
        level,
        struct.pack("<IIHBBHHHIH", len(body) // 2, 0x800, 0, 0, 0, 1, 0, 1, 0, 0),
    )
    out += _record(TAG_PARA_TEXT, level + 1, body)
    out += _record(TAG_CTRL_HEADER, level + 1, ctrl_id + b"\0" * 40)
    table = (
        struct.pack("<IHHH", 0, n_rows, n_cols, 0)
        + b"\0" * 8
        + b"\0" * (2 * n_rows)
        + struct.pack("<HH", 1, 0)
    )
    out += _record(TAG_TABLE, level + 2, table)
    for r, row in enumerate(rows):
        for c in range(n_cols):
            text = row[c] if c < len(row) else ""
            if list_header_bytes == 8:
                list_header = struct.pack("<hHI", 1, 0, 0)
            else:
                list_header = struct.pack("<hI", 1, 0)
            cell = struct.pack("<HHHHII", c, r, 1, 1, 3000, 1000) + b"\0" * 8 + struct.pack("<H", 1)
            out += _record(TAG_LIST_HEADER, level + 2, list_header + cell)
            out += _para(level + 2, text)
    return out


def build_hwp(
    blocks: list[str | list[list[str]]],
    *,
    compressed: bool = True,
    password: bool = False,
    distribution: bool = False,
    list_header_bytes: int = 8,
) -> bytes:
    """`blocks`: strings become paragraphs, lists of rows become tables."""
    flags = (1 if compressed else 0) | (2 if password else 0) | (4 if distribution else 0)
    header = b"HWP Document File".ljust(32, b"\0") + struct.pack("<II", 0x05000300, flags)
    header = header.ljust(256, b"\0")
    section = b"".join(
        _para(0, b) if isinstance(b, str) else _table(0, b, list_header_bytes) for b in blocks
    )
    docinfo = _record(TAG_DOCUMENT_PROPERTIES, 0, struct.pack("<H", 1) + b"\0" * 24)

    def pack(data: bytes) -> bytes:
        if not compressed:
            return data
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()

    return build_cfb(
        {"FileHeader": header, "DocInfo": pack(docinfo), "BodyText/Section0": pack(section)}
    )


def _char_shape(
    size_pt: int,
    *,
    bold: bool = False,
    italic: bool = False,
    underline: bool = False,
    color: int = 0,
) -> bytes:
    """HWPTAG_CHAR_SHAPE (표 33): base size at 42 (1/100 pt), attributes at 46, colour at 52."""
    attr = (1 if italic else 0) | (2 if bold else 0) | (4 if underline else 0)
    head = b"\0" * 14 + bytes([100] * 7) + b"\0" * 7 + bytes([100] * 7) + b"\0" * 7
    return head + struct.pack("<iIbbIIIIHI", size_pt * 100, attr, 0, 0, color, 0, 0, 0, 0, 0)


def _para_shape(align: int) -> bytes:
    """HWPTAG_PARA_SHAPE (표 43): attribute 1 bits 2-4 = alignment."""
    return struct.pack("<I", align << 2) + b"\0" * 50


def build_styled_hwp() -> bytes:
    """A small synthetic HWP with character and paragraph shapes (for the extension viewer).

    Char shapes: 0 = 10pt, 1 = 16pt bold red, 2 = 10pt italic underline.
    Para shapes: 0 = justify, 1 = centre, 2 = right.
    """
    paras = [  # (para shape, [(text, char shape)])
        (1, [("서식 시험 문서 (합성 데이터)", 1)]),
        (0, [("보통 글자 ", 0), ("굵은 빨간 큰 글자", 1), (" 그리고 ", 0), ("기울임 밑줄", 2)]),
        (2, [("오른쪽 정렬 문단", 0)]),
    ]
    section = b""
    for shape, runs in paras:
        text = "".join(t for t, _ in runs)
        body = text.encode("utf-16-le") + struct.pack("<H", 13)
        header = struct.pack("<IIHBBHHHIH", len(body) // 2, 0, shape, 0, 0, len(runs), 0, 1, 0, 0)
        pos, pcs = 0, b""
        for t, cs in runs:
            pcs += struct.pack("<II", pos, cs)
            pos += len(t)
        section += _record(TAG_PARA_HEADER, 0, header) + _record(TAG_PARA_TEXT, 1, body)
        section += _record(TAG_PARA_CHAR_SHAPE, 1, pcs)
    docinfo = _record(TAG_DOCUMENT_PROPERTIES, 0, struct.pack("<H", 1) + b"\0" * 24)
    docinfo += _record(TAG_CHAR_SHAPE, 1, _char_shape(10))
    docinfo += _record(TAG_CHAR_SHAPE, 1, _char_shape(16, bold=True, color=0x0000FF))
    docinfo += _record(TAG_CHAR_SHAPE, 1, _char_shape(10, italic=True, underline=True))
    for align in (0, 3, 2):
        docinfo += _record(TAG_PARA_SHAPE, 1, _para_shape(align))
    header = b"HWP Document File".ljust(32, b"\0") + struct.pack("<II", 0x05000300, 0)
    return build_cfb(
        {"FileHeader": header.ljust(256, b"\0"), "DocInfo": docinfo, "BodyText/Section0": section}
    )


# --- HWPX ---------------------------------------------------------------------------------------

_HP = "http://www.hancom.co.kr/hwpml/2011/paragraph"
_HS = "http://www.hancom.co.kr/hwpml/2011/section"


def _hwpx_p(text: str) -> str:
    return f"<hp:p><hp:run><hp:t>{escape(text)}</hp:t></hp:run></hp:p>"


def _hwpx_table(rows: list[list[str]]) -> str:
    trs = "".join(
        "<hp:tr>"
        + "".join(f"<hp:tc><hp:subList>{_hwpx_p(c)}</hp:subList></hp:tc>" for c in row)
        + "</hp:tr>"
        for row in rows
    )
    return (
        f'<hp:p><hp:run><hp:tbl rowCnt="{len(rows)}" colCnt="{len(rows[0])}">{trs}'
        f"</hp:tbl></hp:run></hp:p>"
    )


def build_hwpx(blocks: list[str | list[list[str]]], *, encrypted: bool = False) -> bytes:
    body = "".join(_hwpx_p(b) if isinstance(b, str) else _hwpx_table(b) for b in blocks)
    section = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<hs:sec xmlns:hs="{_HS}" xmlns:hp="{_HP}">{body}</hs:sec>'
    )
    ns = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
    manifest = f'<?xml version="1.0" encoding="UTF-8"?><odf:manifest xmlns:odf="{ns}">'
    if encrypted:
        manifest += (
            '<odf:file-entry odf:full-path="Contents/section0.xml">'
            "<odf:encryption-data/></odf:file-entry>"
        )
    manifest += "</odf:manifest>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(zipfile.ZipInfo("mimetype"), "application/hwp+zip")
        zf.writestr("version.xml", '<?xml version="1.0"?><hv:HCFVersion xmlns:hv="x" major="5"/>')
        zf.writestr("META-INF/manifest.xml", manifest)
        zf.writestr("Contents/content.hpf", '<?xml version="1.0"?><opf:package xmlns:opf="x"/>')
        zf.writestr("Contents/section0.xml", section, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def build_styled_hwpx() -> bytes:
    """Synthetic HWPX with header.xml char/para properties (for the extension viewer)."""
    hh = "http://www.hancom.co.kr/hwpml/2011/head"
    header = (
        f'<?xml version="1.0" encoding="UTF-8"?><hh:head xmlns:hh="{hh}"><hh:refList>'
        '<hh:charProperties itemCnt="3">'
        '<hh:charPr id="0" height="1000" textColor="#000000"><hh:underline type="NONE"/>'
        '<hh:strikeout shape="NONE"/></hh:charPr>'
        '<hh:charPr id="1" height="1600" textColor="#FF0000"><hh:bold/>'
        '<hh:underline type="NONE"/></hh:charPr>'
        '<hh:charPr id="2" height="1000" textColor="#000000"><hh:italic/>'
        '<hh:underline type="BOTTOM"/></hh:charPr>'
        "</hh:charProperties><hh:paraProperties>"
        '<hh:paraPr id="0"><hh:align horizontal="JUSTIFY"/></hh:paraPr>'
        '<hh:paraPr id="1"><hh:align horizontal="CENTER"/></hh:paraPr>'
        "</hh:paraProperties></hh:refList></hh:head>"
    )

    def run(t: str, cs: int) -> str:
        return f'<hp:run charPrIDRef="{cs}"><hp:t>{escape(t)}</hp:t></hp:run>'

    body = (
        f'<hp:p paraPrIDRef="1">{run("서식 시험 (합성 데이터)", 1)}</hp:p>'
        f'<hp:p paraPrIDRef="0">{run("보통 ", 0)}{run("굵게", 1)}{run(" 기울임", 2)}</hp:p>'
    )
    section = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<hs:sec xmlns:hs="{_HS}" xmlns:hp="{_HP}">{body}</hs:sec>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in [
            ("mimetype", "application/hwp+zip"),
            ("Contents/header.xml", header),
            ("Contents/section0.xml", section),
        ]:
            zf.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), data)
    return buf.getvalue()


# --- PDF ----------------------------------------------------------------------------------------


def _tounicode() -> bytes:
    ranges = "\n".join(
        f"<{h:02X}00> <{h:02X}FF> <{h:02X}00>" for h in range(256) if h not in range(0xD8, 0xE0)
    )
    count = 256 - 8
    return (
        "/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
        "/CMapName /Adobe-Identity-UCS def /CMapType 2 def\n"
        "1 begincodespacerange <0000> <FFFF> endcodespacerange\n"
        f"{count} beginbfrange\n{ranges}\nendbfrange\n"
        "endcmap CMapName currentdict /CMap defineresource pop end end"
    ).encode("ascii")


def build_pdf(pages: list[list[str]]) -> bytes:
    """Each page is a list of text lines. An empty list makes an image-like page (no text)."""
    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    def stream(data: bytes, extra: str = "") -> bytes:
        return f"<< /Length {len(data)} {extra}>>\nstream\n".encode() + data + b"\nendstream"

    catalog = add(b"")  # placeholder
    pages_id = add(b"")
    tounicode = add(stream(_tounicode()))
    descriptor = add(
        b"<< /Type /FontDescriptor /FontName /DPGSynthetic /Flags 4 "
        b"/FontBBox [0 -200 1000 900] /ItalicAngle 0 /Ascent 900 /Descent -200 "
        b"/CapHeight 700 /StemV 80 >>"
    )
    cidfont = add(
        f"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /DPGSynthetic "
        f"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
        f"/FontDescriptor {descriptor} 0 R /DW 1000 /CIDToGIDMap /Identity >>".encode()
    )
    font = add(
        f"<< /Type /Font /Subtype /Type0 /BaseFont /DPGSynthetic /Encoding /Identity-H "
        f"/DescendantFonts [{cidfont} 0 R] /ToUnicode {tounicode} 0 R >>".encode()
    )
    kids = []
    for lines in pages:
        ops = []
        if lines:
            for i, line in enumerate(lines):
                hexed = line.encode("utf-16-be").hex().upper()
                ops.append(f"BT /F1 11 Tf 1 0 0 1 40 {800 - 18 * i} Tm <{hexed}> Tj ET")
        else:
            ops.append("0.8 g 40 300 500 400 re f")  # a grey box: looks like a scanned image
        content = add(stream("\n".join(ops).encode("ascii")))
        kids.append(
            add(
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 {font} 0 R >> >> /Contents {content} 0 R >>".encode()
            )
        )
    objects[catalog - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
    objects[pages_id - 1] = (
        f"<< /Type /Pages /Count {len(kids)} /Kids [" + " ".join(f"{k} 0 R" for k in kids) + "] >>"
    ).encode()

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    ).encode()
    return bytes(out)
