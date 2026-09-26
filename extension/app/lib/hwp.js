// HWP 5.0 viewer model — port of the desktop app's parser (dpg/core/extract/hwp.py).
// 본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다.
// Format (Hancom "글 문서 파일 구조 5.0" rev1.3): CFB streams FileHeader, BodyText/SectionN;
// records = TagID(10) | Level(10) | Size(12, 0xFFF => DWORD follows); PARA_TEXT is UTF-16LE with
// control codes; TABLE = UINT32 flags, UINT16 rows, UINT16 cols; each cell = LIST_HEADER + cell
// attributes (UINT16 col, row, colSpan, rowSpan) after a 6- or 8-byte list header.

import { openCfb, isCfb } from "./cfb.js";
import { inflateAny } from "./inflate.js";
import { MAX_BLOCKS, Unviewable } from "./model.js";

const SIGNATURE = "HWP Document File";
const FLAG_COMPRESSED = 1, FLAG_PASSWORD = 2, FLAG_DISTRIBUTION = 4, FLAG_DRM = 16;
const TAG_PARA_TEXT = 0x010 + 51;
const TAG_LIST_HEADER = 0x010 + 56;
const TAG_TABLE = 0x010 + 61;
const CHAR_CONTROLS = new Set([0, 10, 13, 24, 25, 26, 27, 28, 29, 30, 31]);

export function parseRecords(s) {
  const dv = new DataView(s.buffer, s.byteOffset, s.byteLength);
  const out = [];
  let pos = 0;
  while (pos + 4 <= s.length) {
    const h = dv.getUint32(pos, true);
    pos += 4;
    const tag = h & 0x3ff, level = (h >>> 10) & 0x3ff;
    let size = (h >>> 20) & 0xfff;
    if (size === 0xfff) {
      if (pos + 4 > s.length) throw new Unviewable("한글 파일이 손상되었습니다");
      size = dv.getUint32(pos, true);
      pos += 4;
    }
    if (pos + size > s.length) throw new Unviewable("한글 파일이 손상되었습니다");
    out.push({ tag, level, data: s.subarray(pos, pos + size) });
    pos += size;
  }
  return out;
}

export function paraText(d) {
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
  const count = d.length >> 1;
  let out = "";
  for (let i = 0; i < count; ) {
    const code = dv.getUint16(i * 2, true);
    if (code >= 32) { out += String.fromCharCode(code); i += 1; continue; }
    if (CHAR_CONTROLS.has(code)) {
      if (code === 10 || code === 13) out += "\n";
      else if (code === 30 || code === 31) out += " ";
      i += 1;
    } else {
      if (code === 9) out += "\t";
      i += 8;
    }
  }
  return out.replaceAll("\u0000", "");
}

function cellAttrs(header, offset) {
  if (header.length < offset + 8) return null;
  const dv = new DataView(header.buffer, header.byteOffset, header.byteLength);
  return {
    col: dv.getUint16(offset, true), row: dv.getUint16(offset + 2, true),
    colSpan: dv.getUint16(offset + 4, true) || 1, rowSpan: dv.getUint16(offset + 6, true) || 1,
  };
}

function buildTable(ctx) {
  for (const offset of [8, 6]) {
    const attrs = ctx.cells.map((c) => cellAttrs(c.header, offset));
    const keys = attrs.map((a) => (a ? `${a.row},${a.col}` : "x"));
    if (
      attrs.every((a) => a && a.col < ctx.cols && a.row < ctx.rows) &&
      new Set(keys).size === keys.length
    ) {
      return {
        type: "table", rows: ctx.rows, cols: ctx.cols,
        cells: attrs.map((a, i) => ({ ...a, text: ctx.cells[i].texts.filter(Boolean).join("\n").trim() })),
      };
    }
  }
  const cols = Math.max(ctx.cols, 1);
  const cells = ctx.cells.map((c, i) => ({
    row: Math.floor(i / cols), col: i % cols, rowSpan: 1, colSpan: 1,
    text: c.texts.filter(Boolean).join("\n").trim(),
  }));
  return { type: "table", rows: Math.ceil(cells.length / cols), cols, cells };
}

function section(records, blocks, state) {
  const stack = [];
  const close = (level) => {
    while (stack.length && level < stack.at(-1).level) {
      const ctx = stack.pop();
      const table = buildTable(ctx);
      blocks[ctx.slot] = table; // keep document order: the table sits where it started
      if (stack.length && stack.at(-1).cells.length) {
        stack.at(-1).cells.at(-1).texts.push(...table.cells.map((c) => c.text));
      }
    }
  };
  for (const rec of records) {
    close(rec.level);
    if (rec.tag === TAG_TABLE && rec.data.length >= 8) {
      const dv = new DataView(rec.data.buffer, rec.data.byteOffset, rec.data.byteLength);
      const ctx = { level: rec.level, rows: dv.getUint16(4, true), cols: dv.getUint16(6, true), cells: [], slot: -1 };
      if (!stack.length) { ctx.slot = blocks.length; blocks.push(null); }
      else ctx.slot = blocks.push(null) - 1; // nested tables are also shown after their parent
      stack.push(ctx);
    } else if (rec.tag === TAG_LIST_HEADER && stack.length && rec.level === stack.at(-1).level) {
      stack.at(-1).cells.push({ header: rec.data, texts: [] });
    } else if (rec.tag === TAG_PARA_TEXT) {
      const text = paraText(rec.data).trim();
      if (!text) continue;
      if (stack.length && stack.at(-1).cells.length) stack.at(-1).cells.at(-1).texts.push(text);
      else for (const line of text.split("\n")) blocks.push({ type: "p", text: line });
      if (blocks.length > MAX_BLOCKS) { state.truncated = true; return; }
    }
  }
  close(-1);
}

export async function parseHwp(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (!isCfb(b)) throw new Unviewable("한글(HWP) 파일이 아닙니다");
  const cfb = openCfb(b);
  if (!cfb.has("FileHeader")) throw new Unviewable("한글 파일이 손상되었습니다");
  const header = cfb.read("FileHeader");
  const sig = new TextDecoder("ascii").decode(header.subarray(0, 17));
  if (sig !== SIGNATURE || header.length < 40) throw new Unviewable("한글 파일이 손상되었습니다");
  const flags = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(36, true);
  if (flags & FLAG_PASSWORD) throw new Unviewable("암호가 걸린 한글 파일입니다 — 저장해서 한컴오피스로 여세요");
  if (flags & (FLAG_DISTRIBUTION | FLAG_DRM)) throw new Unviewable("배포용·보안 문서는 이 뷰어로 볼 수 없습니다 — 저장해서 한컴오피스로 여세요");
  const sections = cfb.list()
    .map((p) => /^BodyText\/Section(\d+)$/.exec(p))
    .filter(Boolean)
    .sort((a, b2) => Number(a[1]) - Number(b2[1]))
    .map((m) => m[0]);
  if (!sections.length) throw new Unviewable("한글 파일이 손상되었습니다");
  const blocks = [];
  const state = { truncated: false };
  for (const name of sections) {
    const raw = cfb.read(name);
    const stream = flags & FLAG_COMPRESSED ? await inflateAny(raw) : raw;
    section(parseRecords(stream), blocks, state);
    if (state.truncated) break;
  }
  return { kind: "doc", blocks: blocks.filter(Boolean), truncated: state.truncated };
}
