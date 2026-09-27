// HWP 5.0 viewer model — port of the desktop app's parser (dpg/core/extract/hwp.py).
// 본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다.
// Format (Hancom "글 문서 파일 구조 5.0" rev1.3): CFB streams FileHeader, BodyText/SectionN;
// records = TagID(10) | Level(10) | Size(12, 0xFFF => DWORD follows); PARA_TEXT is UTF-16LE with
// control codes; TABLE = UINT32 flags, UINT16 rows, UINT16 cols; each cell = LIST_HEADER + cell
// attributes (UINT16 col, row, colSpan, rowSpan) after a 6- or 8-byte list header.
// Formatting (E4): DocInfo CHAR_SHAPE (표 33: base size INT32@42 in 1/100 pt, attributes UINT32@46
// — bit0 italic, bit1 bold, bits2-3 underline, bits18-20 strike — colour COLORREF@52) and
// PARA_SHAPE (표 43/44: attribute 1 bits 2-4 = alignment); PARA_HEADER paraShape UINT16@8;
// PARA_CHAR_SHAPE = (UINT32 position, UINT32 char shape id) pairs (표 61).

import { openCfb, isCfb } from "./cfb.js";
import { inflateAny } from "./inflate.js";
import { MAX_BLOCKS, Unviewable } from "./model.js";

const SIGNATURE = "HWP Document File";
const FLAG_COMPRESSED = 1, FLAG_PASSWORD = 2, FLAG_DISTRIBUTION = 4, FLAG_DRM = 16;
const TAG_CHAR_SHAPE = 0x010 + 5;
const TAG_PARA_SHAPE = 0x010 + 9;
const TAG_PARA_HEADER = 0x010 + 50;
const TAG_PARA_TEXT = 0x010 + 51;
const TAG_PARA_CHAR_SHAPE = 0x010 + 52;
const ALIGN = ["justify", "left", "right", "center", "justify", "justify"];
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

/** Text pieces with the WCHAR position each starts at (for PARA_CHAR_SHAPE). */
export function paraPieces(d) {
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
  const count = d.length >> 1;
  const out = [];
  const push = (pos, t) => { if (t) out.push({ pos, text: t }); };
  for (let i = 0; i < count; ) {
    const code = dv.getUint16(i * 2, true);
    if (code >= 32) { push(i, String.fromCharCode(code)); i += 1; continue; }
    if (CHAR_CONTROLS.has(code)) {
      push(i, code === 10 || code === 13 ? "\n" : code === 30 || code === 31 ? " " : "");
      i += 1;
    } else {
      push(i, code === 9 ? "\t" : "");
      i += 8;
    }
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

export function readShapes(records) {
  const chars = [];
  const paras = [];
  for (const rec of records) {
    const d = rec.data;
    const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
    if (rec.tag === TAG_CHAR_SHAPE && d.length >= 56) {
      const attr = dv.getUint32(46, true);
      const c = dv.getUint32(52, true);
      chars.push({
        size: dv.getInt32(42, true) / 100, i: !!(attr & 1), b: !!(attr & 2),
        u: ((attr >>> 2) & 3) !== 0, s: ((attr >>> 18) & 7) !== 0,
        color: `#${[c & 255, (c >>> 8) & 255, (c >>> 16) & 255].map((x) => x.toString(16).padStart(2, "0")).join("")}`,
      });
    } else if (rec.tag === TAG_CHAR_SHAPE) {
      chars.push(null);
    } else if (rec.tag === TAG_PARA_SHAPE) {
      paras.push(d.length >= 4 ? ALIGN[(dv.getUint32(0, true) >>> 2) & 7] || "justify" : "justify");
    }
  }
  return { chars, paras };
}

/** Split a paragraph into lines of styled runs. */
function styledLines(pieces, charPos, shapes) {
  const lines = [[]];
  let k = 0;
  for (const p of pieces) {
    while (k + 1 < charPos.length && charPos[k + 1].pos <= p.pos) k++;
    const style = charPos.length ? shapes.chars[charPos[k].id] || null : null;
    const line = lines.at(-1);
    if (p.text === "\n") { lines.push([]); continue; }
    const last = line.at(-1);
    if (last && last.style === style) last.text += p.text;
    else line.push({ text: p.text, style });
  }
  return lines.map((runs) => {
    if (runs.length) { runs[0].text = runs[0].text.trimStart(); runs.at(-1).text = runs.at(-1).text.trimEnd(); }
    return runs.filter((r) => r.text).map((r) => ({ text: r.text, ...(r.style || {}) }));
  });
}

function section(records, blocks, state, shapes) {
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
  let paraAlign = null;
  let pending = null; // top-level paragraph waiting for its PARA_CHAR_SHAPE record
  const flush = () => {
    if (!pending) return;
    for (const runs of styledLines(pending.pieces, pending.charPos, shapes)) {
      const text = runs.map((r) => r.text).join("").trim();
      if (text) blocks.push({ type: "p", text, runs, ...(pending.align ? { align: pending.align } : {}) });
    }
    pending = null;
  };
  for (const rec of records) {
    close(rec.level);
    if (rec.tag !== TAG_PARA_CHAR_SHAPE) flush();
    if (rec.tag === TAG_PARA_HEADER && rec.data.length >= 10) {
      const id = new DataView(rec.data.buffer, rec.data.byteOffset, rec.data.byteLength).getUint16(8, true);
      paraAlign = shapes.paras[id] || null;
    }
    if (rec.tag === TAG_PARA_CHAR_SHAPE && pending) {
      const dv = new DataView(rec.data.buffer, rec.data.byteOffset, rec.data.byteLength);
      for (let o = 0; o + 8 <= rec.data.length; o += 8) pending.charPos.push({ pos: dv.getUint32(o, true), id: dv.getUint32(o + 4, true) });
      flush();
      continue;
    }
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
      else pending = { pieces: paraPieces(rec.data), charPos: [], align: paraAlign };
      if (blocks.length > MAX_BLOCKS) { state.truncated = true; return; }
    }
  }
  flush();
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
  let shapes = { chars: [], paras: [] };
  if (cfb.has("DocInfo")) {
    try {
      const raw = cfb.read("DocInfo");
      shapes = readShapes(parseRecords(flags & FLAG_COMPRESSED ? await inflateAny(raw) : raw));
    } catch { /* formatting is optional: show plain text */ }
  }
  const blocks = [];
  const state = { truncated: false };
  for (const name of sections) {
    const raw = cfb.read(name);
    const stream = flags & FLAG_COMPRESSED ? await inflateAny(raw) : raw;
    section(parseRecords(stream), blocks, state, shapes);
    if (state.truncated) break;
  }
  return { kind: "doc", blocks: blocks.filter(Boolean), truncated: state.truncated };
}
