// TXT / CSV / TSV: UTF-8 (with or without BOM), else EUC-KR (common for Korean school files).

import { MAX_COLS, MAX_ROWS } from "./model.js";

export function decodeText(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder("utf-16le").decode(b.subarray(2));
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(b).replace(/^﻿/, "");
  } catch {
    return new TextDecoder("euc-kr").decode(b);
  }
}

export function parseCsvText(text, sep = ",") {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === sep) { row.push(field); field = ""; }
    else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(field); rows.push(row); row = []; field = "";
      if (rows.length >= MAX_ROWS) break;
    } else field += ch;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows;
}

export function parseCsv(bytes, sep = ",") {
  const rows = parseCsvText(decodeText(bytes), sep);
  const cells = [];
  let cols = 0;
  rows.forEach((r, ri) => r.slice(0, MAX_COLS).forEach((v, ci) => {
    cols = Math.max(cols, ci + 1);
    if (v !== "") cells.push({ row: ri, col: ci, rowSpan: 1, colSpan: 1, text: v });
  }));
  return {
    kind: "sheets",
    sheets: [{ name: "CSV", table: { type: "table", rows: rows.length, cols, cells } }],
    truncated: rows.length >= MAX_ROWS,
  };
}

export function parseTxt(bytes) {
  const text = decodeText(bytes);
  const limit = 2_000_000;
  return { kind: "text", text: text.slice(0, limit), truncated: text.length > limit };
}
