// XLSX viewer model: every sheet with values (shared/inline strings, numbers, booleans,
// dates by number format), merged cells, and a row/column cap. Formulas show cached values.

import { openZip } from "./zip.js";
import { MAX_COLS, MAX_ROWS, Unviewable } from "./model.js";

const local = (n) => (n.localName || n.nodeName || "").replace(/^.*:/, "");
const kids = (n, tag) => Array.from(n.childNodes || []).filter((c) => c.nodeType === 1 && (!tag || local(c) === tag));
const first = (n, tag) => kids(n, tag)[0];
const all = (n, tag) => Array.from(n.getElementsByTagName("*")).filter((c) => local(c) === tag);
const textIn = (n) => all(n, "t").map((t) => t.textContent).join("") || (local(n) === "t" ? n.textContent : "");

const DATE_BUILTIN = new Set([14, 15, 16, 17, 18, 19, 20, 21, 22, 45, 46, 47]);

export function colIndex(ref) {
  const m = /^([A-Z]+)(\d+)$/.exec(ref);
  if (!m) return null;
  let col = 0;
  for (const ch of m[1]) col = col * 26 + (ch.charCodeAt(0) - 64);
  return { col: col - 1, row: Number(m[2]) - 1 };
}

function isDateFormat(code) {
  const stripped = code.replace(/"[^"]*"|\[[^\]]*]|\\./g, "");
  return /[yd]/i.test(stripped) || (/m/i.test(stripped) && !/[hs]/i.test(stripped) && /[yd]/i.test(stripped));
}

function formatDate(serial, date1904, withTime) {
  const epoch = date1904 ? Date.UTC(1904, 0, 1) : Date.UTC(1899, 11, 30);
  const ms = Math.round(serial * 86400000);
  const d = new Date(epoch + ms);
  const pad = (n) => String(n).padStart(2, "0");
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  return withTime && serial % 1 ? `${date} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}` : date;
}

function formatNumber(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return v;
  return String(parseFloat(n.toPrecision(15)));
}

export async function parseXlsx(bytes, parseXml) {
  const zip = openZip(bytes);
  if (!zip.has("xl/workbook.xml")) throw new Unviewable("엑셀(XLSX) 파일이 아닙니다");
  const wb = parseXml(await zip.text("xl/workbook.xml")).documentElement;
  const date1904 = all(wb, "workbookPr").some((p) => ["1", "true"].includes(p.getAttribute("date1904")));
  const rels = new Map();
  if (zip.has("xl/_rels/workbook.xml.rels")) {
    for (const r of all(parseXml(await zip.text("xl/_rels/workbook.xml.rels")).documentElement, "Relationship")) {
      rels.set(r.getAttribute("Id"), r.getAttribute("Target"));
    }
  }
  const shared = [];
  if (zip.has("xl/sharedStrings.xml")) {
    for (const si of all(parseXml(await zip.text("xl/sharedStrings.xml")).documentElement, "si")) {
      shared.push(textIn(si));
    }
  }
  const dateStyles = new Set();
  const timeStyles = new Set();
  if (zip.has("xl/styles.xml")) {
    const st = parseXml(await zip.text("xl/styles.xml")).documentElement;
    const custom = new Map(all(st, "numFmt").map((f) => [Number(f.getAttribute("numFmtId")), f.getAttribute("formatCode") || ""]));
    const xfs = first(st, "cellXfs") ? kids(first(st, "cellXfs"), "xf") : [];
    xfs.forEach((xf, i) => {
      const id = Number(xf.getAttribute("numFmtId") || 0);
      const code = custom.get(id);
      if (DATE_BUILTIN.has(id) || (code && isDateFormat(code))) {
        dateStyles.add(i);
        if ([18, 19, 20, 21, 22, 45, 46, 47].includes(id) || (code && /h/i.test(code))) timeStyles.add(i);
      }
    });
  }
  const sheets = [];
  let truncated = false;
  for (const s of all(wb, "sheet")) {
    const rid = s.getAttribute("r:id") || s.getAttributeNS?.("http://schemas.openxmlformats.org/officeDocument/2006/relationships", "id");
    let target = rels.get(rid) || "";
    target = target.startsWith("/") ? target.slice(1) : `xl/${target.replace(/^\.\//, "")}`;
    if (!zip.has(target)) continue;
    const doc = parseXml(await zip.text(target)).documentElement;
    const cells = [];
    let rows = 0, cols = 0;
    for (const row of all(doc, "row")) {
      for (const c of kids(row, "c")) {
        const pos = colIndex(c.getAttribute("r") || "");
        if (!pos) continue;
        if (pos.row >= MAX_ROWS || pos.col >= MAX_COLS) { truncated = true; continue; }
        const t = c.getAttribute("t") || "n";
        const vNode = first(c, "v");
        const v = vNode ? vNode.textContent : "";
        let text = "";
        if (t === "s") text = shared[Number(v)] ?? "";
        else if (t === "inlineStr") text = first(c, "is") ? textIn(first(c, "is")) : "";
        else if (t === "b") text = v === "1" ? "TRUE" : "FALSE";
        else if (t === "str" || t === "e") text = v;
        else if (v !== "") {
          const style = Number(c.getAttribute("s") || 0);
          text = dateStyles.has(style) ? formatDate(Number(v), date1904, timeStyles.has(style)) : formatNumber(v);
        }
        if (text === "") continue;
        cells.push({ row: pos.row, col: pos.col, rowSpan: 1, colSpan: 1, text });
        rows = Math.max(rows, pos.row + 1);
        cols = Math.max(cols, pos.col + 1);
      }
    }
    for (const m of all(doc, "mergeCell")) {
      const [a, b] = (m.getAttribute("ref") || "").split(":").map(colIndex);
      if (!a || !b || a.row >= MAX_ROWS || a.col >= MAX_COLS) continue;
      const cell = cells.find((x) => x.row === a.row && x.col === a.col);
      const span = { rowSpan: b.row - a.row + 1, colSpan: b.col - a.col + 1 };
      if (cell) Object.assign(cell, span);
      else cells.push({ row: a.row, col: a.col, text: "", ...span });
      rows = Math.max(rows, Math.min(b.row + 1, MAX_ROWS));
      cols = Math.max(cols, Math.min(b.col + 1, MAX_COLS));
    }
    sheets.push({ name: s.getAttribute("name") || `시트 ${sheets.length + 1}`, table: { type: "table", rows, cols, cells } });
  }
  if (!sheets.length) throw new Unviewable("엑셀 시트를 찾지 못했습니다");
  return { kind: "sheets", sheets, truncated };
}
