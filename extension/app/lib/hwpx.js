// HWPX (OWPML, zip + XML) viewer model: paragraphs and tables in document order,
// including merged cells (cellAddr / cellSpan).

import { openZip } from "./zip.js";
import { MAX_BLOCKS, Unviewable } from "./model.js";

const local = (n) => (n.localName || n.nodeName || "").replace(/^.*:/, "");
const kids = (n) => Array.from(n.childNodes || []).filter((c) => c.nodeType === 1);

function textOf(node, skipTables) {
  let out = "";
  for (const c of Array.from(node.childNodes || [])) {
    if (c.nodeType === 3) {
      if (local(node) === "t") out += c.nodeValue;
    } else if (c.nodeType === 1) {
      const tag = local(c);
      if (skipTables && tag === "tbl") continue;
      if (tag === "tab") out += "\t";
      else if (tag === "lineBreak") out += "\n";
      else out += textOf(c, skipTables);
    }
  }
  return out;
}

function cellText(tc) {
  const paras = [];
  const walk = (n) => {
    for (const c of kids(n)) {
      if (local(c) === "p") paras.push(textOf(c, false).trim());
      else walk(c);
    }
  };
  walk(tc);
  return paras.filter(Boolean).join("\n");
}

function table(tbl) {
  const cells = [];
  let r = 0;
  let maxCol = 0;
  for (const tr of kids(tbl).filter((n) => local(n) === "tr")) {
    let c = 0;
    for (const tc of kids(tr).filter((n) => local(n) === "tc")) {
      const addr = kids(tc).find((n) => local(n) === "cellAddr");
      const span = kids(tc).find((n) => local(n) === "cellSpan");
      const col = addr ? Number(addr.getAttribute("colAddr")) : c;
      const row = addr ? Number(addr.getAttribute("rowAddr")) : r;
      const colSpan = span ? Number(span.getAttribute("colSpan")) || 1 : 1;
      const rowSpan = span ? Number(span.getAttribute("rowSpan")) || 1 : 1;
      cells.push({ row, col, rowSpan, colSpan, text: cellText(tc) });
      maxCol = Math.max(maxCol, col + colSpan);
      c = col + colSpan;
    }
    r += 1;
  }
  const rows = Math.max(Number(tbl.getAttribute("rowCnt")) || 0, r, ...cells.map((x) => x.row + x.rowSpan));
  const cols = Math.max(Number(tbl.getAttribute("colCnt")) || 0, maxCol);
  return { type: "table", rows, cols, cells };
}

function walkSection(node, blocks) {
  for (const c of kids(node)) {
    if (blocks.length > MAX_BLOCKS) return;
    if (local(c) === "p") {
      const text = textOf(c, true).trim();
      for (const line of text ? text.split("\n") : []) if (line.trim()) blocks.push({ type: "p", text: line.trim() });
      const tables = [];
      const find = (n) => {
        for (const k of kids(n)) {
          if (local(k) === "tbl") tables.push(k);
          else if (local(k) !== "p") find(k);
        }
      };
      find(c);
      for (const t of tables) blocks.push(table(t));
    } else {
      walkSection(c, blocks);
    }
  }
}

export async function parseHwpx(bytes, parseXml) {
  const zip = openZip(bytes);
  const names = zip.names();
  const manifest = names.find((n) => n.toLowerCase() === "meta-inf/manifest.xml");
  if (manifest && (await zip.text(manifest)).includes("encryption-data")) {
    throw new Unviewable("암호가 걸린 한글 파일입니다 — 저장해서 한컴오피스로 여세요");
  }
  const sections = names
    .map((n) => /^Contents\/section(\d+)\.xml$/i.exec(n))
    .filter(Boolean)
    .sort((a, b) => Number(a[1]) - Number(b[1]))
    .map((m) => m[0]);
  if (!sections.length) throw new Unviewable("한글(HWPX) 파일이 아닙니다");
  const blocks = [];
  for (const name of sections) {
    walkSection(parseXml(await zip.text(name)).documentElement, blocks);
  }
  return { kind: "doc", blocks, truncated: blocks.length > MAX_BLOCKS };
}
