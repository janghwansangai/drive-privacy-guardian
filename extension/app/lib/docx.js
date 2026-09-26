// DOCX (WordprocessingML, zip + XML) viewer model: paragraphs and tables in document order,
// including merged cells (gridSpan / vMerge).

import { openZip } from "./zip.js";
import { MAX_BLOCKS, Unviewable } from "./model.js";

const local = (n) => (n.localName || n.nodeName || "").replace(/^.*:/, "");
const kids = (n) => Array.from(n.childNodes || []).filter((c) => c.nodeType === 1);
const attr = (n, name) => n.getAttribute(`w:${name}`) ?? n.getAttribute(name);
const child = (n, name) => kids(n).find((c) => local(c) === name);

function paraText(p) {
  let out = "";
  const walk = (n) => {
    for (const c of kids(n)) {
      const tag = local(c);
      if (tag === "t") out += c.textContent;
      else if (tag === "tab") out += "\t";
      else if (tag === "br" || tag === "cr") out += "\n";
      else if (tag === "tbl" || tag === "del" || tag === "instrText") continue; // deleted text is not shown
      else walk(c);
    }
  };
  walk(p);
  return out;
}

function cellText(tc) {
  const paras = [];
  const walk = (n) => {
    for (const c of kids(n)) {
      if (local(c) === "p") paras.push(paraText(c).trim());
      else if (local(c) !== "tbl") walk(c);
    }
  };
  walk(tc);
  return paras.filter(Boolean).join("\n");
}

function rowsOf(tbl) {
  const rows = [];
  const walk = (n) => {
    for (const c of kids(n)) {
      if (local(c) === "tr") rows.push(c);
      else if (local(c) === "sdt" || local(c) === "sdtContent") walk(c);
    }
  };
  walk(tbl);
  return rows;
}

function cellsOf(tr) {
  const cells = [];
  const walk = (n) => {
    for (const c of kids(n)) {
      if (local(c) === "tc") cells.push(c);
      else if (local(c) === "sdt" || local(c) === "sdtContent") walk(c);
    }
  };
  walk(tr);
  return cells;
}

function table(tbl) {
  const cells = [];
  const open = new Map(); // col → cell still growing downward (vMerge="restart")
  let cols = 0;
  const trs = rowsOf(tbl);
  trs.forEach((tr, r) => {
    let c = 0;
    for (const tc of cellsOf(tr)) {
      const pr = child(tc, "tcPr");
      const span = Math.max(1, Number(pr && child(pr, "gridSpan") && attr(child(pr, "gridSpan"), "val")) || 1);
      const vm = pr && child(pr, "vMerge");
      const vmVal = vm ? attr(vm, "val") || "continue" : null;
      if (vmVal === "continue" && open.has(c)) {
        open.get(c).rowSpan += 1;
      } else {
        const cell = { row: r, col: c, rowSpan: 1, colSpan: span, text: cellText(tc) };
        cells.push(cell);
        if (vmVal === "restart") open.set(c, cell);
        else open.delete(c);
      }
      c += span;
    }
    cols = Math.max(cols, c);
  });
  return { type: "table", rows: trs.length, cols, cells };
}

function walkBody(node, blocks) {
  for (const c of kids(node)) {
    if (blocks.length > MAX_BLOCKS) return;
    const tag = local(c);
    if (tag === "p") {
      for (const line of paraText(c).split("\n")) if (line.trim()) blocks.push({ type: "p", text: line.trim() });
    } else if (tag === "tbl") {
      blocks.push(table(c));
    } else if (tag === "sdt" || tag === "sdtContent" || tag === "customXml" || tag === "ins") {
      walkBody(c, blocks);
    }
  }
}

export async function parseDocx(bytes, parseXml) {
  if (bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0) {
    throw new Unviewable("암호가 걸렸거나 옛 형식(.doc)인 워드 파일입니다 — 저장해서 워드로 여세요");
  }
  const zip = openZip(bytes);
  if (!zip.has("word/document.xml")) throw new Unviewable("워드(DOCX) 파일이 아닙니다");
  const doc = parseXml(await zip.text("word/document.xml")).documentElement;
  const body = kids(doc).find((n) => local(n) === "body");
  const blocks = [];
  if (body) walkBody(body, blocks);
  return { kind: "doc", blocks, truncated: blocks.length > MAX_BLOCKS };
}
