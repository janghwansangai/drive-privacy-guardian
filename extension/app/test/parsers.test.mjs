// Parity: the extension reads the same content as the desktop app's extractors (synthetic data).
import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { SYN, read, parseXml, expected, norm, normGrid } from "./helpers.mjs";
import { parseHwp, paraText } from "../lib/hwp.js";
import { parseHwpx } from "../lib/hwpx.js";
import { parseXlsx, colIndex } from "../lib/xlsx.js";
import { parseCsv, parseCsvText, decodeText } from "../lib/text.js";
import { viewModel } from "../lib/view.js";
import { gridOf } from "../lib/model.js";

const paragraphs = (m) => m.blocks.filter((b) => b.type === "p").map((b) => norm(b.text));
const tables = (m) => m.blocks.filter((b) => b.type === "table").map((t) => normGrid(gridOf(t)));

test("HWP 5.0: same paragraphs and tables as the desktop app", async () => {
  const m = await parseHwp(read(path.join(SYN, "상담기록_가상.hwp")));
  const exp = expected("상담기록_가상.hwp");
  assert.equal(m.kind, "doc");
  assert.deepEqual(paragraphs(m), exp.segments.map(norm));
  assert.deepEqual(tables(m), exp.tables.map(normGrid));
});

test("HWP: document order keeps tables where they appear", async () => {
  const m = await parseHwp(read(path.join(SYN, "상담기록_가상.hwp")));
  assert.ok(m.blocks.some((b) => b.type === "table"));
  assert.ok(m.blocks[0].type === "p");
});

test("HWP distribution / password documents are refused with a clear reason", async () => {
  for (const name of ["배포용_가상.hwp", "암호_가상.hwp"]) {
    const v = await viewModel(name, read(path.join(SYN, name)), parseXml);
    assert.equal(v.kind, "unsupported", name);
    assert.match(v.reason, /한컴오피스/);
  }
});

test("HWPX: same paragraphs and tables as the desktop app", async () => {
  const m = await parseHwpx(read(path.join(SYN, "학생명단_가상.hwpx")), parseXml);
  const exp = expected("학생명단_가상.hwpx");
  assert.deepEqual(paragraphs(m), exp.segments.map(norm));
  assert.deepEqual(tables(m), exp.tables.map(normGrid));
});

test("XLSX: same cell values as the desktop app", async () => {
  const m = await parseXlsx(read(path.join(SYN, "6-2_학생_연락처.xlsx")), parseXml);
  const exp = expected("6-2_학생_연락처.xlsx");
  assert.equal(m.kind, "sheets");
  assert.deepEqual(m.sheets.map((s) => normGrid(gridOf(s.table))), exp.tables.map(normGrid));
});

test("CSV: same rows as the desktop app, EUC-KR fallback", async () => {
  const m = parseCsv(read(path.join(SYN, "6-2_학생_연락처.csv")));
  const exp = expected("6-2_학생_연락처.csv");
  assert.deepEqual(normGrid(gridOf(m.sheets[0].table)), exp.tables.map(normGrid)[0]);
  const euc = new Uint8Array([0xc7, 0xd0, 0xbb, 0xfd]); // "학생" in EUC-KR
  assert.equal(decodeText(euc), "학생");
  assert.deepEqual(parseCsvText('a,"b,""c"""\r\n1,2'), [["a", 'b,"c"'], ["1", "2"]]);
});

test("small helpers", () => {
  assert.deepEqual(colIndex("AB12"), { col: 27, row: 11 });
  // PARA_TEXT: 'A', an inline control (8 WCHARs), 'B', line break
  const d = new Uint16Array([65, 9, 0, 0, 0, 0, 0, 0, 9, 66, 13]);
  assert.equal(paraText(new Uint8Array(d.buffer)), "A\tB\n");
});

test("unsupported and damaged files never throw", async () => {
  const pdf = await viewModel("a.pdf", new Uint8Array([1, 2, 3]), parseXml);
  assert.equal(pdf.kind, "unsupported");
  for (const name of ["x.hwp", "x.hwpx", "x.xlsx"]) {
    const v = await viewModel(name, new Uint8Array(600).fill(7), parseXml);
    assert.equal(v.kind, "unsupported", name);
  }
});
