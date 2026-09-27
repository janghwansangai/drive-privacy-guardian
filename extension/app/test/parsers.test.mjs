// Parity: the extension reads the same content as the desktop app's extractors (synthetic data).
import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { SYN, read, parseXml, expected, norm, normGrid } from "./helpers.mjs";
import { parseHwp, paraText } from "../lib/hwp.js";
import { parseHwpx } from "../lib/hwpx.js";
import { parseXlsx, colIndex } from "../lib/xlsx.js";
import { parseDocx } from "../lib/docx.js";
import { FIX } from "./helpers.mjs";
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
  const other = await viewModel("a.pptx", new Uint8Array([1, 2, 3]), parseXml);
  assert.equal(other.kind, "unsupported");
  for (const name of ["x.hwp", "x.hwpx", "x.xlsx", "x.docx"]) {
    const v = await viewModel(name, new Uint8Array(600).fill(7), parseXml);
    assert.equal(v.kind, "unsupported", name);
  }
});

test("DOCX: same paragraphs as the desktop app", async () => {
  const m = await parseDocx(read(path.join(SYN, "가정통신문_체험학습.docx")), parseXml);
  const exp = expected("가정통신문_체험학습.docx");
  assert.equal(m.kind, "doc");
  assert.deepEqual(paragraphs(m), exp.segments.map(norm));
});

test("DOCX: tables in order with horizontal and vertical merges", async () => {
  const m = await parseDocx(read(path.join(FIX, "표병합_가상.docx")), parseXml);
  assert.deepEqual(m.blocks.map((b) => b.type), ["p", "table", "p"]);
  const t = m.blocks[1];
  assert.equal(t.rows, 3);
  assert.equal(t.cols, 3);
  const at = (r, c) => t.cells.find((x) => x.row === r && x.col === c);
  assert.deepEqual([at(0, 0).text, at(0, 0).colSpan], ["가로병합", 2]);
  assert.deepEqual([at(1, 2).text, at(1, 2).rowSpan], ["세로병합", 2]);
  assert.equal(at(2, 2), undefined);
  assert.equal(at(2, 0).text, "칸20");
});

test("DOCX with a password (OLE container) is refused with a clear reason", async () => {
  const cfb = new Uint8Array(1024);
  cfb.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  const v = await viewModel("암호.docx", cfb, parseXml);
  assert.equal(v.kind, "unsupported");
  assert.match(v.reason, /워드로 여세요/);
});

test("PDF and pictures are handed to the page renderer; unknown types say to save", async () => {
  const pdf = read(path.join(SYN, "보호자_안내문.pdf"));
  assert.equal((await viewModel("a.PDF", pdf, parseXml)).kind, "pdf");
  const img = await viewModel("사진.JPG", new Uint8Array([0xff, 0xd8]), parseXml);
  assert.deepEqual([img.kind, img.mime], ["image", "image/jpeg"]);
  assert.equal((await viewModel("그림.svg", new Uint8Array(4), parseXml)).kind, "unsupported"); // SVG not rendered
  assert.match((await viewModel("a.pptx", new Uint8Array(4), parseXml)).reason, /저장/);
});

const styledRuns = (m) => m.blocks.filter((b) => b.type === "p").map((b) => ({ align: b.align, runs: b.runs.map((r) => [r.text, !!r.b, !!r.i, !!r.u, r.size, r.color]) }));

test("E4 HWP formatting: bold / italic / underline / size / colour and alignment (Hancom 표 33·43·61)", async () => {
  const m = await parseHwp(read(path.join(FIX, "서식_가상.hwp")));
  assert.deepEqual(styledRuns(m), [
    { align: "center", runs: [["서식 시험 문서 (합성 데이터)", true, false, false, 16, "#ff0000"]] },
    { align: "justify", runs: [
      ["보통 글자 ", false, false, false, 10, "#000000"], ["굵은 빨간 큰 글자", true, false, false, 16, "#ff0000"],
      [" 그리고 ", false, false, false, 10, "#000000"], ["기울임 밑줄", false, true, true, 10, "#000000"]] },
    { align: "right", runs: [["오른쪽 정렬 문단", false, false, false, 10, "#000000"]] },
  ]);
});

test("E4 HWPX formatting from header.xml (charPr / paraPr)", async () => {
  const m = await parseHwpx(read(path.join(FIX, "서식_가상.hwpx")), parseXml);
  assert.deepEqual(styledRuns(m), [
    { align: "center", runs: [["서식 시험 (합성 데이터)", true, false, false, 16, "#ff0000"]] },
    { align: "justify", runs: [["보통 ", false, false, false, 10, "#000000"], ["굵게", true, false, false, 16, "#ff0000"], [" 기울임", false, true, true, 10, "#000000"]] },
  ]);
});

test("E4 DOCX direct formatting and alignment", async () => {
  const m = await parseDocx(read(path.join(FIX, "서식_가상.docx")), parseXml);
  assert.deepEqual(styledRuns(m), [
    { align: "center", runs: [["서식 시험 (합성 데이터)", true, false, false, 16, "#ff0000"]] },
    { align: undefined, runs: [["보통 ", false, false, false, undefined, undefined], ["기울임 밑줄", false, true, true, undefined, undefined]] },
  ]);
});
