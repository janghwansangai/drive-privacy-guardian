// D-093: the extension's personal-data rules find exactly what the desktop app finds.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { FIX, SYN, read, parseXml } from "./helpers.mjs";
import { detectExtracted, detectText, detectFilename, summarize, rrnChecksumOk, luhnOk, HIGH } from "../lib/detect.js";
import { extractForDetect } from "../lib/scan.js";

const NAMES = ["상담기록_가상.hwp", "학생명단_가상.hwpx", "6-2_학생_연락처.xlsx", "6-2_학생_연락처.csv", "가정통신문_체험학습.docx"];
const desktop = (name) => JSON.parse(fs.readFileSync(path.join(FIX, "expected", `${name}.detect.json`), "utf8"));
const compact = (sum) => Object.fromEntries(Object.entries(sum).sort().map(([k, v]) => [k, [v.count, v.confidence]]));

for (const name of NAMES) {
  test(`rules: same findings as the desktop app on the desktop's extracted text — ${name}`, () => {
    const ex = JSON.parse(fs.readFileSync(path.join(FIX, "expected", `${name}.json`), "utf8"));
    const doc = {
      segments: ex.segments.map((text, i) => ({ text, location: `문단 ${i + 1}` })),
      tables: ex.tables.map((rows, i) => ({ rows, location: `표 ${i + 1}` })),
    };
    assert.deepEqual(compact(summarize(detectExtracted(doc))), desktop(name));
  });

  test(`end to end: the extension's own parser + rules find the same kinds — ${name}`, async () => {
    const doc = await extractForDetect(name, read(path.join(SYN, name)), parseXml);
    const mine = compact(summarize(detectExtracted(doc)));
    assert.deepEqual(Object.keys(mine), Object.keys(desktop(name)));
    for (const [k, [n]] of Object.entries(desktop(name))) assert.equal(mine[k][0], n, `${name} ${k}`);
  });
}

test("validators and context rules", () => {
  assert.ok(luhnOk("4111 1111 1111 1111"));
  assert.ok(!luhnOk("4111 1111 1111 1112"));
  assert.equal(detectText("계좌 1234567890123", "x")[0]?.kind, "account");
  assert.equal(detectText("주문번호 1234567890123", "x").length, 0); // no bank/account context
  assert.deepEqual(detectFilename("6-2 학생 연락처.xlsx").map((f) => f.kind), ["filename_hint"]);
  const noDate = detectText("991399-1234567", "x"); // month 13: not a birth date
  assert.equal(noDate.length, 0);
  assert.equal(typeof rrnChecksumOk("0001013000004"), "boolean");
  assert.equal(HIGH, 3);
});

test("findings carry kind / confidence / location only — never the matched value", () => {
  const text = "학생 주민번호 000101-3000004, 휴대전화 010-1234-5678, 신한은행 계좌 110-123-456789 입금";
  for (const f of detectText(text, "문단 1")) {
    assert.deepEqual(Object.keys(f).sort(), ["confidence", "kind", "location"]);
    assert.ok(!JSON.stringify(f).match(/\d{3,}/), "no digits of the value");
  }
  const sum = summarize(detectText(text, "문단 1"));
  assert.ok(!JSON.stringify(sum).includes("010-1234"));
});
