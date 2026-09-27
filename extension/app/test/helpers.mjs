import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DOMParser } from "@xmldom/xmldom";
import { setLoader } from "../lib/vault.js";

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIX = path.join(HERE, "fixtures");
export const SYN = path.resolve(HERE, "../../../tests/fixtures/synthetic");
export const read = (p) => new Uint8Array(fs.readFileSync(p));
export const parseXml = (text) => new DOMParser().parseFromString(text, "text/xml");
export const expected = (name) => JSON.parse(fs.readFileSync(path.join(FIX, "expected", `${name}.json`), "utf8"));
export const recoveryKey = () => fs.readFileSync(path.join(FIX, "recovery.txt"), "utf8").split("\n")[0].trim();

// Under Node, 7-Zip WASM records its own exit status (2 = wrong password, which the tests expect)
// as the process exit code; the test runner would read that as a failed file.
process.on("beforeExit", () => { if (process.exitCode === 2) process.exitCode = 0; });

setLoader(async () => (await import("../vendor/7z-wasm/7zz.es6.js")).default);

/** Collapse whitespace and drop trailing empty cells/rows so both sides compare fairly. */
export const norm = (s) => s.replace(/\s+/g, " ").trim();
export function normGrid(rows) {
  const g = rows.map((r) => r.map((c) => norm(String(c))));
  for (const r of g) while (r.length && r.at(-1) === "") r.pop();
  while (g.length && g.at(-1).length === 0) g.pop();
  return g;
}
