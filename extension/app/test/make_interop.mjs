// Writes test/fixtures/확장_2026-09-27_5a6b7c8d.7z: an archive made by the EXTENSION's 7z writer
// with the synthetic recovery key, so the desktop app's tests can prove they open it (E3 interop).
//   node test/make_interop.mjs
import fs from "node:fs";
import path from "node:path";
import { FIX, SYN, read, recoveryKey } from "./helpers.mjs";
import { create7z, derivePassword, parseRecoveryKey } from "../lib/vault.js";

const files = new Map([
  ["상담기록_가상.hwp", read(path.join(SYN, "상담기록_가상.hwp"))],
  ["폴더/6-2_학생_연락처.xlsx", read(path.join(SYN, "6-2_학생_연락처.xlsx"))],
]);
const raw = await parseRecoveryKey(recoveryKey());
const blob = await create7z(files, await derivePassword(raw, "5a6b7c8d"));
fs.writeFileSync(path.join(FIX, "확장_2026-09-27_5a6b7c8d.7z"), blob);
console.log("written", blob.length);
