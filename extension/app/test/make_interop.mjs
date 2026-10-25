// Writes test/fixtures/확장_2026-09-27_5a6b7c8d.7z: an archive made by the EXTENSION's 7z writer
// with the synthetic recovery key, and 확장_2026-10-25_9a8b7c6d.zip: its standard ZIP (D-107) with
// a common password derived from the synthetic key, so the desktop app's tests can prove they open them (E3 interop).
//   node test/make_interop.mjs
import fs from "node:fs";
import path from "node:path";
import { COMMON_TEST_TAG, FIX, SYN, read, recoveryKey } from "./helpers.mjs";
import { create7z, createArchive, derivePassword, parseRecoveryKey } from "../lib/vault.js";

const files = new Map([
  ["상담기록_가상.hwp", read(path.join(SYN, "상담기록_가상.hwp"))],
  ["폴더/6-2_학생_연락처.xlsx", read(path.join(SYN, "6-2_학생_연락처.xlsx"))],
]);
const raw = await parseRecoveryKey(recoveryKey());
const blob = await create7z(files, await derivePassword(raw, "5a6b7c8d"));
fs.writeFileSync(path.join(FIX, "확장_2026-09-27_5a6b7c8d.7z"), blob);
// common password derived from the synthetic key with the tag tools/make_ext_fixtures.py uses
const zip = await createArchive(files, await derivePassword(raw, COMMON_TEST_TAG), "zip");
fs.writeFileSync(path.join(FIX, "확장_2026-10-25_9a8b7c6d.zip"), zip);
console.log("written", blob.length, zip.length);
