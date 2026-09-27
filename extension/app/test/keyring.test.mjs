// D-088: recovery key = master key, personal password unlocks a wrapped copy, auto-lock.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { FIX, recoveryKey } from "./helpers.mjs";
import { parseRecoveryKey } from "../lib/vault.js";

function area() {
  const data = {};
  return {
    data,
    get: async (k) => ({ [k]: data[k] }),
    set: async (o) => { Object.assign(data, JSON.parse(JSON.stringify(o))); },
    remove: async (k) => { delete data[k]; },
  };
}
globalThis.chrome = { storage: { local: area(), session: area() } };
const keyring = await import("../lib/keyring.js");
const reset = () => { for (const a of ["local", "session"]) for (const k of Object.keys(chrome.storage[a].data)) delete chrome.storage[a].data[k]; };

test("fingerprint is the desktop app's (same key → same 8 characters)", async () => {
  const raw = await parseRecoveryKey(recoveryKey());
  const desktop = fs.readFileSync(path.join(FIX, "expected", "recovery_fingerprint.txt"), "utf8").trim();
  assert.equal(await keyring.fingerprint(raw), desktop);
});

test("a recovery key made here has the desktop format and parses back", async () => {
  const { raw, text } = await keyring.newRecoveryKey();
  assert.match(text, /^[A-Z2-7]{5}(-[A-Z2-7]{5}){6}$/);
  assert.deepEqual(await parseRecoveryKey(text), raw);
});

test("personal password unlocks; the stored copy is encrypted; wrong password fails", async () => {
  reset();
  const raw = await parseRecoveryKey(recoveryKey());
  assert.equal(await keyring.isSetUp(), false);
  await keyring.setPassword(raw, "개인비번-1234");
  const stored = JSON.stringify(chrome.storage.local.data);
  assert.ok(!stored.includes(btoa(String.fromCharCode(...raw))), "the raw key is never stored in local storage");
  assert.ok(!stored.includes("개인비번"));
  await keyring.lock();
  assert.equal(await keyring.currentKey(), null);
  await assert.rejects(keyring.unlock("틀린비번-0000"), keyring.BadPassword);
  assert.deepEqual(await keyring.unlock("개인비번-1234"), raw);
  assert.deepEqual(await keyring.currentKey(), raw);
});

test("forgot the password: the same recovery key is accepted, a different one is refused", async () => {
  const other = (await keyring.newRecoveryKey()).raw;
  await assert.rejects(keyring.checkRecoveryKey(other), keyring.WrongRecoveryKey);
  const raw = await parseRecoveryKey(recoveryKey());
  await keyring.checkRecoveryKey(raw);
  await keyring.setPassword(raw, "새비밀번호-5678");
  await keyring.lock();
  await assert.rejects(keyring.unlock("개인비번-1234"), keyring.BadPassword);
  assert.deepEqual(await keyring.unlock("새비밀번호-5678"), raw);
});

test("auto-lock: idle longer than the chosen minutes → locked", async () => {
  await keyring.setLockMinutes(5);
  assert.equal(await keyring.lockMinutes(), 5);
  chrome.storage.session.data.vaultKey.at = Date.now() - 6 * 60000;
  assert.equal(await keyring.currentKey(), null);
  assert.equal(chrome.storage.session.data.vaultKey, undefined);
  await assert.rejects(keyring.setLockMinutes(7));
  assert.equal(keyring.checkNewPassword("short", "short"), "개인 비밀번호는 8자 이상으로 정해 주세요");
  assert.equal(keyring.checkNewPassword("long-enough", "different"), "비밀번호 확인이 다릅니다");
});
