// The recovery key is the master key (D-088): every archive's password is derived from it
// (vault.derivePassword, same as the desktop app). The user's personal password only unlocks a
// copy of that key kept on this computer, encrypted:
//   chrome.storage.local  "vaultWrap" = AES-GCM(key = PBKDF2-SHA256(password, salt, 600 000), raw key)
//   chrome.storage.session "vaultKey" = the unlocked key + last use (memory only, gone when the
//   browser closes; content scripts cannot read session storage) — removed after `lockMinutes`
//   without use (checked on every use and by the background alarm).
// Forgot the password → type the recovery key → set a new password.

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ITERATIONS = 600000;
export const LOCK_CHOICES = [5, 15, 30, 60];
export const DEFAULT_LOCK_MINUTES = 15;

export class BadPassword extends Error {}
export class WrongRecoveryKey extends Error {}

const enc = new TextEncoder();
const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
const unb64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const local = () => chrome.storage.local;
const session = () => chrome.storage.session;

function b32encode(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

/** A new recovery key in the desktop app's format (20 random bytes, Base32 + 3-char checksum). */
export async function newRecoveryKey() {
  const raw = crypto.getRandomValues(new Uint8Array(20));
  const check = b32encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...enc.encode("dpg-rk"), ...raw])))).slice(0, 3);
  const text = b32encode(raw) + check;
  return { raw, text: text.match(/.{5}/g).join("-") };
}

/** Same as the desktop app's `recovery.fingerprint` (not secret: recognises the same key). */
export async function fingerprint(raw) {
  const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode("dpg-fingerprint")));
  return [...mac.slice(0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function wrappingKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export function checkNewPassword(password, again) {
  if ((password || "").length < 8) return "개인 비밀번호는 8자 이상으로 정해 주세요";
  if (password !== again) return "비밀번호 확인이 다릅니다";
  return null;
}

export async function isSetUp() {
  return !!(await local().get("vaultWrap")).vaultWrap;
}

export async function storedFingerprint() {
  return (await local().get("vaultWrap")).vaultWrap?.fp || null;
}

/** Keep the key on this computer, encrypted with the personal password; also unlocks it. */
export async function setPassword(raw, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await wrappingKey(password, salt, ITERATIONS);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw));
  const vaultWrap = { v: 1, iter: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct), fp: await fingerprint(raw) };
  await local().set({ vaultWrap });
  await keep(raw);
}

/** Personal password → the key (unlocked for this browser session). */
export async function unlock(password) {
  const w = (await local().get("vaultWrap")).vaultWrap;
  if (!w) throw new BadPassword("아직 설정하지 않았습니다");
  let raw;
  try {
    const key = await wrappingKey(password, unb64(w.salt), w.iter);
    raw = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(w.iv) }, key, unb64(w.ct)));
  } catch {
    throw new BadPassword("개인 비밀번호가 맞지 않습니다");
  }
  await keep(raw);
  return raw;
}

/** "Forgot the password": the recovery key itself (must be the same key as before, if any). */
export async function checkRecoveryKey(raw) {
  const fp = await storedFingerprint();
  if (fp && fp !== (await fingerprint(raw))) {
    throw new WrongRecoveryKey("이 컴퓨터에 설정된 복구 키와 다른 복구 키입니다 (오타 또는 다른 키)");
  }
}

async function keep(raw) {
  await session().set({ vaultKey: { k: b64(raw), at: Date.now() } });
}

export async function lockMinutes() {
  const m = Number((await local().get("lockMinutes")).lockMinutes);
  return LOCK_CHOICES.includes(m) ? m : DEFAULT_LOCK_MINUTES;
}

export async function setLockMinutes(value) {
  if (!LOCK_CHOICES.includes(value)) throw new Error("잠금 시간 선택지가 아닙니다");
  await local().set({ lockMinutes: value });
}

export async function lock() {
  await session().remove("vaultKey");
}

/** The unlocked key, or null (locked, or idle longer than the lock time → locked now). */
export async function currentKey({ touch = true } = {}) {
  const v = (await session().get("vaultKey")).vaultKey;
  if (!v) return null;
  if (Date.now() - v.at > (await lockMinutes()) * 60000) { await lock(); return null; }
  if (touch && Date.now() - v.at > 20000) await session().set({ vaultKey: { k: v.k, at: Date.now() } });
  return unb64(v.k);
}

/** Remove the encrypted copy from this computer (the recovery key on paper still opens everything). */
export async function forget() {
  await lock();
  await local().remove("vaultWrap");
}
