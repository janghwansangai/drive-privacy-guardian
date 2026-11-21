// 드라이브 잠금 (D-112): a password asked before Google Drive opens in this Chrome — the whole
// Drive, or only the folders the user locked (and everything inside them). It is an access gate
// of this extension, not encryption: the files stay as they are, and without the extension (or in
// another browser / the phone app) Drive opens normally. ZIP encryption protects the files
// themselves (lib/reencrypt.js).
//
//   chrome.storage.local   "driveLock"     = { v, mode: "none"|"all"|"folders", folders: [Drive IDs],
//                                              check: PBKDF2-SHA256(password) } — IDs only, no names
//   chrome.storage.session "driveLockOpen" = { at } — unlocked for this browser session, until the
//                                              auto-lock time (0 = until the browser closes)
// Default: no driveLock record = 잠금 없음. 「전체 비활성화」 removes the record (every lock gone).

import { expired } from "./keyring.js";

export const MODES = ["none", "all", "folders"];
const ITERATIONS = 600000;
const ID = /^[\w-]{10,}$/;
const MAX_FOLDERS = 500;
export class LockPasswordError extends Error {} // message is Korean and safe to show

const enc = new TextEncoder();
const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
const unb64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const local = () => chrome.storage.local;
const session = () => chrome.storage.session;

async function hash(password, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return b64(new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, 256)));
}

export function lockPasswordProblem(password, again = password) {
  if ((password || "").length < 4) return "잠금 비밀번호는 4자 이상으로 정해 주세요";
  if (password !== again) return "비밀번호 확인이 다릅니다";
  return null;
}

/** { mode, folders: [ids], hasPassword } — a missing or damaged record reads as 잠금 없음. */
export async function getLock() {
  const r = (await local().get("driveLock")).driveLock;
  const mode = MODES.includes(r?.mode) ? r.mode : "none";
  const folders = Array.isArray(r?.folders) ? r.folders.filter((x) => typeof x === "string" && ID.test(x)) : [];
  return { mode, folders, hasPassword: !!r?.check?.hash };
}

async function save(next) { await local().set({ driveLock: next }); }
async function record() { return (await local().get("driveLock")).driveLock || null; }

/** Is the typed password the lock password? (Constant work either way.) */
export async function checkPassword(password) {
  const r = await record();
  if (!r?.check?.hash) return false;
  return (await hash(password || "", unb64(r.check.salt), r.check.iter)) === r.check.hash;
}

/** Unlocked in this browser session (and not idle past the auto-lock time)? */
export async function isOpen() {
  const v = (await session().get("driveLockOpen")).driveLockOpen;
  if (!v) return false;
  if (await expired(v.at)) { await session().remove("driveLockOpen"); return false; }
  return true;
}
export async function touchOpen() {
  const v = (await session().get("driveLockOpen")).driveLockOpen;
  if (v && Date.now() - v.at > 20000 && !(await expired(v.at))) await session().set({ driveLockOpen: { at: Date.now() } });
}
export async function relock() { await session().remove("driveLockOpen"); }

/** The lock password typed at the gate (or in the panel) → open for this session. */
export async function unlock(password) {
  if (!(await checkPassword(password))) throw new LockPasswordError("잠금 비밀번호가 맞지 않습니다");
  await session().set({ driveLockOpen: { at: Date.now() } });
}

/** Turn a lock on or change it. The first time a password is chosen (password + again); after
 *  that the lock password is needed unless it was already typed in this session. */
export async function setLock({ mode, folders, password, again }) {
  if (!MODES.includes(mode)) throw new LockPasswordError("알 수 없는 잠금 방식입니다");
  const r = await record();
  let check = r?.check;
  if (!check?.hash) {
    if (mode === "none") { await local().remove("driveLock"); return; }
    const bad = lockPasswordProblem(password, again);
    if (bad) throw new LockPasswordError(bad);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    check = { iter: ITERATIONS, salt: b64(salt), hash: await hash(password, salt, ITERATIONS) };
    await save({ v: 1, mode: "none", folders: [], check });
    await session().set({ driveLockOpen: { at: Date.now() } });
  } else if (!(await isOpen())) {
    await unlock(password); // throws on a wrong password
  }
  const list = [...new Set((folders ?? r?.folders ?? []).filter((x) => typeof x === "string" && ID.test(x)))].slice(0, MAX_FOLDERS);
  await save({ v: 1, mode, folders: list, check });
}

/** Lock more folders (keeps the mode, except 잠금 없음 → 잠근 폴더만). */
export async function addFolders(ids, password, again) {
  const now = await getLock();
  await setLock({ mode: now.mode === "all" ? "all" : "folders", folders: [...now.folders, ...ids], password, again });
}

export async function removeFolder(id, password) {
  const now = await getLock();
  const folders = now.folders.filter((x) => x !== id);
  await setLock({ mode: now.mode === "folders" && !folders.length ? "none" : now.mode, folders, password });
}

/** 「전체 비활성화」: every lock (whole Drive and every folder) and the lock password go away. */
export async function disableAll(password) {
  const r = await record();
  if (r?.check?.hash && !(await isOpen()) && !(await checkPassword(password))) {
    throw new LockPasswordError("잠금 비밀번호가 맞지 않습니다");
  }
  await local().remove("driveLock");
  await relock();
}

/** What a Drive / Docs address shows: { site: "drive"|"docs", id } (id null = a list, home, search). */
export function targetOf(text) {
  let u;
  try { u = new URL(text); } catch { return null; }
  if (u.protocol !== "https:") return null;
  if (u.hostname === "drive.google.com") {
    const path = u.pathname.replace(/^\/drive\/u\/\d+\//, "/drive/").replace(/^\/u\/\d+\//, "/");
    let m = /^\/(?:drive\/)?file\/d\/([\w-]+)/.exec(path) || /^\/drive\/folders\/([\w-]+)/.exec(path);
    if (m && ID.test(m[1])) return { site: "drive", id: m[1] };
    m = u.searchParams.get("id");
    if (/^\/(open|uc)$/.test(u.pathname) && m && ID.test(m)) return { site: "drive", id: m };
    return { site: "drive", id: null };
  }
  if (u.hostname === "docs.google.com") {
    const m = /^\/(?:document|spreadsheets|presentation|forms|drawings)\/(?:u\/\d+\/)?d\/(?:e\/)?([\w-]+)/.exec(u.pathname);
    return { site: "docs", id: m && ID.test(m[1]) ? m[1] : null };
  }
  return null;
}

/**
 * Should this address be covered by the password screen?
 * ancestorsOf(id) → [parent ids up to the top] (may throw: not signed in → asked, fail closed).
 * Returns { block, why: "all"|"folder"|"unknown"|null, active }.
 */
export async function decide(url, { lock, open, ancestorsOf }) {
  const active = lock.mode !== "none";
  const t = targetOf(url);
  if (!active || !t) return { block: false, why: null, active };
  if (open) return { block: false, why: null, active };
  if (lock.mode === "all") return { block: true, why: "all", active };
  if (!t.id || !lock.folders.length) return { block: false, why: null, active };
  const locked = new Set(lock.folders);
  if (locked.has(t.id)) return { block: true, why: "folder", active };
  let up;
  try { up = await ancestorsOf(t.id); } catch { return { block: true, why: "unknown", active }; }
  return up.some((id) => locked.has(id)) ? { block: true, why: "folder", active } : { block: false, why: null, active };
}
