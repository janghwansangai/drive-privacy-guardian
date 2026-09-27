// E3: build a new encrypted archive from the opened one (+ edited files picked from this
// computer), then the desktop app's safety sequence:
//   encrypt → decrypt again and compare every file → upload → download again and compare
//   → only then (if asked) move the old archive to the Drive trash. Never a permanent delete.

import { create7z, verifyArchive, sha256hex, newArchiveName, derivePassword, tagFromName } from "./vault.js";

export class ReencryptFailed extends Error {} // message is Korean and safe to show

const MAX_PICKED = 500 * 1024 * 1024;

/**
 * Plan the new archive: existing members stay unless removed; a picked file with the same
 * base name replaces that member (keeping its folder), other picked files are added at the top.
 * Returns { files: Map(name → bytes), rows: [{ name, state: "그대로"|"바꿈"|"추가"|"뺌" }] }.
 */
export function planMembers(existing, picked, removed = new Set()) {
  const files = new Map();
  const rows = [];
  const byBase = new Map();
  for (const name of existing.keys()) {
    const base = name.split("/").pop();
    if (!byBase.has(base)) byBase.set(base, name); // first one wins if two folders share a name
  }
  const replaced = new Map();
  const added = [];
  let total = 0;
  for (const p of picked) {
    total += p.bytes.length;
    const target = byBase.get(p.name);
    if (target) replaced.set(target, p.bytes);
    else added.push(p);
  }
  if (total > MAX_PICKED) throw new ReencryptFailed("고른 파일이 너무 큽니다 (500MB 초과)");
  for (const [name, data] of existing) {
    if (replaced.has(name)) { files.set(name, replaced.get(name)); rows.push({ name, state: "바꿈" }); }
    else if (removed.has(name)) rows.push({ name, state: "뺌" });
    else { files.set(name, data); rows.push({ name, state: "그대로" }); }
  }
  for (const p of added) {
    let name = p.name;
    for (let i = 2; files.has(name); i++) name = p.name.replace(/(\.[^.]*)?$/, ` (${i})$1`);
    files.set(name, p.bytes);
    rows.push({ name, state: "추가" });
  }
  return { files, rows };
}

/** secret = { raw } (recovery key → a fresh password per archive) or { password } (reused as is). */
export async function passwordForNew(secret, name) {
  if (secret.raw) return derivePassword(secret.raw, tagFromName(name));
  if (secret.password) return secret.password;
  throw new ReencryptFailed("비밀번호가 없습니다");
}

/**
 * drive: { upload(name, parent, bytes), download({ id, size }), trash(id) }
 * trashIds: the replaced archive, or the Drive originals that were just encrypted.
 * Returns { name, id, verified, uploadVerified, trashedOld, trashFailed, parentFallback }.
 */
export async function reencrypt({ files, secret, parent, trashIds = [], trashOld, drive, names, onStep = () => {} }) {
  if (!files.size) throw new ReencryptFailed("보관할 파일이 없습니다");
  const name = newArchiveName(names?.length ? names : [...files.keys()]); // e.g. a folder's name
  const password = await passwordForNew(secret, name);
  if (trashIds.some((id) => typeof id !== "string" || !/^[\w-]+$/.test(id))) throw new ReencryptFailed("파일 ID 형식이 아닙니다");
  onStep("암호화하는 중…");
  const blob = await create7z(files, password);
  onStep("검증하는 중 (다시 풀어서 비교)…");
  if (!(await verifyArchive(blob, password, files))) {
    throw new ReencryptFailed("만든 보관 파일을 풀어 비교했더니 달라서 중단했습니다. 드라이브는 그대로입니다.");
  }
  const digest = await sha256hex(blob);
  onStep("올리는 중…");
  let meta;
  let parentFallback = false;
  try {
    meta = await drive.upload(name, parent || null, blob);
  } catch (e) {
    if (parent && (e.status === 403 || e.status === 404)) {
      // drive.file may not allow writing into a folder this app has never seen → top of My Drive
      meta = await drive.upload(name, null, blob);
      parentFallback = true;
    } else {
      throw new ReencryptFailed(`올리지 못했습니다 (${e.message}). 예전 보관 파일은 그대로입니다.`);
    }
  }
  onStep("올린 파일 확인 중…");
  let uploadVerified = false;
  try {
    uploadVerified = (await sha256hex(await drive.download({ id: meta.id, size: blob.length }))) === digest;
  } catch { uploadVerified = false; }
  let trashed = 0;
  if (trashOld && trashIds.length && uploadVerified) {
    onStep("원래 파일을 휴지통으로…");
    for (const id of trashIds) {
      try { await drive.trash(id); trashed += 1; } catch { /* reported below */ }
    }
  }
  return {
    name, id: meta.id, verified: true, uploadVerified,
    trashedOld: trashIds.length > 0 && trashed === trashIds.length, trashFailed: trashIds.length - trashed,
    parentFallback,
  };
}
