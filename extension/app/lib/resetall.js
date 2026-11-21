// 「모두 풀기 (초기화)」 (D-112): before removing the extension, every encrypted file this program
// made goes back to normal files in the same Drive folder, one archive at a time, each with the
// all-or-nothing decrypt of lib/restore.js (upload → download again → compare SHA-256 → only then
// the archive goes to the trash). An archive that cannot be opened or checked stays untouched.

import { openArchive, derivePassword, passwordFor, tagFromName, WrongPassword } from "./vault.js";
import { restoreToDrive } from "./restore.js";

/** Passwords to try for one archive: the typed ones (a typed recovery key becomes this archive's
 *  password) and, for archives tagged with the recovery key, the unlocked key. */
export async function candidates(name, typed, raw) {
  const out = [];
  for (const t of typed) if (t) out.push(await passwordFor(name, t));
  const tag = tagFromName(name);
  if (raw && tag) out.push(await derivePassword(raw, tag));
  return [...new Set(out)];
}

/**
 * archives: Drive files [{ id, name, size, parents }] (lib/drive.listVaultFiles)
 * typed: passwords the user typed (common password, older ones, a recovery key)
 * raw: the unlocked recovery key or null
 * Returns [{ name, ok, reason, files }] — ok = restored, checked and the archive trashed.
 */
export async function resetAll({ archives, typed = [], raw = null, drive, onStep = () => {}, stopped = () => false }) {
  const results = [];
  for (const [i, f] of archives.entries()) {
    if (stopped()) { results.push({ name: f.name, ok: false, reason: "중지함 (그대로 둠)" }); continue; }
    const at = `${i + 1}/${archives.length}`;
    let members = null;
    try {
      onStep(`${at} 「${f.name}」 받는 중…`);
      const bytes = await drive.download(f);
      for (const pw of await candidates(f.name, typed, raw)) {
        try { members = await openArchive(bytes, pw); break; } catch (e) { if (!(e instanceof WrongPassword)) throw e; }
      }
      if (!members) { results.push({ name: f.name, ok: false, reason: "비밀번호가 맞지 않음 (그대로 둠)" }); continue; }
      const r = await restoreToDrive({
        members, parent: f.parents?.[0] || null, archiveId: f.id, trashArchive: true, drive,
        onStep: (t) => onStep(`${at} 「${f.name}」 ${t}`),
      });
      if (!r.allVerified) results.push({ name: f.name, ok: false, reason: "올린 파일 확인이 맞지 않아 되돌림 (그대로 둠)" });
      else if (!r.trashedArchive) results.push({ name: f.name, ok: false, reason: "풀었지만 암호화 파일을 휴지통으로 옮기지 못함", files: r.files.length });
      else results.push({ name: f.name, ok: true, files: r.files.length });
    } catch (e) {
      results.push({ name: f.name, ok: false, reason: `${e.message || "오류"} (그대로 둠)` });
    } finally {
      if (members) { for (const d of members.values()) d.fill(0); members.clear(); }
    }
  }
  return results;
}
