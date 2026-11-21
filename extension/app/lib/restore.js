// Decrypt back into Drive (like the desktop app's "드라이브의 같은 폴더에 풀기"): each file is
// uploaded under its original name to the archive's folder — folders inside the archive are
// created again — downloaded again and compared (SHA-256); only if every file checks out (and
// the user asked) the archive goes to the trash.
// D-112 (all-or-nothing): if any file cannot be uploaded or does not check out, every copy made
// so far (and any folder made for them) goes back to the trash and the archive stays as it was —
// so trying again never leaves half a folder or duplicates behind.

import { sha256hex } from "./vault.js";

export class RestoreFailed extends Error {} // message is Korean and safe to show

const MIME = {
  ".hwp": "application/x-hwp", ".hwpx": "application/hwp+zip", ".pdf": "application/pdf",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".csv": "text/csv", ".txt": "text/plain", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
};
export const mimeOf = (name) => MIME[(name.match(/\.[^.]+$/) || [""])[0].toLowerCase()] || "application/octet-stream";

/** Archive member paths → { dir: "폴더/하위", name } with duplicate names numbered per folder. */
export function restorePlan(paths) {
  const taken = new Map(); // dir → names used
  return paths.map((p) => {
    const parts = p.split("/").filter(Boolean);
    const base = parts.pop() || "파일";
    const dir = parts.join("/");
    const used = taken.get(dir) || new Set();
    let name = base;
    for (let i = 2; used.has(name); i++) name = base.replace(/(\.[^.]*)?$/, ` (${i})$1`);
    used.add(name);
    taken.set(dir, used);
    return { dir, name };
  });
}

/** drive: { upload(name, parent, bytes, mime), download({ id, size }), trash(id), createFolder(name, parent) } */
export async function restoreToDrive({ members, parent, archiveId, trashArchive, drive, onStep = () => {} }) {
  if (!members.size) throw new RestoreFailed("풀 파일이 없습니다");
  const paths = [...members.keys()];
  const plan = restorePlan(paths);
  const folders = new Map([["", parent || null]]); // "폴더/하위" → Drive folder id
  const folderOf = async (dir) => {
    if (folders.has(dir)) return folders.get(dir);
    const parts = dir.split("/");
    const up = await folderOf(parts.slice(0, -1).join("/"));
    onStep(`폴더 만드는 중… ${parts.at(-1)}`);
    const folder = await drive.createFolder(parts.at(-1), up);
    folders.set(dir, folder.id);
    made.push(folder.id);
    return folder.id;
  };
  const done = [];
  const made = []; // folders created here, in order
  const rollback = async () => {
    let ok = true;
    for (const d of done) { try { await drive.trash(d.id); } catch { ok = false; } }
    for (const id of made.reverse()) { try { await drive.trash(id); } catch { ok = false; } }
    return ok;
  };
  for (const [i, path] of paths.entries()) {
    const data = members.get(path);
    const { dir, name } = plan[i];
    const shown = dir ? `${dir}/${name}` : name;
    onStep(`드라이브에 올리는 중… ${i + 1}/${paths.length}`);
    let meta;
    try {
      meta = await drive.upload(name, await folderOf(dir), data, mimeOf(name));
    } catch (e) {
      const clean = await rollback();
      throw new RestoreFailed(`「${shown}」을(를) 올리지 못했습니다 (${e.message}). 암호화 파일은 그대로입니다.${done.length ? (clean ? ` 먼저 올린 ${done.length}개는 휴지통으로 되돌렸습니다.` : ` 먼저 올린 ${done.length}개 중 일부를 되돌리지 못했습니다 — 드라이브에서 확인해 주세요.`) : ""}`);
    }
    let ok = false;
    try { ok = (await sha256hex(await drive.download({ id: meta.id, size: data.length }))) === (await sha256hex(data)); } catch { ok = false; }
    done.push({ name: shown, id: meta.id, ok });
  }
  const allVerified = done.every((d) => d.ok);
  let rolledBack = false;
  if (!allVerified) {
    onStep("확인이 맞지 않아 올린 사본을 되돌리는 중…");
    rolledBack = await rollback();
  }
  let trashedArchive = false;
  if (trashArchive && archiveId && allVerified) {
    onStep("암호화 파일을 휴지통으로…");
    try { await drive.trash(archiveId); trashedArchive = true; } catch { trashedArchive = false; }
  }
  return { files: done, allVerified, trashedArchive, rolledBack };
}
