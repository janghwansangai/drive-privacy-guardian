// Decrypt back into Drive (like the desktop app's "드라이브의 같은 폴더에 풀기"): each file is
// uploaded under its original name to the archive's folder — folders inside the archive are
// created again — downloaded again and compared (SHA-256); only if every file checks out (and
// the user asked) the archive goes to the trash.

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
    const made = await drive.createFolder(parts.at(-1), up);
    folders.set(dir, made.id);
    return made.id;
  };
  const done = [];
  for (const [i, path] of paths.entries()) {
    const data = members.get(path);
    const { dir, name } = plan[i];
    const shown = dir ? `${dir}/${name}` : name;
    onStep(`드라이브에 올리는 중… ${i + 1}/${paths.length}`);
    let meta;
    try {
      meta = await drive.upload(name, await folderOf(dir), data, mimeOf(name));
    } catch (e) {
      throw new RestoreFailed(`「${shown}」을(를) 올리지 못했습니다 (${e.message}). 암호화 파일은 그대로입니다.${done.length ? ` 먼저 올린 ${done.length}개는 드라이브에 있습니다.` : ""}`);
    }
    let ok = false;
    try { ok = (await sha256hex(await drive.download({ id: meta.id, size: data.length }))) === (await sha256hex(data)); } catch { ok = false; }
    done.push({ name: shown, id: meta.id, ok });
  }
  const allVerified = done.every((d) => d.ok);
  let trashedArchive = false;
  if (trashArchive && archiveId && allVerified) {
    onStep("암호화 파일을 휴지통으로…");
    try { await drive.trash(archiveId); trashedArchive = true; } catch { trashedArchive = false; }
  }
  return { files: done, allVerified, trashedArchive };
}
