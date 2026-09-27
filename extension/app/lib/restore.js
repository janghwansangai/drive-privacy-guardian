// Decrypt back into Drive (like the desktop app's "드라이브의 같은 폴더에 풀기"): each file is
// uploaded under its original name to the archive's folder, downloaded again and compared
// (SHA-256); only if every file checks out (and the user asked) the archive goes to the trash.

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

/** Archive member paths → Drive file names (folders flattened, duplicates numbered). */
export function restoreNames(paths) {
  const taken = new Set();
  return paths.map((p) => {
    const base = p.split("/").pop() || "파일";
    let name = base;
    for (let i = 2; taken.has(name); i++) name = base.replace(/(\.[^.]*)?$/, ` (${i})$1`);
    taken.add(name);
    return name;
  });
}

/** drive: { upload(name, parent, bytes, mime), download({ id, size }), trash(id) } */
export async function restoreToDrive({ members, parent, archiveId, trashArchive, drive, onStep = () => {} }) {
  if (!members.size) throw new RestoreFailed("풀 파일이 없습니다");
  const paths = [...members.keys()];
  const names = restoreNames(paths);
  const done = [];
  for (const [i, path] of paths.entries()) {
    const data = members.get(path);
    onStep(`드라이브에 올리는 중… ${i + 1}/${paths.length}`);
    let meta;
    try {
      meta = await drive.upload(names[i], parent || null, data, mimeOf(names[i]));
    } catch (e) {
      throw new RestoreFailed(`「${names[i]}」을(를) 올리지 못했습니다 (${e.message}). 암호화 파일은 그대로입니다.${done.length ? ` 먼저 올린 ${done.length}개는 드라이브에 있습니다.` : ""}`);
    }
    let ok = false;
    try { ok = (await sha256hex(await drive.download({ id: meta.id, size: data.length }))) === (await sha256hex(data)); } catch { ok = false; }
    done.push({ name: names[i], id: meta.id, ok });
  }
  const allVerified = done.every((d) => d.ok);
  let trashedArchive = false;
  if (trashArchive && archiveId && allVerified) {
    onStep("암호화 파일을 휴지통으로…");
    try { await drive.trash(archiveId); trashedArchive = true; } catch { trashedArchive = false; }
  }
  return { files: done, allVerified, trashedArchive };
}
