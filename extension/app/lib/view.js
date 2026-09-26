// Choose a parser by file name; returns a view model or { kind: "unsupported" }.

import { parseHwp } from "./hwp.js";
import { parseHwpx } from "./hwpx.js";
import { parseXlsx } from "./xlsx.js";
import { parseCsv, parseTxt } from "./text.js";
import { parseDocx } from "./docx.js";
import { Unviewable } from "./model.js";

export const IMAGES = {
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
  ".webp": "image/webp", ".bmp": "image/bmp",
};
export const VIEWABLE = [".hwp", ".hwpx", ".xlsx", ".docx", ".pdf", ".csv", ".tsv", ".txt", ...Object.keys(IMAGES)];

export async function viewModel(name, bytes, parseXml) {
  const ext = (name.match(/\.[^.]+$/) || [""])[0].toLowerCase();
  try {
    if (ext === ".hwp") return await parseHwp(bytes);
    if (ext === ".hwpx") return await parseHwpx(bytes, parseXml);
    if (ext === ".xlsx") return await parseXlsx(bytes, parseXml);
    if (ext === ".docx") return await parseDocx(bytes, parseXml);
    if (ext === ".pdf") return { kind: "pdf", bytes };
    if (IMAGES[ext]) return { kind: "image", mime: IMAGES[ext], bytes };
    if (ext === ".csv") return parseCsv(bytes, ",");
    if (ext === ".tsv") return parseCsv(bytes, "\t");
    if (ext === ".txt") return parseTxt(bytes);
    return { kind: "unsupported", reason: "이 형식은 바로 볼 수 없습니다 — 「저장」해서 해당 프로그램으로 여세요" };
  } catch (e) {
    if (e instanceof Unviewable) return { kind: "unsupported", reason: e.message };
    return { kind: "unsupported", reason: "파일을 읽지 못했습니다 (손상되었거나 지원하지 않는 구조)" };
  }
}
