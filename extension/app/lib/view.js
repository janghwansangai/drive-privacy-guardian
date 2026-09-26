// Choose a parser by file name; returns a view model or { kind: "unsupported" }.

import { parseHwp } from "./hwp.js";
import { parseHwpx } from "./hwpx.js";
import { parseXlsx } from "./xlsx.js";
import { parseCsv, parseTxt } from "./text.js";
import { Unviewable } from "./model.js";

export const VIEWABLE = [".hwp", ".hwpx", ".xlsx", ".csv", ".tsv", ".txt"];

export async function viewModel(name, bytes, parseXml) {
  const ext = (name.match(/\.[^.]+$/) || [""])[0].toLowerCase();
  try {
    if (ext === ".hwp") return await parseHwp(bytes);
    if (ext === ".hwpx") return await parseHwpx(bytes, parseXml);
    if (ext === ".xlsx") return await parseXlsx(bytes, parseXml);
    if (ext === ".csv") return parseCsv(bytes, ",");
    if (ext === ".tsv") return parseCsv(bytes, "\t");
    if (ext === ".txt") return parseTxt(bytes);
    return { kind: "unsupported", reason: "이 형식은 아직 바로 볼 수 없습니다 (다음 단계에서 PDF·사진·워드 추가 예정)" };
  } catch (e) {
    if (e instanceof Unviewable) return { kind: "unsupported", reason: e.message };
    return { kind: "unsupported", reason: "파일을 읽지 못했습니다 (손상되었거나 지원하지 않는 구조)" };
  }
}
