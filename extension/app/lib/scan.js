// Personal-data check of files chosen in Drive (D-093): download into memory → the viewer's own
// parsers → lib/detect.js rules → keep only kind / count / confidence / position, drop the
// content. Nothing is stored; results live in the panel until it closes.

import { viewModel } from "./view.js";
import { gridOf } from "./model.js";
import { detectExtracted, detectFilename, summarize } from "./detect.js";

export const MAX_SCAN_BYTES = 50 * 1024 * 1024; // same limit as the desktop app (SPEC 5.2)

export class Unscannable extends Error {} // message: the reason, in Korean

/** File bytes → { segments, tables } like the desktop's Extracted. PDFs need `pdfText`. */
export async function extractForDetect(name, bytes, parseXml, pdfText) {
  const model = await viewModel(name, bytes, parseXml);
  const doc = { segments: [], tables: [] };
  if (model.kind === "doc") {
    let p = 0, t = 0;
    for (const b of model.blocks) {
      if (b.type === "p") doc.segments.push({ text: b.text, location: `문단 ${++p}` });
      else doc.tables.push({ rows: gridOf(b), location: `표 ${++t}` });
    }
  } else if (model.kind === "sheets") {
    for (const s of model.sheets) doc.tables.push({ rows: gridOf(s.table), location: `시트 ${s.name}` });
  } else if (model.kind === "text") {
    model.text.split("\n").forEach((line, i) => { if (line.trim()) doc.segments.push({ text: line, location: `${i + 1}줄` }); });
  } else if (model.kind === "pdf") {
    if (!pdfText) throw new Unscannable("PDF 글자를 읽을 수 없습니다");
    const pages = await pdfText(bytes);
    if (!pages.some((t) => t.trim())) throw new Unscannable("글자가 없는 PDF(스캔 이미지일 수 있음)");
    pages.forEach((text, i) => doc.segments.push({ text, location: `${i + 1}쪽` }));
  } else if (model.kind === "image") {
    throw new Unscannable("사진은 글자를 읽지 않습니다");
  } else {
    throw new Unscannable(model.reason || "지원하지 않는 형식");
  }
  return doc;
}

/**
 * One Drive file → { file, status: "found"|"none"|"unscannable", kinds, reason }
 * fetch(file) → { name, bytes } (drive.fetchContent)
 */
export async function scanFile(file, { fetch, parseXml, pdfText }) {
  const nameFindings = detectFilename(file.name);
  if (Number(file.size || 0) > MAX_SCAN_BYTES) {
    return { file, status: "unscannable", kinds: summarize(nameFindings), reason: "파일이 너무 큼(50MB 초과)" };
  }
  let got;
  try {
    got = await fetch(file);
    const doc = await extractForDetect(got.name, got.bytes, parseXml, pdfText);
    const kinds = summarize([...nameFindings, ...detectExtracted(doc)]);
    const real = Object.keys(kinds).some((k) => k !== "filename_hint");
    return { file, status: real ? "found" : "none", kinds };
  } catch (e) {
    return { file, status: "unscannable", kinds: summarize(nameFindings), reason: e instanceof Unscannable ? e.message : "읽지 못함(손상·권한 없음 등)" };
  } finally {
    got?.bytes?.fill?.(0); // best-effort wipe of the downloaded copy
  }
}
