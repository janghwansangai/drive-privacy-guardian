// PDF pages drawn to <canvas> with the bundled pdf.js (offline: fonts, CMaps and decoders are
// loaded from the extension itself). No scripting, no eval, no text layer, no annotations links.

const BASE = new URL("../vendor/pdfjs/", import.meta.url).href;
const MAX_PAGES = 200;
let lib = null;

async function pdfjs() {
  if (!lib) {
    lib = await import("../vendor/pdfjs/pdf.min.mjs");
    lib.GlobalWorkerOptions.workerSrc = BASE + "pdf.worker.min.mjs";
  }
  return lib;
}

/** Render into `box`; returns { destroy } so the caller can drop the document on close. */
export async function renderPdf(bytes, box, onNotice) {
  const { getDocument } = await pdfjs();
  const task = getDocument({
    data: bytes.slice(), // pdf.js transfers the buffer to its worker
    cMapUrl: BASE + "cmaps/",
    cMapPacked: true,
    standardFontDataUrl: BASE + "standard_fonts/",
    wasmUrl: BASE + "wasm/",
    isEvalSupported: false,
    enableXfa: false,
    useSystemFonts: true,
  });
  let cancelled = false;
  const handle = { destroy: () => { cancelled = true; task.destroy(); } };
  try {
    const doc = await task.promise;
    const count = Math.min(doc.numPages, MAX_PAGES);
    if (doc.numPages > MAX_PAGES) onNotice?.(`쪽이 많아 앞 ${MAX_PAGES}쪽만 보여 줍니다.`);
    const width = Math.max(Math.min(box.clientWidth || 900, 1000), 600); // CSS shrinks it on narrow windows
    for (let n = 1; n <= count && !cancelled; n++) {
      const page = await doc.getPage(n);
      const base = page.getViewport({ scale: 1 });
      const scale = width / base.width;
      const vp = page.getViewport({ scale: scale * (window.devicePixelRatio || 1) });
      const canvas = document.createElement("canvas");
      canvas.className = "pdfPage";
      canvas.width = Math.floor(vp.width);
      canvas.height = Math.floor(vp.height);
      canvas.style.width = `${Math.floor(base.width * scale)}px`;
      box.append(canvas);
      await page.render({ canvas, viewport: vp }).promise;
      page.cleanup();
    }
  } catch (e) {
    if (!cancelled) {
      const p = document.createElement("p");
      p.className = "unsupported";
      p.textContent = e?.name === "PasswordException"
        ? "암호가 걸린 PDF입니다 — 저장해서 PDF 프로그램으로 여세요"
        : "PDF를 읽지 못했습니다 (손상되었거나 지원하지 않는 구조)";
      box.append(p);
    }
  }
  return handle;
}
