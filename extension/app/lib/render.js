// View model → DOM. Only textContent is used (never innerHTML): document text cannot inject markup.

const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

const ALIGNS = new Set(["left", "right", "center", "justify"]);

function readable(color) {
  if (!/^#[0-9a-f]{6}$/.test(color || "")) return null;
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(color.slice(i, i + 2), 16));
  return 0.299 * r + 0.587 * g + 0.114 * b > 225 ? null : color; // skip white-ish text on white
}

/** A paragraph with styled runs; styles are set as properties (never markup). */
export function renderParagraph(b) {
  const p = el("p");
  if (ALIGNS.has(b.align)) p.style.textAlign = b.align;
  if (!b.runs?.length) { p.textContent = b.text; return p; }
  for (const r of b.runs) {
    const span = el("span", "", r.text);
    if (r.b) span.style.fontWeight = "bold";
    if (r.i) span.style.fontStyle = "italic";
    const deco = [r.u && "underline", r.s && "line-through"].filter(Boolean).join(" ");
    if (deco) span.style.textDecoration = deco;
    if (r.size > 0) span.style.fontSize = `${Math.min(Math.max(r.size, 7), 40)}pt`;
    const c = readable(r.color);
    if (c && c !== "#000000") span.style.color = c;
    p.append(span);
  }
  return p;
}

export function renderTable(table) {
  const t = el("table", "grid");
  const covered = new Set();
  const at = new Map(table.cells.map((c) => [`${c.row},${c.col}`, c]));
  for (let r = 0; r < table.rows; r++) {
    const tr = el("tr");
    for (let c = 0; c < table.cols; c++) {
      if (covered.has(`${r},${c}`)) continue;
      const cell = at.get(`${r},${c}`);
      const td = el("td", "", cell ? cell.text : "");
      if (cell && (cell.rowSpan > 1 || cell.colSpan > 1)) {
        td.rowSpan = cell.rowSpan;
        td.colSpan = cell.colSpan;
        for (let dr = 0; dr < cell.rowSpan; dr++)
          for (let dc = 0; dc < cell.colSpan; dc++) if (dr || dc) covered.add(`${r + dr},${c + dc}`);
      }
      tr.append(td);
    }
    t.append(tr);
  }
  return t;
}

/** `track(handle)` receives { destroy } for anything that must be released on close. */
export function renderModel(model, onNotice, track) {
  const box = el("div", "doc");
  if (model.kind === "doc") {
    for (const b of model.blocks) box.append(b.type === "p" ? renderParagraph(b) : renderTable(b));
    if (!model.blocks.length) box.append(el("p", "muted", "(내용이 없습니다)"));
  } else if (model.kind === "sheets") {
    const tabs = el("div", "tabs");
    const body = el("div", "sheet");
    model.sheets.forEach((s, i) => {
      const btn = el("button", i === 0 ? "tab on" : "tab", s.name);
      btn.onclick = () => {
        tabs.querySelectorAll(".tab").forEach((x) => x.classList.remove("on"));
        btn.classList.add("on");
        body.replaceChildren(renderTable(s.table));
      };
      tabs.append(btn);
    });
    body.append(renderTable(model.sheets[0].table));
    if (model.sheets.length > 1) box.append(tabs);
    box.append(body);
  } else if (model.kind === "image") {
    const url = URL.createObjectURL(new Blob([model.bytes], { type: model.mime }));
    track?.({ destroy: () => URL.revokeObjectURL(url) });
    const img = el("img", "picture");
    img.alt = "";
    img.onerror = () => img.replaceWith(el("p", "unsupported", "사진을 읽지 못했습니다"));
    img.src = url;
    box.append(img);
  } else if (model.kind === "pdf") {
    box.classList.add("pdf");
    import("./pdf.js").then(async ({ renderPdf }) => track?.(await renderPdf(model.bytes, box, onNotice)));
  } else if (model.kind === "text") {
    box.append(el("pre", "text", model.text));
  } else {
    box.append(el("p", "unsupported", model.reason));
  }
  if (model.truncated) onNotice?.("파일이 커서 앞부분만 보여 줍니다.");
  return box;
}
