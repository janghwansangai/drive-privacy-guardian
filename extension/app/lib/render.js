// View model → DOM. Only textContent is used (never innerHTML): document text cannot inject markup.

const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

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

export function renderModel(model, onNotice) {
  const box = el("div", "doc");
  if (model.kind === "doc") {
    for (const b of model.blocks) box.append(b.type === "p" ? el("p", "", b.text) : renderTable(b));
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
  } else if (model.kind === "text") {
    box.append(el("pre", "text", model.text));
  } else {
    box.append(el("p", "unsupported", model.reason));
  }
  if (model.truncated) onNotice?.("파일이 커서 앞부분만 보여 줍니다.");
  return box;
}
