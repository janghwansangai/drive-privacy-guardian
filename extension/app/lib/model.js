// Neutral view model shared by all parsers and the renderer (no HTML here).
//   { kind: "doc", blocks: [{ type: "p", text, runs?, align? } | Table], truncated }
//     runs = [{ text, b?, i?, u?, s?, size? (pt), color? ("#rrggbb") }], align = left|right|center|justify
//   { kind: "sheets", sheets: [{ name, table: Table }], truncated }
//   { kind: "text", text, truncated }
//   { kind: "image", mime, bytes } · { kind: "pdf", bytes }   (drawn by render.js / pdf.js)
//   { kind: "unsupported", reason }
// Table = { type: "table", rows, cols, cells: [{ row, col, rowSpan, colSpan, text }] }

export const MAX_BLOCKS = 20000;
export const MAX_ROWS = 5000;
export const MAX_COLS = 200;

export class Unviewable extends Error {} // message is Korean and safe to show

export function gridOf(table) {
  const grid = Array.from({ length: table.rows }, () => Array(table.cols).fill(""));
  for (const c of table.cells) {
    if (c.row < table.rows && c.col < table.cols) grid[c.row][c.col] = c.text;
  }
  return grid;
}

/** Styled runs (may contain "\n") → paragraph blocks, one per line, trimmed at the line ends. */
export function pushRunLines(blocks, runs, align) {
  let line = [];
  const emit = () => {
    if (line.length) { line[0].text = line[0].text.trimStart(); line.at(-1).text = line.at(-1).text.trimEnd(); }
    const kept = line.filter((r) => r.text);
    const text = kept.map((r) => r.text).join("").trim();
    if (text) blocks.push({ type: "p", text, runs: kept, ...(align ? { align } : {}) });
    line = [];
  };
  for (const r of runs) {
    const parts = r.text.split("\n");
    parts.forEach((t, i) => {
      if (i > 0) emit();
      if (t) line.push({ ...r, text: t });
    });
  }
  emit();
}
