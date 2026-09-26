// Neutral view model shared by all parsers and the renderer (no HTML here).
//   { kind: "doc", blocks: [{ type: "p", text } | Table], truncated }
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
