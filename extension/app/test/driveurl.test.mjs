import test from "node:test";
import assert from "node:assert/strict";
import { parseDriveUrl } from "../lib/driveurl.js";

test("Drive tab URL → folder / file / nothing", () => {
  const F = "1AbCdEfGhIjKlMnOpQ";
  assert.deepEqual(parseDriveUrl(`https://drive.google.com/drive/folders/${F}`), { folder: F });
  assert.deepEqual(parseDriveUrl(`https://drive.google.com/drive/u/1/folders/${F}?usp=sharing`), { folder: F });
  assert.deepEqual(parseDriveUrl("https://drive.google.com/drive/my-drive"), { folder: "root" });
  assert.deepEqual(parseDriveUrl("https://drive.google.com/drive/u/0/my-drive"), { folder: "root" });
  assert.deepEqual(parseDriveUrl(`https://drive.google.com/file/d/${F}/view?usp=drive_link`), { file: F });
  assert.deepEqual(parseDriveUrl(`https://drive.google.com/drive/u/2/file/d/${F}/view`), { file: F });
  assert.deepEqual(parseDriveUrl(`https://drive.google.com/open?id=${F}`), { file: F });
  for (const bad of ["https://drive.google.com/drive/recent", "https://drive.google.com/drive/search?q=x",
    `http://drive.google.com/drive/folders/${F}`, `https://evil.example/drive/folders/${F}`,
    "https://drive.google.com/drive/folders/'or'1'='1", "not a url"]) {
    assert.equal(parseDriveUrl(bad), null, bad);
  }
});
