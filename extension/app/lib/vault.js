// Archive decryption in memory with 7-Zip WASM (same formats as the desktop app) and the
// recovery-key password derivation (identical to dpg/core/vault/recovery.py).

export class WrongPassword extends Error {}
export class ArchiveError extends Error {}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MAX_MEMBERS_BYTES = 1024 * 1024 * 1024;
const TOO_BIG = "파일이 너무 커서 브라우저 메모리로 열 수 없습니다 — 데스크톱 앱에서 푸세요";

let loader = null;
export function setLoader(fn) { loader = fn; } // tests inject a Node loader

async function newSevenZip() {
  const load = loader || (async () => (await import("../vendor/7z-wasm/7zz.es6.js")).default);
  const SevenZip = await load();
  const lines = [];
  // A fresh instance per operation: 7-Zip throws on a wrong password and may leave state behind.
  return SevenZip({ print: (s) => lines.push(s), printErr: (s) => lines.push(s) });
}

function b32decode(s) {
  let bits = "";
  for (const ch of s) bits += B32.indexOf(ch).toString(2).padStart(5, "0");
  const out = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}
function b32encode(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

/** Returns the 20 raw key bytes, or null if `text` is not a (valid) recovery key. */
export async function parseRecoveryKey(text) {
  const clean = text.replace(/[\s-]/g, "").toUpperCase().replace(/0/g, "O").replace(/1/g, "I").replace(/8/g, "B");
  if (clean.length !== 35 || !/^[A-Z2-7]+$/.test(clean)) return null;
  const raw = b32decode(clean.slice(0, 32));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...new TextEncoder().encode("dpg-rk"), ...raw])));
  return b32encode(digest).slice(0, 3) === clean.slice(32) ? raw : null;
}

export function tagFromName(name) {
  const m = /_([0-9a-f]{8})\.(?:7z|zip)$/.exec(name);
  return m ? m[1] : null;
}

export async function derivePassword(raw, tag) {
  const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  for (let counter = 0; ; counter++) {
    const stream = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`dpg-vault-v1|${tag}|${counter}`)));
    const chars = [...stream].filter((b) => b < 248).map((b) => ALPHABET[b % 62]).slice(0, 24);
    const s = chars.join("");
    if (chars.length === 24 && /[a-z]/.test(s) && /[A-Z]/.test(s) && /[0-9]/.test(s)) {
      return [0, 4, 8, 12, 16, 20].map((i) => s.slice(i, i + 4)).join("-");
    }
  }
}

/** A typed recovery key becomes that archive's password; anything else is used as typed. */
export async function passwordFor(archiveName, typed) {
  const tag = tagFromName(archiveName);
  const raw = tag ? await parseRecoveryKey(typed) : null;
  return raw ? derivePassword(raw, tag) : typed;
}

function safeName(name) {
  const n = name.replace(/\\/g, "/");
  if (!n || n.startsWith("/") || n.split("/").includes("..") || n.includes("\0")) {
    throw new ArchiveError("안전하지 않은 파일 이름이 들어 있습니다");
  }
  return n;
}

/** Decrypt an archive (Uint8Array) entirely in memory → Map(name → Uint8Array). */
export async function openArchive(bytes, password) {
  if (!password) throw new WrongPassword();
  const sz = await newSevenZip();
  const put = (path, data) => { const s = sz.FS.open(path, "w+"); sz.FS.write(s, data, 0, data.length); sz.FS.close(s); };
  put("/a", bytes);
  sz.FS.mkdir("/o");
  let code;
  try {
    // -p is an argument to an in-memory function call, not a process command line.
    code = sz.callMain(["x", "/a", `-p${password}`, "-o/o", "-y", "-bso0", "-bsp0"]);
  } catch (e) {
    if (e instanceof RangeError || /memory/i.test(String(e?.message))) throw new ArchiveError(TOO_BIG);
    throw new WrongPassword();
  }
  if (code !== 0) throw new WrongPassword();
  const out = new Map();
  let total = 0;
  const walk = (dir, prefix) => {
    for (const n of sz.FS.readdir(dir)) {
      if (n === "." || n === "..") continue;
      const p = `${dir}/${n}`;
      const st = sz.FS.stat(p);
      if (sz.FS.isDir(st.mode)) walk(p, `${prefix}${n}/`);
      else {
        total += st.size;
        if (total > MAX_MEMBERS_BYTES) throw new ArchiveError("보관 파일이 너무 큽니다");
        out.set(safeName(prefix + n), sz.FS.readFile(p));
      }
    }
  };
  walk("/o", "");
  return out;
}

/** 7z AES-256 with header encryption (same format as the desktop app). Folder names are kept. */
export async function create7z(files, password) {
  if (!password) throw new ArchiveError("비밀번호가 없습니다");
  const sz = await newSevenZip();
  sz.FS.mkdir("/in");
  const names = [];
  for (const [name, data] of files) {
    const n = safeName(name);
    const parts = n.split("/");
    let dir = "/in";
    for (const part of parts.slice(0, -1)) {
      dir += `/${part}`;
      if (!sz.FS.analyzePath(dir).exists) sz.FS.mkdir(dir);
    }
    const s = sz.FS.open(`/in/${n}`, "w+"); sz.FS.write(s, data, 0, data.length); sz.FS.close(s);
    if (!names.includes(parts[0])) names.push(parts[0]);
  }
  sz.FS.chdir("/in"); // relative names → the archive keeps "folder/file" paths
  const code = sz.callMain(["a", "/out.7z", ...names, `-p${password}`, "-mhe=on", "-mx=7", "-bso0", "-bsp0"]);
  if (code !== 0) throw new ArchiveError("암호화에 실패했습니다");
  return sz.FS.readFile("/out.7z");
}

export async function sha256hex(bytes) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Decrypt `blob` again and compare every file (SHA-256) with the originals, like the desktop app. */
export async function verifyArchive(blob, password, originals) {
  let back;
  try { back = await openArchive(blob, password); } catch { return false; }
  if (back.size !== originals.size) return false;
  for (const [name, data] of originals) {
    if (!back.has(name) || (await sha256hex(back.get(name))) !== (await sha256hex(data))) return false;
  }
  return true;
}

/** A neutral name like the desktop app's: 보관_YYYY-MM-DD_xxxxxxxx.7z (local date, random tag). */
export function newArchiveName(now = new Date()) {
  const tag = [...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const d = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  return `보관_${d}_${tag}.7z`;
}
