// Minimal ZIP reader for XLSX / HWPX (stored + deflate), in memory, with zip-bomb limits.
// Reads the central directory; never follows paths (entries are only looked up by name).

import { inflate } from "./inflate.js";

export class ZipError extends Error {}

const MAX_ENTRIES = 5000;
const MAX_TOTAL = 500 * 1024 * 1024;

function u16(b, o) { return b[o] | (b[o + 1] << 8); }
function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

export function openZip(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) {
    if (u32(b, i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new ZipError("ZIP 형식이 아닙니다");
  const count = u16(b, eocd + 10);
  const cdOffset = u32(b, eocd + 16);
  if (count > MAX_ENTRIES) throw new ZipError("항목이 너무 많습니다");
  const entries = new Map();
  let p = cdOffset;
  let declared = 0;
  const utf8 = new TextDecoder("utf-8");
  for (let n = 0; n < count; n++) {
    if (u32(b, p) !== 0x02014b50) throw new ZipError("ZIP 목록이 손상되었습니다");
    const flags = u16(b, p + 8);
    const method = u16(b, p + 10);
    const csize = u32(b, p + 20);
    const usize = u32(b, p + 24);
    const nlen = u16(b, p + 28), xlen = u16(b, p + 30), clen = u16(b, p + 32);
    const local = u32(b, p + 42);
    const name = utf8.decode(b.subarray(p + 46, p + 46 + nlen));
    declared += usize;
    if (declared > MAX_TOTAL) throw new ZipError("압축을 푼 크기가 너무 큽니다");
    entries.set(name, { flags, method, csize, usize, local });
    p += 46 + nlen + xlen + clen;
  }
  return {
    names: () => [...entries.keys()],
    has: (name) => entries.has(name),
    async read(name) {
      const e = entries.get(name);
      if (!e) throw new ZipError(`항목 없음: ${name}`);
      if (e.flags & 1) throw new ZipError("암호가 걸린 ZIP 항목입니다");
      if (u32(b, e.local) !== 0x04034b50) throw new ZipError("ZIP 항목이 손상되었습니다");
      const start = e.local + 30 + u16(b, e.local + 26) + u16(b, e.local + 28);
      const data = b.subarray(start, start + e.csize);
      if (e.method === 0) return data.slice();
      if (e.method === 8) return inflate(data, { limit: Math.min(MAX_TOTAL, e.usize + 1024) });
      throw new ZipError(`지원하지 않는 압축 방식(${e.method})`);
    },
    async text(name) {
      return utf8.decode(await this.read(name));
    },
  };
}
