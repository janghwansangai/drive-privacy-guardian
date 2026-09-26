// Minimal Compound File Binary (OLE) reader for HWP 5.0 — enough to list and read streams.
// [MS-CFB]: 512-byte header, FAT/DIFAT, directory entries (128 bytes), mini stream (<4096).

export class CfbError extends Error {}

const SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;

export function isCfb(b) {
  return b.length >= 512 && SIG.every((v, i) => b[i] === v);
}

export function openCfb(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (!isCfb(b)) throw new CfbError("OLE 파일이 아닙니다");
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u32 = (o) => dv.getUint32(o, true);
  const sectorShift = dv.getUint16(30, true);
  const miniShift = dv.getUint16(32, true);
  const size = 1 << sectorShift;
  const miniSize = 1 << miniShift;
  const nFat = u32(44), dirStart = u32(48), miniCutoff = u32(56);
  const miniFatStart = u32(60), nMiniFat = u32(64), difatStart = u32(68), nDifat = u32(72);
  const sectorOffset = (s) => (s + 1) * size;
  const maxSectors = Math.floor(b.length / size);

  const fatSectors = [];
  for (let i = 0; i < 109 && fatSectors.length < nFat; i++) fatSectors.push(u32(76 + i * 4));
  let d = difatStart;
  for (let k = 0; k < nDifat && d !== ENDOFCHAIN && d !== FREESECT; k++) {
    const o = sectorOffset(d);
    for (let i = 0; i < size / 4 - 1 && fatSectors.length < nFat; i++) fatSectors.push(u32(o + i * 4));
    d = u32(o + size - 4);
  }
  const fat = [];
  for (const s of fatSectors) {
    if (s >= maxSectors) throw new CfbError("OLE FAT 손상");
    const o = sectorOffset(s);
    for (let i = 0; i < size / 4; i++) fat.push(u32(o + i * 4));
  }
  const chain = (start, table, limit) => {
    const out = [];
    const seen = new Set();
    for (let s = start; s !== ENDOFCHAIN && s !== FREESECT; s = table[s]) {
      if (seen.has(s) || s >= limit || out.length > limit) throw new CfbError("OLE 체인 손상");
      seen.add(s);
      out.push(s);
    }
    return out;
  };
  const readChain = (start, len) => {
    const out = new Uint8Array(len);
    let pos = 0;
    for (const s of chain(start, fat, maxSectors)) {
      const o = sectorOffset(s);
      const n = Math.min(size, len - pos);
      if (n <= 0) break;
      out.set(b.subarray(o, o + n), pos);
      pos += n;
    }
    return out.subarray(0, pos);
  };

  // directory
  const dirSectors = chain(dirStart, fat, maxSectors);
  const entries = [];
  const utf16 = new TextDecoder("utf-16le");
  for (const s of dirSectors) {
    const o = sectorOffset(s);
    for (let i = 0; i < size / 128; i++) {
      const e = o + i * 128;
      const nameLen = dv.getUint16(e + 64, true);
      const type = b[e + 66];
      entries.push({
        name: nameLen >= 2 ? utf16.decode(b.subarray(e, e + nameLen - 2)) : "",
        type, // 1 storage, 2 stream, 5 root
        left: u32(e + 68), right: u32(e + 72), child: u32(e + 76),
        start: u32(e + 116), size: u32(e + 120),
      });
    }
  }
  const root = entries[0];
  if (!root || root.type !== 5) throw new CfbError("OLE 루트 없음");
  const miniStream = readChain(root.start, root.size);
  const miniFat = [];
  if (nMiniFat) {
    const raw = readChain(miniFatStart, nMiniFat * size);
    const mdv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    for (let i = 0; i < raw.length / 4; i++) miniFat.push(mdv.getUint32(i * 4, true));
  }
  const readMini = (start, len) => {
    const out = new Uint8Array(len);
    let pos = 0;
    for (const s of chain(start, miniFat, miniFat.length)) {
      const o = s * miniSize;
      const n = Math.min(miniSize, len - pos);
      if (n <= 0) break;
      out.set(miniStream.subarray(o, o + n), pos);
      pos += n;
    }
    return out.subarray(0, pos);
  };

  // paths: walk the red-black tree of each storage
  const paths = new Map();
  const walk = (idx, prefix, depth = 0) => {
    if (idx === FREESECT || idx >= entries.length || depth > 64) return;
    const e = entries[idx];
    walk(e.left, prefix, depth + 1);
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.type === 2) paths.set(path, e);
    if (e.type === 1) walk(e.child, path, depth + 1);
    walk(e.right, prefix, depth + 1);
  };
  walk(root.child, "");

  return {
    list: () => [...paths.keys()],
    has: (p) => paths.has(p),
    read(p) {
      const e = paths.get(p);
      if (!e) throw new CfbError(`스트림 없음: ${p}`);
      return e.size < miniCutoff ? readMini(e.start, e.size) : readChain(e.start, e.size);
    },
  };
}
