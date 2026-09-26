// Raw/zlib inflate with a hard output limit, using the platform DecompressionStream
// (Chrome 103+, Node 18+). No third-party code.

export class TooLarge extends Error {}

export async function inflate(bytes, { format = "deflate-raw", limit = 200 * 1024 * 1024 } = {}) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      throw new TooLarge("압축을 푼 크기가 너무 큽니다");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

/** HWP streams are raw deflate; some writers use a zlib header. Try both. */
export async function inflateAny(bytes, limit) {
  try {
    return await inflate(bytes, { format: "deflate-raw", limit });
  } catch (e) {
    if (e instanceof TooLarge) throw e;
    return inflate(bytes, { format: "deflate", limit });
  }
}
