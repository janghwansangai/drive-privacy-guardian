// Dev-only harness: runs viewer.js in a normal page with stubbed chrome.* APIs and a fake Drive
// that serves the synthetic fixture archives. No network, no Google account. Not shipped.
const FIX = "../fixtures/";
const FILES = [
  { id: "f7z", parents: ["folderA"], name: "보관_2026-09-27_0a1b2c3d.7z", size: "50000", createdTime: "2026-09-27T00:00:00Z" },
  { id: "fzip", name: "보관_2026-09-27_4e5f6a7b.zip", size: "50000", createdTime: "2026-09-26T00:00:00Z" },
  // E2 formats: built in the page with the extension's own 7z writer (recovery-key password)
  { id: "fe2", name: "보관_2026-09-27_9c8d7e6f.7z", size: "90000", createdTime: "2026-09-25T00:00:00Z" },
];
const built = {};
async function e2Archive() {
  if (built.fe2) return built.fe2;
  const { create7z, parseRecoveryKey, derivePassword } = await import("../../lib/vault.js");
  const get = async (p) => new Uint8Array(await (await realFetch(p)).arrayBuffer());
  const SYN = "/tests/fixtures/synthetic/"; // the harness server serves the repository root
  const c = Object.assign(document.createElement("canvas"), { width: 320, height: 200 });
  const g = c.getContext("2d");
  g.fillStyle = "#2a6"; g.fillRect(0, 0, 320, 200); g.fillStyle = "#fff"; g.font = "28px sans-serif";
  g.fillText("합성 사진", 90, 110);
  const png = new Uint8Array(await (await new Promise((r) => c.toBlob(r, "image/png"))).arrayBuffer());
  const members = {
    "보호자_안내문.pdf": await get(SYN + encodeURIComponent("보호자_안내문.pdf")),
    "가정통신문_체험학습.docx": await get(SYN + encodeURIComponent("가정통신문_체험학습.docx")),
    "표병합_가상.docx": await get(FIX + encodeURIComponent("표병합_가상.docx")),
    "사진.png": png,
  };
  const raw = await parseRecoveryKey(window.harnessKey);
  built.fe2 = await create7z(Object.entries(members), await derivePassword(raw, "9c8d7e6f"));
  return built.fe2;
}
const store = { clientId: "123-harness.apps.googleusercontent.com" };
globalThis.chrome = {
  storage: { local: { get: async (k) => ({ [k]: store[k] }), set: async (o) => Object.assign(store, o) } },
  identity: {
    getRedirectURL: () => "https://gjlomabldjleleakkeffjojhjdgeekgj.chromiumapp.org/",
    launchWebAuthFlow: async ({ url }) => {
      const u = new URL(url);
      const p = new URLSearchParams({ access_token: "fake-token", expires_in: "3600", state: u.searchParams.get("state"), scope: u.searchParams.get("scope") });
      return `${u.searchParams.get("redirect_uri")}#${p}`;
    },
  },
};
const realFetch = window.fetch.bind(window);
window.harnessCalls = [];
window.harnessUploads = 0;
window.fetch = async (input, init) => {
  const url = new URL(String(input), location.href);
  if (url.hostname === "www.googleapis.com") {
    window.harnessCalls.push(`${init?.method || "GET"} ${url.pathname}`);
    if (url.pathname.startsWith("/upload/") && init?.method === "POST") {
      const meta = JSON.parse(init.body);
      const id = `up${++window.harnessUploads}`;
      FILES.unshift({ id, name: meta.name, parents: meta.parents, size: "0", createdTime: new Date().toISOString() });
      return new Response("{}", { headers: { Location: `https://www.googleapis.com/upload/drive/v3/files?upload_id=${id}` } });
    }
    if (url.pathname.startsWith("/upload/") && init?.method === "PUT") {
      const id = url.searchParams.get("upload_id");
      built[id] = new Uint8Array(init.body);
      FILES.find((f) => f.id === id).size = String(built[id].length);
      return new Response(JSON.stringify({ id }), { headers: { "content-type": "application/json" } });
    }
    if (init?.method === "PATCH") {
      const id = decodeURIComponent(/\/files\/([^/?]+)/.exec(url.pathname)[1]);
      FILES.splice(FILES.findIndex((f) => f.id === id), 1);
      return new Response(JSON.stringify({ id, trashed: true }), { headers: { "content-type": "application/json" } });
    }
    const m = /\/files\/([^/?]+)$/.exec(url.pathname);
    if (m && url.searchParams.get("alt") === "media") {
      const f = FILES.find((x) => x.id === decodeURIComponent(m[1]));
      if (f.id === "fe2") return new Response(await e2Archive());
      if (built[f.id]) return new Response(built[f.id]);
      return realFetch(FIX + encodeURIComponent(f.name));
    }
    return new Response(JSON.stringify({ files: FILES }), { headers: { "content-type": "application/json" } });
  }
  return realFetch(input, init);
};
const html = await (await realFetch("../../viewer.html")).text();
document.body.innerHTML = new DOMParser().parseFromString(html, "text/html").body.innerHTML; // own trusted file
document.querySelectorAll("script").forEach((s) => s.remove());
window.harnessKey = (await (await realFetch(FIX + "recovery.txt")).text()).split("\n")[0].trim();
await import("../../viewer.js");
