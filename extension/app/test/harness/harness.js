// Dev-only harness: runs viewer.js in a normal page with stubbed chrome.* APIs and a fake Drive
// that serves the synthetic fixture archives. No network, no Google account. Not shipped.
const FIX = "../fixtures/";
const FILES = [
  { id: "f7z", name: "보관_2026-09-27_0a1b2c3d.7z", size: "50000", createdTime: "2026-09-27T00:00:00Z" },
  { id: "fzip", name: "보관_2026-09-27_4e5f6a7b.zip", size: "50000", createdTime: "2026-09-26T00:00:00Z" },
];
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
window.fetch = async (input, init) => {
  const url = new URL(String(input), location.href);
  if (url.hostname === "www.googleapis.com") {
    window.harnessCalls.push(url.pathname + url.search);
    const m = /\/files\/([^/?]+)$/.exec(url.pathname);
    if (m && url.searchParams.get("alt") === "media") {
      const f = FILES.find((x) => x.id === decodeURIComponent(m[1]));
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
