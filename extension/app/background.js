import { currentKey, currentCommon } from "./lib/keyring.js";
import * as drivelock from "./lib/drivelock.js";
import { parentsQuiet } from "./lib/drive.js";

// The toolbar icon opens the viewer as a side panel next to the current tab (Google Drive),
// so encrypted files open on the same screen. The viewer can also open as a full tab.
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

// Auto-lock (D-088, D-112: off by default): drop the unlocked key, the common password and the
// 드라이브 잠금 opening after the chosen idle time, even when no extension page is open.
chrome.alarms.create("autolock", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name !== "autolock") return;
  currentKey({ touch: false }).catch(() => {});
  currentCommon({ touch: false }).catch(() => {});
  drivelock.isOpen().catch(() => {});
});

const GATE_PAGE = chrome.runtime.getURL("gate.html");
const SITES = /^https:\/\/(drive|docs)\.google\.com\//;

// 드라이브 잠금 (D-112): is a Drive / Docs item inside a locked folder? Parent folders are read
// from the Drive API (no sign-in window is ever opened here) and kept in memory for 5 minutes.
const parentCache = new Map(); // id → { parents, at }
async function ancestorsOf(id) {
  const out = [];
  const seen = new Set([id]);
  let level = [id];
  for (let depth = 0; depth < 60 && level.length; depth++) {
    const next = [];
    for (const x of level) {
      let hit = parentCache.get(x);
      if (!hit || Date.now() - hit.at > 300000) {
        hit = { parents: await parentsQuiet(x), at: Date.now() };
        parentCache.set(x, hit);
      }
      for (const p of hit.parents) if (!seen.has(p)) { seen.add(p); out.push(p); next.push(p); }
    }
    level = next;
  }
  return out;
}

async function gateAnswer(url) {
  const lock = await drivelock.getLock();
  const open = lock.mode !== "none" && (await drivelock.isOpen());
  if (open) await drivelock.touchOpen();
  return drivelock.decide(url, { lock, open, ancestorsOf });
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return undefined;
  // the page watcher on Drive / Docs (drive_gate.js): "should this page be covered?"
  if (msg?.type === "gateCheck" && sender.tab && SITES.test(sender.url || "")) {
    const url = typeof msg.url === "string" && SITES.test(msg.url) ? msg.url : sender.url;
    gateAnswer(url).then(reply, () => reply({ block: true, why: "unknown", active: true }));
    return true;
  }
  // the password screen (gate.html, this extension's own page inside Drive's tab)
  if (msg?.type === "gateUnlock" && (sender.url || "").startsWith(GATE_PAGE)) {
    drivelock.unlock(String(msg.password || "")).then(() => reply({ ok: true }), (e) => reply({ ok: false, error: e.message }));
    return true;
  }
  if (sender.tab || msg?.type !== "openTab") return undefined;
  const url = chrome.runtime.getURL("viewer.html");
  chrome.tabs.query({ url }).then(([tab]) => (tab ? chrome.tabs.update(tab.id, { active: true }) : chrome.tabs.create({ url })));
  return undefined;
});
