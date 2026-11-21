// D-112: 드라이브 잠금 — 잠금 없음 by default, whole Drive or locked folders, 전체 비활성화.
import test from "node:test";
import assert from "node:assert/strict";

function area() {
  const data = {};
  return {
    data,
    get: async (k) => ({ [k]: data[k] }),
    set: async (o) => { Object.assign(data, JSON.parse(JSON.stringify(o))); },
    remove: async (k) => { delete data[k]; },
  };
}
globalThis.chrome = { storage: { local: area(), session: area() } };
const lock = await import("../lib/drivelock.js");
const keyring = await import("../lib/keyring.js");
const reset = () => { for (const a of ["local", "session"]) for (const k of Object.keys(chrome.storage[a].data)) delete chrome.storage[a].data[k]; };

const F1 = "folderLocked0000000001";
const F2 = "folderOther00000000002";
const SUB = "folderSub000000000003";
const FILE = "fileInside00000000004";
const tree = { [SUB]: [F1], [FILE]: [SUB], [F1]: ["root0000000000"], [F2]: ["root0000000000"] };
const ancestorsOf = async (id) => { const out = []; for (let x = tree[id]; x?.length; x = tree[x[0]]) out.push(x[0]); return out; };
const at = (url) => lock.getLock().then(async (l) => lock.decide(url, { lock: l, open: await lock.isOpen(), ancestorsOf }));

test("default: 잠금 없음 — nothing is covered, and the auto-lock is off", async () => {
  reset();
  assert.deepEqual(await lock.getLock(), { mode: "none", folders: [], hasPassword: false });
  assert.equal((await at("https://drive.google.com/drive/my-drive")).block, false);
  assert.equal((await at(`https://drive.google.com/drive/folders/${F1}`)).block, false);
  assert.equal(await keyring.lockMinutes(), 0);
  assert.equal(await keyring.expired(Date.now() - 24 * 3600000), false); // never with 0
});

test("addresses: folders, files, open?id, Docs editors; lists have no item", () => {
  assert.deepEqual(lock.targetOf(`https://drive.google.com/drive/u/1/folders/${F1}?usp=x`), { site: "drive", id: F1 });
  assert.deepEqual(lock.targetOf(`https://drive.google.com/file/d/${FILE}/view`), { site: "drive", id: FILE });
  assert.deepEqual(lock.targetOf(`https://drive.google.com/open?id=${FILE}`), { site: "drive", id: FILE });
  assert.deepEqual(lock.targetOf(`https://docs.google.com/spreadsheets/u/0/d/${FILE}/edit`), { site: "docs", id: FILE });
  assert.deepEqual(lock.targetOf("https://drive.google.com/drive/recent"), { site: "drive", id: null });
  assert.equal(lock.targetOf("https://example.com/drive/folders/x"), null);
  assert.equal(lock.targetOf("http://drive.google.com/"), null);
});

test("locked folders: the folder, its sub-folders and files inside are covered; others are not", async () => {
  reset();
  await assert.rejects(lock.addFolders([F1], "abc", "abc"), /4자 이상/);
  await assert.rejects(lock.addFolders([F1], "pin-1234", "pin-9999"), /확인이 다릅니다/);
  await lock.addFolders([F1, "bad id!"], "pin-1234", "pin-1234");
  assert.deepEqual(await lock.getLock(), { mode: "folders", folders: [F1], hasPassword: true });
  assert.ok(!JSON.stringify(chrome.storage.local.data).includes("pin-1234"), "only a PBKDF2 value is stored");
  await lock.relock();
  assert.deepEqual(await at(`https://drive.google.com/drive/folders/${F1}`), { block: true, why: "folder", active: true });
  assert.equal((await at(`https://drive.google.com/drive/folders/${SUB}`)).block, true);
  assert.equal((await at(`https://docs.google.com/document/d/${FILE}/edit`)).block, true);
  assert.equal((await at(`https://drive.google.com/drive/folders/${F2}`)).block, false);
  assert.equal((await at("https://drive.google.com/drive/my-drive")).block, false);
  // not signed in → cannot tell → asked (fail closed)
  const l = await lock.getLock();
  assert.deepEqual(await lock.decide(`https://drive.google.com/drive/folders/${F2}`, { lock: l, open: false, ancestorsOf: async () => { throw new Error("no sign-in"); } }), { block: true, why: "unknown", active: true });
  await assert.rejects(lock.unlock("wrong"), lock.LockPasswordError);
  await lock.unlock("pin-1234");
  assert.equal((await at(`https://drive.google.com/drive/folders/${F1}`)).block, false);
});

test("whole Drive: every Drive / Docs page; auto-lock time applies to the opening", async () => {
  reset();
  await lock.setLock({ mode: "all", password: "pin-1234", again: "pin-1234" });
  await lock.relock();
  assert.deepEqual(await at("https://drive.google.com/drive/recent"), { block: true, why: "all", active: true });
  assert.equal((await at(`https://docs.google.com/presentation/d/${FILE}/edit`)).block, true);
  await lock.unlock("pin-1234");
  assert.equal((await at("https://drive.google.com/drive/recent")).block, false);
  await keyring.setLockMinutes(5);
  chrome.storage.session.data.driveLockOpen.at = Date.now() - 6 * 60000;
  assert.equal((await at("https://drive.google.com/drive/recent")).block, true);
  await keyring.setLockMinutes(0);
  // changing the lock needs the password when not opened in this session
  await assert.rejects(lock.setLock({ mode: "none", password: "wrong" }), lock.LockPasswordError);
});

test("전체 비활성화: needs the lock password, then every lock and the password are gone", async () => {
  reset();
  await lock.addFolders([F1, F2], "pin-1234", "pin-1234");
  await lock.relock();
  await assert.rejects(lock.disableAll("wrong"), lock.LockPasswordError);
  assert.equal((await lock.getLock()).folders.length, 2);
  await lock.disableAll("pin-1234");
  assert.deepEqual(await lock.getLock(), { mode: "none", folders: [], hasPassword: false });
  assert.equal(chrome.storage.local.data.driveLock, undefined);
  assert.equal((await at(`https://drive.google.com/drive/folders/${F1}`)).block, false);
  // removing the last locked folder → back to 잠금 없음
  await lock.addFolders([F1], "pin-5678", "pin-5678");
  await lock.removeFolder(F1);
  assert.equal((await lock.getLock()).mode, "none");
});
