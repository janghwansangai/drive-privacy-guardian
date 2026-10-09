// Resumable sharing audit (D-101). The scan advances one page per step() and its whole state
// (a checkpoint: where it is, what it found) is plain JSON the panel keeps in session memory
// (chrome.storage.session — gone when the browser closes). Closing the panel, switching tabs or
// losing the connection therefore costs at most one page: 「이어서 점검」 goes on from there.
//
// Scopes: the whole My Drive ('me' in owners; once it is big, in createdTime windows like the
// desktop app, D-097, so an expired page token re-reads one window) or one folder tree, folder
// by folder (the folder being read is what the panel shows as "지금 보는 곳").

export const SPLIT_SEEN = 10000;
const WINDOWS_FROM = 2012;
const FOLDER_MIME = "application/vnd.google-apps.folder";
const ID = /^[\w-]{10,}$/;

export function newRun(scope, now = new Date()) {
  const run = { v: 1, scope, status: "running", seen: 0, files: [], token: "", windows: null, window: 0, queue: null, startedAt: now.toISOString(), updatedAt: now.toISOString() };
  if (scope.kind === "folder") run.queue = [{ id: scope.id, path: `${scope.name || "폴더"}/` }];
  return run;
}

export function windowsUntil(now) {
  const edges = [];
  for (let y = WINDOWS_FROM; y <= now.getUTCFullYear(); y++) {
    for (const m of [1, 7]) if (y < now.getUTCFullYear() || m <= now.getUTCMonth() + 1) edges.push(`${y}-${String(m).padStart(2, "0")}-01T00:00:00`);
  }
  const out = [[null, edges[0]]];
  for (let i = 0; i + 1 < edges.length; i++) out.push([edges[i], edges[i + 1]]);
  out.push([edges[edges.length - 1], null]);
  return out;
}

function windowQuery([lo, hi]) {
  return [lo && `createdTime >= '${lo}'`, hi && `createdTime < '${hi}'`].filter(Boolean).join(" and ");
}

function windowLabel([lo, hi]) {
  if (!lo) return `${WINDOWS_FROM}년 이전에 만든 파일`;
  return `${lo.slice(0, 4)}년 ${lo.slice(5, 7) === "01" ? "상반기" : "하반기"}${hi ? "" : " 이후"}에 만든 파일`;
}

/** Where the scan is (or stopped), for people: "내 드라이브 전체 · 2019년 하반기에 만든 파일 (16/31)". */
export function where(run) {
  if (run.scope.kind === "folder") {
    if (run.status === "done") return `폴더 「${run.scope.name || ""}」 전체`;
    const at = run.queue?.[0];
    return at ? `폴더 ${at.path}` : `폴더 「${run.scope.name || ""}」`;
  }
  if (run.windows && run.window < run.windows.length && run.status !== "done") {
    return `내 드라이브 전체 · ${windowLabel(run.windows[run.window])} (${run.window + 1}/${run.windows.length})`;
  }
  return "내 드라이브 전체";
}

function keep(run, items) {
  const at = new Map(run.files.map((f, i) => [f.id, i]));
  for (const f of items) {
    if (!f.shared) continue; // not shared → nothing to check
    if (at.has(f.id)) run.files[at.get(f.id)] = f;
    else { at.set(f.id, run.files.length); run.files.push(f); }
  }
}

/**
 * One page. listPage({ q, pageToken, drive }) → { files, nextPageToken } (Drive files.list).
 * Mutates and returns the run; status becomes "done" after the last page.
 */
export async function step(run, listPage, now = new Date()) {
  if (run.status === "done") return run;
  run.status = "running";
  let q;
  if (run.scope.kind === "folder") {
    while (run.queue.length && !ID.test(run.queue[0].id)) run.queue.shift();
    if (!run.queue.length) { run.status = "done"; return run; }
    q = `'${run.queue[0].id}' in parents and trashed = false`;
  } else {
    if (run.windows && run.window >= run.windows.length) { run.status = "done"; return run; }
    q = "'me' in owners and trashed = false" + (run.windows ? ` and ${windowQuery(run.windows[run.window])}` : "");
  }
  let body;
  try {
    body = await listPage({ q, pageToken: run.token, drive: run.scope.kind === "folder" });
  } catch (e) {
    if (run.token && e.status === 400) { // page tokens last some hours: read this part again
      run.token = "";
      if (run.scope.kind !== "folder" && !run.windows && run.seen >= SPLIT_SEEN) startWindows(run, now);
      return run;
    }
    throw e;
  }
  const files = body.files || [];
  run.seen += files.length;
  keep(run, files);
  run.token = body.nextPageToken || "";
  if (run.scope.kind === "folder") {
    const here = run.queue[0];
    for (const f of files) {
      if (f.mimeType === FOLDER_MIME && ID.test(f.id)) run.queue.push({ id: f.id, path: `${here.path}${String(f.name).replace(/\//g, "_")}/` });
    }
    if (!run.token) run.queue.shift();
    if (!run.queue.length) run.status = "done";
  } else if (!run.windows) {
    if (run.token && run.seen >= SPLIT_SEEN) startWindows(run, now); // big drive: go on in windows
    else if (!run.token) run.status = "done";
  } else if (!run.token) {
    run.window += 1;
    if (run.window >= run.windows.length) run.status = "done";
  }
  run.updatedAt = now.toISOString();
  return run;
}

function startWindows(run, now) {
  run.windows = windowsUntil(now);
  run.window = 0;
  run.token = "";
}
