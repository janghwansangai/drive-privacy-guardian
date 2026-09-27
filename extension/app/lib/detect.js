// Korean personal-data detection — a line-by-line port of the desktop app's rules
// (dpg/core/detect/rules.py + validators.py, SPEC 6.3), checked against it on the same content
// (test/detect.test.mjs). Output is { kind, confidence, location } only: matched values never
// leave this module and are never stored (D-093).

export const LOW = 1, MEDIUM = 2, HIGH = 3;
export const KIND_LABEL = {
  rrn: "주민·외국인등록번호", rrn_suspect: "주민등록번호 의심(검증식 불일치)", passport: "여권번호",
  driver_license: "운전면허번호", mobile: "휴대전화", landline: "일반전화", account: "계좌번호",
  card: "카드번호", email: "이메일", address: "주소", student_roster: "학생 명단·주소록",
  sensitive_suspect: "민감정보 의심", filename_hint: "파일명에 개인정보 암시",
};
export const CONFIDENCE_LABEL = { 1: "낮음(의심)", 2: "중간", 3: "높음" };
export const HIGH_SENSITIVITY = new Set(["rrn", "passport", "driver_license", "account", "card", "student_roster"]);

const CONTEXT = 30;
const BANKS = ["국민", "KB", "신한", "우리", "하나", "농협", "NH", "기업", "IBK", "SC제일", "제일", "씨티", "카카오뱅크", "케이뱅크", "토스뱅크", "새마을", "신협", "우체국", "수협", "대구은행", "부산은행", "경남은행", "광주은행", "전북은행", "제주은행", "산업은행", "은행"];
const ACCOUNT_WORDS = ["계좌", "예금주", "입금", "환불", "이체", "송금"];
const SENSITIVE_WORDS = ["상담", "진단", "병명", "복약", "투약", "장애", "학교폭력", "학폭", "정신과", "치료", "가정폭력", "자해", "자살", "우울", "ADHD", "심리검사"];
const FILENAME_WORDS = ["명단", "연락처", "주소록", "상담", "생활기록", "생기부", "성적", "건강", "신상", "개인정보", "보호자"];
const SIDO = "서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|충청북|충청남|전북|전남|전라북|전라남|경북|경남|경상북|경상남|제주";

const RRN = /(?<!\d)(\d{6})(\s?[-–]\s?|)(\d{7})(?!\d)/g;
const CARD = /(?<!\d)(?:\d{4}[-\s]?){3}\d{4}(?!\d)/g;
const MOBILE = /(?<!\d)01[016789][-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)/g;
const LANDLINE = /(?<!\d)\(?0(?:2|3[1-3]|4[1-4]|5[1-5]|6[1-4]|70)\)?[-.)\s]\s?\d{3,4}[-.\s]\d{4}(?!\d)/g;
const PASSPORT = /(?<![A-Za-z0-9])([A-Z])(\d{8}|\d{3}[A-Z]\d{4})(?![A-Za-z0-9])/g;
const LICENSE = /(?<!\d)(\d{2})-(\d{2})-(\d{6})-(\d{2})(?!\d)/g;
const ACCOUNT = /(?<!\d)\d{2,6}(?:-\d{2,7}){1,3}(?!\d)|(?<!\d)\d{10,14}(?!\d)/g;
const EMAIL = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
const ADDRESS = new RegExp(`(?:${SIDO})(?:특별자치시|특별자치도|특별시|광역시|도)?\\s*[가-힣]{1,10}(?:시|군|구)(?:\\s*[가-힣]{1,10}(?:시|군|구))?\\s*[가-힣0-9]{1,20}(?:로|길)\\s*\\d{1,5}(?:-\\d{1,5})?`, "g");
const KOREAN_NAME = /^[가-힣]{2,4}$/;
const NAME_NEAR = /[가-힣]{2,4}\s?(?:학생|님|군|양|어린이|아동)|(?:성명|이름)\s?[:：]?\s?[가-힣]{2,4}/;
const ROSTER_GROUPS = [["성명", "이름", "학생명"], ["학번", "번호", "출석번호"], ["반", "학년반", "학급"], ["생년월일", "생일"], ["보호자", "학부모", "부모"], ["연락처", "전화", "휴대폰", "핸드폰"], ["주소"]];
const ROSTER_MIN_ROWS = 5;
const CENTURY = { 9: 1800, 0: 1800, 1: 1900, 2: 1900, 5: 1900, 6: 1900, 3: 2000, 4: 2000, 7: 2000, 8: 2000 };
const W = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];

const digits = (s) => s.replace(/\D/g, "");
export function rrnBirthOk(v) {
  const d = digits(v);
  if (d.length !== 13 || CENTURY[d[6]] === undefined) return false;
  const y = CENTURY[d[6]] + Number(d.slice(0, 2)), m = Number(d.slice(2, 4)), day = Number(d.slice(4, 6));
  const dt = new Date(Date.UTC(y, m - 1, day));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === day;
}
const weighted = (d) => W.reduce((t, w, i) => t + Number(d[i]) * w, 0);
export const rrnChecksumOk = (v) => { const d = digits(v); return d.length === 13 && (11 - (weighted(d) % 11)) % 10 === Number(d[12]); };
const foreignerChecksumOk = (v) => { const d = digits(v); return (13 - (weighted(d) % 11)) % 10 === Number(d[12]); };
export function luhnOk(v) {
  const d = digits(v);
  if (d.length < 12 || d.length > 19) return false;
  let t = 0;
  [...d].reverse().forEach((ch, i) => { let n = Number(ch); if (i % 2) { n *= 2; if (n > 9) n -= 9; } t += n; });
  return t % 10 === 0;
}

const win = (text, s, e) => text.slice(Math.max(0, s - CONTEXT), e + CONTEXT);

export function detectText(text, location, header = "") {
  const found = [];
  const taken = [];
  const overlaps = (s, e) => taken.some(([ts, te]) => s < te && ts < e);
  const add = (kind, confidence, s, e) => { found.push({ kind, confidence, location }); taken.push([s, e]); };
  const all = (re) => text.matchAll(re);
  header = header || "";

  for (const m of all(RRN)) {
    const value = m[1] + m[3];
    if (!rrnBirthOk(value) || !"12345678".includes(value[6])) continue;
    const s = m.index, e = s + m[0].length;
    const keyword = ["주민", "등록번호", "외국인"].some((k) => (win(text, s, e) + header).includes(k));
    if (rrnChecksumOk(value) || ("5678".includes(value[6]) && foreignerChecksumOk(value))) add("rrn", HIGH, s, e);
    else if (m[2] || keyword) add("rrn_suspect", LOW, s, e);
  }
  for (const m of all(CARD)) { const s = m.index, e = s + m[0].length; if (!overlaps(s, e) && luhnOk(m[0])) add("card", HIGH, s, e); }
  for (const m of all(MOBILE)) { const s = m.index, e = s + m[0].length; if (!overlaps(s, e)) add("mobile", HIGH, s, e); }
  for (const m of all(LANDLINE)) { const s = m.index, e = s + m[0].length; if (!overlaps(s, e)) add("landline", MEDIUM, s, e); }
  for (const m of all(PASSPORT)) {
    const s = m.index, e = s + m[0].length;
    if (overlaps(s, e)) continue;
    const ctx = win(text, s, e) + header;
    if (ctx.includes("여권") || ctx.toLowerCase().includes("passport")) add("passport", HIGH, s, e);
    else if ("MSRGD".includes(m[1])) add("passport", LOW, s, e);
  }
  for (const m of all(LICENSE)) {
    const s = m.index, e = s + m[0].length;
    if (overlaps(s, e) || Number(m[1]) < 11 || Number(m[1]) > 28) continue;
    const ctx = win(text, s, e) + header;
    add("driver_license", ctx.includes("면허") || ctx.includes("운전") ? MEDIUM : LOW, s, e);
  }
  for (const m of all(ACCOUNT)) {
    const s = m.index, e = s + m[0].length, n = digits(m[0]).length;
    if (overlaps(s, e) || n < 10 || n > 14) continue;
    const ctx = win(text, s, e) + " " + header;
    const bank = BANKS.some((b) => ctx.includes(b)), word = ACCOUNT_WORDS.some((w) => ctx.includes(w));
    if (bank && word) add("account", HIGH, s, e);
    else if (bank || word) add("account", MEDIUM, s, e);
  }
  for (const m of all(ADDRESS)) { const s = m.index, e = s + m[0].length; if (!overlaps(s, e)) add("address", header.includes("주소") ? HIGH : MEDIUM, s, e); }
  for (const m of all(EMAIL)) { const s = m.index, e = s + m[0].length; if (!overlaps(s, e)) add("email", LOW, s, e); }
  if (SENSITIVE_WORDS.some((w) => text.includes(w)) && NAME_NEAR.test(text)) found.push({ kind: "sensitive_suspect", confidence: LOW, location });
  return found;
}

function headerRow(rows) {
  for (let i = 0; i < Math.min(5, rows.length); i++) {
    const row = rows[i];
    const groups = ROSTER_GROUPS.filter((g) => g.some((k) => row.some((c) => k === c.replaceAll(" ", "") || c.includes(k)))).length;
    if (groups >= 2) return { index: i, row };
  }
  return null;
}

/** rows: string[][] (a table / sheet) */
export function detectTable(rows, location) {
  const found = [];
  const h = headerRow(rows);
  const start = h ? h.index + 1 : 0;
  const headers = h ? h.row : [];
  rows.slice(start).forEach((row, r) => {
    row.forEach((cell, c) => { if (cell) found.push(...detectText(cell, `${location}, ${start + r + 1}행`, headers[c])); });
  });
  if (h) {
    const nameCols = headers.map((c, i) => (ROSTER_GROUPS[0].some((k) => c.includes(k)) ? i : -1)).filter((i) => i >= 0);
    const cand = nameCols.length ? nameCols : headers.map((_, i) => i);
    const nameRows = rows.slice(start).filter((row) => cand.some((i) => i < row.length && KOREAN_NAME.test(row[i]))).length;
    if (nameRows >= ROSTER_MIN_ROWS) found.push({ kind: "student_roster", confidence: HIGH, location });
  }
  return found;
}

/** { segments: [{ text, location }], tables: [{ rows, location }] } — the desktop's Extracted shape */
export function detectExtracted(doc) {
  const found = [];
  for (const s of doc.segments) found.push(...detectText(s.text, s.location));
  for (const t of doc.tables) found.push(...detectTable(t.rows, t.location));
  return found;
}

export function detectFilename(name) {
  const found = detectText(name, "파일명");
  if (FILENAME_WORDS.some((w) => name.includes(w))) found.push({ kind: "filename_hint", confidence: LOW, location: "파일명" });
  return found;
}

/** kind → { count, confidence, locations (up to 5) } */
export function summarize(findings, maxLocations = 5) {
  const out = {};
  for (const f of findings) {
    const s = (out[f.kind] ||= { count: 0, confidence: LOW, locations: [] });
    s.count += 1;
    s.confidence = Math.max(s.confidence, f.confidence);
    if (!s.locations.includes(f.location) && s.locations.length < maxLocations) s.locations.push(f.location);
  }
  return out;
}
