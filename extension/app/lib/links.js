// Pages opened in a new browser tab when the user asks (D-109) — never fetched by the extension:
// connect-src allows only the Drive API (manifest CSP), and test/security.test.mjs checks that
// these are only handed to window.open.
//   「오류 신고」: the maker's report form (only the app name, version and view in the address)
//   「새 버전 확인」: the latest release page (the extension never checks by itself)
export const BUG_REPORT_URL = "https://script.google.com/macros/s/AKfycbxsRD7vRlEP9oKlvlDDPww8cYaDadTTIp1KrqYWSVU5qE5_gUh3bNUskBhHDlXH6FskvA/exec";
export const BUG_REPORT_APP = "google-scerct";
export const RELEASES_URL = "https://github.com/janghwansangai/drive-privacy-guardian/releases/latest";

export function bugReportUrl(version, where) {
  const q = new URLSearchParams({ app: BUG_REPORT_APP, v: version || "", where: where || "" });
  return `${BUG_REPORT_URL}?${q}`;
}
