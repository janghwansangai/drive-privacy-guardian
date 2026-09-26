# DECISIONS

결정 기록. 새 의존성은 라이선스와 이유를 여기에 남긴다 (CLAUDE.md).
형식: `D-번호 (날짜) 제목` — 결정 / 이유 / 출처.

---

## A. 설계 결정 (SPEC 2·3장 요약, 2026-09-26)

**D-001 배포·인증: 사용자 자체 OAuth 클라이언트(BYO Client)**
앱에 OAuth 클라이언트를 내장하지 않는다. 사용자가 클라이언트 JSON을 불러오는 단일 경로만 구현.
C 방식(개인이 자기 Cloud 프로젝트에서 발급, 기본) / B 방식(학교 Workspace 관리자가 내부 클라이언트 발급).
이유: Drive 스코프는 모두 제한 스코프라 공용 클라이언트는 심사·100명 상한·7일 만료 문제가 있음. 배포물에 비밀 정보가 없어짐. (SPEC 3.1)

**D-002 앱 형태: 로컬 데스크톱 앱, PySide6, 서버 없음**
GUI와 분리된 core 엔진 + CLI(개발용) + GUI. Streamlit(포트 개방)·Tauri+사이드카(복잡도) 폐기. (SPEC 2.2, 3.2)

**D-003 기술 스택·라이선스**
Python 3.12, 앱 라이선스 MIT. AGPL/GPL 정적 포함 금지(PyMuPDF, pyhwp 등). HWP는 olefile+zlib 자체 파서. PDF는 pypdf. (SPEC 3.3)

**D-004 제안서 ②에서 폐기한 것**
서비스 계정·도메인 전체 위임, 위반 즉시 `permissions.delete`, 원본 자동 삭제, 단순 정규식, PyPDF2, 예측 가능한 비밀번호 규칙, Cloud DLP API. (SPEC 2.2)

**D-005 네트워크 정책**
허용 호스트: `accounts.google.com`, `oauth2.googleapis.com`, `www.googleapis.com`, `*.googleusercontent.com`, 루프백 `127.0.0.1`/`::1`. 자동 업데이트 없음(버튼 → 브라우저로 Releases 페이지). (SPEC 3.4) — V8로 최종 확정 예정.

**D-006 데이터 분류**
A 원문=메모리만 / B 비밀=OS 보안 저장소 / C 민감 메타데이터(파일명·이메일)=AES-GCM 암호화 열 / D 일반 메타데이터=평문. 보존 기본 30일. (SPEC 5.1)

**D-007 OAuth 스코프 단계적 요청**
감사 `drive.metadata.readonly` → 탐지 `drive.readonly` → 변경 `drive`. (SPEC 5.3)

---

## B. Phase 0 구현 결정 (2026-09-26)

**D-008 net_guard 이중 구조**
1) `HostPolicy.check_url()` — Phase 1에서 HTTP 전송 계층 래퍼가 모든 요청 전에 호출.
2) `NetGuard.install()` — `socket.getaddrinfo`/`gethostbyname(_ex)`와 `socket.connect`/`connect_ex`/`sendto`를 감싼다.
   허용되지 않은 호스트는 DNS 조회 전에 차단, 허용 호스트에서 해석되지 않은 IP로의 연결은 패킷 전송 전에 차단.
이유: SPEC은 httplib2/requests 래핑을 제시했지만, 소켓 계층에서 막으면 라이브러리 종류와 무관하게 강제된다. URL 검사는 스킴(https)까지 확인하는 보완 계층.
한계: Python `socket` 모듈을 거치지 않는 네이티브 코드(예: Qt `QtNetwork`, `QtWebEngine`)는 막지 못한다 → GUI에서 사용 금지, `tests/privacy/test_network_isolation.py`가 import를 검사. `localhost` 이름은 허용하지 않고 IP 리터럴만 허용(호스트 파일 조작 방지).

**D-009 로그 마스킹 방식**
- 필터는 로거가 아니라 **핸들러**에 붙인다(로거 필터는 자식 로거에서 전파된 레코드를 보지 못함). `dpg` 로거는 `propagate=False`.
- 로그에서는 부분 마스킹(`901012-1******`) 대신 유형 토큰(`<RRN>`, `<PHONE>` 등)으로 **전부** 치환. 화면 표시용 부분 마스킹은 Phase 4에서 별도 함수로.
- 패턴은 과탐 허용 방향(`dpg/core/detect/patterns.py`). 하이픈으로 이어진 10자리 이상 숫자열은 모두 `<NUM>`(계좌·면허·카드 대응). 공백은 구분자로 보지 않아 타임스탬프는 보존.
- 예외는 필터 안에서 문자열로 렌더링 후 마스킹, 지역 변수는 포함하지 않음.
- 알려진 부작용: 숫자가 10자리 이상 연속된 Drive 파일 ID 일부가 가려질 수 있음 — 유출보다 낫다고 판단.

**D-010 fake_drive 설계 가정 (실제 API와 다를 수 있어 해당 Phase에서 재확인)**
- `fields` 미지정 시 최소 필드만 반환(코드가 필요한 필드를 반드시 명시하도록 보수적으로).
- `permissions.list` 기본 필드를 `kind,id,type,role`로 가정.
- 내 드라이브 항목은 `permissionDetails` 없음, 공유 드라이브 항목만 상속 정보 제공 (V5).
- 권한 ID는 주체별로 고정(`anyoneWithLink` 등), 상속 권한은 하위 항목에서 변경 불가(403).
- `files.export` 한도 10MB 가정 (V7).
- `files.delete`, `files.emptyTrash`, `drives.delete`는 **모든 모드에서** `ForbiddenCallError` (원칙 4).

**D-011 의존성 추가 (Phase 0)**
| 패키지 | 구분 | 라이선스 | 이유 |
|---|---|---|---|
| google-api-python-client | 런타임 | Apache-2.0 | Drive API 클라이언트. fake_drive가 실제 `HttpError`를 던지기 위해 지금 추가 |
| hatchling | 빌드 | MIT | 패키지 빌드 백엔드 |
| pytest | 개발 | MIT | 테스트 |
| pytest-socket | 개발 | MIT | 테스트 전체 소켓 차단 (SPEC 3.4) |
| ruff | 개발 | MIT | lint/format |
| mypy | 개발 | MIT | 타입 검사 |
| pre-commit | 개발 | MIT | gitleaks·ruff 훅 |
| openpyxl | 개발(→Phase 4 런타임) | MIT | 합성 XLSX 생성, 이후 XLSX 추출 |
| python-docx | 개발(→Phase 4 런타임) | MIT | 합성 DOCX 생성, 이후 DOCX 추출 |
| pip-audit | CI 전용 (`uvx`) | Apache-2.0 | 취약점 감사. 잠금 파일을 무겁게 하지 않도록 dev 의존성에서 제외 |
| gitleaks | pre-commit/CI 도구 | MIT | 비밀 커밋 차단 |

**D-012 합성 데이터는 "구조적으로 가짜"**
실존 인물의 값과 우연히 일치할 가능성을 없애기 위해 생성 규칙 자체로 보장한다 (`tools/gen_synthetic.py`, 검사기 `find_non_synthetic`):
- 주민번호: 7번째 자리 3/4 + 출생연도 2050~2099 → 미래 날짜라 살아있는 사람의 번호일 수 없음. 검증식은 통과.
- 휴대전화 010-0xxx/1xxx, 일반전화 국번 0/1 시작 → 할당되지 않는 대역 (※ 대역 미할당 여부는 공식 번호 계획으로 재확인 권장).
- 이메일은 RFC 2606 예약 도메인(example.com/org/net)만. 카드 9999 접두 + Luhn. 계좌 999 접두.
- 주소는 실제 시·도 + 존재하지 않는 구·도로명(가상구, 샘플로 등).
**Phase 4에 주는 영향:** 탐지기가 "미래 생년월일"을 무효로 처리하면 합성 데이터 재현율 측정이 깨진다. 탐지기는 달력상 유효한 날짜만 검사하고 미래 여부는 보지 않는다 — 바꾸려면 생성기 규칙도 함께 바꿀 것.

**D-013 개발 환경**
Python 3.12는 uv가 관리(`.python-version`). 시스템 Python(3.14)은 사용하지 않음. uv는 Homebrew로 설치.

**D-014 저장소 위치**
`google_secret/drive-privacy-guardian/`을 저장소 루트로 사용(계획서 원본은 상위 폴더에 그대로 두고 `SPEC.md`로 복사).

**D-015 라이선스 검사 도구**
pip-licenses 대신 `tools/check_licenses.py`(표준 라이브러리 `importlib.metadata`)로 GPL/AGPL을 차단. 이유: pip-licenses의 `--fail-on`은 부분 일치 시 "LGPLv3"를 "GPLv3"로 오인할 수 있음. 이중 라이선스(예: "Apache-2.0 OR GPL-2.0")도 보수적으로 차단 후 수동 허용 목록에 사유와 함께 추가. `THIRD_PARTY_LICENSES.txt` 생성은 Phase 8에서 pip-licenses로.

---

## C. Phase 1 구현 결정 (2026-09-26)

**D-016 로그인 흐름 직접 구현 (google-auth-oauthlib 미사용)**
표준 라이브러리 `http.server`로 루프백 수신기를 직접 구현했다. 이유:
- 수신 주소를 `127.0.0.1`로 고정 (oauthlib 기본값 `localhost`는 net_guard가 허용하지 않음, 구글도 방화벽 문제로 IP 사용을 권장 — V2).
- 요청 로그 차단 (리디렉션 주소에 인증 코드가 들어 있음), `state` 불일치 요청은 400으로 무시하고 계속 대기, 제한 시간·취소 지원.
- 의존성(requests-oauthlib) 추가 없음. 토큰 교환·철회도 같은 `GuardedHttp`를 거친다.
PKCE S256, 검증 문자열 86자(`secrets.token_urlsafe(64)`), `state` 256비트, 로그인 직후 수신기 종료.

**D-017 인증 요청 매개변수**
`prompt=consent` + `include_granted_scopes=true`를 항상 보낸다: 단계별 권한 추가가 사용자에게 명확히 보이도록. `access_type`은 보내지 않음 — 데스크톱 앱은 갱신 토큰이 항상 발급됨(V2). `client_secret`은 공식 문서상 "선택"이지만 데스크톱 클라이언트에 존재하므로 함께 보낸다.

**D-018 키체인 저장 구조**
- 항목 2개: `oauth-client`(client_id·secret·project_id만), `oauth-token`(갱신 토큰·허용 범위·계정 이메일·발급 client_id). 액세스 토큰은 **메모리에만**.
- 토큰의 client_id가 현재 클라이언트와 다르면 무효 처리. 클라이언트 교체·삭제 시 기존 토큰 철회 후 삭제.
- OS 보안 저장소 백엔드만 허용(macOS Keychain, Windows 자격 증명 관리자, Secret Service/KWallet). keyrings.alt 등 파일 기반·null 백엔드는 거부 → 로그인 정보를 저장하지 않음.
- Windows 자격 증명 관리자 크기 제한(2560바이트, UTF-16) 때문에 값 1200자 상한.

**D-019 토큰 철회는 POST 본문으로**
구글 문서 예시는 `?token=` 쿼리 매개변수지만, 토큰이 URL(프록시·로그)에 남지 않도록 `application/x-www-form-urlencoded` 본문으로 보낸다(RFC 7009 방식). 철회 응답이 200이 아니면 로컬 삭제는 그대로 하고, 사용자에게 myaccount.google.com/connections에서 직접 해제하도록 안내.
**⚠ 사용자 실계정 테스트에서 확인 필요:** `dpg logout` 후 계정의 "타사 연결" 목록에서 앱이 사라지는지.

**D-020 갱신 실패 처리**
`invalid_grant`(7일 만료, 사용자가 연결 해제, 비밀번호 변경 등) → 키체인 토큰 삭제 + `ReauthRequired`("로그인이 만료되었습니다. 다시 로그인해 주세요."). 네트워크 오류는 `NetworkError`로 구분(토큰 유지).

**D-021 프록시 환경 변수 무시**
`GuardedHttp`는 `HTTPS_PROXY` 등을 무시한다(`proxy_info=None`). 프록시는 검증되지 않은 추가 호스트이기 때문. 프록시가 필수인 학교망은 동작하지 않을 수 있음 → **미결 과제**: 필요 시 "사용자가 명시적으로 입력한 프록시 1개만 허용" 설정을 Phase 3 이후 검토.

**D-022 의존성 추가 (Phase 1)**
| 패키지 | 라이선스 | 이유 |
|---|---|---|
| keyring | MIT | OS 보안 저장소 접근 (원칙 7) |
| google-auth | Apache-2.0 | `Credentials`·토큰 갱신 (기존 전이 의존성을 명시) |
| google-auth-httplib2 | Apache-2.0 | httplib2 기반 인증 전송 계층 (기존 전이 의존성을 명시) |
| httplib2 | MIT | `GuardedHttp`의 기반 (기존 전이 의존성을 명시) |
keyring의 전이 의존성(jaraco.*, more-itertools 등)은 모두 MIT. `tools/check_licenses.py` 통과.

**D-023 로그 마스킹에 OAuth 비밀 추가**
토큰은 무작위 문자열이라 개인정보 패턴에 걸리지 않으므로 전용 규칙 추가: 액세스 토큰(`ya29.`), 갱신 토큰(`1//`), 인증 코드(`4/`), 클라이언트 비밀(`GOCSPX-`) → `<TOKEN>`/`<SECRET>`.

**D-024 C 방식 7일 만료 안내**
테스트 상태 유지를 기본으로 안내하고, 본인 전용 클라이언트에 한해 "프로덕션 게시(미심사)"로 7일 만료를 없애는 선택지를 장단점과 함께 안내(`docs/SETUP_GOOGLE_KO.md`). 구글은 공개 서비스에는 심사를 권장하므로 배포자 클라이언트에는 적용하지 않는다(D-001 유지).

**D-019 확인 (2026-09-26):** 사용자 실계정 테스트에서 `dpg logout` 후 계정의 타사 연결 목록에서 앱이 사라짐 → POST 본문 방식 철회가 동작함.

---

## D. Phase 2 구현 결정 (2026-09-26)

**D-025 공개 파일 사전 조회**
`visibility` 검색어는 `anyoneWithLink`·`anyoneCanFind`·`limited` 세 값만 지원(V4). 두 공개 값으로 먼저 조회해 링크 공개 파일을 표시하고, 권한 목록을 볼 수 없는 파일도 "링크 공개"로 표시할 수 있게 한다. 도메인 공유는 검색어로 찾을 수 없어 권한 목록으로만 판정. `folder:` 범위는 하위 트리를 검색어 하나로 표현할 수 없어 사전 조회를 생략.

**D-026 권한 수집 전략 (API 호출 최소화)**
- 내 드라이브: `files.list`의 `permissions` 필드(공유 권한이 있는 파일만 채워짐)를 그대로 사용 → 파일마다 `permissions.list`를 부르지 않음(1만 개 감사 시 호출 0회).
- 공유 드라이브: `files.list`에 권한이 오지 않으므로 `hasAugmentedPermissions=true`(직접 권한 있음)인 항목과 드라이브 자체(멤버)만 `permissions.list`. 직접 권한이 없는 항목은 **부모의 유효 권한과 같다고 보고 계승**(상속 출처 표시). 제한된 액세스 폴더(`inheritedPermissionsDisabled`)는 관리자 외 권한을 "이름만 보기"로 처리.
- 공유 권한이 없는 파일(뷰어 등)은 호출하지 않고 `권한 부족/정보 불완전`.
- 가정: "직접 권한 없음 = 부모와 동일" — 공유 드라이브 실계정 대조는 아직(개인 gmail 테스트 계정에는 공유 드라이브가 없음). 학교 계정 사용 시 확인.
- 내 드라이브 상속 추정(D-027)은 2026-09-26 사용자 실계정 대조에서 일치 확인.

**D-027 내 드라이브 상속 추정**
공식 문서상 `inheritedFrom`은 공유 드라이브에서만 채워짐(V5). 내 드라이브는 부모 폴더에도 같은 권한 ID가 있으면 "상위 폴더에서 온 권한 추정", 없으면 "직접"으로 표시. 권한 ID는 주체(사용자·도메인·링크)별로 같다는 점을 이용. 한계: 같은 사람에게 하위 파일에서 더 높은 역할을 준 경우도 "추정"으로 보일 수 있음.

**D-028 노출도·위험 점수**
노출도(SPEC 6.1 순서): 링크 공개+편집 > 링크 공개+보기 > 외부 계정 > 도메인 공개 > 제한됨. 점수 기준 95/80/60/40/0, 가감: 웹 검색 가능 +5, 외부 편집자 +5, 외부 편집자+재공유 허용 +5, 외부/링크 보기인데 다운로드 제한 −5 (0~100).
- 내부 도메인 = 로그인 계정의 도메인. **gmail.com 같은 개인 계정 도메인은 내부로 보지 않음**(다른 gmail 사용자는 동료가 아님). `--internal-domain`으로 추가.
- "이름만 보기" 항목(`view=metadata`)과 삭제된 계정은 노출 계산에서 제외.

**D-029 모름은 안전이 아님 (원칙 6)**
권한 목록을 못 본 파일은 노출도 `알 수 없음`(점수 없음). 보고서에서 **맨 위**로 정렬해 사람이 확인하게 함. 공개 조회에 걸린 파일은 권한 목록이 없어도 "링크 공개(보기)"로 올림.

**D-030 로컬 저장소 (SPEC 5.1)**
SQLite, 계정별 파일(`data/<계정 해시 16자>.db`, 이메일이 파일명에 없음), 0600. 파일명·소유자·공유 대상 이메일 등은 하나의 AES-256-GCM 암호문 열(AAD=`스캔ID:파일ID`로 행에 묶음), 파일 ID·상태·노출도·점수만 평문. 키는 키체인(`db-key-<해시>`). 키를 잃으면 DB는 설계상 읽을 수 없으므로 삭제 후 새로 시작. `secure_delete=ON`, 열 때 30일 지난 스캔 자동 삭제. 시각은 `Z` 형식(인접한 `+00:00` 시각이 긴 숫자로 이어져 유출 스캐너가 오탐하던 문제 해결).

**D-031 보고서 (SPEC 5.5)**
CSV(UTF-8 BOM, 엑셀 한글 호환), 0600, 로컬 저장만. 기본값: 파일명 첫 글자+확장자만, 이메일 앞 2자+도메인만. `--no-mask`로 원문 포함(경고 표시). **스프레드시트 수식 주입 방지**: `= + - @`로 시작하는 칸 앞에 `'` (남이 공유한 파일 이름은 공격자가 정할 수 있음). XLSX는 Phase 3 GUI에서.

**D-032 중단 후 재개**
단계(`public → list → perms → analyze`)와 페이지 토큰·폴더 대기열을 체크포인트에 저장(ID만). 페이지마다 항목과 체크포인트를 한 트랜잭션으로 저장. 재실행 시 같은 범위의 미완료 스캔을 이어감(`--restart`로 무시). 페이지 토큰이 만료되면(400) 목록을 처음부터 다시 받되 저장된 항목은 덮어씀. Ctrl+C는 "취소"로 기록.

**D-033 재시도 정책**
429, 5xx, 403 `rateLimitExceeded`/`userRateLimitExceeded`, 네트워크 오류 → 지수 백오프(full jitter, 최대 32초, 6회). 401 → 재로그인, 403 범위 부족 → 권한 추가 안내, 그 외 → 즉시 중단(재실행 시 이어서).

**D-034 의존성 추가 (Phase 2)**
| 패키지 | 라이선스 | 이유 |
|---|---|---|
| cryptography | Apache-2.0 OR BSD-3-Clause | DB 민감 열 AES-256-GCM (SPEC 3.3에 명시된 라이브러리) |

---

## E. Phase 3 구현 결정 (2026-09-26)

**D-035 GUI 라이브러리: PySide6-Essentials (LGPL-3.0 선택)**
PySide6 전체 대신 위젯에 필요한 모듈만 담은 `PySide6-Essentials` 사용(배포 크기 축소). 라이선스가 "LGPL-3.0 또는 GPL-2.0/3.0" 이중 라이선스라 라이선스 검사기가 보수적으로 막음 → **LGPL-3.0 조건으로 사용**(onedir 동적 링크, 고지 포함)한다는 사유를 적어 허용 목록에 추가(shiboken6 동일). V13(PyInstaller onedir 준수 조건)은 Phase 8에서 확인.

**D-036 Qt 네트워크 금지 (D-008 강화)**
QtNetwork·QtWebEngine은 Python 소켓 가드를 거치지 않으므로 import 금지(정적 검사) + GUI 테스트에서 창·마법사 생성 후 `sys.modules`에 로드되지 않았는지 확인. 브라우저 열기는 표준 라이브러리 `webbrowser`(사용자 기본 브라우저)로만. → 완료 기준 "로컬 포트 개방 없음": 앱이 여는 수신 소켓은 로그인 중 127.0.0.1 루프백 하나뿐(D-016).

**D-037 GUI 구조**
- 오래 걸리는 작업(로그인·감사·공유 드라이브 목록)은 `QThread`(`gui/tasks.py`)에서 실행, UI는 멈추지 않음. 오류 문구는 `user_message_for`로만 만든다(예외 문자열을 화면에 그대로 내보내지 않음).
- 대화상자는 `AppContext.notify/confirm`을 거쳐 테스트에서 대체 가능.
- 화면에는 파일명·이메일을 가리지 않고 표시(사용자 본인 화면). 보고서만 기본 마스킹.
- 설정(`prefs.json`, 0600)에는 비밀이 아닌 값만: 종료 시 자동 로그아웃, 내부 도메인. 비밀은 계속 키체인에만.
- 마법사의 "원본 JSON 휴지통으로 이동"은 사용자가 버튼을 누를 때만(`QFile.moveToTrash`, 영구 삭제 아님).

**D-038 XLSX 보고서**
openpyxl을 런타임 의존성으로 이동. 모든 셀을 명시적 문자열(`data_type="s"`)로 기록(점수만 정수) → 파일명이 수식으로 해석될 수 없음. CSV와 같은 마스킹·정렬, 0600.

**D-039 취소 처리 보강**
감사 취소 확인을 단계 경계마다 추가. 기존에는 마지막 페이지에서 누른 "중단"이 무시되고 감사가 끝까지 진행됨(GUI 테스트에서 발견).

**D-040 의존성 추가 (Phase 3)**
| 패키지 | 구분 | 라이선스 | 이유 |
|---|---|---|---|
| PySide6-Essentials, shiboken6 | 런타임 | LGPL-3.0 (선택) | GUI (SPEC 3.2) |
| openpyxl (+et-xmlfile) | 런타임(개발→이동) | MIT | XLSX 보고서, Phase 4 XLSX 추출 |
| pytest-qt | 개발 | MIT | GUI 자동 테스트 |

---

## F. Phase 4 구현 결정 (2026-09-26)

**D-041 추출은 전부 메모리에서 (SPEC 5.2)**
모든 형식을 `io.BytesIO`로 처리하고 임시 파일을 만들지 않는다(테스트로 확인). 50MB 초과는 `검사 불가(크기 초과)`. 구글 문서류는 서버 내보내기(10MB 한도, V7) — 초과 시 `검사 불가(내보내기 한도 초과)`. 위치는 "시트 2, 15행"·"3쪽"·"문단 12"처럼 **번호만** 쓴다(시트 이름·제목이 사람 이름일 수 있음). 라이브러리 예외 메시지는 문서 내용을 담을 수 있어 버리고 `손상` 사유만 남긴다.

**D-042 형식별 방식**
- 구글 문서·프레젠테이션 → `text/plain` 내보내기, 구글 시트 → XLSX 내보내기(CSV는 첫 시트만이라 제외, V7).
- PDF: pypdf. **글자 있는 쪽이 하나도 없으면** `검사 불가(스캔)`, 일부만 없으면 검사하되 "일부 검사 불가" 표시(평균 글자 수 기준은 빈 쪽 하나 때문에 정상 PDF를 스캔으로 오판해서 변경).
- HWP 5.0: olefile+zlib 자체 파서(D-003). 암호(bit1)·배포용(bit2)·DRM(bit4) → `검사 불가`. 표 셀 주소는 목록 헤더 뒤 오프셋 6(공식 문서)과 8(한글이 저장한 파일에서 흔히 관찰됨) 중 **주소가 유효·중복 없는 쪽**을 쓰고, 둘 다 아니면 행 우선 순서로 배치.
- HWPX: zip + defusedxml(XML 폭탄 방지), manifest의 `encryption-data` → 암호.
- DOCX/XLSX/HWPX 공통: zip 폭탄 방지(압축 해제 합계 300MB, 비율 검사), zip 암호 플래그 → 암호. **암호 걸린 DOCX/XLSX는 zip이 아니라 OLE(`EncryptedPackage`)** 이므로 이를 확인해 "손상" 대신 "암호"로 표시.
- 이미지·ZIP 등 → `검사 불가(지원하지 않는 형식 / 이미지)`. PPTX는 2차.

**D-043 탐지 규칙 (SPEC 6.3 표 구현)**
- 주민번호: 날짜 유효 + 7번째 자리 1~8. 검증식 통과(내국인식 또는 외국인식) → 높음. 실패 시 구분자나 "주민/등록번호" 문맥이 있으면 `의심`(2020.10 이후 번호는 임의, V10), 13자리 연속 숫자에 문맥도 없으면 보고하지 않음(바코드 등 오탐 방지).
- 여권: "여권/passport" 30자 이내면 높음, 없으면 M/S/R/G/D 시작만 `의심`. 운전면허: 지역코드 11~28 + "면허/운전" 문맥이면 중간.
- 계좌: 10~14자리, 은행명+계좌어 → 높음, 둘 중 하나 → 중간, **문맥 없으면 보고 안 함**(표 열 제목도 문맥으로 인정). 카드: Luhn. 주소: 시·도+시군구+로/길+번호, 열 제목 "주소"면 높음. 이메일: 낮음.
- 학생 명단: 앞 5행 중 열 제목 그룹 2개 이상 + 한글 이름 형태 행 5개 이상. 민감정보 의심: 상담·진단 등 키워드 + 이름 형태가 같은 줄에.
- 파일명도 검사 + "명단·연락처·상담…" 단어는 `파일명에 개인정보 암시`(의심).
- 규칙 적용 순서대로 이미 잡은 구간은 다시 세지 않음(주민번호 안의 숫자를 계좌로 중복 집계 방지).
- **알려진 한계:** 키워드 근접 방식이라 부정문("계좌 아님")을 구분하지 못함. 합성 데이터는 규칙과 같은 사람이 만들었으므로 실제 문서의 정확도는 더 낮을 수 있음 → 실계정 대조로 보완.

**D-044 상태 5분류 + 부분 검사**
탐지(중간 이상) / 의심(낮음만) / 지원 범위 내에서 발견되지 않음 / 검사 불가(사유) / 처리 실패, + 사용자 제외. 일부만 읽은 파일은 `partial` 표시(안전으로 보지 않음). 저장은 유형·건수·신뢰도·위치(최대 5)만, 평문 열(원칙 2 — 값은 저장하지 않음).

**D-045 검토 미리보기**
"검토" 시 파일을 다시 받아 메모리에서만 검사하고, 값은 유형별로 가림(주민번호 `901012-1******`, 전화 `010-****-5678`, 계좌·카드 끝 3자리). 주변 문맥의 다른 패턴도 가림. 저장·로그·보고서에 쓰지 않음.

**D-046 권장 조치 (SPEC 6.4)**
민감도(탐지) × 노출도(공유): 고위험 유형 + 링크 공개 → 긴급 "링크 공개 해제"; 탐지 + 링크 공개 → 높음; 명단 + 외부 → "외부 계정 확인 후 제거"; 검사 불가 + 링크 공개 → 수동 검토; 탐지 + 도메인 → 범위 축소 검토; 1년 이상 미수정 → 암호화 보관/파기 검토; 내부 공유만 → 유지 권장. 앱은 권장만(자동 실행 없음). `action` 키는 Phase 5 권한 변경과 연결 예정.

**D-047 예외 목록**
"이 파일 제외"(대상=파일, 규칙=*), "이 규칙 이 폴더 제외"(대상=폴더, 규칙=유형)를 DB `exclusions`에 저장(파일 ID만). 다음 탐지부터 적용.

**D-048 HWP 공개 문서 표기 (V11)**
한컴 요구에 따라 "본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다."를 소스(`extract/hwp.py`), 사용자 인터페이스(도움말 → 정보), 매뉴얼(USER_GUIDE_KO), README에 기재.

**D-049 테스트용 문서 작성기 (앱에는 포함 안 됨)**
olefile은 읽기만 가능해 합성 HWP를 만들 수 없으므로 `tools/cfb_writer.py`(복합 파일 v3 최소 작성기, 무작위 200개 구조로 olefile 왕복 검증)와 `tools/doc_writers.py`(HWP·HWPX·ToUnicode PDF)를 작성. 합성 데이터 생성기 v2: HWP·HWPX·PDF 및 검사 불가(스캔·암호·배포용) 파일 추가.

**D-050 의존성 추가 (Phase 4)**
| 패키지 | 라이선스 | 이유 |
|---|---|---|
| pypdf | BSD-3-Clause | 텍스트 PDF 추출 (SPEC 3.3) |
| olefile | BSD-2-Clause | HWP 5.0 복합 파일 읽기 (SPEC 3.3) |
| python-docx | MIT | DOCX 추출 (개발→런타임) |
| defusedxml | PSF-2.0 | HWPX XML 안전 파싱 (XML 폭탄 방지) |

**D-051 GUI 백그라운드 작업 수명 관리**
검토·공유 드라이브 목록 등 모든 `QThread` 작업을 창이 보관하고, 창을 닫을 때 끝날 때까지 기다린다. 실행 중인 QThread가 먼저 소멸되면 Qt가 비정상 종료(세그폴트)하는 문제가 전체 테스트 실행 중 간헐적으로 발생해 수정(5회 연속 실행으로 확인).

---

## G. Phase 5 구현 결정 (2026-09-26)

**D-052 쓰기 경로는 하나 (CLAUDE.md)**
드라이브를 바꾸는 요청은 `dpg.core.actions.writer.DriveWriter`에서만 보낸다(권한 삭제·역할 변경·되돌리기용 재생성, 파일의 `writersCanShare`·`downloadRestrictions` 두 설정뿐). 파일 삭제 메서드는 없다. `DriveClient`는 읽기 전용으로 남고, 다른 모듈에서 `.permissions()/.files()/.drives()`의 쓰기 메서드를 부르면 정적 검사 테스트가 실패한다.

**D-053 계획-미리보기-재조회-실행-재검증-기록-되돌리기 (SPEC 6.2)**
- 계획은 감사 결과로만 만든다(API 호출 없음). 미리보기에 파일별 변경 전→후, 제외 사유, 폴더 하위 항목 수, 영향 대상 수.
- 50개 파일 초과 시 "권한 변경 확인" 입력(드라이런은 제외), 한 번에 최대 500개.
- 실행 직전 파일마다 권한을 다시 받아 계획 당시(유형·역할·대상)와 다르면 `충돌`로 분리하고 실행하지 않음(재승인 필요). 공식 문서: 같은 파일의 동시 권한 변경은 마지막 것만 적용됨.
- 실행 후 다시 받아 확인(삭제됨/역할 바뀜/설정 값) — 다르면 `실패`.
- 변경 전 권한 객체(이메일 포함)는 DB 암호화 열에 보관(30일) → 되돌리기. 되돌릴 때도 현재 상태가 실행 결과와 같을 때만 되돌리고, 그 사이 다시 바뀌었으면 `되돌릴 수 없음`.
- 드라이런: 재조회·충돌 판정까지만(쓰기 0건, 테스트로 확인). 설정에서 기본값 지정.
- 부분 실패·취소는 파일 단위로 기록되고, 완료된 것만 되돌린다.

**D-054 바꾸는 대상은 "직접 부여된" 권한뿐**
소유자, 상속, 상속 추정, **출처 불명**, 이름만 보기(`view=metadata`), 삭제된 계정 권한은 계획에서 제외하고 이유를 보여 준다. 출처 불명(예: 나에게 공유된 파일은 상위 폴더가 안 보임)도 상속일 수 있으므로 제외 — SPEC 완료 기준 "상속 권한 변경 시도 0건"을 지키기 위한 보수적 선택. 한계: 공유받은 파일의 링크는 앱에서 바꾸지 못할 수 있음(소유자에게 요청 안내).

**D-055 알림 메일 끄기 (V9)**
삭제·역할 변경은 메일을 보내지 않는다. 되돌리기로 사용자·그룹 권한을 다시 만들 때 `sendNotificationEmail=false`(공식 문서: 사용자·그룹에만 적용, 소유권 이전은 끌 수 없음 — 소유권 이전은 하지 않음). 링크를 다시 만들어도 파일의 resourceKey는 파일 속성이라 바뀌지 않음(링크 주소 유지).

**D-056 다운로드 제한 필드 (V6)**
"뷰어·댓글 작성자 다운로드·인쇄·복사 제한"은 신규 `downloadRestrictions.itemDownloadRestriction.restrictedForReaders`로만 설정(구형 `copyRequiresWriterPermission`과 섞지 않음 — 공식 권고). 소유자(공유 드라이브는 관리자)만 가능 → 내 소유 내 드라이브 파일만 계획. "편집자 재공유 금지"(`writersCanShare`)도 내 드라이브·내 소유 파일만(공유 드라이브는 드라이브 설정).

**D-057 변경 후 표 새로 고침**
실행·되돌리기 후 같은 범위를 다시 감사(처음부터)해 새 공유 상태를 보여 준다. 권한 변경은 파일 내용을 바꾸지 않으므로 직전 개인정보 탐지 결과를 그대로 이어 붙인다(다시 내려받지 않음).

**D-058 유출 스캐너 오탐 수정**
스캐너가 바이트를 `errors="ignore"`로 해석해, 버려진 바이트 양옆 글자가 붙으면서 암호문 속 무작위 바이트가 이메일처럼 "만들어지는" 일이 약 20회에 1번 발생(실제 파일에는 없는 문자열, 원본 오프셋 없음으로 확인). `errors="replace"`로 바꿔 연속되지 않은 글자가 이어지지 않게 함. 실제 텍스트(연속된 유효 UTF-8/UTF-16)는 그대로 탐지(테스트 추가).

**D-059 조치 선택 버그 수정 (사용자 실계정 테스트에서 발견, 2026-09-26)**
미리보기 창에서 조치를 바꾸면 Qt 콤보박스가 `ActionKind`가 아닌 **문자열 값**을 돌려주는데, 계획기가 `is`(동일 객체) 비교를 써서 첫 조치 외에는 항상 "해당하는 공유가 없음"으로 계획하던 문제. 계획기 입구에서 `ActionKind(kind)`로 변환하고 비교를 값 비교(`==`)로 바꿈. 드롭다운을 바꾼 뒤 모든 조치가 올바르게 계획·실행되는지 GUI 회귀 테스트 추가.

## I. Phase 6 구현 결정 (2026-09-26)

**D-060 새 의존성**
py7zr 1.1.3 (LGPL-2.1+, 동적 import라 LGPL 조건 충족, SPEC 5장 선정), pyzipper 0.4.0 (MIT, AES-ZIP 호환 옵션). 하위 의존성(pycryptodomex BSD, pyppmd·pybcj·inflate64·multivolumefile LGPL-2.1+, brotli MIT, texttable MIT, psutil BSD) — 라이선스 검사 0건.

**D-061 비밀번호**
`secrets`로 영문 대·소문자+숫자 24자(4자씩 `-` 구분, 약 143비트), 대·소문자·숫자 각 1개 이상 보장. 단어 6개 방식은 한국어 단어 목록 품질 문제로 제외. 화면에 1회 표시, "적어 두었습니다" 체크 전에는 진행 불가. 선택 시 키체인에 `vault:<보관 파일 이름>`으로 저장, 복구 카드는 인쇄만(파일로 저장하지 않음). CLI는 숨김 입력(getpass)만, 명령행 옵션·환경 변수 없음. 7z 외부 프로그램 호출 없음(정적 검사).

**D-062 보관 흐름**
① `RESTRICT_ALL`(링크·도메인·외부 공유 해제, 직접 권한만) 계획을 미리보기·승인 후 실행(드라이런 불가) → 실패·충돌이 있으면 중단. ② 메모리로 받기(구글 문서→DOCX/XLSX/PPTX, 그림→PDF, 파일당 500MB·합계 1GB) ③ 암호화 ④ 풀어서 파일별 SHA-256 비교 ⑤ `보관_날짜_무작위4자.7z`로 업로드 → 다시 내려받아 SHA-256 비교 ⑥ 두 검증 모두 통과한 결과로만 휴지통 계획 생성, 파일마다 체크. 휴지통 이동도 변경 기록에 남아 되돌리기(복원) 가능. 업로드 위치는 아무와도 공유되지 않은 내 폴더 또는 최상위만 제시. 헤더 암호화 7z는 틀린 비밀번호와 손상을 구분할 수 없어 "비밀번호가 틀렸거나 손상" 한 문구로 안내.

**D-063 정리(6.6)**
분류 제안은 탐지 결과 기반(파기검토: 개인정보+3년 이상 미수정, 암호화보관: 고위험+180일 이상, 개인정보보호: 탐지·의심, 내부공유: 도메인/내부 계정만, 일반: 미발견). 탐지 안 함·검사 불가·권한 부족은 "보류"(원칙 6). 중복은 크기+md5Checksum(구글 문서 제외), 표시만. 이동은 내 드라이브·내 소유만; 목적지 폴더 권한(모두 상속됨)에 지금보다 새로 생기거나 높아지는 대상이 하나라도 있으면 차단. 이동·휴지통은 `Op.MOVE`/`Op.TRASH`로 기존 실행기(재조회·충돌·검증·되돌리기)를 그대로 사용. writer에 `move_file`·`set_trashed`·`upload` 추가, 영구 삭제·휴지통 비우기 메서드는 여전히 없음.

**D-064 사용자 요청 반영 (2026-09-26)**
① 권한 변경 조치 이름을 구글 드라이브 공유 화면 명칭(일반 액세스·제한됨·링크가 있는 모든 사용자·뷰어/편집자·액세스 권한 삭제·설정 ⚙ 문구)으로 바꾸고, 목록을 구글 화면처럼 「일반 액세스 / 액세스 권한이 있는 사용자 / 설정 ⚙」로 묶음. 선택한 조치가 구글 화면의 어느 동작과 같은지 안내 문구 표시. 출처: [구글 드라이브 도움말: 파일 공유](https://support.google.com/drive/answer/2494822?hl=ko). ② 메인 화면에 「암호화 보관·보관 파일 풀기·폴더로 이동·정리 제안」 버튼 줄 추가(메뉴와 같은 기능). ③ 표에서 보관 파일을 선택하고 「보관 파일 풀기」를 누르면 드라이브에서 **메모리로만** 받아 풂(.7z는 디스크에 저장하지 않음, 파일 내용 읽기 권한 필요).

**D-065 내 보관함 (사용자 요청, 2026-09-26)**
이 앱이 만든 보관 파일을 드라이브에서 찾아 폴더별로 보여 주고 골라서 바로 풂. 찾는 방법: 서버에서 MIME(`application/x-7z-compressed`/`application/zip`, 휴지통 제외, 모든 드라이브)으로 검색 → 앱이 이름 규칙 `보관_YYYY-MM-DD_xxxx.7z|zip`에 정확히 맞는 것만 남김(일반 zip 제외). 읽기 전용, 로컬에 목록을 따로 저장하지 않음. 한계: 사용자가 이름을 바꾼 보관 파일은 목록에 나오지 않음(「보관 파일 풀기」로는 풀 수 있음). 키체인에 비밀번호를 저장한 보관 파일은 "저장됨"으로 표시하고, 풀 때 저장된 비밀번호를 쓸지 묻는다.

**D-066 메인 화면 재설계 (사용자 요청, 2026-09-26)**
화면을 작업 순서대로 ① 검사하기 → ② 결과 요약 → ③ 파일 목록 → ④ 고른 파일로 할 일 네 구역으로 나눔. 파일을 고르지 않아도 되는 도구(보고서 저장·정리 제안·제외 목록·변경 기록)는 목록 위에, 고른 파일에 하는 일(공유 설정 바꾸기·암호화 보관·폴더로 옮기기·내용 확인·탐지에서 제외·보관 파일 풀기)은 목록 아래에 모음. 버튼은 고른 파일 수에 따라 켜지고 꺼짐(내용 확인은 1개일 때만). 선택은 표 맨 왼쪽 체크박스(체크가 없으면 줄 선택을 사용), 「보이는 파일 모두 고르기」 지원. 기본 정렬은 「폴더·파일 순」(폴더 다음에 그 안의 파일, 드라이브 트리 순서), 「위치」 열에 상위 폴더 경로 표시, 정렬 목록과 열 머리글로 변경 가능. 「내 보관함」을 결과 요약 칸에 넣고 감사 결과의 보관 파일 수를 표시. 제외한 파일은 보기 목록 '탐지에서 제외한 파일'로 보고, 「제외 목록」에서 체크 후 해제하면 즉시 그 파일만 다시 검사. 권장 조치가 없을 때는 빈칸 대신 "필요 없음"(탐지 후) 또는 "—"(탐지 전)과 이유를 툴팁으로 표시.

**D-067 보관 흐름 변경 (사용자 요청, 2026-09-26)**
① 「내 보관함」은 별도 창을 없애고 결과 요약 칸 → 같은 파일 목록을 '보관 파일만' 보기로 바꿈(D-065의 드라이브 전체 검색 제거: 감사 범위 안의 보관 파일만 보임). 비고 열에 키체인 저장 여부 표시. ② 보관 파일 풀기 기본값은 **드라이브의 같은 폴더에 풀기**: 메모리에서 복호화 → 원래 폴더에 파일 업로드(같은 이름이 있으면 "(복원)" 붙임) → 올린 파일마다 SHA-256 재검증 → 모두 맞으면 보관 파일을 **휴지통으로**(영구 삭제 금지 원칙 유지, 변경 기록에서 되돌리기 가능). 틀린 비밀번호면 아무것도 올리지 않음. 폴더가 공유되어 있으면 먼저 경고. "이 컴퓨터에 저장"도 선택 가능(이때 보관 파일 유지). 구글 문서였던 파일은 DOCX/XLSX/PPTX로 돌아옴. ③ 암호화할 때 둘 곳 기본값은 **원래 있던 자리**(고른 파일이 한 폴더일 때), 다른 폴더 선택 가능, 공유된 폴더면 경고. "확인이 끝나면 원본은 휴지통으로"를 기본 체크하고 결과 창의 원본 체크를 미리 채움 — 휴지통 이동은 여전히 결과 창에서 목록을 보고 버튼을 눌러야 실행(SPEC 6.5-7의 승인 단계 유지, 개별 체크 해제 가능). ④ 비밀번호 창에 저장 위치(키체인 접근 → drive-privacy-guardian → 계정 vault:이름, Windows 자격 증명 관리자) 명시, 키체인 저장을 기본으로 켬. 저장하지 않을 때만 "적어 두었음" 체크 필수. ⑤ ①~④ 구역을 색 번호 배지와 색 테두리로 구분. ⑥ 결과 요약에 '탐지 제외' 칸 추가. ⑦ 권장 조치: 개인정보가 있지만 나만 볼 수 있는 파일에도 "[유지] 나만 볼 수 있음 — 업무가 끝났으면 암호화 보관 권장"을, 검사 불가 파일에는 "직접 열어 확인"을 표시("필요 없음"은 개인정보가 없을 때만).

**D-068 선택·이동·제외 개선 (사용자 요청, 2026-09-26)**
① 탐지 제외한 파일을 고르면 ④의 버튼이 「↩ 탐지 제외 해제」로 바뀌어 바로 복구(즉시 재검사). 「제외 목록」 창도 유지. ② '내 보관함' → '암호화된 파일'로 명칭 변경. ③ 체크박스 열 머리글에 전체 체크박스(지금 보이는 목록 전체 선택/해제, 일부만 체크되면 ■ 표시, 누를 때 정렬하지 않음). 「모든 체크 해제 (다른 보기 포함)」는 다른 칸(보기)에서 체크해 지금 안 보이는 파일까지 해제. 안 보이는 체크가 있으면 선택 문구에 경고(숨은 파일에 조치가 적용되는 것을 막기 위해). ④ 폴더로 옮기기에 「🏠 내 드라이브(최상위)」와 「➕ 이 폴더 안에 새 폴더 만들기」 추가. 새 폴더는 `DriveWriter.create_folder`로 만들며 상위 폴더의 공유를 그대로 물려받는 것으로 계산해 권한 확대 검사를 그대로 적용(공유 폴더 안 새 폴더로도 확대 이동 차단). 빈 폴더 생성은 되돌리기 기록에 넣지 않음(빈 폴더라 위험 없음, 드라이브에서 직접 삭제 가능). ⑤ 폴더 행은 파란 굵은 글씨·연한 파란 배경·`📁 이름 /`로 파일과 구분, 툴팁에 안의 항목 수. ⑥ 드라이브 변경 실시간 반영은 Changes API(`changes.getStartPageToken`/`changes.list`)를 주기적으로 조회하면 요청 1건/주기로 가볍지만, SPEC Phase 7 "증분 검사"의 핵심이므로 그때 구현.

## J. Phase 7 구현 결정 (2026-09-26)

**D-069 증분 검사 (Changes API)**
[changes.list](https://developers.google.com/workspace/drive/api/reference/rest/v3/changes/list) 확인: `drive.metadata.readonly`로 호출 가능, pageSize 최대 1000, 마지막 페이지에만 `newStartPageToken`, Change에 `removed`·`fileId`·`file`. 새 전체 감사는 목록 수집 **전에** `startPageToken`을 받아 체크포인트에 저장(감사 중 바뀐 것도 다음에 잡힘). 증분: 직전 완료 감사를 새 감사로 복사(항목은 AAD에 scan id가 들어가므로 복호화 후 재암호화, 탐지 결과는 그대로 복사) → 변경 적용(삭제·휴지통·범위 밖 → 제거, 폴더 제거 시 하위도 제거) → **공유·상위·제한 액세스가 바뀐 폴더의 하위 항목은 다시 읽음**(Drive는 폴더만 변경으로 알리고 하위 파일은 알리지 않는 경우를 가정) → 공유 드라이브 구성원은 매번 다시 읽음(1건/드라이브) → 공개 링크 힌트 재조회 → 기존 권한·분석 단계 그대로. 수정 시각이 바뀐 파일만 탐지 결과를 지워 다시 읽음. 토큰 만료(400/403/404/410), 이전 감사 없음, '나에게 공유됨' 범위(변경 기록에 공유받음 여부가 없어 정확히 판단 불가)는 전체 감사. **완료 기준 테스트:** 10가지 변경 × 3가지 범위(내 소유·공유 드라이브·특정 폴더) = 30개 시나리오에서 증분 결과가 새 전체 감사와 `FileAudit` 단위로 완전히 같음.

**D-070 자동 반영**
앱이 열려 있고 감사 결과가 있을 때 1분마다 메모리에 든 토큰으로 `changes.list`만 호출(DB 사용 없음, 작업 중이면 건너뜀). 변경이 없으면 끝, 있으면 증분 감사를 실행(탐지를 했던 경우 새·수정 파일만 다시 탐지). 설정에서 끌 수 있음(기본 켬). 비용: 변경 없을 때 작은 GET 1건/분.

**D-071 보존 기한·모든 기록 삭제**
보존 기간 설정(7/30/90/180/365일, 기본 30) — DB를 열 때마다 기간이 지난 검사와 변경 기록 삭제(기존 `purge_older_than`, GUI의 모든 DB 열기에 같은 설정 적용). 「설정 → 모든 기록 삭제」: 모든 계정의 DB와 그 키체인 암호화 키, 로그 삭제('삭제' 입력 확인). 보관 파일 비밀번호(키체인은 목록을 볼 수 없어 `vault:index`로 이름 목록을 관리)와 로그인·클라이언트는 **체크해야만** 삭제(비밀번호를 지우면 보관 파일을 못 열 수 있다는 경고). (사용자 질문 반영) 삭제 창에 "보관 파일은 검사 기록 키가 아니라 각자의 비밀번호로 잠겨 있으며, 저장된 비밀번호 N개는 그대로 둔다"를 표시하고, 비밀번호까지 지우려면 '삭제' 대신 '비밀번호까지 삭제'를 입력해야 함. 앱은 임시 파일을 만들지 않으므로 지울 임시 폴더 없음. Windows에서 열려 있는 로그 파일은 삭제 대신 비움.

**D-072 보안 점검표 (6.7)**
정적 데이터(`dpg.core.checklist`) + 「도움말 → 보안 점검표」 화면 + `docs/SERVER_SECURITY_KO.md`. 네트워크 호출 없음(링크 버튼은 사용자 브라우저로 열기만), 체크 상태는 prefs에만 저장. CSE 안내 문구는 V16 확인 결과 반영. (사용자 요청) 화면·문서에 "스스로 점검하는 표이며, 체크한다고 보안이 강화되지 않는다(앱은 실제 설정을 확인·변경하지 않음)"를 명시.

**D-073 로그인 안내·다시 로그인 (사용자 요청, 2026-09-26)**
로그인 화면에 파란 테두리 단계 안내: ① 계정 선택 ② 'Google에서 확인하지 않은 앱' → 「계속」(없으면 고급 → 이동) ③ 권한 모두 체크 → 「계속」 ④ '로그인 완료' 페이지 닫고 돌아오기, "「계속」을 누르지 않으면 로그인이 끝나지 않음". 권한 추가 때도 같은 화면. 로그아웃 후 오른쪽 위 버튼이 「🔑 로그인」으로 바뀌어 저장된 클라이언트로 바로 다시 로그인. 로그아웃하면 진행 중 작업을 멈추고 화면의 결과를 비움(다음에 다른 계정이 로그인해도 이전 계정 결과가 보이지 않게).

**D-074 복구 키 (사용자 요청 "메일로 마스터 비밀번호 초기화", 2026-09-26)**
암호화는 비밀번호 자체로 잠그므로 "초기화 메일"은 원리상 불가능(누군가 비밀번호나 그 열쇠를 보관해야 함). 사용자에게 선택지를 설명: ① 복구 키(종이) ② 내 Gmail로 복구 키 발송(Gmail 발송 권한 추가 + 암호 파일과 열쇠가 같은 구글 계정에 있게 되어 계정 탈취 시 전부 열림 — 비권장) ③ 만들지 않음 → **사용자가 ① 선택**. 설계: 160비트 무작위 복구 키, Base32 35자(5자×7, 마지막 3자는 오타 검출용 체크섬, 0/O·1/I·8/B 혼동 허용). 키체인(`vault:recovery-key`)과 종이에 보관, prefs에는 비밀이 아닌 지문(HMAC 8자)만. 새 보관 파일 이름의 무작위 태그를 8자리 16진수로 늘리고, 비밀번호 = HMAC-SHA512(복구 키, 태그)에서 편향 없이 뽑은 24자(대·소문자·숫자 포함). 비밀번호를 잃으면 풀기 창의 비밀번호 칸에 복구 키를 입력하면 해당 파일의 비밀번호로 바뀜(로컬 파일 풀기도 동일). 복구 키는 **교체 불가**(이전 보관 파일의 복구가 끊기므로), 다른 지문의 키 입력 시 경고. 모든 기록 삭제에서 '비밀번호까지 삭제'를 고르면 키체인의 복구 키도 지워지며 종이 사본으로는 계속 열림. 한계: 복구 키 이전(태그 4자리)에 만든 보관 파일은 복구 키로 열 수 없음. 복구 키가 유출되면 그 키로 만든 모든 보관 파일이 열림(화면·인쇄물에 경고).

**D-075 원본 삭제 기본값·완료 버튼 (사용자 요청, 2026-09-26)**
암호화 보관 시 "원본 삭제(기본)"를 켠 상태로 시작하고, 결과 창에서 원본이 모두 체크된 채 「✓ 암호화 완료 (원본 N개 휴지통으로)」 한 번으로 끝남(체크 해제 시 그 원본은 남김, 모두 해제하면 「원본 남김」). '삭제'는 **휴지통 이동**(영구 삭제 금지 원칙 유지, 30일 복원·변경 기록 되돌리기). SPEC 6.5-7의 "검증 전 불가·개별 승인"은 유지: 두 검증을 모두 통과해야 체크가 가능하고, 파일 목록을 보여 준 뒤 버튼을 눌러야 실행. 흐름 중 결과 창 버튼도 「다음: 암호화 진행 →」「✓ 암호화 완료」「✓ 풀기 완료」로 표시(닫기 대신).

## K. Phase 8 구현 결정 (2026-09-26)

**D-076 빌드**
PyInstaller 6.22 onedir(`packaging/dpg.spec`), `build` 의존성 그룹(pyinstaller GPL-2.0+부트로더 예외·빌드 전용, pip-licenses MIT — 앱에 포함되지 않음). 번들에서 제외: QtNetwork(유일한 의존자 TUIO 터치 플러그인도 제외 — 네트워크 경로를 가드 밖에 두지 않기 위해), QtQml/Quick/WebEngine 등, googleapiclient의 600개 API 문서 중 drive.v3.json만 유지(211MB→108MB, zip 43MB). 포함: LICENSE, THIRD_PARTY_LICENSES.txt(런타임 의존성만, 오프라인 생성), NOTICE_KO.txt(LGPL·HWP·상표 고지), LGPL-3.0/GPL-3.0 전문. `--selftest`(네트워크 가드 소켓·HTTP 두 계층, 내장 Drive 문서, AES-GCM, 7z/AES-ZIP, 문서 추출기, OS 키체인, Qt, QtNetwork 미로드)를 **빌드된 앱에서 실행**해 실패 시 빌드 중단. 윈도 GUI 실행 파일은 콘솔이 없으므로 `--selftest-out=파일`. macOS는 ad-hoc 서명(PyInstaller 기본), .zip(ditto)+.dmg, SHA256SUMS.txt.

**D-077 배포 워크플로**
`release.yml`: `v*` 태그 → macos-14(Apple Silicon)·windows-latest에서 태그=버전 확인 → 테스트 → 라이선스 검사 → 빌드+자가 진단 → 아티팩트 → 체크섬 합치고 `sha256sum -c` → `attest-build-provenance`(빌드 출처 증명) → **초안(draft)** 릴리스(사람이 확인 후 공개). 모든 액션을 전체 커밋 SHA로 고정(checkout v7.0.1, setup-uv v10.2.0, upload-artifact v7.0.1, download-artifact v8.0.1, attest-build-provenance v4.2.2, action-gh-release v3.0.3 — 각 action.yml에서 입력 호환 확인), 체크아웃 자격 증명 비보존, 릴리스 잡만 쓰기 권한. ci.yml도 같은 SHA로 고정(Phase 0에서 미룬 항목). 「도움말 → 새 버전 확인」은 브라우저로 Releases 페이지를 열 뿐 앱이 직접 확인하지 않음(`dpg.REPOSITORY_URL`, 저장소 생성 후 설정).

**D-078 크롬 확장 프로그램 계획 (사용자 요청, 2026-09-26)**
암호화된 보관 파일을 크롬에서 메모리로만 풀어 확장 프로그램 전용 창에서 보고, 필요 시 저장·다시 암호화. 가능성 검토 결과 가능(7-Zip WASM, WebCrypto로 복구 키 비밀번호 계산, chrome.identity + Drive API). 한계: 키체인 접근 불가(비밀번호·복구 키 입력), 메모리 전용의 OS 수준 한계, 한글 뷰어는 내용 확인용. 사용자 결정: **무료 배포(개발자 모드, GitHub Releases zip)**, **한글·엑셀 우선**. 상세는 `docs/EXTENSION_PLAN.md`. 구현은 Phase 8 마무리 후 E0 검증부터.

**D-079 확장 프로그램 E0 검증 (2026-09-26)**
- **7-Zip WASM:** npm `7z-wasm@1.2.0`(7-Zip 24.09) — GNU LGPL-2.1+ **+ unRAR restriction**(RAR 압축기 제작 금지, 문서·소스에 그 사실을 명시하면 배포 가능; GPL 아님 → 허용). 파일 해시 고정(extension/probe/README.md). **상호 호환 실험(Node)**: 데스크톱 앱(py7zr)이 만든 7z(AES-256+헤더 암호화)·AES-ZIP을 7-Zip WASM이 메모리 파일 시스템에서 해제, 틀린 비밀번호 거부(7z는 예외를 던지므로 작업마다 새 인스턴스·try/catch 필요). WASM으로 만든 `-mhe=on` 7z를 앱이 해제, 파일명 비노출. **WebCrypto HMAC-SHA512로 계산한 복구 키 비밀번호가 파이썬과 동일**.
- **CSP:** [MV3 CSP](https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy) 최소 정책 `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'` → WASM 허용, 원격 스크립트·unsafe-eval 불가. 우리 정책: + `connect-src 'self' https://www.googleapis.com`(자기 wasm 파일과 Drive API만), `base-uri 'none'`.
- **로그인:** [chrome.identity](https://developer.chrome.com/docs/extensions/reference/api/identity) — `getAuthToken`은 manifest에 클라이언트 ID를 고정하고 크롬 프로필 계정을 쓰므로 BYO(사용자별 클라이언트)와 맞지 않음. → `launchWebAuthFlow` + 사용자의 **웹 애플리케이션** 클라이언트(리디렉션 `https://<ID>.chromiumapp.org/`) + 토큰 응답(클라이언트 보안 비밀 불필요, state 검증). ID는 manifest `key`(공개키)로 고정 `gjlomabldjleleakkeffjojhjdgeekgj`, 개인키는 보관하지 않음. 실계정 확인 대기.
- **권한:** [Drive 범위](https://developers.google.com/workspace/drive/api/guides/api-specific-auth): `drive.file` 비민감(앱이 만들거나 연 파일만), `drive.readonly`·`drive` 제한. → 같은 구글 프로젝트의 데스크톱 앱이 만든 보관 파일이 `drive.file`로 보이는지 실계정으로 확인(보이면 확장 프로그램은 `drive.file`만 사용).
- **SheetJS:** npm의 `xlsx@0.18.5`는 오래되어 알려진 취약점 있음(SheetJS는 자체 CDN으로 배포) → E1에서 SheetJS 최신 CE를 받아 고정하거나, zip.js + XML로 직접 해석 중 결정. pdf.js Apache-2.0, zip.js BSD-3, mammoth BSD-2, hwp.js Apache-2.0(0.0.3, 오래됨 → HWP는 앱 파서를 옮기는 쪽이 유력).
- 시험용 확장 프로그램 `extension/probe` + 안내 `docs/EXTENSION_E0_TEST_KO.md`.
- **실계정 결과(2026-09-27):** WASM 성공, 로그인 성공, `drive.file` 2개 = `drive.readonly` 2개 → 같은 프로젝트의 데스크톱 앱이 만든 파일이 `drive.file`로 보임. **확장 프로그램 권한은 `drive.file`(비민감)만 사용**, 제한 범위는 요청하지 않음.

**D-080 확장 프로그램 E1 (2026-09-27)**
`extension/app`(MV3, 빌드 단계 없음, ES 모듈). 로그인 `launchWebAuthFlow` + 사용자 웹 클라이언트, 권한 `drive.file`만, 토큰은 메모리. 목록은 이름 규칙으로 보관 파일만. 복호화는 7-Zip WASM(작업마다 새 인스턴스, 메모리 파일 시스템), 비밀번호 칸에 복구 키(35자)를 넣으면 WebCrypto로 해당 파일 비밀번호 계산, "기억"은 창이 열린 동안 메모리에만. 뷰어: **HWP 5.0**(데스크톱 파서의 규칙을 옮김 + 셀 병합 반영, 자체 CFB 리더), **HWPX**(OWPML, cellAddr/cellSpan), **XLSX**(공유·인라인 문자열, 날짜 서식, 병합 셀, 5000행·200열 제한), CSV/TSV(UTF-8→EUC-KR), TXT. zip·inflate는 브라우저 기본 `DecompressionStream`으로 직접 구현(외부 라이브러리 없음, 압축 폭탄 제한). 렌더링은 `textContent`만(문서 내용이 HTML로 해석되지 않음). 닫기·10분 무입력·탭 종료 시 해제(바이트 0으로 덮어쓰기 시도). 잘못된 비밀번호 재시도 시 암호화된 다운로드를 재사용.
테스트(`npm test`, node:test 19개): 데스크톱 앱 추출기와 **같은 문단·표**(HWP·HWPX·XLSX·CSV, `tools/make_ext_fixtures.py`가 만든 기대값), 데스크톱 앱이 만든 7z·AES-ZIP을 **합성 복구 키**로 해제, 복구 키 비밀번호 파이썬과 일치, 확장 프로그램이 만든 7z 왕복, 개인정보 규칙 정적 검사(접속 대상, 권한, innerHTML·eval 금지, 저장소엔 클라이언트 ID만, drive.file만, HWP 고지, 7-Zip WASM 해시·라이선스). 실제 브라우저 엔진(가짜 chrome API·가짜 Drive 하네스, `test/harness`)에서 로그인→목록→복구 키로 해제→CSV·XLSX·HWP·HWPX 표시→닫기→틀린 비밀번호→기억된 키로 두 번째 파일 열기 확인, 콘솔 오류 0. 테스트 전용 의존성 `@xmldom/xmldom@0.9.12`(MIT, 취약점 없는 버전 고정). CI에 확장 프로그램 잡(`setup-node` SHA 고정), 릴리스에 확장 프로그램 zip(`tools/build_extension.py`, 고정 타임스탬프) 추가. E0 시험용 `extension/probe` 삭제.

**D-081 gitleaks 예외 2건 (조사 후, 2026-09-27)**
E1 푸시 직후 디렉터리 스캔에서 3종 발견 → 모두 조사: ① 확장 프로그램 manifest의 `key` = **RSA 공개키**(확장 프로그램 ID 고정용, 공개가 정상, 개인키는 생성 후 보관하지 않음) ② 테스트 픽스처의 **합성 복구 키에서 계산한 시험용 비밀번호**(실제 데이터를 보호하지 않음) ③ 픽스처 생성기의 합성 복구 키 상수. 조치: ②는 비밀번호 대신 16자 확인값만 저장하도록 바꿈, ③은 상수 이름에서 탐지 키워드를 없앰 → 예외 없이 해결. ①은 제거할 수 없어 **그 공개키 값만** 허용, ②③이 이미 들어간 **푸시된 커밋 1개만** 허용(공개 저장소 이력 강제 재작성 대신). `.gitleaks.toml`에 이유와 함께 기록, 그 외 규칙은 기본값 그대로.

**D-082 확장 프로그램 E2: 저장·PDF·사진·워드 (2026-09-27)**
① **저장**: `downloads` 권한 없이, 경고 창의 「저장」 버튼에서만 한 번짜리 `<a download>` 링크로 저장(권한 최소화, 10초 뒤 URL 해제). ② **PDF**: pdf.js 6.3.289(Apache-2.0)를 npm 배포본 그대로 넣음(sha512 무결성 확인, sha256을 테스트로 고정). 한글 PDF용 CMap·JBIG2/OpenJPEG/qcms 디코더(BSD/MIT)·Foxit 글꼴(BSD) 포함, **GPL인 Liberation 글꼴과 스크립트 엔진(QuickJS)·소스맵은 제외**. `isEvalSupported:false`, XFA 끔, 캔버스로만 그림(텍스트·링크 층 없음), 최대 200쪽. 모든 자원은 확장 프로그램 안에서 불러와 CSP(`connect-src 'self'`) 변경 없음. ③ **DOCX**: mammoth.js 대신 자체 해석기(기존 zip·XML 재사용, 문단·표·가로/세로 병합) — 번들러 없이 의존성 0. 암호 DOCX(OLE)는 안내. ④ **사진**: PNG·JPG·GIF·WEBP·BMP를 blob URL로, 닫으면 해제. SVG는 보이지 않음(안전하게 두기 위해 저장 안내).

**D-083 확장 프로그램 E3: 다시 암호화·업로드 (2026-09-27)**
데스크톱 앱과 같은 안전 순서: 7z AES-256+헤더 암호화 → **다시 풀어 파일별 SHA-256 비교** → 업로드(재개 가능 업로드, 한 번의 PUT) → **다시 받아 SHA-256 비교** → 두 확인이 모두 성공했을 때만(사용자가 켠 경우) 예전 보관 파일을 **휴지통으로**(영구 삭제 없음). 이름은 앱과 같은 `보관_날짜_무작위8자.7z`, 비밀번호는 복구 키로 열었으면 새 태그로 파생(D-074), 입력 비밀번호로 열었으면 그대로 재사용. 비밀(복구 키 원시값·비밀번호)은 보관 파일이 열려 있는 동안만 메모리에. 폴더 구조 유지(7-Zip에 상대 경로). 업로드 위치는 예전 파일의 폴더, `drive.file`로 거부(403/404)되면 내 드라이브 맨 위. 권한은 여전히 `drive.file`만. 상호 호환: 확장 프로그램이 만든 보관 파일을 데스크톱 테스트(`tests/unit/test_extension_interop.py`)가 복구 키로 엶.

---

## H. SPEC 11장 검증 기록

| # | 항목 | 상태 | 확인일 | 출처·결과 |
|---|---|---|---|---|
| V1 | 게시 상태·사용자 유형별 제약 | **확인** | 2026-09-26 | [앱 대상 관리](https://support.google.com/cloud/answer/15549945), [미확인 앱](https://support.google.com/cloud/answer/7454865), [API 제어](https://knowledge.workspace.google.com/admin/apps/control-which-apps-access-google-workspace-data). 테스트 상태: 테스트 사용자 100명, 승인 7일 후 만료(기본 프로필 범위만 쓰는 앱 제외). 미심사 프로덕션: 경고 화면 + 신규 사용자 누적 100명 한도, 소유자 본인 승인 가능. 내부 앱: 심사 불필요, 단 Drive 같은 제한 서비스는 관리 콘솔 API 제어에서 신뢰(Trusted)/특정 데이터 지정 또는 '내부 앱 신뢰' 필요 |
| V2 | 루프백·PKCE, 토큰 철회 엔드포인트 | **확인** | 2026-09-26 | [데스크톱 앱 OAuth](https://developers.google.com/identity/protocols/oauth2/native-app). 리디렉션 `http://127.0.0.1:포트`(또는 `[::1]`), 임의 포트; `localhost`는 방화벽 문제 가능. PKCE: 43~128자, S256 권장. 인증 `accounts.google.com/o/oauth2/v2/auth`, 토큰 `oauth2.googleapis.com/token`, 철회 `oauth2.googleapis.com/revoke`(200=성공, 프로젝트의 모든 범위 철회). 데스크톱 앱은 갱신 토큰 항상 발급. OOB·사용자 지정 URI 스킴은 지원 종료 |
| V3 | `drive.metadata.readonly`로 권한 목록 조회 가능 범위 | **확인** | 2026-09-26 | [permissions.list](https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/list): 이 범위로 호출 가능. 공유 권한 없는 호출자는 거부(403). pageSize 최대 100, 미지정 시 공유 드라이브 100개·내 드라이브 전체 |
| V4 | `visibility` 검색어, 공유 드라이브 매개변수 | **확인** | 2026-09-26 | [파일 검색](https://developers.google.com/workspace/drive/api/guides/search-files), [files.list](https://developers.google.com/workspace/drive/api/reference/rest/v3/files/list): visibility 값은 `anyoneCanFind`/`anyoneWithLink`/`limited` 3개뿐(도메인 값 없음). corpora `user`/`domain`/`drive`/`allDrives`, 공유 드라이브는 `supportsAllDrives`+`includeItemsFromAllDrives`. pageSize 최대 1000. `incompleteSearch=true`면 결과 일부 생략. fake_drive를 이에 맞춰 수정 |
| V5 | 상속 필드 제공 범위, 제한·확장 액세스 폴더 | **확인** | 2026-09-26 | [Permission](https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions), [File](https://developers.google.com/workspace/drive/api/reference/rest/v3/files), [제한된 액세스 폴더](https://developers.google.com/workspace/drive/api/guides/limited-expansive-access): `permissionDetails.inheritedFrom`은 공유 드라이브에서만. File `permissions`·`shared`·`owners`·`writersCanShare`는 공유 드라이브 항목에 없음, `hasAugmentedPermissions`는 공유 드라이브만. `inheritedPermissionsDisabled=true` 폴더는 내 드라이브·공유 드라이브 모두 가능, 차단된 사용자는 `view=metadata`·reader 항목으로 표시. 다운로드 제한은 `downloadRestrictions`(신규)와 `copyRequiresWriterPermission` |
| V6 | 다운로드·인쇄·복사 제한 필드 | **확인** | 2026-09-26 | [콘텐츠 보호](https://developers.google.com/workspace/drive/api/guides/content-restrictions): `downloadRestrictions.itemDownloadRestriction`(설정 가능)과 `effectiveDownloadRestrictionWithContext`(읽기 전용). `restrictedForWriters=true`는 뷰어 제한도 포함. 구형 `copyRequiresWriterPermission=false`로 쓰면 둘 다 해제됨 → 두 필드를 함께 쓰지 말 것. 소유자/관리자만 설정 → D-056 |
| V7 | `files.export` 크기 한도 | **확인** | 2026-09-26 | [다운로드·내보내기](https://developers.google.com/workspace/drive/api/guides/manage-downloads), [내보내기 형식](https://developers.google.com/workspace/drive/api/guides/ref-export-formats): 내보내기 10MB 제한(초과 시 exportLinks로 브라우저 다운로드 권장 → 앱은 `검사 불가`로 표시). 시트 CSV/TSV는 첫 시트만 → XLSX 사용. 내보내기는 부분(Range) 다운로드 불가 |
| V8 | 다운로드 리디렉션 호스트 | 초안 적용 | 2026-09-26 | 공식 문서에 리디렉션 호스트 언급 없음. `alt=media`는 www.googleapis.com으로 요청, 리디렉션 시 GuardedHttp가 대상을 재검사(허용: *.googleusercontent.com). **사용자 실계정 탐지 테스트에서 다운로드 실패(차단)가 없는지로 확정** |
| V9 | 알림 메일 끄기, 리소스 키 변화 | **확인** | 2026-09-26 | [permissions.create](https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/create): `sendNotificationEmail` 기본 true, 사용자·그룹 공유에 적용, 소유권 이전 시 끌 수 없음. [permissions.update](https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/update): 같은 파일 동시 변경은 마지막 것만 적용. resourceKey는 파일 속성으로 권한 재생성과 무관 → D-055 |
| V10 | 주민번호 2020.10 개편, 차세대 여권 형식 | **부분 확인** | 2026-09-26 | [정책브리핑](https://www.korea.kr/briefing/policyBriefingView.do?newsId=148872723): 2020년 10월부터 성별 자리 뒤 6자리 임의번호(지역번호 폐지), 기존 번호는 유지 → 신규 번호는 검증식 불일치 가능 → `의심` 처리. 차세대 전자여권(2021.12.21~) [외교부](https://www.mofa.go.kr/www/brd/m_4080/view.do?seq=371764)는 '번호 체계 변경'만 명시하고 형식은 본문에 없음 → 알려진 형식(영문1+숫자3+영문1+숫자4)과 기존 형식(영문1+숫자8)을 모두 탐지, 키워드 없으면 `의심` |
| V11 | HWP 5.0 공개 문서 사용 조건 | **확인** | 2026-09-26 | [한컴 글 문서 파일 구조 5.0 rev1.3](https://cdn.hancom.com/link/docs/%ED%95%9C%EA%B8%80%EB%AC%B8%EC%84%9C%ED%8C%8C%EC%9D%BC%ED%98%95%EC%8B%9D_5.0_revision1.3.pdf) 저작권 조항: 결과물의 UI·매뉴얼·도움말·소스에 "본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다." 기재, 결과물 저작권은 개발자에게. 레코드 구조·태그 ID·제어 문자 표·표/셀 구조를 같은 문서에서 확인해 파서 구현 → D-048 |
| V12 | py7zr AES-256 + 헤더 암호화 | **부분 확인** | 2026-09-26 | [py7zr API 문서](https://py7zr.readthedocs.io/en/latest/api.html): `password` 지정 시 암호화, `header_encryption=True`로 헤더(파일명) 암호화, 필터 `FILTER_CRYPTO_AES256_SHA256`(7zAES)+LZMA2 지원. py7zr 1.1.3으로 라운드트립·틀린 비밀번호 실패·보관 파일 안에 파일명 평문 없음 확인(테스트). 문서에 원본 7-Zip 암호화 호환 언급 없음(심볼릭 링크만 비호환 명시) → **7-Zip/Keka로 여는 것은 사용자 실계정 테스트에서 확정** |
| V13 | PySide6 LGPL + PyInstaller onedir | **확인** | 2026-09-26 | [Qt LGPL 의무](https://www.qt.io/licensing/open-source-lgpl-obligations): 라이브러리 소스 제공(또는 입수 안내), 동적 링크 시 앱 소스 비공개도 가능(본 앱은 MIT 공개), 사용자가 라이브러리를 바꿔 다시 실행할 수 있어야 함, LGPL 전문과 눈에 띄는 고지, 폐쇄 장치 금지. → onedir로 Qt를 별도 동적 라이브러리로 두고, NOTICE_KO.txt에 교체 방법·소스 주소, LGPL/GPL 전문 동봉, 정보 창·README에 고지 (D-076) |
| V14 | 무료 코드 서명 (Windows) | **확인** | 2026-09-26 | [SignPath Foundation](https://signpath.org/terms): OSS는 무료. 조건: OSI 승인 라이선스(상업 이중 라이선스 불가), 비공개 구성요소 없음, 활발히 유지, 이미 배포 가능한 상태, 팀원 MFA, 역할 분리, 프로젝트 사이트에 코드 서명 정책 게시, 소스에서 빌드 검증. → 1.0 배포 후 신청 검토(첫 릴리스는 미서명 + SmartScreen 안내). macOS 공증은 유료(Apple Developer Program)라 미적용 |
| V15 | 앱 이름 "Drive" 브랜드 가이드라인 | **부분 확인** | 2026-09-26 | [Drive 브랜드 가이드](https://developers.google.com/workspace/drive/api/guides/branding): 앱 이름 규정은 없음. 'Google Drive'를 줄여 쓰지 말 것, 상표 고지 문구 요구. → 앱 이름에 'Google'은 쓰지 않고, 정보 창·README·릴리스 노트·NOTICE에 "Google Drive는 Google LLC의 상표이며 제휴·보증 없음" 고지. OAuth 동의 화면 브랜드 검증을 받을 경우 이름 변경 요구 가능성 있음(사용자별 BYO 클라이언트라 현재는 해당 없음) |
| V16 | CSE 교육용 에디션 지원 범위 | **확인** | 2026-09-26 | [클라이언트 측 암호화 정보](https://knowledge.workspace.google.com/admin/security/about-client-side-encryption?hl=ko): 지원 에디션 Frontline Plus, Enterprise Plus, Education Standard, Education Plus (Education Fundamentals·Teaching and Learning Upgrade는 명시 없음). Drive 파일에 적용. API로 암호화 파일 내용을 읽는 방법은 문서에 없음 → 앱은 CSE 파일을 `검사 불가`로 안내(점검표 문구 D-072) |
