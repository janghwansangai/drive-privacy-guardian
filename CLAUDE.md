# CLAUDE.md — Drive Privacy Guardian

## 최우선 규칙
- 이 앱은 개인정보를 외부로 보내지 않는다. Google 인증·Drive API 허용 호스트 외 네트워크 코드를 추가하지 마라.
- 텔레메트리, 오류 보고 SDK, 외부 AI API, 유료 API, 자동 업데이트 호출을 추가하지 마라.
- 탐지된 개인정보 원문을 DB·로그·파일·예외 메시지·print에 남기지 마라. 저장은 유형·건수·신뢰도·위치만.
- 영구 삭제 API를 호출하는 코드를 작성하지 마라. 모든 쓰기 동작은 actions/ 모듈의 계획-승인-실행 경로로만.
- 서비스 계정, 도메인 전체 위임을 사용하지 마라.
- AGPL/GPL 라이브러리를 추가하지 마라. 새 의존성은 라이선스와 이유를 DECISIONS.md에 기록.

## 개발 데이터 규칙
- 실제 개인정보·실제 계정 데이터를 사용하지 마라. 테스트는 tools/gen_synthetic.py 출력과 tests/fakes/fake_drive.py만 사용.
- 실제 Google 계정으로 실행하는 명령은 사용자에게 실행을 요청하고, 결과는 통과/실패와 오류 코드만 받는다.
- 비밀 파일(*.json 클라이언트, 토큰, *.db, 보고서)을 커밋하지 마라. gitleaks가 막으면 우회하지 마라.

## 작업 방식
- SPEC.md의 Phase 순서를 지킨다. 현재 Phase는 STATUS.md에 있다.
- 기능 구현 전 SPEC.md 11장의 검증 항목을 공식 문서로 확인하고 DECISIONS.md에 날짜와 출처를 기록.
- 모든 변경은 테스트와 함께. tests/privacy/ 테스트가 실패하면 다른 작업보다 먼저 고친다.
- 명령: `uv run pytest`, `uv run ruff check .`, `uv run mypy src`, `uv run pytest tests/privacy`
- 사용자 대상 문구는 한국어, 코드·주석은 영어 식별자 + 필요 시 한국어 주석.

## 저장소 메모 (Phase 0에서 추가)
- 테스트는 pytest-socket으로 소켓이 차단된 상태에서 돈다. 루프백 소켓이 꼭 필요한 테스트만 `@pytest.mark.enable_socket`.
- 로거는 `dpg.core.logging.get_logger()`로만 만든다. `configure_logging()`이 모든 핸들러에 MaskingFilter를 붙인다.
- Drive API가 필요한 테스트는 `tests/fakes/fake_drive.py`의 `FakeDrive().service()`를 쓴다. 기본은 읽기 전용이며 쓰기 호출 시 테스트가 실패한다.
- 합성 데이터 재생성: `uv run python tools/gen_synthetic.py --out tests/fixtures/synthetic`
- 라이선스 검사: `uv run python tools/check_licenses.py`

## 저장소 메모 (Phase 1에서 추가)
- 모든 HTTP 요청은 `dpg.core.net_guard.http.GuardedHttp`(또는 `AuthManager.authorized_http()`)로만 보낸다.
- 인증 테스트는 `tests/fakes/fake_google_auth.py`의 `FakeGoogle`(가짜 토큰·철회·about 엔드포인트, 가짜 브라우저)와 `MemorySecretStore`를 쓴다. 실제 키체인을 건드리지 않는다.
- 테스트 중 앱 데이터 폴더는 `DPG_HOME`으로 임시 폴더에 격리된다(conftest 자동 적용).

## 저장소 메모 (Phase 2에서 추가)
- Drive 읽기는 `dpg.core.drive.client.DriveClient`로만 한다(쓰기 메서드 없음). 새 요청 매개변수는 `tests/unit/test_drive_real_client.py`(실제 클라이언트 + 번들 디스커버리)로 이름을 검증한다.
- 감사 결과 저장은 `dpg.core.store.audit_store.AuditStore`: 파일명·이메일은 반드시 `secret`(암호화) 열에만.
- 보고서는 `dpg.core.audit.report`: 기본 마스킹 + 수식 주입 방지 유지.

## 저장소 메모 (Phase 3에서 추가)
- GUI는 `uv run dpg-gui`. 테스트는 pytest-qt, 오프스크린(`QT_QPA_PLATFORM=offscreen`, conftest가 설정).
- GUI에서 QtNetwork·QtWebEngine을 쓰지 마라(가드 우회). 브라우저 열기는 `AppContext.open_url`(webbrowser).
- 대화상자는 `AppContext.notify/confirm`으로, 오류 문구는 `gui.tasks.user_message_for`로만.

## 저장소 메모 (Phase 4에서 추가)
- 추출기는 `dpg.core.extract`(메모리만, 위치는 번호만, 예외 메시지에 본문 금지). 새 형식은 `plan_for`에 등록.
- 탐지 규칙 변경 후 `uv run python tools/measure_detection.py --check`로 정밀도·재현율 확인. 새 규칙은 합성 데이터(`tools/gen_synthetic.py`)에 정답을 먼저 추가.
- HWP 파서를 고칠 때 한컴 공개 문서 표기(D-048)를 지우지 마라.

## 저장소 메모 (Phase 5에서 추가)
- 드라이브 쓰기는 `dpg.core.actions.writer.DriveWriter`에만 추가하라(정적 검사 테스트가 다른 곳의 쓰기를 막음). 실행은 항상 `ActionExecutor`(재조회·충돌·검증·기록)를 거친다.
- 권한 변경 계획은 `Origin.DIRECT` 권한만 대상으로 한다(D-054).

## 저장소 메모 (Phase 6에서 추가)
- 보관은 `dpg.core.vault`(archive: 메모리 암호화·검증, job: 받기→암호화→검증→업로드→재검증). 비밀번호는 로그·DB·명령행·파일 어디에도 두지 않는다(키체인 선택 저장만).
- 원본 휴지통은 `vault.job.trash_plan`(검증 통과 결과만)으로만, 이동은 `dpg.core.organize.build_move_plan`(권한 확대 차단)으로만 계획한다.

## 저장소 메모 (Phase 7에서 추가)
- 감사는 `AuditRunner.run_incremental`(변경분) → 불가하면 `run`(전체). 증분 로직을 바꾸면 `tests/integration/test_incremental.py`(증분 = 전체)를 반드시 통과시킨다. fake_drive에서 항목을 직접 고치는 테스트는 `fake.touch(id)`로 변경을 기록한다.
- GUI에서 DB는 `MainWindow._open_store()`로만 연다(보존 기간 설정 적용).
- 보관 비밀번호를 키체인에 저장할 때는 `store.wipe.remember_vault_password`(목록 관리 → 모든 기록 삭제에서 지울 수 있게).

## 저장소 메모 (Phase 8에서 추가)
- 설치 파일: `uv run --group build python tools/build.py` → `dist/`. 빌드된 앱에서 `--selftest`가 실패하면 빌드가 멈춘다. 새 런타임 의존성이나 데이터 파일을 추가하면 `packaging/dpg.spec`와 `dpg.selftest`를 함께 확인.
- 번들에 QtNetwork·Qt 네트워크 플러그인을 넣지 마라(spec의 `_DROP_BINARIES`).
- 워크플로의 액션은 전체 커밋 SHA로만 고정한다. 릴리스는 초안으로 만들어 사람이 공개한다.

## 저장소 메모 (확장 프로그램)
- `extension/app`은 빌드 단계가 없다. 테스트: `cd extension/app && npm ci && npm test`. 뷰어 화면 확인은 `.claude/launch.json`의 `extension-harness`(저장소 루트를 서빙: `/extension/app/test/harness/index.html`, 가짜 chrome API·가짜 Drive·가짜 업로드/휴지통). `test/harness/serve.py`(캐시 끔)로 서빙하며 주소는 `http://127.0.0.1:8765/...`.
- 확장 프로그램 코드는 `textContent`만 쓰고(innerHTML 금지), 접속은 googleapis.com만, 저장소에는 클라이언트 ID만 — `test/security.test.mjs`가 검사한다.
- 콘텐츠 스크립트는 `drive_watch.js` 하나(drive.google.com, 파일 ID만 전달, 페이지에는 크게 보기 iframe 하나만, 네트워크·저장 금지).
- 새 보관 파일은 항상 복구 키 파생 비밀번호(`lib/keyring.js`의 잠금 해제된 키). 저장소 허용 키: local `clientId`·`vaultWrap`(암호화)·`lockMinutes`, session `auth`·`vaultKey`. 전체 `drive` 범위는 `requestFullAccess()`(드라이브 파일 암호화)에서만.
- 파서를 바꾸면 `uv run python tools/make_ext_fixtures.py`로 기대값을 다시 만들고 데스크톱 앱과 같은 결과인지 확인한다.
- 확장 프로그램의 7z 쓰기를 바꾸면 `node test/make_interop.mjs`로 상호 호환 픽스처를 다시 만들고 `uv run pytest tests/unit/test_extension_interop.py`로 데스크톱 앱이 여는지 확인한다.
- 드라이브 쓰기는 `lib/drive.js`의 `upload`·`trash`만(영구 삭제 없음). 예전 보관 파일 휴지통은 `lib/reencrypt.js`에서 두 번의 확인 뒤에만.
- 확장 프로그램의 개인정보 규칙(`lib/detect.js`)은 데스크톱 `detect/rules.py`의 복사본이다. 한쪽을 바꾸면 다른 쪽도 바꾸고 `tools/make_ext_fixtures.py`로 기대값을 다시 만든 뒤 `test/detect.test.mjs`를 통과시킨다.
