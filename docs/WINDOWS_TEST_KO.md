# 윈도우에서 Claude와 함께 테스트하기

Mac에서 개발·자동 테스트는 하지만, **윈도우 화면·설치·키체인(자격 증명 관리자)·작업 표시줄 아이콘·시작 프로그램**은 실제 윈도우에서만 확인할 수 있습니다. 윈도우 PC의 Claude Code에게 이 문서를 주면 같은 저장소로 이어서 점검·수정할 수 있습니다.

## 1. 윈도우 PC 준비 (한 번)

PowerShell을 열고 차례로 실행합니다.

1. Git: <https://git-scm.com/download/win> 설치
2. uv(파이썬 도구):
   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```
3. Node.js LTS: <https://nodejs.org> (확장 프로그램 테스트용)
4. GitHub CLI: <https://cli.github.com> 설치 후 `gh auth login` (변경을 올릴 때 필요)
5. Claude Code: Claude 데스크톱 앱(Code 탭) 또는 `npm install -g @anthropic-ai/claude-code`
6. 저장소 받기 (한글·공백이 없는 경로 권장):
   ```powershell
   cd $HOME; git clone https://github.com/janghwansangai/drive-privacy-guardian.git; cd drive-privacy-guardian
   ```

## 2. Claude에게 줄 첫 메시지 (그대로 복사)

> 이 저장소는 「개인정보 보안관」(Drive Privacy Guardian)이야. 먼저 `CLAUDE.md`, `docs/WINDOWS_TEST_KO.md`, `DECISIONS.md`의 마지막 D-097~D-105를 읽어. 그다음 `uv sync --group build`, `uv run pytest -q`, `uv run ruff check .`, `uv run mypy src`, `cd extension/app; npm ci; npm test`를 돌려 결과를 알려 줘. 그 뒤 이 문서 4장의 윈도우 점검표를 나와 함께 하나씩 진행하고, 문제가 있으면 원인을 찾아 테스트와 함께 고쳐서 `windows-test` 브랜치로 올려 줘. 실제 구글 계정 로그인·권한 변경·암호화는 내가 직접 할게. 나에게 비밀번호·복구 키·토큰·클라이언트 JSON 내용을 묻지 마.

## 3. 소스에서 바로 실행 (설치 파일 없이)

```powershell
uv run dpg-gui
```

- 설치한 앱과 **같은 키체인(자격 증명 관리자) 항목과 설정**을 씁니다. 따라서 이미 로그인했다면 그대로 이어집니다.
- 따로 시험하려면 실행 전에 `$env:DPG_HOME = "$HOME\dpg-test"`로 기록 폴더를 나눌 수 있습니다. 로그인 정보는 키체인에 있어 공유됩니다.
- 설치 파일 만들기: `uv run --group build python tools/build.py` → `dist\` (만든 앱의 자가 진단까지 자동으로 확인)

## 4. 윈도우 점검표 (성공/실패 기록)

| # | 확인할 것 | 어떻게 |
|---|---|---|
| 1 | 설치·첫 실행 | 사이트에서 Windows용 zip → 압축 풀기 → exe → "PC 보호" → 추가 정보 → 실행 |
| 2 | 자가 진단 | `& ".\Drive Privacy Guardian.exe" --selftest --selftest-out=selftest.txt; Get-Content selftest.txt` → "결과: 정상" |
| 3 | 로그인·열쇠 | 설정 마법사 → JSON 선택 → 로그인. 계정 줄에 「열쇠: 프로젝트」 표시 |
| 4 | 공유 점검 | 「링크로 공개된 내 파일만」 → 위치 칸에 **전체 폴더 경로** |
| 5 | 공유 설정 바꾸기 | 파일 체크 → 「🔗 공유 설정 바꾸기」 → **미리보기가 열려야 함**(v0.2.5 버그) |
| 6 | 상위 폴더 | 상속 공유면 「📁 상위 폴더에서 바꾸기」로 이동 |
| 7 | 내용 확인·열기 | 파일 하나 클릭 → 「🔍 내용 확인」, 「↗ 드라이브에서 열기」가 **그 파일**을 여는지 |
| 8 | 개인정보 검사 | 「🔎 개인정보 검사」(고른 파일만) |
| 9 | 복구 키·암호화 | 처음 암호화 → 복구 키 만들기 → 마지막 5자 입력 → 암호화 → 원본 휴지통 → 「보관 파일 풀기」 |
| 10 | 한글 경로 | 바탕화면의 한글 폴더에서 실행·보고서 저장 |
| 11 | 예약·아이콘 | 「⏰ 예약」 몇 분 뒤 → 창 닫기 → 작업 표시줄 ★ → 시작·완료 알림 |
| 12 | 시작 프로그램 | 「로그인하면 자동으로 켜기」 → 설정 → 앱 → 시작 프로그램에 「개인정보 보안관」 → 재부팅 후 ★ |
| 13 | 잠자기 방지 | 긴 검사 중 절전 시간 지나도 안 잠기는지 |
| 14 | 모든 기록 삭제 | 설정 → 모든 기록 삭제 → 시작 프로그램 항목도 사라지는지 |
| 15 | 화면 배율 | 디스플레이 배율 125%·150%에서 글자·버튼이 잘리지 않는지 |

## 5. 결과를 Mac 쪽과 합치기

- 윈도우 Claude가 `windows-test` 브랜치로 올리면, Mac 쪽(또는 GitHub)에서 검토해 `main`에 합칩니다.
- GitHub Actions가 Mac·Windows·Linux 테스트를 모두 다시 돌립니다.
- 두 컴퓨터에서 **같은 브랜치를 동시에 고치지 않도록**, 한쪽 작업이 끝나면 올리고 다른 쪽은 `git pull` 후 이어 갑니다.
