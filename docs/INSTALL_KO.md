# 설치 안내 (Mac · Windows)

## 1. 내려받기
GitHub 저장소의 **Releases** 페이지에서 최신 버전을 받습니다.

| 컴퓨터 | 파일 |
|---|---|
| Mac (Apple 칩: M1 이후) | `DrivePrivacyGuardian-버전-macOS-arm64.dmg` (또는 `.zip`) |
| Windows 10/11 (64비트) | `DrivePrivacyGuardian-버전-Windows-x64.zip` |

## 2. (권장) 파일이 진짜인지 확인
같은 페이지의 `SHA256SUMS.txt`에 적힌 값과 내 파일의 값이 같은지 봅니다.

- Mac 터미널: `shasum -a 256 ~/Downloads/DrivePrivacyGuardian-*.dmg`
- Windows PowerShell: `Get-FileHash $HOME\Downloads\DrivePrivacyGuardian-*.zip -Algorithm SHA256`

GitHub CLI가 있으면 빌드 출처(이 저장소의 GitHub Actions에서 만들어졌는지)도 확인할 수 있습니다:
`gh attestation verify 파일이름 --repo <저장소 주소>`

## 3. 설치와 첫 실행

이 앱은 무료 배포라 **코드 서명(유료 인증서)이 없습니다.** 그래서 처음 실행할 때 운영체제가 한 번 막습니다. 아래 순서로 한 번만 허용하면 됩니다.

### Mac
1. `.dmg`를 열고 **Drive Privacy Guardian**을 **응용 프로그램(Applications)** 폴더로 끌어다 놓습니다.
2. 응용 프로그램 폴더에서 앱을 엽니다 → "확인되지 않은 개발자" 경고가 나오면 **완료(또는 취소)**를 누릅니다.
3. **시스템 설정 → 개인정보 보호 및 보안** → 아래쪽 "Drive Privacy Guardian이(가) 차단되었습니다" 옆 **그래도 열기** → 비밀번호 입력 → 다시 **열기**.
4. 다음부터는 그냥 열립니다.

### Windows
1. `.zip`을 오른쪽 클릭 → **압축 풀기** (zip 안에서 바로 실행하지 마세요).
2. 풀린 폴더의 **Drive Privacy Guardian.exe**를 실행합니다.
3. "Windows의 PC 보호" 화면이 나오면 **추가 정보 → 실행**.
4. 폴더를 원하는 곳(예: `문서`)에 두고, exe를 오른쪽 클릭 → 바탕화면에 바로 가기를 만들어 쓰면 편합니다.

## 4. 설치가 잘 됐는지 자가 진단 (선택)
- Mac 터미널: `"/Applications/Drive Privacy Guardian.app/Contents/MacOS/Drive Privacy Guardian" --selftest`
- Windows PowerShell(앱 폴더에서): `& ".\Drive Privacy Guardian.exe" --selftest --selftest-out=selftest.txt; Get-Content selftest.txt`

"결과: 정상"이 나오면 됩니다. 인터넷에 접속하지 않고 확인합니다.

## 5. 처음 설정
앱이 열리면 설정 마법사가 구글 로그인까지 안내합니다: [SETUP_GOOGLE_KO.md](SETUP_GOOGLE_KO.md) · 사용법: [USER_GUIDE_KO.md](USER_GUIDE_KO.md)

## 6. 업데이트
자동 업데이트는 없습니다(외부 통신을 하지 않기 위해). 「도움말 → 새 버전 확인」을 누르면 브라우저로 Releases 페이지가 열립니다. 새 버전을 받아 기존 앱을 바꾸면 되고, 설정·기록은 그대로 남습니다.

## 7. 삭제
1. (선택) 앱에서 **로그아웃**(구글 권한 철회), 「설정 → 모든 기록 삭제」.
2. 앱을 지웁니다 (Mac: 응용 프로그램에서 휴지통으로 / Windows: 폴더 삭제).
3. 남은 설정 폴더를 지우려면:
   - Mac: `~/Library/Application Support/Drive Privacy Guardian`
   - Windows: `%LOCALAPPDATA%\DrivePrivacyGuardian`
4. 키체인에 남은 항목은 이름 `drive-privacy-guardian`으로 찾을 수 있습니다. **보관 파일 비밀번호와 복구 키를 지우기 전에, 종이에 적어 둔 복구 키가 있는지 꼭 확인하세요.**
