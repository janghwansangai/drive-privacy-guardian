## 개인정보 보안관

구글 드라이브의 **공유권한 점검 · 개인정보 점검 · 암호화 관리**를 내 컴퓨터 안에서만 하는 무료 앱입니다. 구글 외 어떤 서버와도 통신하지 않습니다.

소개·사용법: https://privacy-guardian.janhan97.workers.dev

### v0.2.0 새 기능
- **크롬 확장 프로그램**: 구글 드라이브 옆 패널에서 공유 점검 · 개인정보 점검 · 암호화 관리
  - 드라이브에서 선택한 파일·폴더를 바로 암호화, 더블클릭으로 크게 보기, 같은 폴더에 풀기
  - 한글·엑셀·워드·PDF·사진 미리보기 (메모리에서만)
  - 복구 키 = 만능 키, 개인 비밀번호 한 번으로 잠금 해제, 15분 자동 잠금
  - 로그인 한 번, 그림 설명서
- 암호화 파일 이름에 원래 이름 표시: `상담기록.hwp (암호화 a1b2c3d4).7z`
- 데스크톱 앱: 처리한 항목의 체크 해제, 이름을 「개인정보 보안관」으로

### 받을 파일
- **Windows 10/11 (64비트)**: `DrivePrivacyGuardian-Windows-x64.zip`
- **Mac (Apple 칩)**: `DrivePrivacyGuardian-macOS-arm64.dmg` (또는 `.zip`)
- **크롬 확장 프로그램**: `DrivePrivacyGuardian-Extension.zip` — 설치: `docs/EXTENSION_SETUP_KO.md`
- 버전 번호가 붙은 파일은 같은 내용입니다.
- `SHA256SUMS.txt`: 파일 확인용 체크섬

### 처음 실행할 때 (코드 서명 없음)
- **Mac**: 앱을 연 뒤 막히면 **시스템 설정 → 개인정보 보호 및 보안 → 그래도 열기**
- **Windows**: 압축을 푼 뒤 실행, "PC 보호" 화면에서 **추가 정보 → 실행**

자세한 안내: `docs/INSTALL_KO.md` · 사용법: `docs/USER_GUIDE_KO.md` · 개인정보: `PRIVACY.md`

### 확인 방법
- 체크섬: `SHA256SUMS.txt`와 비교
- 빌드 출처: `gh attestation verify <파일> --repo <이 저장소>`

---
본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다. Qt/PySide6는 LGPL-3.0으로 사용합니다(앱 안의 NOTICE_KO.txt). Google Drive는 Google LLC의 상표이며, 이 앱은 Google과 제휴하지 않았습니다.
