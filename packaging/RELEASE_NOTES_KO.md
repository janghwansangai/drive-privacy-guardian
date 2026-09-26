## Drive Privacy Guardian

구글 드라이브 공유 권한·개인정보 포함 파일을 **내 컴퓨터 안에서만** 점검하는 무료 앱입니다. 구글 외 어떤 서버와도 통신하지 않습니다.

### 받을 파일
- **Mac (Apple 칩)**: `DrivePrivacyGuardian-*-macOS-arm64.dmg`
- **Windows 10/11 (64비트)**: `DrivePrivacyGuardian-*-Windows-x64.zip`
- **크롬 확장 프로그램(선택)**: `DrivePrivacyGuardian-Extension-*.zip` — 암호화된 파일을 크롬에서 메모리로만 풀어 보기(한글·엑셀 등). 설치: `docs/EXTENSION_SETUP_KO.md`
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
