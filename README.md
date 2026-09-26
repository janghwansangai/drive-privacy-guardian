# Drive Privacy Guardian

구글 드라이브의 공유 권한과 개인정보 포함 파일을 **내 컴퓨터 안에서만** 점검하는 무료 데스크톱 앱입니다 (Mac·Windows).

**할 수 있는 일**
- 공유 권한 감사: 링크 공개·외부 공유·도메인 공개 파일 찾기 (내 드라이브·공유 드라이브·특정 폴더)
- 개인정보 탐지: 주민번호·연락처·계좌 등, 한글(HWP·HWPX)·오피스·PDF·구글 문서 지원
- 공유 설정 일괄 변경: 구글 공유 화면과 같은 용어, 미리보기·되돌리기
- 암호화 보관: 7z(AES-256, 파일명까지 암호화), 복구 키, 드라이브에서 바로 풀기
- 변경분만 다시 검사·자동 반영, 폴더 정리, 보안 점검표

**설치**: [docs/INSTALL_KO.md](docs/INSTALL_KO.md) · **사용법**: [docs/USER_GUIDE_KO.md](docs/USER_GUIDE_KO.md)

## 약속
- 데이터는 사용자 PC ↔ 구글 서버 사이에서만 오갑니다. 개발자 서버, 원격 분석, 외부 AI 호출이 없습니다.
- 탐지한 개인정보 원문은 저장하지 않습니다(유형·건수·위치만).
- 기본은 읽기 전용이며, 변경은 미리보기 → 승인 후에만 실행합니다. 영구 삭제 기능은 없습니다.

구글 로그인 설정: [docs/SETUP_GOOGLE_KO.md](docs/SETUP_GOOGLE_KO.md) · 학교 관리자: [docs/ADMIN_SETUP_KO.md](docs/ADMIN_SETUP_KO.md) · 보안 점검표: [docs/SERVER_SECURITY_KO.md](docs/SERVER_SECURITY_KO.md)

자세한 내용: [PRIVACY.md](PRIVACY.md) · 설계: [SPEC.md](SPEC.md) · 결정 기록: [DECISIONS.md](DECISIONS.md)

## 개발
```bash
uv sync
uv run pytest            # 소켓 차단 상태로 실행
uv run ruff check . && uv run mypy src
uv run pre-commit install
uv run --group build python tools/build.py   # 설치 파일 만들기 (dist/)
```

배포: `v버전` 태그를 올리면 GitHub Actions가 Mac·Windows 설치 파일, 체크섬, 빌드 출처 증명을 만들어 **초안(draft) 릴리스**를 만듭니다(`.github/workflows/release.yml`).

라이선스: MIT · Qt/PySide6는 LGPL-3.0 ([packaging/NOTICE_KO.txt](packaging/NOTICE_KO.txt))

Google Drive는 Google LLC의 상표입니다. 이 프로젝트는 Google과 제휴하거나 Google의 보증을 받지 않았습니다.

---
본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다.
