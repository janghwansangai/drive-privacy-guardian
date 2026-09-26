# E0 시험용 확장 프로그램

확장 프로그램 계획(docs/EXTENSION_PLAN.md)의 E0 검증용입니다. 로그인, Drive 권한(drive.file / drive.readonly), 7-Zip WASM 실행만 확인합니다. 드라이브를 바꾸지 않고, 파일 내용을 받지 않습니다.

- 확장 프로그램 ID(고정): `gjlomabldjleleakkeffjojhjdgeekgj` — manifest의 `key`(공개키)로 고정. 개인키는 보관하지 않습니다(압축해제 설치에는 필요 없음).
- vendor/7z-wasm: npm `7z-wasm@1.2.0` (7-Zip 24.09, GNU LGPL + unRAR restriction — License.txt, unRarLicense.txt). 이 코드는 RAR(WinRAR) 호환 압축 프로그램을 만드는 데 사용할 수 없습니다.
  - 7zz.es6.js sha256 `f2010cb8d734cac7290a2b27278b30f2bbcd0d354f900173b4cad6b7d46a767a`
  - 7zz.wasm   sha256 `e16c6997e2eaa89575c0dd1f305074be629c3f4d87246244d37fd19debc8a285`

사용 방법: docs/EXTENSION_E0_TEST_KO.md
