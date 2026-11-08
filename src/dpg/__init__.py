"""Drive Privacy Guardian."""

__version__ = "0.2.10"

# Public source repository (set when the GitHub repository is created). "새 버전 확인" only opens
# its Releases page in the user's browser — the app itself never checks for updates (SPEC 9).
REPOSITORY_URL = "https://github.com/janghwansangai/drive-privacy-guardian"

# 「오류 신고」 (D-109): the maker's report form, opened in the user's browser with only the app
# name, version and screen name in the address. The app itself sends nothing (CLAUDE.md rule 1).
BUG_REPORT_URL = (
    "https://script.google.com/macros/s/"
    "AKfycbxsRD7vRlEP9oKlvlDDPww8cYaDadTTIp1KrqYWSVU5qE5_gUh3bNUskBhHDlXH6FskvA/exec"
)
BUG_REPORT_APP = "google-scerct"
# 면책 안내: shown in the About box (the MIT LICENSE carries the binding English text).
DISCLAIMER_KO = (
    '이 프로그램은 무료로 "있는 그대로" 제공됩니다. '
    "개인정보 탐지는 놓치거나 잘못 찾을 수 있고, 프로그램에 오류가 있을 수 있습니다. "
    "중요한 파일은 미리 백업하고, 바꾸기 전 미리보기를 꼭 확인하세요. "
    "프로그램 사용으로 생긴 손해에 대해 만든 사람은 책임을 지지 않으며, "
    "개인정보 보호의 최종 책임은 사용자에게 있습니다."
)
MAKER_KO = "다있쌤"
