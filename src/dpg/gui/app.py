"""GUI entry point (`dpg-gui`)."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from PySide6.QtWidgets import QApplication

from dpg.core.logging import configure_logging
from dpg.core.net_guard import global_guard
from dpg.core.paths import app_data_dir, ensure_private_dir, log_dir
from dpg.gui.context import AppContext
from dpg.gui.main_window import MainWindow


def default_context() -> AppContext:
    from dpg.cli.audit_cmd import default_service
    from dpg.cli.main import default_manager

    return AppContext(manager_factory=default_manager, service_factory=default_service)


def create_window(ctx: AppContext) -> MainWindow:
    window = MainWindow(ctx)
    return window


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv
    if "--version" in args:
        from dpg import __version__

        print(f"Drive Privacy Guardian {__version__}")
        return 0
    if "--selftest" in args:
        from dpg.selftest import run

        skip = {"OS 보안 저장소"} if "--no-keychain" in args else None
        out = next((a.split("=", 1)[1] for a in args if a.startswith("--selftest-out=")), None)
        if out is None:
            return run(skip=skip)
        # A windowed build has no console (sys.stdout is None): write the report to a file.
        lines: list[str] = []
        code = run(lines.append, skip=skip)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return code
    # Principle 1: the network guard is installed before anything else runs.
    global_guard().install()
    ensure_private_dir(app_data_dir())
    configure_logging(ensure_private_dir(log_dir()))

    app = QApplication(args)
    app.setApplicationName("Drive Privacy Guardian")
    ctx = default_context()
    window = create_window(ctx)
    window.show()
    if not ctx.manager.status().logged_in:
        window.run_setup()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
