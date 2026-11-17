"""Entry point for PPV VPN desktop application."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import sys

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from ppv.single_instance import SingleInstanceController
from ppv.theme import DARK_STYLESHEET, create_dark_palette
from ppv.ui.main_window import MainWindow


def _set_app_user_model_id() -> None:
    with contextlib.suppress(Exception):
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PPV.PerAppVPN.Client.1")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PPV VPN — Per-App WireGuard & WARP+ Client")
    parser.add_argument("--connect", action="store_true", help="Tự động kết nối khi khởi động")
    parser.add_argument("--minimized", action="store_true", help="Thu nhỏ xuống khay hệ thống")
    parser.add_argument("--elevated", action="store_true", help="Đánh dấu khởi chạy lại với quyền Admin")
    args, qt_args = parser.parse_known_args(argv)

    _set_app_user_model_id()
    app = QApplication([sys.argv[0], *qt_args])
    app.setQuitOnLastWindowClosed(False)
    app.setFont(QFont("Segoe UI", 10))
    app.setPalette(create_dark_palette())
    app.setStyleSheet(DARK_STYLESHEET)

    single = SingleInstanceController(parent=app)
    wait_sec = 3.0 if args.elevated else 0.0
    if not single.start_listening(wait_for_release_sec=wait_sec):
        if not args.minimized:
            single.try_notify_existing()
        return 0

    window = MainWindow(
        auto_connect=args.connect,
        start_minimized=args.minimized,
        single_instance=single,
    )
    single.show_requested.connect(window.bring_to_front)
    if not args.minimized:
        window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
