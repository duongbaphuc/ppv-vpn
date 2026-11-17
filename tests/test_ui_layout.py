"""UI smoke, font, mnemonic, and layout geometry tests."""

from __future__ import annotations

import re
import sys

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QPushButton,
    QRadioButton,
)

from ppv.models import AppRule, AppSettings, WireGuardProfile
from ppv.theme import DARK_STYLESHEET, create_app_pixmap, create_dark_palette
from ppv.ui.dashboard_page import DashboardPage
from ppv.ui.main_window import MainWindow
from ppv.ui.monitor_page import MonitorPage


def _ensure_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    assert isinstance(app, QApplication)
    app.setPalette(create_dark_palette())
    app.setStyleSheet(DARK_STYLESHEET)
    return app


def test_dashboard_hero_button_not_clipped_with_both_banners() -> None:
    app = _ensure_app()
    settings = AppSettings(
        active_profile_id="p1",
        app_rules=[
            AppRule(
                display_name="Chrome",
                exe_name="chrome.exe",
                exe_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                enabled=True,
            )
        ],
    )
    prof = WireGuardProfile(
        id="p1",
        name="WARP+ (warpplus.conf)",
        private_key="A" * 43 + "=",
        addresses=["172.16.0.2/32"],
        dns=["1.1.1.1"],
        public_key="B" * 43 + "=",
        endpoint_host="engage.cloudflareclient.com",
        endpoint_port=2408,
    )
    page = DashboardPage(settings=settings, profiles=[prof])
    page.resize(750, 620)
    page.conflict_label.setText(
        "Cảnh báo: Dịch vụ VPN toàn hệ thống (WireGuardTunnel$warpplus) đang chạy."
    )
    page.conflict_banner.setVisible(True)
    page.admin_banner.setVisible(True)
    page.show()
    app.processEvents()

    assert page.connect_btn.height() == 130
    assert page.connect_btn.width() == 130
    hero = page.connect_btn.parentWidget()
    assert hero is not None
    # Hero card must stay taller than the 130px hero button + vertical padding
    assert hero.height() >= 174
    page.close()


def test_main_window_no_accidental_mnemonics_and_clean_fonts() -> None:
    app = _ensure_app()
    win = MainWindow(auto_connect=False, start_minimized=False, single_instance=None)
    win.show()
    app.processEvents()

    # Check every clickable button/checkbox/radio text escapes literal '&' as '&&'
    single_amp_re = re.compile(r"(?<!&)&(?!&)")
    for cls in (QPushButton, QCheckBox, QRadioButton):
        for widget in win.findChildren(cls):
            txt = widget.text()
            assert not single_amp_re.search(txt), f"Unescaped '&' in widget text: {txt!r}"

    nav_texts = [btn.text() for btn in win.nav_buttons]
    assert "Giám sát && Nhật ký" in nav_texts

    mon: MonitorPage = win.monitor_page
    assert "Consolas" in mon.log_box.font().family() or "Consolas" in mon.log_box.styleSheet()
    win._force_quit = True
    win.close()


def test_tray_icon_colors_by_state() -> None:
    _ensure_app()
    # Sample interior shield pixel below center fork stem (x=24, y=42 out of 64)
    idle_img = create_app_pixmap(connected=False, size=64).toImage()
    idle_px = idle_img.pixelColor(22, 40)
    # Gray slate (#64748b): B is slightly higher than R (~39 diff), never bright blue
    assert idle_px.red() >= 90 and idle_px.blue() < 160

    conn_img = create_app_pixmap(connected=True, size=64).toImage()
    conn_px = conn_img.pixelColor(22, 40)
    assert conn_px.green() > conn_px.red() and conn_px.green() > conn_px.blue()

    err_img = create_app_pixmap(state="error", size=64).toImage()
    err_px = err_img.pixelColor(22, 40)
    assert err_px.red() > err_px.green() and err_px.red() > err_px.blue()
