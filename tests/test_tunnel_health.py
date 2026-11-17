"""Tests for WireGuard handshake health detection and probe helpers."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from ppv.core_manager import (
    VpnCoreManager,
    _is_noisy_debug_log,
    _parse_cloudflare_trace,
)
from ppv.models import AppSettings, WireGuardProfile
from ppv.theme import DARK_STYLESHEET, create_dark_palette
from ppv.ui.dashboard_page import DashboardPage


def _ensure_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    assert isinstance(app, QApplication)
    app.setPalette(create_dark_palette())
    app.setStyleSheet(DARK_STYLESHEET)
    return app


def test_parse_cloudflare_trace_and_noisy_filter() -> None:
    parsed = _parse_cloudflare_trace("fl=11f1\nip=104.28.222.46\nloc=SG\nwarp=plus\n")
    assert parsed["ip"] == "104.28.222.46"
    assert parsed["loc"] == "SG"
    assert parsed["warp"] == "plus"

    assert _is_noisy_debug_log(
        "+0700 2026-11-17 11:15:02 DEBUG endpoint/wireguard[wg-out]: routine: handshake worker 1 - started"
    )
    assert not _is_noisy_debug_log(
        "+0700 2026-11-17 11:15:02 DEBUG endpoint/wireguard[wg-out]: peer(bmXO) - received handshake response"
    )


def test_tunnel_health_warning_on_handshake_timeout_and_clear(tmp_path: Path) -> None:
    _ensure_app()
    mgr = VpnCoreManager(tmp_path / "rt")
    mgr._active_endpoint_host = "engage.cloudflareclient.com"
    mgr._active_endpoint_port = 2408

    warnings: list[str] = []
    mgr.tunnel_warning.connect(warnings.append)

    mgr._inspect_tunnel_health_log(
        "+0700 2026-11-17 11:15:08 DEBUG endpoint/wireguard[wg-out]: peer(bmXO) - handshake did not complete after 5 seconds, retrying (try 2)"
    )
    assert warnings == []

    mgr._inspect_tunnel_health_log(
        "+0700 2026-11-17 11:15:13 DEBUG endpoint/wireguard[wg-out]: peer(bmXO) - handshake did not complete after 5 seconds, retrying (try 3)"
    )
    assert len(warnings) == 1
    assert "engage.cloudflareclient.com:2408" in warnings[0]

    # Receiving a handshake response clears the warning
    mgr._inspect_tunnel_health_log(
        "+0700 2026-11-17 11:15:15 DEBUG endpoint/wireguard[wg-out]: peer(bmXO) - received handshake response"
    )
    assert warnings[-1] == ""


def test_tunnel_health_warning_on_repeated_endpoint_lookup_at_info_level(tmp_path: Path) -> None:
    _ensure_app()
    mgr = VpnCoreManager(tmp_path / "rt2")
    mgr._active_endpoint_host = "engage.cloudflareclient.com"
    mgr._active_endpoint_port = 2408

    warnings: list[str] = []
    mgr.tunnel_warning.connect(warnings.append)

    for _ in range(3):
        mgr._inspect_tunnel_health_log(
            "+0700 2026-11-17 11:06:09 INFO dns: lookup succeed for engage.cloudflareclient.com: 162.159.192.1"
        )
    assert len(warnings) == 1
    assert "TLS handshake timeout" in warnings[0]


def test_dashboard_tunnel_warn_banner_visibility() -> None:
    app = _ensure_app()
    settings = AppSettings(active_profile_id="p1")
    prof = WireGuardProfile(
        id="p1",
        name="WARP",
        private_key="A" * 43 + "=",
        addresses=["172.16.0.2/32"],
        public_key="B" * 43 + "=",
        endpoint_host="engage.cloudflareclient.com",
        endpoint_port=2408,
    )
    page = DashboardPage(settings=settings, profiles=[prof])
    page.resize(800, 680)
    page.show()
    app.processEvents()

    assert not page.tunnel_warn_banner.isVisible()
    page.set_tunnel_warning("Tunnel WireGuard chưa bắt tay được")
    app.processEvents()
    assert page.tunnel_warn_banner.isVisible()
    assert page.connect_btn.height() == 130

    page.set_tunnel_warning("")
    app.processEvents()
    assert not page.tunnel_warn_banner.isVisible()
    page.close()
