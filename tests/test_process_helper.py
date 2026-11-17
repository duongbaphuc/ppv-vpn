"""Tests for third-party VPN detection and cleanup helpers."""

from __future__ import annotations

import os
import sys

from PySide6.QtWidgets import QApplication

from ppv import process_helper
from ppv.models import AppSettings
from ppv.ui.dashboard_page import DashboardPage
from ppv.ui.main_window import MainWindow


def test_is_conflicting_vpn_service_filters_system_services() -> None:
    assert process_helper._is_conflicting_vpn_service("WireGuardTunnel$warpplus", "WireGuard Tunnel: warpplus")
    assert process_helper._is_conflicting_vpn_service("WireGuardManager", "WireGuard Manager")
    assert process_helper._is_conflicting_vpn_service("CloudflareWARP", "Cloudflare WARP")
    assert process_helper._is_conflicting_vpn_service("OpenVPNService", "OpenVPNService")

    # Never touch Windows Direct3D WARP JIT or unrelated services
    assert not process_helper._is_conflicting_vpn_service("WarpJITSvc", "WarpJITSvc")
    assert not process_helper._is_conflicting_vpn_service("wuauserv", "Windows Update")


def test_find_and_stop_conflicting_vpns_order(monkeypatch) -> None:
    monkeypatch.setattr(
        process_helper,
        "find_running_wireguard_tunnels",
        lambda: [
            ("WireGuardTunnel$warpplus", "WireGuard Tunnel: warpplus"),
            ("WireGuardManager", "WireGuard Manager"),
        ],
    )
    self_pid = os.getpid()
    proc_list_calls = {"count": 0}

    def fake_iter():
        proc_list_calls["count"] += 1
        if proc_list_calls["count"] <= 2:
            return [
                (self_pid, "python.exe"),
                (1111, "chrome.exe"),
                (2222, "PPV-VPN.exe"),
                (3333, "apkcombovpn.exe"),
                (4444, "Cloudflare WARP.exe"),
            ]
        # After stopping services, 3333 exited automatically while 4444 remained
        return [(4444, "Cloudflare WARP.exe")]

    monkeypatch.setattr(process_helper, "_iter_process_entries", fake_iter)
    monkeypatch.setattr(process_helper, "_query_process_path", lambda pid: rf"C:\Fake\{pid}.exe")

    found = process_helper.find_conflicting_vpns()
    assert [(c.kind, c.identifier) for c in found] == [
        ("service", "WireGuardTunnel$warpplus"),
        ("service", "WireGuardManager"),
        ("process", "apkcombovpn.exe"),
        ("process", "Cloudflare WARP.exe"),
    ]

    actions: list[str] = []

    def fake_stop_svc(name: str, wait_timeout_sec: float = 4.0) -> tuple[bool, str]:
        actions.append(f"svc:{name}")
        return True, f"Stopped {name}"

    def fake_term_pid(pid: int, wait_ms: int = 3000) -> tuple[bool, str]:
        actions.append(f"pid:{pid}")
        return True, f"Killed {pid}"

    monkeypatch.setattr(process_helper, "stop_windows_service", fake_stop_svc)
    monkeypatch.setattr(process_helper, "terminate_process_by_pid", fake_term_pid)

    stopped, errors = process_helper.stop_conflicting_vpns()
    assert not errors
    # Services stopped first, and only still-running PID 4444 required TerminateProcess
    assert actions == [
        "svc:WireGuardTunnel$warpplus",
        "svc:WireGuardManager",
        "pid:4444",
    ]
    assert len(stopped) == 4


def test_dashboard_conflict_banner_and_stopping_state(monkeypatch) -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    _ = app

    monkeypatch.setattr(
        "ppv.ui.dashboard_page.find_conflicting_vpns",
        lambda: [
            process_helper.ConflictingVpn("service", "WireGuardManager", "WireGuard Manager"),
            process_helper.ConflictingVpn("process", "apkcombovpn.exe", "APKCombo VPN", pid=999),
        ],
    )
    settings = AppSettings(auto_stop_other_vpns=True)
    page = DashboardPage(settings=settings, profiles=[])
    page.refresh_conflicts()

    assert not page.conflict_banner.isHidden()
    assert "APKCombo VPN" in page.conflict_label.text()
    assert "tự động tắt" in page.conflict_label.text()

    page.set_connection_state("stopping_others")
    assert "ĐANG TẮT" in page.connect_btn.text()
    assert page.connect_btn.property("state") == "connecting"
    page.close()


def test_cleanup_stale_ppv_and_banner_hides_while_connected(monkeypatch) -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    _ = app

    with monkeypatch.context() as m:
        m.setattr(process_helper.sys, "frozen", True, raising=False)
        m.setattr(
            process_helper.sys,
            "executable",
            r"D:\MyProject\ppv\dist_v2\PPV-VPN\PPV-VPN.exe",
            raising=False,
        )
        self_pid = os.getpid()
        m.setattr(
            process_helper,
            "_iter_process_entries",
            lambda: [
                (self_pid, "PPV-VPN.exe"),
                (777, "PPV-VPN.exe"),
                (888, "PPV-VPN.exe"),
            ],
        )
        m.setattr(
            process_helper,
            "_query_process_path",
            lambda pid: (
                r"D:\MyProject\ppv\dist\PPV-VPN\PPV-VPN.exe"
                if pid == 777
                else r"D:\MyProject\ppv\dist_v2\PPV-VPN\PPV-VPN.exe"
            ),
        )
        killed_pids: list[int] = []
        m.setattr(
            process_helper,
            "terminate_process_by_pid",
            lambda pid, wait_ms=3000: (killed_pids.append(pid) or True, "ok"),
        )
        assert process_helper.cleanup_stale_ppv_instances() == 1
        assert killed_pids == [777]

    # Verify Dashboard conflict banner disappears when MainWindow transitions to connected
    fake_conflicts = [process_helper.ConflictingVpn("service", "WireGuardManager", "WireGuard Manager")]
    monkeypatch.setattr("ppv.ui.dashboard_page.find_conflicting_vpns", lambda: list(fake_conflicts))
    win = MainWindow(auto_connect=False, start_minimized=False, single_instance=None)
    assert not win.dashboard_page.conflict_banner.isHidden()

    fake_conflicts.clear()
    win.core._state = "connected"
    win._on_periodic_refresh()
    assert win.dashboard_page.conflict_banner.isHidden()
    win._force_quit = True
    win.close()
