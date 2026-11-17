"""Tests for Simple Firewall (Windows Firewall COM sync, models, and Simplewall-style UI)."""

from __future__ import annotations

import sys
from typing import Any

from PySide6.QtWidgets import QApplication

from ppv import firewall_manager
from ppv.core_manager import VpnCoreManager
from ppv.models import AppRule, AppSettings
from ppv.process_helper import DiscoveredApp
from ppv.theme import DARK_STYLESHEET, create_dark_palette
from ppv.ui.apps_page import _ROW_BG, AppsPage
from ppv.ui.monitor_page import MonitorPage


class _FakeFwRule:
    def __init__(self) -> None:
        self.Name = ""
        self.Grouping = ""
        self.Description = ""
        self.ApplicationName = ""
        self.Action = 1
        self.Direction = 1
        self.Profiles = 7
        self.Protocol = 256
        self.RemotePorts = ""
        self.Enabled = False


class _FakeRulesCollection:
    def __init__(self, initial: list[Any] | None = None) -> None:
        self._items: list[Any] = list(initial or [])

    def __iter__(self):
        return iter(list(self._items))

    def Add(self, rule: Any) -> None:
        self._items.append(rule)

    def Remove(self, name: str) -> None:
        self._items = [r for r in self._items if r.Name != name]


class _FakeFwPolicy2:
    def __init__(self) -> None:
        self._enabled = {1: False, 2: False, 4: False}
        self._outbound = {1: 1, 2: 1, 4: 1}
        keep = _FakeFwRule()
        keep.Name = "Core Networking - DNS"
        keep.Grouping = "Core Networking"
        stale = _FakeFwRule()
        stale.Name = "PPV-FW STALE"
        stale.Grouping = firewall_manager.RULE_GROUP
        self.Rules = _FakeRulesCollection([keep, stale])

    def FirewallEnabled(self, profile_bit: int, value: bool | None = None) -> bool:
        if value is not None:
            self._enabled[profile_bit] = bool(value)
        return self._enabled[profile_bit]

    def DefaultOutboundAction(self, profile_bit: int, value: int | None = None) -> int:
        if value is not None:
            self._outbound[profile_bit] = int(value)
        return self._outbound[profile_bit]


def test_app_rule_and_settings_firewall_backward_compatibility() -> None:
    legacy = AppRule.from_dict({"display_name": "Chrome", "exe_name": "chrome.exe", "exe_path": r"C:\chrome.exe"})
    assert legacy.action == "vpn"
    assert legacy.added_at == ""

    settings = AppSettings(
        firewall_enabled=True,
        firewall_mode="allowlist",
        firewall_saved_profiles={"1": {"enabled": False, "outbound": 1}},
        app_rules=[
            AppRule("Chrome", "chrome.exe", r"C:\chrome.exe", action="vpn"),
            AppRule("Curl", "curl.exe", r"C:\Windows\System32\curl.exe", action="block"),
        ],
    )
    reloaded = AppSettings.from_dict(settings.to_dict())
    assert reloaded.firewall_enabled is True
    assert reloaded.firewall_mode == "allowlist"
    assert reloaded.firewall_saved_profiles == {"1": {"enabled": False, "outbound": 1}}
    assert [r.action for r in reloaded.app_rules] == ["vpn", "block"]


def test_sync_windows_firewall_blacklist_allowlist_and_restore() -> None:
    policy = _FakeFwPolicy2()
    settings = AppSettings(
        firewall_enabled=True,
        firewall_mode="blacklist",
        app_rules=[
            AppRule("Chrome", "chrome.exe", r"C:\Apps\chrome.exe", enabled=True, action="vpn"),
            AppRule("Code", "code.exe", r"C:\Apps\code.exe", enabled=True, action="allow"),
            AppRule(
                "BadTool",
                "curl.exe",
                r"C:\Windows\System32\curl.exe",
                enabled=True,
                match_type="name",
                action="block",
            ),
        ],
    )
    running = [
        DiscoveredApp("Curl Extra", "curl.exe", r"D:\Tools\curl.exe", "running", pid=500),
    ]

    # 1. Blacklist mode: snapshot original disabled state, enable profiles with DefaultOutbound=Allow (1)
    res_bl = firewall_manager.sync_windows_firewall(
        settings,
        running_apps=running,
        policy=policy,
        rule_factory=_FakeFwRule,
    )
    assert not res_bl.errors
    assert settings.firewall_saved_profiles is not None
    assert policy.FirewallEnabled(2) is True
    assert policy.DefaultOutboundAction(2) == firewall_manager.NET_FW_ACTION_ALLOW
    # Block rule applies to BOTH configured path and extra running path
    assert res_bl.applied_block == 2
    assert res_bl.applied_allow == 0
    names = [r.Name for r in policy.Rules]
    assert "Core Networking - DNS" in names
    assert "PPV-FW STALE" not in names

    # 2. Switch to Allowlist (Simplewall strict mode): DefaultOutbound=Block (0) + allow essentials & vpn/allow rules
    settings.firewall_mode = "allowlist"
    res_al = firewall_manager.sync_windows_firewall(
        settings,
        running_apps=running,
        policy=policy,
        rule_factory=_FakeFwRule,
    )
    assert not res_al.errors
    assert policy.DefaultOutboundAction(2) == firewall_manager.NET_FW_ACTION_BLOCK
    assert res_al.applied_block == 2
    assert res_al.applied_allow >= 5  # sing-box/ppv/DNS/DHCP essentials + Chrome + Code
    rule_apps = {r.ApplicationName for r in policy.Rules if r.Action == firewall_manager.NET_FW_ACTION_ALLOW}
    assert r"C:\Apps\chrome.exe" in rule_apps
    assert r"C:\Apps\code.exe" in rule_apps

    # 3. Disable firewall: remove all PPV-FW rules & restore exact original disabled profile state
    res_off = firewall_manager.disable_windows_firewall(settings, policy=policy)
    assert not res_off.errors
    assert settings.firewall_saved_profiles is None
    assert policy.FirewallEnabled(1) is False
    assert policy.FirewallEnabled(2) is False
    assert policy.DefaultOutboundAction(2) == firewall_manager.NET_FW_ACTION_ALLOW
    remaining_names = [r.Name for r in policy.Rules]
    assert remaining_names == ["Core Networking - DNS"]


def test_apps_page_unified_process_list_colors_and_actions(monkeypatch) -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    assert isinstance(app, QApplication)
    app.setPalette(create_dark_palette())
    app.setStyleSheet(DARK_STYLESHEET)

    monkeypatch.setattr("ppv.ui.apps_page.is_simplewall_running", lambda: False)
    settings = AppSettings(
        firewall_enabled=False,
        firewall_mode="blacklist",
        app_rules=[
            AppRule("Chrome", "chrome.exe", r"C:\Apps\chrome.exe", enabled=True, action="vpn"),
            AppRule("Code", "code.exe", r"C:\Apps\code.exe", enabled=True, action="allow"),
            AppRule("Curl", "curl.exe", r"C:\Windows\System32\curl.exe", enabled=True, action="block"),
        ],
    )
    page = AppsPage(settings=settings)
    page._on_scan_ready(
        [
            DiscoveredApp("Chrome", "chrome.exe", r"C:\Apps\chrome.exe", "running", True, 100),
            DiscoveredApp("Notepad", "notepad.exe", r"C:\Windows\notepad.exe", "running", True, 200),
        ]
    )

    # 3 saved rules + 1 unmanaged running app (notepad.exe)
    assert page.table.rowCount() == 4
    assert page.table.item(0, 1).background().color().name() == _ROW_BG["vpn"]
    assert page.table.item(1, 1).background().color().name() == _ROW_BG["allow"]
    assert page.table.item(2, 1).background().color().name() == _ROW_BG["block"]
    assert "Đang chạy" in page.table.item(3, 1).text()

    # Assigning "block" to the unmanaged running process (row 3) creates an active AppRule
    sync_calls: list[bool] = []
    page.firewall_sync_requested.connect(lambda: sync_calls.append(True))
    settings.firewall_enabled = True
    page._on_action_changed(3, "block")

    assert len(settings.app_rules) == 4
    assert settings.app_rules[3].exe_name == "notepad.exe"
    assert settings.app_rules[3].action == "block"
    assert sync_calls == [True]

    # Filtering by permission "block" hides non-block rows cleanly
    block_idx = page.perm_filter_combo.findData("block")
    page.perm_filter_combo.setCurrentIndex(block_idx)
    app.processEvents()
    assert page.table.isRowHidden(0)
    assert page.table.isRowHidden(1)
    assert not page.table.isRowHidden(2)
    assert not page.table.isRowHidden(3)

    # Select visible rows and batch-set permission to "allow"
    page._select_all_visible()
    page._batch_set_action("allow")
    assert settings.app_rules[2].action == "allow"
    assert settings.app_rules[3].action == "allow"

    page.stop_workers()
    page.close()


def test_core_manager_tracks_blocked_connections_and_monitor_displays(tmp_path) -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    _ = app

    mgr = VpnCoreManager(tmp_path)
    mgr._blocked_exe_names = {"nhcaagent.exe"}
    mgr._blocked_exact_paths = {r"c:\program files\estsoft\ayia.exe"}

    mgr._track_log_event("+0700 2026-11-17 10:43:09 INFO [566031197 0ms] inbound/tun[tun-in]: inbound connection to 172.27.120.22:9991")
    mgr._track_log_event(r"+0700 2026-11-17 10:43:09 INFO [566031197 0ms] router: found process path: C:\Program Files (x86)\IZEX\NHCAAgent.exe")
    mgr._track_log_event("+0700 2026-11-17 10:43:10 INFO [566031198 0ms] inbound/tun[tun-in]: inbound connection to 172.27.120.22:9991")
    mgr._track_log_event(r"+0700 2026-11-17 10:43:10 INFO [566031198 0ms] router: found process path: C:\Program Files (x86)\IZEX\NHCAAgent.exe")

    blocked = list(mgr._blocked_events.values())
    assert len(blocked) == 1
    assert blocked[0].process_name == "NHCAAgent.exe"
    assert blocked[0].destination == "172.27.120.22:9991"
    assert blocked[0].blocked_count == 2
    assert blocked[0].rule_outbound == "reject"

    mon = MonitorPage()
    reject_idx = mon.outbound_filter.findData("reject")
    mon.outbound_filter.setCurrentIndex(reject_idx)
    mon.update_connections(blocked)
    assert mon.table.rowCount() == 1
    assert "Bị chặn" in mon.table.item(0, 3).text()
    assert "2x" in mon.table.item(0, 4).text()
    mon.close()


def test_allowlist_blocks_unassigned_running_apps_and_core_tracks_reject(
    monkeypatch, tmp_path
) -> None:
    # 1. Default AppSettings uses allowlist mode + blocks unassigned in VPN; unassigned running apps get explicit BLOCK rules
    default_settings = AppSettings()
    assert default_settings.firewall_mode == "allowlist"
    assert default_settings.block_unassigned_in_vpn is True
    assert default_settings.is_unassigned_blocked_in_vpn is True

    policy = _FakeFwPolicy2()
    settings = AppSettings(
        firewall_enabled=True,
        firewall_mode="allowlist",
        app_rules=[
            AppRule("Chrome", "chrome.exe", r"C:\Apps\chrome.exe", enabled=True, action="vpn"),
        ],
    )
    running = [
        DiscoveredApp("Chrome", "chrome.exe", r"C:\Apps\chrome.exe", "running", True, 100),
        DiscoveredApp("Edge", "msedge.exe", r"C:\Apps\msedge.exe", "running", True, 300),
        DiscoveredApp(
            "Service Host",
            "svchost.exe",
            r"C:\Windows\System32\svchost.exe",
            "running",
            True,
            88,
        ),
    ]
    res = firewall_manager.sync_windows_firewall(
        settings,
        running_apps=running,
        policy=policy,
        rule_factory=_FakeFwRule,
    )
    assert not res.errors

    block_unassigned_rules = [
        r for r in policy.Rules if "PPV-FW BLOCK UNASSIGNED" in r.Name
    ]
    assert len(block_unassigned_rules) == 1
    edge_rule = block_unassigned_rules[0]
    assert edge_rule.Action == firewall_manager.NET_FW_ACTION_BLOCK
    assert edge_rule.Direction == firewall_manager.NET_FW_RULE_DIR_OUT
    assert edge_rule.ApplicationName == r"C:\Apps\msedge.exe"
    assert not any(
        "svchost.exe" in (r.ApplicationName or "").lower()
        and r.Action == firewall_manager.NET_FW_ACTION_BLOCK
        for r in policy.Rules
    )
    assert any(
        "chrome.exe" in (r.ApplicationName or "").lower()
        and r.Action == firewall_manager.NET_FW_ACTION_ALLOW
        for r in policy.Rules
    )

    # 2. VpnCoreManager tracks catch-all `=> reject` once per cid and skips svchost DNS noise
    mgr = VpnCoreManager(tmp_path)
    mgr._blocked_exe_names = {"curl.exe"}

    # Unassigned msedge.exe rejected by catch-all
    mgr._track_log_event(
        "+0700 2026-11-17 13:10:01 INFO [7001 0ms] inbound/tun[tun-in]: inbound connection to 93.184.216.34:443"
    )
    mgr._track_log_event(
        r"+0700 2026-11-17 13:10:01 INFO [7001 0ms] router: found process path: C:\Apps\msedge.exe"
    )
    mgr._track_log_event(
        "+0700 2026-11-17 13:10:01 DEBUG [7001 1ms] router: match[7] => reject"
    )
    mgr._track_log_event(
        "+0700 2026-11-17 13:10:01 DEBUG [7001 2ms] router: connection closed: rejected"
    )

    # svchost.exe DNS packet reject is ignored as DNS noise
    mgr._track_log_event(
        "+0700 2026-11-17 13:10:02 INFO [7002 0ms] inbound/tun[tun-in]: inbound DNS packet from 172.19.0.1:53000"
    )
    mgr._track_log_event(
        r"+0700 2026-11-17 13:10:02 INFO [7002 0ms] router: found process path: C:\Windows\System32\svchost.exe"
    )
    mgr._track_log_event(
        "+0700 2026-11-17 13:10:02 DEBUG [7002 1ms] router: match[8] => reject"
    )

    # Explicit block rule is recorded once even when `=> reject` also logs on the same cid
    mgr._track_log_event(
        "+0700 2026-11-17 13:10:03 INFO [7003 0ms] inbound/tun[tun-in]: inbound connection to 1.2.3.4:80"
    )
    mgr._track_log_event(
        r"+0700 2026-11-17 13:10:03 INFO [7003 0ms] router: found process path: C:\Windows\System32\curl.exe"
    )
    mgr._track_log_event(
        "+0700 2026-11-17 13:10:03 DEBUG [7003 1ms] router: match[1] => reject"
    )

    blocked_rows = list(mgr._blocked_events.values())
    assert len(blocked_rows) == 2
    by_proc = {row.process_name.lower(): row for row in blocked_rows}
    assert by_proc["msedge.exe"].destination == "93.184.216.34:443"
    assert by_proc["msedge.exe"].blocked_count == 1
    assert by_proc["msedge.exe"].rule_outbound == "reject"
    assert by_proc["curl.exe"].blocked_count == 1
    assert "svchost.exe" not in by_proc

    # 3. AppsPage UI: allowlist is first item, fw_off_block_banner warns when FW off, vpn_allowlist_chk toggles setting
    app = QApplication.instance() or QApplication(sys.argv)
    _ = app
    monkeypatch.setattr("ppv.ui.apps_page.is_simplewall_running", lambda: False)
    ui_settings = AppSettings(firewall_enabled=False, firewall_mode="allowlist")
    page = AppsPage(settings=ui_settings)
    assert page.fw_mode_combo.itemData(0) == "allowlist"
    assert page.fw_mode_combo.currentData() == "allowlist"
    assert not page.fw_off_block_banner.isHidden()
    assert page.vpn_allowlist_chk.isChecked()
    assert "Chưa gán: Chặn mạng" in page.summary_label.text()

    changed: list[bool] = []
    page.rules_changed.connect(lambda: changed.append(True))
    page.vpn_allowlist_chk.setChecked(False)
    app.processEvents()
    assert ui_settings.block_unassigned_in_vpn is False
    assert changed == [True]
    assert "Chưa gán: Mở" in page.summary_label.text()

    page.vpn_allowlist_chk.setChecked(True)
    app.processEvents()
    assert ui_settings.block_unassigned_in_vpn is True
    assert len(changed) == 2
    assert "Chưa gán: Chặn mạng" in page.summary_label.text()

    page.stop_workers()
    page.close()


class _FakeOleObject:
    def __init__(self, owner: _FakeCDispatchFwPolicy2) -> None:
        self._owner = owner

    def GetIDsOfNames(self, _lcid: int, name: str) -> int:
        if name == "FirewallEnabled":
            return 2
        if name == "DefaultOutboundAction":
            return 13
        raise KeyError(name)

    def InvokeTypes(
        self,
        dispid: int,
        _lcid: int,
        wflags: int,
        _ret_type: tuple[int, int],
        _arg_types: tuple[tuple[int, int], ...],
        profile_bit: int,
        value: Any,
    ) -> None:
        assert wflags == firewall_manager.pythoncom.DISPATCH_PROPERTYPUT
        if dispid == 2:
            self._owner._enabled[profile_bit] = bool(value)
        elif dispid == 13:
            self._owner._outbound[profile_bit] = int(value)
        else:
            raise AssertionError(f"Unexpected dispid: {dispid}")


class _FakeCDispatchFwPolicy2:
    """Mimics win32com CDispatch where indexed property getters reject setter args."""

    def __init__(self) -> None:
        self._enabled = {1: True, 2: True, 4: True}
        self._outbound = {1: 1, 2: 1, 4: 1}
        self.Rules = _FakeRulesCollection()
        self._oleobj_ = _FakeOleObject(self)

    def FirewallEnabled(self, profile_bit: int) -> bool:
        return self._enabled[profile_bit]

    def DefaultOutboundAction(self, profile_bit: int) -> int:
        return self._outbound[profile_bit]


def test_sync_windows_firewall_uses_com_propertyput_on_cdispatch() -> None:
    policy = _FakeCDispatchFwPolicy2()
    settings = AppSettings(
        firewall_enabled=True,
        firewall_mode="allowlist",
        app_rules=[
            AppRule("Chrome", "chrome.exe", r"C:\Apps\chrome.exe", enabled=True, action="vpn"),
        ],
    )
    res_on = firewall_manager.sync_windows_firewall(
        settings,
        running_apps=[],
        policy=policy,
        rule_factory=_FakeFwRule,
    )
    assert not res_on.errors
    assert all(policy.DefaultOutboundAction(b) == firewall_manager.NET_FW_ACTION_BLOCK for b in (1, 2, 4))

    res_off = firewall_manager.disable_windows_firewall(settings, policy=policy)
    assert not res_off.errors
    assert all(policy.DefaultOutboundAction(b) == firewall_manager.NET_FW_ACTION_ALLOW for b in (1, 2, 4))
