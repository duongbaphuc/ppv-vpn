"""Tests for sing-box 1.14 configuration generation and live `sing-box check` validation."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from ppv.core_manager import find_singbox_binary
from ppv.models import AppRule, AppSettings, WireGuardProfile
from ppv.singbox_config import build_probe_config, build_singbox_config, rule_to_process_regex


def _sample_profile(with_v6: bool = True, reserved: list[int] | None = None) -> WireGuardProfile:
    addrs = ["172.16.0.2/24"]
    allowed = ["0.0.0.0/0"]
    if with_v6:
        addrs.append("fd01:5ca1:ab1e:8714:7297:f261:6863:2fab/120")
        allowed.append("::/0")
    return WireGuardProfile(
        name="WARP Test",
        private_key="ERERERERERERERERERERERERERERERERERERERERERE=",
        addresses=addrs,
        dns=["1.1.1.1"],
        public_key="IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=",
        endpoint_host="engage.cloudflareclient.com",
        endpoint_port=2408,
        allowed_ips=allowed,
        reserved=reserved,
    )


def test_rule_to_process_regex() -> None:
    r_name = AppRule(
        display_name="Chrome",
        exe_name="chrome.exe",
        exe_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        match_type="name",
    )
    assert rule_to_process_regex(r_name) == r"(?i)(^|[\\/])chrome\.exe$"

    r_path = AppRule(
        display_name="Custom App",
        exe_name="app+1.exe",
        exe_path=r"C:\Program Files (x86)\My [Test]\app+1.exe",
        match_type="path",
    )
    assert (
        rule_to_process_regex(r_path)
        == r"(?i)^C:\\Program Files \(x86\)\\My \[Test\]\\app\+1\.exe$"
    )


@pytest.mark.parametrize("split_mode", ["include", "exclude"])
@pytest.mark.parametrize("dns_mode", ["split", "vpn_all", "local"])
@pytest.mark.parametrize("ipv6_enabled", [False, True])
def test_build_singbox_config_passes_singbox_check(
    tmp_path: Path,
    split_mode: str,
    dns_mode: str,
    ipv6_enabled: bool,
) -> None:
    binary = find_singbox_binary()
    if binary is None:
        pytest.skip("bin/sing-box.exe not found")

    settings = AppSettings(
        split_mode=split_mode,  # type: ignore[arg-type]
        dns_mode=dns_mode,  # type: ignore[arg-type]
        ipv6_enabled=ipv6_enabled,
        firewall_mode="blacklist",
        app_rules=[
            AppRule(
                display_name="Chrome",
                exe_name="chrome.exe",
                exe_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                enabled=True,
                match_type="name",
            ),
            AppRule(
                display_name="App (x86)",
                exe_name="my-app.exe",
                exe_path=r"C:\Program Files (x86)\Vendor\my-app.exe",
                enabled=True,
                match_type="path",
            ),
            AppRule(
                display_name="Disabled App",
                exe_name="notepad.exe",
                exe_path=r"C:\Windows\System32\notepad.exe",
                enabled=False,
                match_type="name",
            ),
        ],
    )
    prof = _sample_profile(with_v6=True, reserved=[249, 86, 237])
    cfg = build_singbox_config(prof, settings, api_port=19123, api_secret="secret123")

    if split_mode == "include":
        assert cfg["route"]["final"] == "direct"
    else:
        assert cfg["route"]["final"] == "wg-out"

    if not ipv6_enabled:
        assert cfg["inbounds"][0]["address"] == ["172.19.0.1/30"]
        assert cfg["endpoints"][0]["address"] == ["172.16.0.2/24"]

    cfg_file = tmp_path / f"cfg_{split_mode}_{dns_mode}_{ipv6_enabled}.json"
    cfg_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    res = subprocess.run(
        [str(binary), "check", "-c", str(cfg_file)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert res.returncode == 0, f"sing-box check failed: {res.stderr}\n{res.stdout}"


@pytest.mark.parametrize("split_mode", ["include", "exclude"])
def test_build_singbox_config_block_and_allow_rules_pass_check(
    tmp_path: Path, split_mode: str
) -> None:
    binary = find_singbox_binary()
    if binary is None:
        pytest.skip("bin/sing-box.exe not found")

    settings = AppSettings(
        split_mode=split_mode,  # type: ignore[arg-type]
        dns_mode="split",
        app_rules=[
            AppRule("Chrome", "chrome.exe", r"C:\Apps\chrome.exe", enabled=True, action="vpn"),
            AppRule("Code", "code.exe", r"C:\Apps\code.exe", enabled=True, action="allow"),
            AppRule("BlockedApp", "curl.exe", r"C:\Windows\System32\curl.exe", enabled=True, action="block"),
        ],
    )
    cfg = build_singbox_config(_sample_profile(), settings, api_port=19124, api_secret="s")
    rules = cfg["route"]["rules"]
    assert rules[1]["action"] == "reject"
    assert any("curl" in pat for pat in rules[1]["process_path_regex"])

    cfg_file = tmp_path / f"fw_{split_mode}.json"
    cfg_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    res = subprocess.run(
        [str(binary), "check", "-c", str(cfg_file)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert res.returncode == 0, f"sing-box check failed: {res.stderr}\n{res.stdout}"


def test_build_probe_config_passes_singbox_check(tmp_path: Path) -> None:
    binary = find_singbox_binary()
    if binary is None:
        pytest.skip("bin/sing-box.exe not found")

    prof = _sample_profile(with_v6=False, reserved=[90, 245, 140])
    cfg = build_probe_config(
        prof,
        http_port=19895,
        log_output=str(tmp_path / "probe.log"),
        bind_interface="Ethernet",
    )
    assert cfg["inbounds"][0]["type"] == "http"
    assert cfg["endpoints"][0]["tag"] == "wg-out"
    assert cfg["endpoints"][0]["bind_interface"] == "Ethernet"
    assert cfg["route"]["auto_detect_interface"] is True
    assert cfg["log"]["level"] == "debug"

    cfg_file = tmp_path / "probe.json"
    cfg_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    res = subprocess.run(
        [str(binary), "check", "-c", str(cfg_file)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert res.returncode == 0, f"sing-box probe check failed: {res.stderr}\n{res.stdout}"


@pytest.mark.parametrize(
    ("firewall_enabled", "firewall_mode", "block_unassigned_in_vpn"),
    [
        (True, "allowlist", False),
        (False, "allowlist", True),
    ],
)
@pytest.mark.parametrize("split_mode", ["include", "exclude"])
def test_build_singbox_config_strict_allowlist_rejects_unassigned_and_passes_check(
    tmp_path: Path,
    firewall_enabled: bool,
    firewall_mode: str,
    block_unassigned_in_vpn: bool,
    split_mode: str,
) -> None:
    binary = find_singbox_binary()
    if binary is None:
        pytest.skip("bin/sing-box.exe not found")

    settings = AppSettings(
        split_mode=split_mode,  # type: ignore[arg-type]
        dns_mode="split",
        firewall_enabled=firewall_enabled,
        firewall_mode=firewall_mode,  # type: ignore[arg-type]
        block_unassigned_in_vpn=block_unassigned_in_vpn,
        bypass_lan=True,
        app_rules=[
            AppRule(
                "Antigravity",
                "Antigravity IDE.exe",
                r"C:\Apps\Antigravity IDE.exe",
                enabled=True,
                action="vpn",
            ),
            AppRule("Chrome", "chrome.exe", r"C:\Apps\chrome.exe", enabled=True, action="allow"),
            AppRule("Blocked", "curl.exe", r"C:\Apps\curl.exe", enabled=True, action="block"),
        ],
    )
    cfg = build_singbox_config(_sample_profile(), settings, api_port=19125, api_secret="sec")
    rules = cfg["route"]["rules"]

    # Catch-all reject rule must be the final rule so unassigned apps cannot leak out
    assert rules[-1] == {"action": "reject"}

    # Essential core/system connectivity remains direct
    assert any(
        r.get("outbound") == "direct"
        and "sing-box.exe" in r.get("process_name", [])
        and "PPV-VPN.exe" in r.get("process_name", [])
        for r in rules
    )
    assert any(
        r.get("outbound") == "direct"
        and r.get("port") == [53, 67, 68]
        and "svchost.exe" in r.get("process_name", [])
        for r in rules
    )

    # Assigned rules route properly and LAN bypass is scoped to vpn_regexes (never global)
    assert any(
        r.get("outbound") == "wg-out"
        and "ip_is_private" not in r
        and any("Antigravity" in p for p in r.get("process_path_regex", []))
        for r in rules
    )
    assert any(
        r.get("outbound") == "direct"
        and any("chrome" in p for p in r.get("process_path_regex", []))
        for r in rules
    )
    private_rules = [r for r in rules if r.get("ip_is_private") is True]
    assert private_rules
    assert all("process_path_regex" in r for r in private_rules)

    cfg_file = (
        tmp_path
        / f"allowlist_{split_mode}_{int(firewall_enabled)}_{firewall_mode}_{int(block_unassigned_in_vpn)}.json"
    )
    cfg_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    res = subprocess.run(
        [str(binary), "check", "-c", str(cfg_file)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert res.returncode == 0, f"sing-box strict allowlist check failed: {res.stderr}\n{res.stdout}"
