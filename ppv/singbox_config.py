"""Builds sing-box 1.14+ configuration dictionaries for Per-App WireGuard split tunneling."""

from __future__ import annotations

import ipaddress
import os
from typing import Any

from ppv.models import AppRule, AppSettings, WireGuardProfile

_RE2_META = set(r"\.+*?()|[]{}^$")


def escape_re2(value: str) -> str:
    """Escape characters that have special meaning in Go RE2 regular expressions."""
    out: list[str] = []
    for ch in value:
        if ch in _RE2_META:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def rule_to_process_regex(rule: AppRule) -> str:
    """Convert an AppRule into a case-insensitive Go RE2 regex matching `process_path_regex`."""
    if rule.match_type == "path" and rule.exe_path:
        normalized = os.path.normpath(rule.exe_path.strip()).replace("/", "\\")
        return f"(?i)^{escape_re2(normalized)}$"
    exe_name = os.path.basename(rule.exe_name.strip() or rule.exe_path.strip())
    return f"(?i)(^|[\\\\/]){escape_re2(exe_name)}$"


def _filter_cidrs(cidrs: list[str], allow_v6: bool) -> list[str]:
    if allow_v6:
        return list(cidrs)
    v4 = []
    for c in cidrs:
        try:
            if ipaddress.ip_network(c, strict=False).version == 4:
                v4.append(c)
        except ValueError:
            pass
    return v4


def _pick_vpn_dns(profile: WireGuardProfile) -> str:
    for d in profile.dns:
        try:
            if ipaddress.ip_address(d).version == 4:
                return d
        except ValueError:
            pass
    return "1.1.1.1"


def _wireguard_use_v6(profile: WireGuardProfile, ipv6_enabled: bool) -> bool:
    has_profile_v4 = any(
        ipaddress.ip_interface(a).version == 4 for a in profile.addresses
    )
    has_profile_v6 = any(
        ipaddress.ip_interface(a).version == 6 for a in profile.addresses
    )
    use_v6 = ipv6_enabled and has_profile_v6
    if not has_profile_v4 and has_profile_v6:
        use_v6 = True
    return use_v6


def _build_wireguard_endpoint(
    profile: WireGuardProfile,
    default_mtu: int,
    use_v6: bool,
) -> dict[str, Any]:
    wg_addresses = _filter_cidrs(profile.addresses, allow_v6=use_v6)
    wg_allowed_ips = _filter_cidrs(profile.allowed_ips, allow_v6=use_v6)
    if not wg_allowed_ips:
        wg_allowed_ips = ["0.0.0.0/0", "::/0"] if use_v6 else ["0.0.0.0/0"]

    peer_block: dict[str, Any] = {
        "address": profile.endpoint_host,
        "port": profile.endpoint_port,
        "public_key": profile.public_key,
        "allowed_ips": wg_allowed_ips,
        "persistent_keepalive_interval": profile.persistent_keepalive or 25,
    }
    if profile.preshared_key:
        peer_block["pre_shared_key"] = profile.preshared_key
    if profile.reserved and len(profile.reserved) == 3:
        peer_block["reserved"] = list(profile.reserved)

    return {
        "type": "wireguard",
        "tag": "wg-out",
        "system": False,
        "mtu": profile.mtu or default_mtu,
        "address": wg_addresses,
        "private_key": profile.private_key,
        "peers": [peer_block],
    }


def build_singbox_config(
    profile: WireGuardProfile,
    settings: AppSettings,
    api_port: int = 19090,
    api_secret: str = "",
    interface_name: str = "PPV-Tunnel",
    log_level: str = "debug",
) -> dict[str, Any]:
    """Generate a sing-box 1.14.x JSON configuration for Per-App WireGuard VPN."""
    use_v6 = _wireguard_use_v6(profile, settings.ipv6_enabled)

    enabled_rules = [r for r in settings.app_rules if r.enabled]
    block_regexes = list(
        dict.fromkeys(rule_to_process_regex(r) for r in enabled_rules if r.action == "block")
    )
    allow_regexes = list(
        dict.fromkeys(rule_to_process_regex(r) for r in enabled_rules if r.action == "allow")
    )
    vpn_regexes = list(
        dict.fromkeys(rule_to_process_regex(r) for r in enabled_rules if r.action == "vpn")
    )

    # DNS setup
    vpn_dns_ip = _pick_vpn_dns(profile)
    dns_servers: list[dict[str, Any]] = [
        {"tag": "dns-local", "type": "local"},
        {
            "tag": "dns-vpn",
            "type": "udp",
            "server": vpn_dns_ip,
            "detour": "wg-out",
        },
    ]

    dns_rules: list[dict[str, Any]] = [
        {"process_name": ["sing-box.exe"], "server": "dns-local"}
    ]
    if settings.dns_mode == "local":
        dns_final = "dns-local"
    elif settings.dns_mode == "vpn_all":
        dns_final = "dns-vpn"
    else:
        # "split" mode: DNS follows each app's explicit VPN/Direct routing decision
        if allow_regexes:
            dns_rules.append({"process_path_regex": allow_regexes, "server": "dns-local"})
        if settings.split_mode == "include":
            if vpn_regexes:
                dns_rules.append({"process_path_regex": vpn_regexes, "server": "dns-vpn"})
            dns_final = "dns-local"
        else:
            if vpn_regexes:
                dns_rules.append({"process_path_regex": vpn_regexes, "server": "dns-vpn"})
            dns_final = "dns-vpn"

    dns_strategy = "prefer_ipv4" if use_v6 else "ipv4_only"

    wg_endpoint = _build_wireguard_endpoint(
        profile=profile,
        default_mtu=settings.default_mtu,
        use_v6=use_v6,
    )

    # TUN inbound
    tun_addresses = ["172.19.0.1/30"]
    if use_v6:
        tun_addresses.append("fdfe:dcba:9876::1/126")

    tun_inbound: dict[str, Any] = {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": interface_name,
        "address": tun_addresses,
        "mtu": profile.mtu or settings.default_mtu,
        "auto_route": True,
        "strict_route": settings.strict_route,
        "stack": "gvisor",
    }

    # Routing rules
    strict_allowlist = settings.is_unassigned_blocked_in_vpn
    route_rules: list[dict[str, Any]] = [
        {"action": "sniff"},
    ]
    if block_regexes:
        route_rules.append({"process_path_regex": block_regexes, "action": "reject"})
    route_rules.append({"protocol": "dns", "action": "hijack-dns"})

    if strict_allowlist:
        route_rules.extend(
            [
                {
                    "process_name": ["sing-box.exe", "PPV-VPN.exe"],
                    "action": "route",
                    "outbound": "direct",
                },
                {
                    "process_name": ["svchost.exe"],
                    "port": [53, 67, 68],
                    "action": "route",
                    "outbound": "direct",
                },
            ]
        )
        if allow_regexes:
            route_rules.append(
                {
                    "process_path_regex": allow_regexes,
                    "action": "route",
                    "outbound": "direct",
                }
            )
        if vpn_regexes:
            if settings.bypass_lan:
                route_rules.append(
                    {
                        "process_path_regex": vpn_regexes,
                        "ip_is_private": True,
                        "action": "route",
                        "outbound": "direct",
                    }
                )
            route_rules.append(
                {
                    "process_path_regex": vpn_regexes,
                    "action": "route",
                    "outbound": "wg-out",
                }
            )
        route_rules.append({"action": "reject"})
        route_final = "direct"
    else:
        route_rules.append(
            {"process_name": ["sing-box.exe"], "action": "route", "outbound": "direct"}
        )
        if settings.bypass_lan:
            route_rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})

        if allow_regexes:
            route_rules.append(
                {
                    "process_path_regex": allow_regexes,
                    "action": "route",
                    "outbound": "direct",
                }
            )

        if vpn_regexes:
            route_rules.append(
                {
                    "process_path_regex": vpn_regexes,
                    "action": "route",
                    "outbound": "wg-out",
                }
            )
        route_final = "direct" if settings.split_mode == "include" else "wg-out"

    config: dict[str, Any] = {
        "log": {
            "disabled": False,
            "level": log_level,
            "timestamp": True,
        },
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": dns_final,
            "strategy": dns_strategy,
        },
        "endpoints": [wg_endpoint],
        "inbounds": [tun_inbound],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "auto_detect_interface": True,
            "find_process": True,
            "default_domain_resolver": "dns-local",
            "rules": route_rules,
            "final": route_final,
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{api_port}",
                "secret": api_secret,
            }
        },
    }
    return config


def build_probe_config(
    profile: WireGuardProfile,
    http_port: int = 19885,
    default_mtu: int = 1280,
    ipv6_enabled: bool = False,
    log_output: str | None = None,
    bind_interface: str | None = None,
) -> dict[str, Any]:
    """Build a non-TUN HTTP->WireGuard config to probe WireGuard handshake and egress."""
    use_v6 = _wireguard_use_v6(profile, ipv6_enabled)
    wg_endpoint = _build_wireguard_endpoint(
        profile=profile,
        default_mtu=default_mtu,
        use_v6=use_v6,
    )
    if bind_interface:
        wg_endpoint["bind_interface"] = bind_interface
    log_cfg: dict[str, Any] = {
        "disabled": False,
        "level": "debug",
        "timestamp": True,
    }
    if log_output:
        log_cfg["output"] = log_output
    return {
        "log": log_cfg,
        "dns": {
            "servers": [
                {"tag": "dns-local", "type": "local"},
                {
                    "tag": "dns-vpn",
                    "type": "udp",
                    "server": _pick_vpn_dns(profile),
                    "detour": "wg-out",
                },
            ],
            "final": "dns-vpn",
            "strategy": "prefer_ipv4" if use_v6 else "ipv4_only",
        },
        "endpoints": [wg_endpoint],
        "inbounds": [
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": http_port,
            }
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "dns-local",
            "final": "wg-out",
        },
    }
