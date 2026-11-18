"""Windows Defender Firewall (WFP) manager for Simplewall-style per-app Allow/Block rules."""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pythoncom
import win32com.client

from ppv.core_manager import find_singbox_binary
from ppv.models import AppRule, AppSettings
from ppv.process_helper import DiscoveredApp, _iter_process_entries, is_admin, list_running_apps
from ppv.storage import get_data_dir

RULE_PREFIX = "PPV-FW "
RULE_GROUP = "PPV VPN Simple Firewall"

NET_FW_ACTION_BLOCK = 0
NET_FW_ACTION_ALLOW = 1
NET_FW_RULE_DIR_IN = 1
NET_FW_RULE_DIR_OUT = 2
NET_FW_PROFILE2_ALL = 7  # Domain (1) | Private (2) | Public (4)
_PROFILE_BITS = (1, 2, 4)

_ALLOWLIST_PROTECTED_EXES = frozenset(
    {
        "system",
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "wininit.exe",
        "csrss.exe",
        "smss.exe",
        "sing-box.exe",
        "ppv-vpn.exe",
    }
)


@dataclass
class FirewallSyncResult:
    """Summary returned after applying or clearing PPV Windows Firewall rules."""

    enabled: bool
    mode: str
    applied_block: int = 0
    applied_allow: int = 0
    removed: int = 0
    errors: list[str] = field(default_factory=list)


def is_simplewall_running() -> bool:
    """Return True if simplewall.exe is currently running."""
    return any(name.lower() == "simplewall.exe" for _pid, name in _iter_process_entries())


def _default_policy_factory() -> Any:
    return win32com.client.Dispatch("HNetCfg.FwPolicy2")


def _default_rule_factory() -> Any:
    return win32com.client.Dispatch("HNetCfg.FWRule")


def _remove_ppv_rules(policy: Any) -> int:
    """Remove all Windows Firewall rules owned by PPV VPN."""
    names_to_remove: list[str] = []
    for rule in policy.Rules:
        name = str(getattr(rule, "Name", "") or "")
        group = str(getattr(rule, "Grouping", "") or "")
        if name.startswith(RULE_PREFIX) or group == RULE_GROUP:
            names_to_remove.append(name)

    removed = 0
    for name in names_to_remove:
        with contextlib.suppress(Exception):
            policy.Rules.Remove(name)
            removed += 1
    return removed


def _set_indexed_policy_prop(
    policy: Any,
    prop_name: str,
    dispid_fallback: int,
    arg_types: tuple[tuple[int, int], ...],
    profile_bit: int,
    value: int | bool,
) -> None:
    """Set an indexed INetFwPolicy2 COM property via DISPATCH_PROPERTYPUT (or test fake method)."""
    oleobj = getattr(policy, "_oleobj_", None)
    if oleobj is not None:
        try:
            dispid = oleobj.GetIDsOfNames(0, prop_name)
        except Exception:
            dispid = dispid_fallback
        oleobj.InvokeTypes(
            dispid,
            0,
            pythoncom.DISPATCH_PROPERTYPUT,
            (24, 0),
            arg_types,
            int(profile_bit),
            value,
        )
        return
    setter = getattr(policy, f"Set{prop_name}", None)
    if callable(setter):
        setter(profile_bit, value)
        return
    getattr(policy, prop_name)(profile_bit, value)


def _set_firewall_enabled(policy: Any, profile_bit: int, enabled: bool) -> None:
    _set_indexed_policy_prop(
        policy,
        "FirewallEnabled",
        2,
        ((3, 1), (11, 1)),
        profile_bit,
        bool(enabled),
    )


def _set_default_outbound(policy: Any, profile_bit: int, action: int) -> None:
    _set_indexed_policy_prop(
        policy,
        "DefaultOutboundAction",
        13,
        ((3, 1), (3, 1)),
        profile_bit,
        int(action),
    )


def _snapshot_profiles(policy: Any) -> dict[str, dict[str, int | bool]]:
    snapshot: dict[str, dict[str, int | bool]] = {}
    for bit in _PROFILE_BITS:
        snapshot[str(bit)] = {
            "enabled": bool(policy.FirewallEnabled(bit)),
            "outbound": int(policy.DefaultOutboundAction(bit)),
        }
    return snapshot


def _restore_profiles(policy: Any, snapshot: dict[str, dict[str, int | bool]]) -> None:
    for bit in _PROFILE_BITS:
        entry = snapshot.get(str(bit))
        if not entry:
            continue
        with contextlib.suppress(Exception):
            _set_default_outbound(policy, bit, int(entry.get("outbound", NET_FW_ACTION_ALLOW)))
        with contextlib.suppress(Exception):
            _set_firewall_enabled(policy, bit, bool(entry.get("enabled", True)))


def _resolve_rule_paths(
    rule: AppRule,
    running_by_exe: dict[str, set[str]],
) -> list[str]:
    """Return normalized executable paths to target in Windows Firewall for a rule."""
    paths: list[str] = []
    seen: set[str] = set()

    def _add(raw_path: str) -> None:
        cleaned = raw_path.strip()
        if not cleaned:
            return
        norm = "System" if cleaned.lower() == "system" else os.path.normpath(cleaned).replace("/", "\\")
        key = norm.lower()
        if key not in seen:
            seen.add(key)
            paths.append(norm)

    _add(rule.exe_path)
    if rule.match_type == "name":
        exe_key = os.path.basename(rule.exe_name or rule.exe_path).lower()
        for running_path in sorted(running_by_exe.get(exe_key, ())):
            _add(running_path)
    return paths


def _sanitize_rule_name(name: str) -> str:
    # Windows Firewall API (FWAddFirewallRule) rejects '|' because it is the registry serializer delimiter.
    return name.replace("|", "-").strip() or "PPV-FW Rule"


def _add_app_rule(
    policy: Any,
    rule_factory: Callable[[], Any],
    name: str,
    app_path: str,
    action: int,
    direction: int,
    protocol: int | None = None,
    remote_ports: str | None = None,
) -> None:
    fw_rule = rule_factory()
    fw_rule.Name = _sanitize_rule_name(name)
    fw_rule.Description = "Managed by PPV VPN Simple Firewall"
    if app_path:
        fw_rule.ApplicationName = app_path
    fw_rule.Action = action
    fw_rule.Direction = direction
    if protocol is not None:
        fw_rule.Protocol = protocol
        if remote_ports:
            fw_rule.RemotePorts = remote_ports
    fw_rule.Profiles = NET_FW_PROFILE2_ALL
    fw_rule.Grouping = RULE_GROUP
    fw_rule.Enabled = True
    policy.Rules.Add(fw_rule)


def _add_allowlist_essentials(
    policy: Any,
    rule_factory: Callable[[], Any],
    seen_allow_paths: set[str],
) -> int:
    """Permit PPV VPN itself, sing-box, and core DNS/DHCP so Strict Mode doesn't break DNS/VPN."""
    added = 0
    essentials: list[tuple[str, str]] = []

    singbox_bin = find_singbox_binary()
    if singbox_bin is not None:
        essentials.append(("sing-box", str(singbox_bin)))
    data_singbox = get_data_dir() / "bin" / "sing-box.exe"
    if data_singbox.exists():
        essentials.append(("sing-box-data", str(data_singbox)))

    self_exe = Path(sys.executable).resolve()
    if self_exe.exists():
        essentials.append(("PPV-VPN", str(self_exe)))

    for label, raw_path in essentials:
        norm = os.path.normpath(raw_path)
        key = norm.lower()
        if key in seen_allow_paths:
            continue
        seen_allow_paths.add(key)
        _add_app_rule(
            policy,
            rule_factory,
            name=f"{RULE_PREFIX}SYS ALLOW - {label}",
            app_path=norm,
            action=NET_FW_ACTION_ALLOW,
            direction=NET_FW_RULE_DIR_OUT,
        )
        added += 1

    # Permit svchost.exe DNS (UDP/TCP 53) and DHCP (UDP 67-68) cleanly
    svchost = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "svchost.exe"
    svchost_str = str(svchost)
    for label, proto, ports in (
        ("DNS UDP", 17, "53"),
        ("DNS TCP", 6, "53"),
        ("DHCP UDP", 17, "67,68"),
    ):
        _add_app_rule(
            policy,
            rule_factory,
            name=f"{RULE_PREFIX}SYS CORE - {label}",
            app_path=svchost_str,
            action=NET_FW_ACTION_ALLOW,
            direction=NET_FW_RULE_DIR_OUT,
            protocol=proto,
            remote_ports=ports,
        )
        added += 1

    return added


def sync_windows_firewall(
    settings: AppSettings,
    running_apps: list[DiscoveredApp] | None = None,
    policy: Any | None = None,
    rule_factory: Callable[[], Any] | None = None,
) -> FirewallSyncResult:
    """Apply or clear PPV VPN's Simple Firewall rules in Windows Defender Firewall (WFP)."""
    if policy is None and not is_admin():
        return FirewallSyncResult(
            enabled=settings.firewall_enabled,
            mode=settings.firewall_mode,
            errors=["Cần quyền Administrator để cấu hình Windows Firewall."],
        )

    use_com = policy is None
    if use_com:
        pythoncom.CoInitialize()

    try:
        fw_policy = policy if policy is not None else _default_policy_factory()
        mk_rule = rule_factory if rule_factory is not None else _default_rule_factory

        if not settings.firewall_enabled:
            removed = _remove_ppv_rules(fw_policy)
            if settings.firewall_saved_profiles is not None:
                _restore_profiles(fw_policy, settings.firewall_saved_profiles)
                settings.firewall_saved_profiles = None
            return FirewallSyncResult(
                enabled=False,
                mode=settings.firewall_mode,
                removed=removed,
            )

        # Snapshot original Windows Firewall profile state once before modifying
        if settings.firewall_saved_profiles is None:
            settings.firewall_saved_profiles = _snapshot_profiles(fw_policy)

        # Enable profiles safely first, keeping DefaultOutboundAction open until allowlist rules succeed
        for bit in _PROFILE_BITS:
            _set_firewall_enabled(fw_policy, bit, True)

        removed = _remove_ppv_rules(fw_policy)

        if running_apps is None and use_com:
            running_apps = list_running_apps(include_background=True, include_system_binaries=True)
        running_by_exe: dict[str, set[str]] = {}
        for app in running_apps or []:
            running_by_exe.setdefault(app.exe_name.lower(), set()).add(app.exe_path)

        applied_block = 0
        applied_allow = 0
        errors: list[str] = []
        seen_block_paths: set[str] = set()
        seen_allow_paths: set[str] = set()
        allowed_name_keys: set[str] = set()

        if settings.firewall_mode == "allowlist":
            try:
                essentials_added = _add_allowlist_essentials(fw_policy, mk_rule, seen_allow_paths)
                applied_allow += essentials_added
            except Exception as exc:
                essentials_added = 0
                errors.append(f"Không thể thêm rule hệ thống thiết yếu: {exc}")
            if essentials_added == 0:
                _remove_ppv_rules(fw_policy)
                if settings.firewall_saved_profiles is not None:
                    _restore_profiles(fw_policy, settings.firewall_saved_profiles)
                    settings.firewall_saved_profiles = None
                settings.firewall_enabled = False
                return FirewallSyncResult(
                    enabled=False,
                    mode=settings.firewall_mode,
                    removed=removed,
                    errors=errors
                    or ["Không thể tạo rule hệ thống thiết yếu cho Allowlist; đã tự hủy bật Firewall để tránh mất mạng."],
                )

        for idx, rule in enumerate(settings.app_rules):
            if not rule.enabled:
                continue
            target_paths = _resolve_rule_paths(rule, running_by_exe)
            if settings.firewall_mode == "allowlist" and rule.action in ("vpn", "allow") and rule.match_type == "name":
                exe_key = os.path.basename(rule.exe_name or rule.exe_path).lower()
                if exe_key:
                    allowed_name_keys.add(exe_key)
            for p_idx, path_str in enumerate(target_paths):
                key = path_str.lower()
                if rule.action == "block":
                    if key in seen_block_paths:
                        continue
                    seen_block_paths.add(key)
                    try:
                        _add_app_rule(
                            fw_policy,
                            mk_rule,
                            name=f"{RULE_PREFIX}BLOCK OUT - {rule.exe_name} ({idx}-{p_idx})",
                            app_path=path_str,
                            action=NET_FW_ACTION_BLOCK,
                            direction=NET_FW_RULE_DIR_OUT,
                        )
                        _add_app_rule(
                            fw_policy,
                            mk_rule,
                            name=f"{RULE_PREFIX}BLOCK IN - {rule.exe_name} ({idx}-{p_idx})",
                            app_path=path_str,
                            action=NET_FW_ACTION_BLOCK,
                            direction=NET_FW_RULE_DIR_IN,
                        )
                        applied_block += 1
                    except Exception as exc:
                        errors.append(f"Block {rule.exe_name} ({path_str}): {exc}")
                elif settings.firewall_mode == "allowlist" and rule.action in ("vpn", "allow"):
                    if key in seen_allow_paths:
                        continue
                    seen_allow_paths.add(key)
                    try:
                        _add_app_rule(
                            fw_policy,
                            mk_rule,
                            name=f"{RULE_PREFIX}ALLOW OUT - {rule.exe_name} ({idx}-{p_idx})",
                            app_path=path_str,
                            action=NET_FW_ACTION_ALLOW,
                            direction=NET_FW_RULE_DIR_OUT,
                        )
                        applied_allow += 1
                    except Exception as exc:
                        errors.append(f"Allow {rule.exe_name} ({path_str}): {exc}")

        if settings.firewall_mode == "allowlist":
            # Explicitly block unassigned running apps so pre-existing Windows Allow rules cannot bypass Allowlist
            for u_idx, app in enumerate(running_apps or []):
                norm_path = os.path.normpath(app.exe_path.strip()).replace("/", "\\")
                key = norm_path.lower()
                exe_low = app.exe_name.lower()
                if (
                    not norm_path
                    or exe_low in _ALLOWLIST_PROTECTED_EXES
                    or key in seen_allow_paths
                    or exe_low in allowed_name_keys
                    or key in seen_block_paths
                ):
                    continue
                seen_block_paths.add(key)
                try:
                    _add_app_rule(
                        fw_policy,
                        mk_rule,
                        name=f"{RULE_PREFIX}BLOCK UNASSIGNED - {app.exe_name} ({u_idx})",
                        app_path=norm_path,
                        action=NET_FW_ACTION_BLOCK,
                        direction=NET_FW_RULE_DIR_OUT,
                    )
                    applied_block += 1
                except Exception as exc:
                    errors.append(f"Block unassigned {app.exe_name} ({norm_path}): {exc}")

        target_outbound = (
            NET_FW_ACTION_BLOCK
            if settings.firewall_mode == "allowlist"
            else NET_FW_ACTION_ALLOW
        )
        for bit in _PROFILE_BITS:
            _set_default_outbound(fw_policy, bit, target_outbound)

        return FirewallSyncResult(
            enabled=True,
            mode=settings.firewall_mode,
            applied_block=applied_block,
            applied_allow=applied_allow,
            removed=removed,
            errors=errors,
        )
    except Exception as exc:
        return FirewallSyncResult(
            enabled=settings.firewall_enabled,
            mode=settings.firewall_mode,
            errors=[f"Lỗi cấu hình Windows Firewall: {exc}"],
        )
    finally:
        if use_com:
            with contextlib.suppress(Exception):
                pythoncom.CoUninitialize()


def disable_windows_firewall(
    settings: AppSettings,
    policy: Any | None = None,
) -> FirewallSyncResult:
    """Disable PPV Simple Firewall rules and restore original Windows Firewall profile settings."""
    settings.firewall_enabled = False
    return sync_windows_firewall(settings, policy=policy)
