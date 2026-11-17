"""Windows process discovery, Start Menu app scanning, icon extraction, and UAC helpers."""

from __future__ import annotations

import contextlib
import ctypes
import os
import subprocess
import sys
import time
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

import win32api
import win32com.client
import win32con
import win32gui
import win32process
import win32service
import win32ui
from PySide6.QtGui import QImage, QPixmap


@dataclass
class DiscoveredApp:
    """An application discovered from running processes, Start Menu, or Registry."""

    display_name: str
    exe_name: str
    exe_path: str
    source: str  # "running" | "installed"
    has_window: bool = False
    pid: int | None = None


@dataclass
class ConflictingVpn:
    """A running third-party VPN service or process that may conflict with PPV VPN."""

    kind: str  # "service" | "process"
    identifier: str  # Windows service name or process exe_name
    display_name: str
    pid: int | None = None
    exe_path: str | None = None


_CONFLICT_SERVICE_NAMES = {
    "wireguardmanager",
    "cloudflarewarp",
    "openvpnservice",
    "openvpnserviceinteractive",
    "openvpnserv",
    "openvpnserv2",
    "protonvpn service",
    "protonvpnwireguardservice",
    "protonvpn.wireguardservice",
    "nordvpn-service",
    "mullvad-daemon",
    "surfshark service",
    "windscribeservice",
    "expressvpnservice",
    "expressvpnd",
    "tailscale",
}

_CONFLICT_PROCESS_NAMES = {
    "apkcombovpn.exe": "APKCombo VPN",
    "wireguard.exe": "WireGuard",
    "cloudflare warp.exe": "Cloudflare WARP",
    "warp-cli.exe": "Cloudflare WARP CLI",
    "warp-svc.exe": "Cloudflare WARP Service",
    "openvpn.exe": "OpenVPN",
    "openvpn-gui.exe": "OpenVPN GUI",
    "protonvpn.exe": "Proton VPN",
    "protonvpn-app.exe": "Proton VPN",
    "nordvpn.exe": "NordVPN",
    "mullvad-vpn.exe": "Mullvad VPN",
    "mullvad-gui.exe": "Mullvad VPN",
    "mullvad-daemon.exe": "Mullvad VPN Service",
    "surfshark.exe": "Surfshark",
    "windscribe.exe": "Windscribe",
    "expressvpn.exe": "ExpressVPN",
    "expressvpn-ui.exe": "ExpressVPN",
    "tailscale-ipn.exe": "Tailscale",
    "tailscaled.exe": "Tailscale Daemon",
    "clash-verge.exe": "Clash Verge",
    "clash-verge-service.exe": "Clash Verge Service",
    "clash-nyanpasu.exe": "Clash Nyanpasu",
    "mihomo.exe": "Mihomo Core",
    "v2rayn.exe": "v2rayN",
    "nekobox.exe": "NekoBox",
    "nekoray.exe": "Nekoray",
    "hiddify.exe": "Hiddify",
    "1.1.1.1.exe": "Cloudflare 1.1.1.1",
}


_SYSTEM_EXE_IGNORE = {
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "conhost.exe",
    "dllhost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
    "searchapp.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "textinputhost.exe",
    "audiodg.exe",
    "spoolsv.exe",
    "wudfhost.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "sing-box.exe",
}

_UNINSTALLER_KEYWORDS = ("uninst", "setup", "installer", "update", "updater", "helper")


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(extra_args: list[str] | None = None) -> bool:
    """Relaunch the current application with UAC elevation."""
    args: list[str] = []
    if not getattr(sys, "frozen", False):
        args.extend(["-m", "ppv"])
    if extra_args:
        args.extend(extra_args)

    params = subprocess.list2cmdline(args)
    cwd = str(Path(__file__).resolve().parent.parent if not getattr(sys, "frozen", False) else Path(sys.executable).parent)
    exe = sys.executable
    if not getattr(sys, "frozen", False):
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        if pythonw.exists():
            exe = str(pythonw)

    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, cwd, 1)
    return int(rc) > 32


def _iter_process_entries() -> list[tuple[int, str]]:
    """Return list of `(pid, exe_name)` for all running processes."""
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value:
        return []

    items: list[tuple[int, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        has_more = ctypes.windll.kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while has_more:
            items.append((int(entry.th32ProcessID), str(entry.szExeFile)))
            has_more = ctypes.windll.kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        ctypes.windll.kernel32.CloseHandle(snap)
    return items


def cleanup_orphan_singbox(binary_path: Path) -> int:
    """Terminate any lingering sing-box.exe launched from our bin directory."""
    target_norm = os.path.normpath(str(binary_path)).lower()
    target_parent = os.path.normpath(str(binary_path.parent.parent)).lower()
    killed = 0
    PROCESS_TERMINATE = 0x0001
    SYNCHRONIZE = 0x00100000

    for pid, exe_name in _iter_process_entries():
        if exe_name.lower() != "sing-box.exe" or pid <= 4:
            continue
        full_path = _query_process_path(pid)
        if not full_path:
            continue
        norm_proc = os.path.normpath(full_path).lower()
        # Match exact binary or another PPV-VPN bundled sing-box binary
        if (
            norm_proc == target_norm
            or norm_proc.startswith(target_parent + "\\")
            or ("\\ppv-vpn\\" in norm_proc and norm_proc.endswith("\\bin\\sing-box.exe"))
        ):
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_TERMINATE | SYNCHRONIZE, False, pid
            )
            if handle:
                try:
                    if ctypes.windll.kernel32.TerminateProcess(handle, 1):
                        ctypes.windll.kernel32.WaitForSingleObject(handle, 3000)
                        killed += 1
                finally:
                    ctypes.windll.kernel32.CloseHandle(handle)
    return killed


def _is_conflicting_vpn_service(svc_name: str, display_name: str) -> bool:
    low_name = svc_name.lower()
    low_disp = display_name.lower()
    return (
        low_name.startswith("wireguardtunnel$")
        or low_name in _CONFLICT_SERVICE_NAMES
        or "apkcombo" in low_name
        or "apkcombo" in low_disp
    )


def find_running_wireguard_tunnels() -> list[tuple[str, str]]:
    """Return list of `(service_name, display_name)` for running WireGuard/APKCombo/VPN services."""
    conflicts: list[tuple[str, str]] = []
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
    except Exception:
        return conflicts

    try:
        services = win32service.EnumServicesStatus(
            scm, win32service.SERVICE_WIN32, win32service.SERVICE_ACTIVE
        )
        for svc_name, display_name, _status in services:
            if _is_conflicting_vpn_service(svc_name, display_name):
                conflicts.append((svc_name, display_name))
    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            win32service.CloseServiceHandle(scm)
    # Stop specific WireGuard tunnel instances before WireGuardManager
    conflicts.sort(key=lambda item: (0 if item[0].lower().startswith("wireguardtunnel$") else 1, item[0].lower()))
    return conflicts


def find_conflicting_vpns() -> list[ConflictingVpn]:
    """Detect all running third-party VPN Windows services and desktop processes."""
    results: list[ConflictingVpn] = []

    for svc_name, display_name in find_running_wireguard_tunnels():
        results.append(
            ConflictingVpn(
                kind="service",
                identifier=svc_name,
                display_name=display_name or svc_name,
            )
        )

    self_pid = os.getpid()
    for pid, exe_name in _iter_process_entries():
        if pid <= 4 or pid == self_pid:
            continue
        low_exe = exe_name.lower()
        friendly = _CONFLICT_PROCESS_NAMES.get(low_exe)
        if friendly is None:
            continue
        results.append(
            ConflictingVpn(
                kind="process",
                identifier=exe_name,
                display_name=friendly,
                pid=pid,
                exe_path=_query_process_path(pid),
            )
        )
    return results


def stop_windows_service(service_name: str, wait_timeout_sec: float = 4.0) -> tuple[bool, str]:
    """Stop a Windows service cleanly and wait until it stops (requires Admin privileges)."""
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    except Exception as exc:
        return False, f"Không thể mở Service Control Manager: {exc}"

    try:
        svc = win32service.OpenService(
            scm,
            service_name,
            win32service.SERVICE_STOP | win32service.SERVICE_QUERY_STATUS,
        )
        try:
            try:
                status = win32service.ControlService(svc, win32service.SERVICE_CONTROL_STOP)
            except Exception as exc:
                # 1062 == ERROR_SERVICE_NOT_ACTIVE (already stopped)
                if getattr(exc, "winerror", None) == 1062:
                    return True, f"Dịch vụ {service_name} đã dừng."
                raise
            deadline = time.monotonic() + max(0.0, wait_timeout_sec)
            while status[1] != win32service.SERVICE_STOPPED and time.monotonic() < deadline:
                time.sleep(0.15)
                status = win32service.QueryServiceStatus(svc)
            return True, f"Đã dừng dịch vụ {service_name}."
        finally:
            win32service.CloseServiceHandle(svc)
    except Exception as exc:
        return False, f"Không thể dừng dịch vụ {service_name}: {exc}"
    finally:
        win32service.CloseServiceHandle(scm)


def terminate_process_by_pid(pid: int, wait_ms: int = 3000) -> tuple[bool, str]:
    """Terminate a running process by PID and wait briefly for exit."""
    PROCESS_TERMINATE = 0x0001
    SYNCHRONIZE = 0x00100000
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
    if not handle:
        # Process may already have exited after its service stopped
        if _query_process_path(pid) is None:
            return True, f"Tiến trình PID {pid} đã kết thúc."
        return False, f"Không đủ quyền hoặc không thể mở tiến trình PID {pid}."
    try:
        if ctypes.windll.kernel32.TerminateProcess(handle, 0):
            ctypes.windll.kernel32.WaitForSingleObject(handle, wait_ms)
            return True, f"Đã tắt tiến trình PID {pid}."
        return False, f"Không thể kết thúc tiến trình PID {pid}."
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def stop_conflicting_vpns(settle_sec: float = 1.0) -> tuple[list[str], list[str]]:
    """Stop all detected conflicting VPN services and processes.

    Returns `(stopped_labels, error_messages)`.
    """
    conflicts = find_conflicting_vpns()
    stopped: list[str] = []
    errors: list[str] = []
    stopped_services = False

    # 1. Stop services first (tunnels before manager) so adapters/routes tear down cleanly
    for item in conflicts:
        if item.kind != "service":
            continue
        ok, msg = stop_windows_service(item.identifier)
        if ok:
            stopped.append(f"{item.display_name} ({item.identifier})")
            stopped_services = True
        else:
            errors.append(msg)

    # 2. Terminate remaining VPN GUI / background processes (re-check PIDs in case stopping a service already closed them)
    proc_items = [c for c in conflicts if c.kind == "process" and c.pid is not None]
    if proc_items:
        still_running = {pid for pid, _name in _iter_process_entries()}
        for item in proc_items:
            assert item.pid is not None
            if item.pid not in still_running:
                stopped.append(f"{item.display_name} ({item.identifier})")
                continue
            ok, msg = terminate_process_by_pid(item.pid)
            if ok:
                stopped.append(f"{item.display_name} ({item.identifier})")
            else:
                errors.append(f"{item.identifier}: {msg}")

    if stopped_services and settle_sec > 0:
        # Give Windows PnP / Wintun a moment to finish tearing down the old TUN device
        time.sleep(settle_sec)

    return stopped, errors


def cleanup_stale_ppv_instances() -> int:
    """Terminate older PPV-VPN.exe processes running from a different directory (e.g. legacy dist/)."""
    if not getattr(sys, "frozen", False):
        return 0
    current_pid = os.getpid()
    current_exe = os.path.normpath(sys.executable).lower()
    cleaned = 0
    for pid, exe_name in _iter_process_entries():
        if pid <= 4 or pid == current_pid or exe_name.lower() != "ppv-vpn.exe":
            continue
        full_path = _query_process_path(pid)
        if not full_path:
            continue
        if os.path.normpath(full_path).lower() != current_exe:
            ok, _msg = terminate_process_by_pid(pid)
            if ok:
                cleaned += 1
    return cleaned


def _get_visible_window_pids() -> dict[int, str]:
    pid_titles: dict[int, str] = {}

    def _cb(hwnd: int, _extra: int) -> bool:
        if not win32gui.IsWindowVisible(hwnd):
            return True
        title = win32gui.GetWindowText(hwnd).strip()
        if not title:
            return True
        try:
            _tid, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid and pid not in pid_titles:
                pid_titles[pid] = title
        except Exception:
            pass
        return True

    with contextlib.suppress(Exception):
        win32gui.EnumWindows(_cb, 0)
    return pid_titles


def _query_process_path(pid: int) -> str | None:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        buf_len = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(1024)
        ok = ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(buf_len))
        if ok:
            return buf.value
        return None
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _get_exe_friendly_name(exe_path: str) -> str:
    stem = Path(exe_path).stem
    try:
        lang_cp = win32api.GetFileVersionInfo(exe_path, "\\VarFileInfo\\Translation")
        if lang_cp:
            lang, cp = lang_cp[0]
            str_info = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\FileDescription"
            desc = win32api.GetFileVersionInfo(exe_path, str_info)
            if desc and str(desc).strip():
                return str(desc).strip()
    except Exception:
        pass
    return stem


_SYS32_NETWORK_TOOLS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "curl.exe",
    "ssh.exe",
    "scp.exe",
    "sftp.exe",
    "winget.exe",
    "cscript.exe",
    "wscript.exe",
    "msiexec.exe",
}


def list_running_apps(
    include_background: bool = True,
    include_system_binaries: bool = False,
) -> list[DiscoveredApp]:
    """List currently running Windows applications deduplicated by executable path."""
    window_pids = _get_visible_window_pids()
    by_path: dict[str, DiscoveredApp] = {}

    for pid, exe_name in _iter_process_entries():
        low_name = exe_name.lower()
        if pid <= 4 or low_name in _SYSTEM_EXE_IGNORE:
            continue
        has_win = pid in window_pids
        if not has_win and not include_background:
            continue
        full_path = _query_process_path(pid)
        if not full_path or not full_path.lower().endswith(".exe") or not os.path.exists(full_path):
            continue
        norm_key = full_path.lower()
        # Skip noisy Windows internal binaries unless requested, visible window, or CLI tool
        is_sys32 = "\\windows\\system32\\" in norm_key or "\\windows\\syswow64\\" in norm_key
        if is_sys32 and not include_system_binaries and not has_win and low_name not in _SYS32_NETWORK_TOOLS:
            continue
        existing = by_path.get(norm_key)
        if existing is None:
            friendly = _get_exe_friendly_name(full_path)
            by_path[norm_key] = DiscoveredApp(
                display_name=friendly,
                exe_name=os.path.basename(full_path),
                exe_path=full_path,
                source="running",
                has_window=has_win,
                pid=pid,
            )
        elif has_win and not existing.has_window:
            existing.has_window = True

    apps = list(by_path.values())
    apps.sort(key=lambda a: (not a.has_window, a.display_name.lower()))
    return apps


def list_installed_apps() -> list[DiscoveredApp]:
    """Scan Windows Start Menu shortcuts and Registry App Paths for installed .exe apps."""
    by_path: dict[str, DiscoveredApp] = {}
    start_dirs = [
        Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs",
        Path(os.environ.get("APPDATA", ""))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs",
    ]

    try:
        shell = win32com.client.Dispatch("WScript.Shell")
    except Exception:
        shell = None

    if shell is not None:
        for base_dir in start_dirs:
            if not base_dir.exists():
                continue
            for lnk in base_dir.rglob("*.lnk"):
                stem_low = lnk.stem.lower()
                if any(kw in stem_low for kw in _UNINSTALLER_KEYWORDS):
                    continue
                try:
                    shortcut = shell.CreateShortCut(str(lnk))
                    target = str(shortcut.Targetpath or "").strip()
                except Exception:
                    continue
                if not target or not target.lower().endswith(".exe"):
                    continue
                if not os.path.exists(target):
                    continue
                low_base = os.path.basename(target).lower()
                if low_base in _SYSTEM_EXE_IGNORE or any(kw in low_base for kw in _UNINSTALLER_KEYWORDS):
                    continue
                norm_key = os.path.normpath(target).lower()
                if norm_key not in by_path:
                    by_path[norm_key] = DiscoveredApp(
                        display_name=lnk.stem,
                        exe_name=os.path.basename(target),
                        exe_path=os.path.normpath(target),
                        source="installed",
                    )

    # Also inspect HKLM & HKCU App Paths
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            key = winreg.OpenKey(root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths")
        except OSError:
            continue
        try:
            idx = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(key, idx)
                    idx += 1
                except OSError:
                    break
                if not sub_name.lower().endswith(".exe"):
                    continue
                try:
                    sub_key = winreg.OpenKey(key, sub_name)
                    val, _ = winreg.QueryValueEx(sub_key, "")
                    winreg.CloseKey(sub_key)
                except OSError:
                    continue
                target = str(val or "").strip().strip('"')
                if not target or not os.path.exists(target):
                    continue
                norm_key = os.path.normpath(target).lower()
                if norm_key not in by_path:
                    by_path[norm_key] = DiscoveredApp(
                        display_name=_get_exe_friendly_name(target),
                        exe_name=os.path.basename(target),
                        exe_path=os.path.normpath(target),
                        source="installed",
                    )
        finally:
            winreg.CloseKey(key)

    apps = list(by_path.values())
    apps.sort(key=lambda a: a.display_name.lower())
    return apps


_ICON_CACHE: dict[str, QPixmap] = {}


def extract_exe_icon(exe_path: str, size: int = 32) -> QPixmap | None:
    """Extract the application icon from a Windows .exe and return it as a QPixmap."""
    if not exe_path or not os.path.exists(exe_path):
        return None
    cache_key = f"{exe_path.lower()}::{size}"
    if cache_key in _ICON_CACHE:
        return _ICON_CACHE[cache_key]

    large_icons, small_icons = [], []
    with contextlib.suppress(Exception):
        large_icons, small_icons = win32gui.ExtractIconEx(exe_path, 0, 1)

    hicon = None
    if size <= 20 and small_icons:
        hicon = small_icons[0]
    elif large_icons:
        hicon = large_icons[0]
    elif small_icons:
        hicon = small_icons[0]

    pixmap: QPixmap | None = None
    if hicon:
        try:
            hdc_screen = win32gui.GetDC(0)
            hdc = win32ui.CreateDCFromHandle(hdc_screen)
            mem_dc = hdc.CreateCompatibleDC()
            bmp = win32ui.CreateBitmap()
            bmp.CreateCompatibleBitmap(hdc, size, size)
            mem_dc.SelectObject(bmp)
            win32gui.DrawIconEx(
                mem_dc.GetSafeHdc(), 0, 0, hicon, size, size, 0, None, win32con.DI_NORMAL
            )
            bmp_info = bmp.GetInfo()
            bmp_bits = bmp.GetBitmapBits(True)
            img = QImage(
                bmp_bits,
                bmp_info["bmWidth"],
                bmp_info["bmHeight"],
                QImage.Format.Format_ARGB32,
            ).copy()
            pixmap = QPixmap.fromImage(img)
            mem_dc.DeleteDC()
            hdc.DeleteDC()
            win32gui.ReleaseDC(0, hdc_screen)
            win32gui.DeleteObject(bmp.GetHandle())
        except Exception:
            pixmap = None

    for ic in large_icons + small_icons:
        with contextlib.suppress(Exception):
            win32gui.DestroyIcon(ic)

    if pixmap and not pixmap.isNull():
        _ICON_CACHE[cache_key] = pixmap
        return pixmap
    return None
