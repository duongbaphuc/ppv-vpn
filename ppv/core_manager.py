"""Manages the sing-box core process, config validation, and Clash API telemetry."""

from __future__ import annotations

import atexit
import contextlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from PySide6.QtCore import QObject, Signal

from ppv.models import AppSettings, WireGuardProfile
from ppv.process_helper import cleanup_orphan_singbox
from ppv.singbox_config import build_probe_config, build_singbox_config
from ppv.storage import get_app_root, get_data_dir

_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-9;?]*[A-Za-z]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
_LOG_CONN_ID_RE = re.compile(r"\[(\d+)\s+[^\]]+\]")
_LOG_INBOUND_TO_RE = re.compile(r"inbound (?:(packet) )?connection to (\S+)")
_LOG_PROC_PATH_RE = re.compile(r"router:\s*found process path:\s*(.+)$")
_LOG_ROUTER_REJECT_RE = re.compile(
    r"router:\s*(?:match\[\d+\]\s*=>\s*reject|connection closed:\s*rejected)",
    re.I,
)

WARP_ENDPOINT_CANDIDATES: tuple[tuple[str, int], ...] = (
    ("engage.cloudflareclient.com", 2408),
    ("162.159.192.1", 2408),
    ("162.159.192.1", 4500),
    ("162.159.192.1", 500),
    ("162.159.192.1", 1701),
    ("162.159.192.1", 894),
    ("162.159.192.1", 908),
    ("162.159.192.1", 854),
    ("188.114.96.1", 2408),
    ("162.159.195.1", 2408),
)


@dataclass
class WireGuardProbeResult:
    """Result of probing a WireGuard/WARP profile via headless sing-box HTTP->wg-out."""

    ok: bool
    handshake_ok: bool
    endpoint_host: str
    endpoint_port: int
    latency_ms: int | None = None
    exit_ip: str = ""
    warp_status: str = ""
    loc: str = ""
    error: str = ""


def _parse_cloudflare_trace(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        if "=" in raw_line:
            k, v = raw_line.split("=", 1)
            parsed[k.strip()] = v.strip()
    return parsed


def _is_noisy_debug_log(line: str) -> bool:
    low = line.lower()
    return "endpoint/wireguard[" in low and "routine:" in low


def _is_wintun_adapter_collision(detail: str) -> bool:
    """Return True when Wintun fails due to a transient/stale Windows TUN adapter collision."""
    low = detail.lower()
    return "cannot create a file when that file already exists" in low or (
        "configure tun interface" in low and "element not found" in low
    )


def strip_ansi(text: str) -> str:
    """Remove ANSI color/control escape sequences from log text."""
    return _ANSI_ESCAPE_RE.sub("", text)


@dataclass
class ConnectionRow:
    """Single active/recent connection entry returned by sing-box Clash API or block log."""

    conn_id: str
    process_name: str
    destination: str
    network: str
    rule_outbound: str
    upload_bytes: int
    download_bytes: int
    blocked_count: int = 0
    timestamp: str = ""


def find_singbox_binary() -> Path | None:
    """Locate sing-box.exe next to the app, in PyInstaller bundle, or on PATH."""
    candidates: list[Path] = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "bin" / "sing-box.exe")
        candidates.append(Path(sys.executable).resolve().parent / "bin" / "sing-box.exe")
    app_root = get_app_root()
    candidates.append(app_root / "bin" / "sing-box.exe")
    candidates.append(app_root / "sing-box.exe")
    candidates.append(get_data_dir() / "bin" / "sing-box.exe")

    for cand in candidates:
        if cand.exists():
            return cand

    which = shutil.which("sing-box")
    return Path(which) if which else None


def _pick_free_port(preferred: int = 19090) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return int(sock.getsockname()[1])
            except OSError:
                continue
    return 19090


class VpnCoreManager(QObject):
    """Lifecycle controller for the sing-box tunnel process."""

    state_changed = Signal(str)  # "disconnected" | "connecting" | "connected" | "error"
    log_received = Signal(str)
    stats_updated = Signal(int, int, int, int, list)  # up_bps, down_bps, up_total, down_total, conns
    error_occurred = Signal(str)
    tunnel_warning = Signal(str)  # non-empty when WireGuard handshake fails/stalls; "" when healthy

    def __init__(self, runtime_dir: Path, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.runtime_dir / "singbox-active.json"
        self.log_path = self.runtime_dir / "singbox.log"

        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._state = "disconnected"
        self._api_port = 19090
        self._api_secret = ""
        self._prev_up = 0
        self._prev_down = 0
        self._prev_ts = 0.0
        self._recent_logs: deque[str] = deque(maxlen=25)
        self._blocked_exact_paths: set[str] = set()
        self._blocked_exe_names: set[str] = set()
        self._pending_log_conns: dict[str, dict[str, Any]] = {}
        self._blocked_events: dict[tuple[str, str], ConnectionRow] = {}
        self._active_endpoint_host = ""
        self._active_endpoint_port = 0
        self._handshake_ok = False
        self._handshake_failures = 0
        self._endpoint_lookup_times: deque[float] = deque(maxlen=10)
        self._wg_first_outbound_ts = 0.0
        self._last_tunnel_warning = ""
        self._active_binary: Path | None = None
        self._active_profile: WireGuardProfile | None = None
        self._active_settings: AppSettings | None = None
        self._tun_retry_used = False

        atexit.register(self.stop_sync)

    @property
    def state(self) -> str:
        return self._state

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def _set_state(self, new_state: str) -> None:
        self._state = new_state
        self.state_changed.emit(new_state)

    def validate_config(self, config_dict: dict[str, Any]) -> tuple[bool, str]:
        """Write config to disk and validate it with `sing-box check`."""
        binary = find_singbox_binary()
        if binary is None:
            return False, "Không tìm thấy sing-box.exe trong thư mục bin/."

        self.config_path.write_text(
            json.dumps(config_dict, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            res = subprocess.run(
                [str(binary), "--disable-color", "check", "-c", str(self.config_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                creationflags=creation_flags,
            )
        except Exception as exc:
            return False, f"Lỗi khi kiểm tra cấu hình sing-box: {exc}"

        if res.returncode != 0:
            msg = strip_ansi(
                res.stderr or res.stdout or "Cấu hình sing-box không hợp lệ."
            ).strip()
            return False, msg
        return True, "OK"

    def _spawn_singbox_process(
        self,
        binary: Path,
        profile: WireGuardProfile,
        settings: AppSettings,
        interface_name: str = "PPV-Tunnel",
        append_log: bool = False,
    ) -> bool:
        self._api_port = _pick_free_port(19090)
        self._api_secret = secrets.token_hex(12)
        config_dict = build_singbox_config(
            profile=profile,
            settings=settings,
            api_port=self._api_port,
            api_secret=self._api_secret,
            interface_name=interface_name,
        )

        ok, check_msg = self.validate_config(config_dict)
        if not ok:
            self.log_received.emit(f"[LỖI CẤU HÌNH] {check_msg}")
            self.error_occurred.emit(check_msg)
            self._set_state("error")
            return False

        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
        try:
            proc = subprocess.Popen(
                [str(binary), "--disable-color", "run", "-c", str(self.config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creation_flags,
            )
        except Exception as exc:
            err = f"Không thể khởi chạy sing-box: {exc}"
            self.log_received.emit(f"[LỖI] {err}")
            self.error_occurred.emit(err)
            self._set_state("error")
            return False

        with self._lock:
            self._proc = proc

        self.log_received.emit(
            f"[PPV] Đang khởi động tunnel ({profile.name} -> {profile.endpoint}, iface={interface_name})..."
        )
        threading.Thread(
            target=self._read_logs_loop, args=(proc, append_log), daemon=True
        ).start()
        threading.Thread(target=self._poll_api_loop, args=(proc,), daemon=True).start()
        return True

    def start(self, profile: WireGuardProfile, settings: AppSettings) -> None:
        """Start the sing-box tunnel in background threads."""
        if self.is_running:
            self.stop_sync()

        binary = find_singbox_binary()
        if binary is None:
            err = "Không tìm thấy bin/sing-box.exe."
            self.error_occurred.emit(err)
            self._set_state("error")
            return

        self._stop_event.clear()
        self._recent_logs.clear()
        with self._lock:
            self._pending_log_conns.clear()
            self._blocked_events.clear()
            self._active_binary = binary
            self._active_profile = profile
            self._active_settings = settings
            self._tun_retry_used = False
            self._active_endpoint_host = (profile.endpoint_host or "").strip()
            self._active_endpoint_port = int(profile.endpoint_port or 2408)
            self._handshake_ok = False
            self._handshake_failures = 0
            self._endpoint_lookup_times.clear()
            self._wg_first_outbound_ts = 0.0
            self._blocked_exact_paths = {
                os.path.normpath(r.exe_path).lower()
                for r in settings.app_rules
                if r.enabled and r.action == "block" and r.match_type == "path" and r.exe_path
            }
            self._blocked_exe_names = {
                os.path.basename(r.exe_name or r.exe_path).lower()
                for r in settings.app_rules
                if r.enabled and r.action == "block" and r.match_type == "name" and (r.exe_name or r.exe_path)
            }
        self._emit_tunnel_warning("")
        self._prev_up = 0
        self._prev_down = 0
        self._prev_ts = time.monotonic()
        self._set_state("connecting")

        cleaned = cleanup_orphan_singbox(binary)
        if cleaned:
            self.log_received.emit(
                f"[PPV] Đã dọn {cleaned} tiến trình sing-box cũ còn sót lại."
            )
            self._stop_event.wait(0.8)

        self._spawn_singbox_process(binary, profile, settings, interface_name="PPV-Tunnel")

    def _read_logs_loop(self, proc: subprocess.Popen[str], append_log: bool = False) -> None:
        assert proc.stdout is not None
        saw_started = False
        log_mode = "a" if append_log else "w"
        try:
            with self.log_path.open(log_mode, encoding="utf-8") as log_file:
                for raw_line in proc.stdout:
                    line = strip_ansi(raw_line.rstrip("\r\n"))
                    if not line:
                        continue
                    self._inspect_tunnel_health_log(line)
                    if _is_noisy_debug_log(line):
                        continue
                    self._recent_logs.append(line)
                    self._track_log_event(line)
                    log_file.write(line + "\n")
                    log_file.flush()
                    self.log_received.emit(line)
                    if not saw_started and "sing-box started" in line.lower():
                        saw_started = True
                        if not self._stop_event.is_set():
                            self._set_state("connected")
        except Exception:
            pass

        rc = proc.wait()
        with self._lock:
            if self._proc is proc:
                self._proc = None

        self._emit_tunnel_warning("")
        if self._stop_event.is_set():
            self._set_state("disconnected")
            self.stats_updated.emit(0, 0, 0, 0, [])
            return

        if rc != 0:
            self.log_received.emit(f"[PPV] sing-box thoát bất ngờ (mã {rc}).")
            detail = self._extract_error_detail()
            if (
                not saw_started
                and not self._tun_retry_used
                and _is_wintun_adapter_collision(detail)
                and self._active_binary is not None
                and self._active_profile is not None
                and self._active_settings is not None
            ):
                self._tun_retry_used = True
                self.log_received.emit(
                    "[PPV] Adapter TUN 'PPV-Tunnel' đang kẹt trong Windows; "
                    "đang tự thử lại với tên adapter dự phòng..."
                )
                if self._stop_event.wait(1.2):
                    self._set_state("disconnected")
                    self.stats_updated.emit(0, 0, 0, 0, [])
                    return
                self._recent_logs.clear()
                fallback_iface = f"PPV-TUN-{secrets.token_hex(2).upper()}"
                self._spawn_singbox_process(
                    self._active_binary,
                    self._active_profile,
                    self._active_settings,
                    interface_name=fallback_iface,
                    append_log=True,
                )
                return

            msg = f"Tiến trình VPN dừng đột ngột (mã {rc})."
            if detail:
                msg += f"\n\nChi tiết: {detail}"
            else:
                msg += " Hãy kiểm tra quyền Admin hoặc tab Giám sát & Nhật ký."
            self.error_occurred.emit(msg)
            self._set_state("error")
        else:
            self._set_state("disconnected")
        self.stats_updated.emit(0, 0, 0, 0, [])

    def _emit_tunnel_warning(self, message: str) -> None:
        with self._lock:
            if message == self._last_tunnel_warning:
                return
            self._last_tunnel_warning = message
        self.tunnel_warning.emit(message)

    def _build_handshake_warning(self) -> str:
        ep = (
            f"{self._active_endpoint_host}:{self._active_endpoint_port}"
            if self._active_endpoint_host
            else "Endpoint WireGuard"
        )
        return (
            f"Tunnel WireGuard (wg-out) chưa bắt tay được với {ep} — các app 'Qua VPN' sẽ bị "
            "timeout (TLS handshake timeout). Hãy bấm 'Kiểm tra Profile' để tìm Endpoint/Port WARP "
            "hoạt động hoặc tạo profile Cloudflare WARP mới."
        )

    def _inspect_tunnel_health_log(self, line: str) -> None:
        low = line.lower()
        now = time.monotonic()

        if "received handshake response" in low:
            with self._lock:
                self._handshake_ok = True
                self._handshake_failures = 0
                self._endpoint_lookup_times.clear()
            self._emit_tunnel_warning("")
            return

        if "handshake did not complete after" in low:
            warn_msg = ""
            with self._lock:
                if not self._handshake_ok:
                    self._handshake_failures += 1
                    if self._handshake_failures >= 2:
                        warn_msg = self._build_handshake_warning()
            if warn_msg:
                self._emit_tunnel_warning(warn_msg)
            return

        if "endpoint/wireguard[wg-out]: outbound " in low:
            with self._lock:
                if self._wg_first_outbound_ts == 0.0:
                    self._wg_first_outbound_ts = now
            return

        if "outbound/wireguard[wg-out]" in low and (
            "operation timed out" in low or "i/o timeout" in low
        ):
            warn_msg = ""
            with self._lock:
                if not self._handshake_ok:
                    warn_msg = self._build_handshake_warning()
            if warn_msg:
                self._emit_tunnel_warning(warn_msg)
            return

        host = self._active_endpoint_host.lower()
        if host and f"dns: lookup succeed for {host}" in low:
            warn_msg = ""
            with self._lock:
                if not self._handshake_ok:
                    self._endpoint_lookup_times.append(now)
                    while (
                        self._endpoint_lookup_times
                        and now - self._endpoint_lookup_times[0] > 20.0
                    ):
                        self._endpoint_lookup_times.popleft()
                    if len(self._endpoint_lookup_times) >= 3:
                        warn_msg = self._build_handshake_warning()
            if warn_msg:
                self._emit_tunnel_warning(warn_msg)

    def clear_blocked_history(self) -> None:
        """Clear recorded blocked-connection history shown in Monitor."""
        with self._lock:
            self._blocked_events.clear()

    def _is_blocked_process_path(self, proc_path: str) -> bool:
        norm = os.path.normpath(proc_path.strip()).lower()
        name = os.path.basename(norm)
        return norm in self._blocked_exact_paths or name in self._blocked_exe_names

    def _record_blocked_event_locked(
        self, cid: str, entry: dict[str, Any], proc_path: str
    ) -> None:
        proc_name = Path(proc_path).name or proc_path
        dest = str(entry.get("dest") or "(Gói mạng / Socket)")
        net = str(entry.get("network") or "TCP/UDP")
        key = (proc_name.lower(), dest)
        now_str = datetime.now().strftime("%H:%M:%S")
        existing = self._blocked_events.get(key)
        if existing is None:
            if len(self._blocked_events) >= 200:
                first_key = next(iter(self._blocked_events))
                self._blocked_events.pop(first_key, None)
            self._blocked_events[key] = ConnectionRow(
                conn_id=f"blk-{cid}",
                process_name=proc_name,
                destination=dest,
                network=net,
                rule_outbound="reject",
                upload_bytes=0,
                download_bytes=0,
                blocked_count=1,
                timestamp=now_str,
            )
        else:
            existing.blocked_count += 1
            existing.timestamp = now_str
        entry["recorded_blocked"] = True

    def _track_log_event(self, line: str) -> None:
        conn_match = _LOG_CONN_ID_RE.search(line)
        if conn_match is None:
            return
        cid = conn_match.group(1)

        with self._lock:
            entry = self._pending_log_conns.setdefault(cid, {})
            if len(self._pending_log_conns) > 600:
                oldest_key = next(iter(self._pending_log_conns))
                if oldest_key != cid:
                    self._pending_log_conns.pop(oldest_key, None)

            m_to = _LOG_INBOUND_TO_RE.search(line)
            if m_to:
                entry["network"] = "UDP" if m_to.group(1) else "TCP"
                entry["dest"] = m_to.group(2)
                return

            if "inbound dns packet" in line.lower():
                entry.setdefault("network", "UDP")
                entry.setdefault("dest", "DNS (53)")
                return

            m_proc = _LOG_PROC_PATH_RE.search(line)
            if m_proc:
                proc_path = m_proc.group(1).strip()
                entry["proc_path"] = proc_path
                if self._is_blocked_process_path(proc_path) and not entry.get(
                    "recorded_blocked"
                ):
                    self._record_blocked_event_locked(cid, entry, proc_path)
                return

            if _LOG_ROUTER_REJECT_RE.search(line) and not entry.get("recorded_blocked"):
                proc_path = str(entry.get("proc_path") or "").strip()
                if not proc_path:
                    return
                proc_name = (Path(proc_path).name or proc_path).lower()
                if proc_name == "svchost.exe" and entry.get("dest") == "DNS (53)":
                    return
                self._record_blocked_event_locked(cid, entry, proc_path)

    def _extract_error_detail(self) -> str:
        for line in reversed(self._recent_logs):
            low = line.lower()
            if "fatal" in low or "error" in low:
                return line
        return self._recent_logs[-1] if self._recent_logs else ""

    def _poll_api_loop(self, proc: subprocess.Popen[str]) -> None:
        url = f"http://127.0.0.1:{self._api_port}/connections"
        headers = {"Authorization": f"Bearer {self._api_secret}"}
        session = requests.Session()

        # Give sing-box a brief moment to bind clash_api and wintun
        for _ in range(10):
            if self._stop_event.is_set() or proc.poll() is not None:
                return
            time.sleep(0.25)
            try:
                resp = session.get(url, headers=headers, timeout=1.0)
                if resp.ok:
                    if self._state == "connecting":
                        self._set_state("connected")
                    break
            except Exception:
                pass

        while not self._stop_event.is_set() and proc.poll() is None:
            try:
                resp = session.get(url, headers=headers, timeout=1.5)
                if resp.ok:
                    if self._state == "connecting":
                        self._set_state("connected")
                    data = resp.json()
                    up_total = int(data.get("uploadTotal") or 0)
                    down_total = int(data.get("downloadTotal") or 0)
                    now = time.monotonic()
                    dt = max(now - self._prev_ts, 0.2)
                    up_bps = max(0, int((up_total - self._prev_up) / dt))
                    down_bps = max(0, int((down_total - self._prev_down) / dt))
                    self._prev_up = up_total
                    self._prev_down = down_total
                    self._prev_ts = now

                    rows: list[ConnectionRow] = []
                    for c in data.get("connections") or []:
                        meta = c.get("metadata") or {}
                        proc_path = str(meta.get("processPath") or "")
                        proc_name = Path(proc_path).name if proc_path else str(meta.get("process") or "system")
                        host = meta.get("host") or meta.get("destinationIP") or ""
                        port = meta.get("destinationPort") or ""
                        dest = f"{host}:{port}" if port else str(host)
                        chains = c.get("chains") or []
                        outbound = str(chains[-1] if chains else c.get("rule") or "")
                        rows.append(
                            ConnectionRow(
                                conn_id=str(c.get("id") or ""),
                                process_name=proc_name or "unknown",
                                destination=dest,
                                network=str(meta.get("network") or "").upper(),
                                rule_outbound=outbound,
                                upload_bytes=int(c.get("upload") or 0),
                                download_bytes=int(c.get("download") or 0),
                            )
                        )
                    with self._lock:
                        blocked_snapshot = list(reversed(self._blocked_events.values()))
                    rows.extend(blocked_snapshot)

                    wg_rows = [r for r in rows if "wg-out" in r.rule_outbound.lower()]
                    wg_down = sum(r.download_bytes for r in wg_rows)
                    warn_msg = ""
                    if wg_down > 0:
                        with self._lock:
                            self._handshake_ok = True
                            self._handshake_failures = 0
                        self._emit_tunnel_warning("")
                    elif wg_rows:
                        with self._lock:
                            if not self._handshake_ok:
                                if self._wg_first_outbound_ts == 0.0:
                                    self._wg_first_outbound_ts = now
                                elif now - self._wg_first_outbound_ts >= 10.0:
                                    warn_msg = self._build_handshake_warning()
                        if warn_msg:
                            self._emit_tunnel_warning(warn_msg)

                    self.stats_updated.emit(up_bps, down_bps, up_total, down_total, rows)
            except Exception:
                pass
            self._stop_event.wait(1.0)

    def stop_sync(self) -> None:
        """Stop the running sing-box process cleanly."""
        self._stop_event.set()
        self._emit_tunnel_warning("")
        with self._lock:
            proc = self._proc
        if proc is None:
            if self._state != "disconnected":
                self._set_state("disconnected")
            return

        if proc.poll() is None:
            self.log_received.emit("[PPV] Đang ngắt kết nối tunnel...")
            try:
                if hasattr(signal, "CTRL_BREAK_EVENT"):
                    with contextlib.suppress(Exception):
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                    proc.wait(timeout=2.5)
            except subprocess.TimeoutExpired:
                pass
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2.5)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(Exception):
                        proc.kill()
                        proc.wait(timeout=2.0)
                except Exception:
                    pass

        with self._lock:
            if self._proc is proc:
                self._proc = None
        self._set_state("disconnected")
        self.stats_updated.emit(0, 0, 0, 0, [])


def _detect_physical_interface_when_tun_active() -> str | None:
    """Return active physical interface name if PPV-Tunnel is currently capturing default routes."""
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        ps = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "if (Get-NetAdapter -Name 'PPV-Tun*' -ErrorAction SilentlyContinue) { "
                "(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
                "| Where-Object { $_.InterfaceAlias -notmatch 'PPV-Tun|Loopback' -and $_.NextHop -ne '0.0.0.0' } "
                "| Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1).InterfaceAlias }",
            ],
            capture_output=True,
            text=True,
            timeout=2.5,
            creationflags=creation_flags,
        )
        name = (ps.stdout or "").strip()
        return name or None
    except Exception:
        return None


def probe_wireguard_profile(
    profile: WireGuardProfile,
    timeout: float = 4.5,
    default_mtu: int = 1280,
    ipv6_enabled: bool = False,
    bind_interface: str | None = None,
) -> WireGuardProbeResult:
    """Test WireGuard handshake and HTTPS reachability without creating a TUN adapter."""
    binary = find_singbox_binary()
    if binary is None:
        return WireGuardProbeResult(
            ok=False,
            handshake_ok=False,
            endpoint_host=profile.endpoint_host,
            endpoint_port=profile.endpoint_port,
            error="Không tìm thấy bin/sing-box.exe.",
        )

    if bind_interface is None:
        bind_interface = _detect_physical_interface_when_tun_active()

    probe_profile = profile
    host = (profile.endpoint_host or "").strip()
    if host:
        with contextlib.suppress(OSError):
            resolved_ip = socket.gethostbyname(host)
            if resolved_ip and resolved_ip != host:
                probe_profile = replace(profile, endpoint_host=resolved_ip)

    http_port = _pick_free_port(19885)
    tmp_dir = Path(tempfile.mkdtemp(prefix="ppv_probe_"))
    cfg_path = tmp_dir / "probe.json"
    log_path = tmp_dir / "probe.log"
    cfg = build_probe_config(
        profile=probe_profile,
        http_port=http_port,
        default_mtu=default_mtu,
        ipv6_enabled=ipv6_enabled,
        log_output=str(log_path),
        bind_interface=bind_interface,
    )
    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")

    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
        subprocess, "CREATE_NEW_PROCESS_GROUP", 0
    )
    proc: subprocess.Popen[str] | None = None
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(
            [str(binary), "--disable-color", "run", "-c", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        # Wait briefly for HTTP proxy port to bind
        ready = False
        for _ in range(20):
            if proc.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", http_port), timeout=0.2):
                    ready = True
                    break
            except OSError:
                time.sleep(0.1)

        if not ready:
            return WireGuardProbeResult(
                ok=False,
                handshake_ok=False,
                endpoint_host=profile.endpoint_host,
                endpoint_port=profile.endpoint_port,
                error="sing-box probe không khởi động được cổng kiểm tra nội bộ.",
            )

        proxies = {
            "http": f"http://127.0.0.1:{http_port}",
            "https": f"http://127.0.0.1:{http_port}",
        }
        try:
            resp = requests.get(
                "https://www.cloudflare.com/cdn-cgi/trace",
                proxies=proxies,
                timeout=timeout,
            )
            latency_ms = int((time.monotonic() - t0) * 1000)
            if resp.ok:
                info = _parse_cloudflare_trace(resp.text)
                return WireGuardProbeResult(
                    ok=True,
                    handshake_ok=True,
                    endpoint_host=profile.endpoint_host,
                    endpoint_port=profile.endpoint_port,
                    latency_ms=latency_ms,
                    exit_ip=info.get("ip", ""),
                    warp_status=info.get("warp", ""),
                    loc=info.get("loc", ""),
                )
            err_msg = f"HTTP {resp.status_code} qua tunnel WireGuard"
        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {exc}"
    finally:
        if proc is not None and proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.terminate()
                proc.wait(timeout=2.0)
            if proc.poll() is None:
                with contextlib.suppress(Exception):
                    proc.kill()
                    proc.wait(timeout=1.5)

        log_text = ""
        with contextlib.suppress(Exception):
            if log_path.exists():
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
        shutil.rmtree(tmp_dir, ignore_errors=True)

    low_log = log_text.lower()
    handshake_ok = "received handshake response" in low_log
    if not handshake_ok:
        err_msg = (
            f"Không nhận được phản hồi bắt tay WireGuard từ "
            f"{profile.endpoint_host}:{profile.endpoint_port} (handshake timeout)."
        )
    return WireGuardProbeResult(
        ok=False,
        handshake_ok=handshake_ok,
        endpoint_host=profile.endpoint_host,
        endpoint_port=profile.endpoint_port,
        error=err_msg,
    )


def find_working_warp_endpoint(
    profile: WireGuardProfile,
    candidates: tuple[tuple[str, int], ...] = WARP_ENDPOINT_CANDIDATES,
    timeout_per_try: float = 3.5,
    cancel_event: threading.Event | None = None,
    progress_cb: Callable[[int, int, str, int], None] | None = None,
) -> WireGuardProbeResult:
    """Try the profile's endpoint first, then known Cloudflare WARP endpoint/port pairs."""
    ordered: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for host, port in [(profile.endpoint_host, profile.endpoint_port), *candidates]:
        key = (host.strip(), int(port))
        if not key[0] or key in seen:
            continue
        seen.add(key)
        ordered.append(key)

    first_failure: WireGuardProbeResult | None = None
    physical_if = _detect_physical_interface_when_tun_active() or ""
    total = len(ordered)
    for idx, (host, port) in enumerate(ordered, 1):
        if cancel_event is not None and cancel_event.is_set():
            break
        if progress_cb is not None:
            progress_cb(idx, total, host, port)
        candidate = replace(profile, endpoint_host=host, endpoint_port=port)
        res = probe_wireguard_profile(
            candidate,
            timeout=timeout_per_try,
            bind_interface=physical_if,
        )
        if res.ok:
            return res
        if first_failure is None:
            first_failure = res

    return first_failure or WireGuardProbeResult(
        ok=False,
        handshake_ok=False,
        endpoint_host=profile.endpoint_host,
        endpoint_port=profile.endpoint_port,
        error="Không tìm thấy Endpoint/Port WARP nào phản hồi.",
    )
