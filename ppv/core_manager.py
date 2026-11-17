"""Manages the sing-box core process, config validation, and Clash API telemetry."""

from __future__ import annotations

import atexit
import contextlib
import json
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from PySide6.QtCore import QObject, Signal

from ppv.models import AppSettings, WireGuardProfile
from ppv.process_helper import cleanup_orphan_singbox
from ppv.singbox_config import build_singbox_config
from ppv.storage import get_app_root, get_data_dir

_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-9;?]*[A-Za-z]|\][^\x07\x1b]*(?:\x07|\x1b\\))")


def strip_ansi(text: str) -> str:
    """Remove ANSI color/control escape sequences from log text."""
    return _ANSI_ESCAPE_RE.sub("", text)


@dataclass
class ConnectionRow:
    """Single active/recent connection entry returned by sing-box Clash API."""

    conn_id: str
    process_name: str
    destination: str
    network: str
    rule_outbound: str
    upload_bytes: int
    download_bytes: int


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

        self._api_port = _pick_free_port(19090)
        self._api_secret = secrets.token_hex(12)
        config_dict = build_singbox_config(
            profile=profile,
            settings=settings,
            api_port=self._api_port,
            api_secret=self._api_secret,
        )

        ok, check_msg = self.validate_config(config_dict)
        if not ok:
            self.log_received.emit(f"[LỖI CẤU HÌNH] {check_msg}")
            self.error_occurred.emit(check_msg)
            self._set_state("error")
            return

        self._stop_event.clear()
        self._recent_logs.clear()
        self._prev_up = 0
        self._prev_down = 0
        self._prev_ts = time.monotonic()
        self._set_state("connecting")

        cleaned = cleanup_orphan_singbox(binary)
        if cleaned:
            self.log_received.emit(
                f"[PPV] Đã dọn {cleaned} tiến trình sing-box cũ còn sót lại."
            )

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
            return

        with self._lock:
            self._proc = proc

        self.log_received.emit(
            f"[PPV] Đang khởi động tunnel ({profile.name} -> {profile.endpoint})..."
        )
        threading.Thread(target=self._read_logs_loop, args=(proc,), daemon=True).start()
        threading.Thread(target=self._poll_api_loop, args=(proc,), daemon=True).start()

    def _read_logs_loop(self, proc: subprocess.Popen[str]) -> None:
        assert proc.stdout is not None
        saw_started = False
        try:
            with self.log_path.open("w", encoding="utf-8") as log_file:
                for raw_line in proc.stdout:
                    line = strip_ansi(raw_line.rstrip("\r\n"))
                    if not line:
                        continue
                    self._recent_logs.append(line)
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

        if self._stop_event.is_set():
            self._set_state("disconnected")
            self.stats_updated.emit(0, 0, 0, 0, [])
            return

        if rc != 0:
            self.log_received.emit(f"[PPV] sing-box thoát bất ngờ (mã {rc}).")
            detail = self._extract_error_detail()
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
                    self.stats_updated.emit(up_bps, down_bps, up_total, down_total, rows)
            except Exception:
                pass
            self._stop_event.wait(1.0)

    def stop_sync(self) -> None:
        """Stop the running sing-box process cleanly."""
        self._stop_event.set()
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
