"""Tests for automatic sing-box download and SHA-256 verification."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from ppv import core_manager, singbox_downloader


def _make_zip_bytes(inner_path: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(inner_path, payload)
    return buf.getvalue()


def test_download_singbox_binary_verifies_sha256(tmp_path: Path, monkeypatch) -> None:
    fake_exe = b"MZ-fake-singbox-binary"
    expected_sha = hashlib.sha256(fake_exe).hexdigest()
    zip_bytes = _make_zip_bytes("sing-box-1.14.4-windows-amd64/sing-box.exe", fake_exe)

    class FakeResp:
        headers = {"content-length": str(len(zip_bytes))}

        def raise_for_status(self) -> None:
            return None

        def iter_content(self, chunk_size: int = 1024):
            yield zip_bytes[:16]
            yield zip_bytes[16:]

    monkeypatch.setattr(singbox_downloader.requests, "get", lambda *a, **kw: FakeResp())

    progress_events: list[tuple[int, int]] = []
    dest = tmp_path / "bin" / "sing-box.exe"
    out = singbox_downloader.download_singbox_binary(
        target_path=dest,
        progress_cb=lambda done, total: progress_events.append((done, total)),
        expected_sha256=expected_sha,
    )
    assert out == dest
    assert dest.read_bytes() == fake_exe
    assert progress_events[-1][0] == len(zip_bytes)

    # Hash mismatch raises cleanly and keeps no corrupt target
    bad_dest = tmp_path / "bin2" / "sing-box.exe"
    with pytest.raises(singbox_downloader.SingBoxDownloadError):
        singbox_downloader.download_singbox_binary(
            target_path=bad_dest,
            expected_sha256="0" * 64,
        )
    assert not bad_dest.exists()


def test_find_singbox_binary_checks_data_dir_fallback(tmp_path: Path, monkeypatch) -> None:
    app_root = tmp_path / "readonly_root"
    app_root.mkdir()
    data_dir = tmp_path / "appdata"
    fallback_exe = data_dir / "bin" / "sing-box.exe"
    fallback_exe.parent.mkdir(parents=True)
    fallback_exe.write_bytes(b"fake")

    monkeypatch.setattr(core_manager, "get_app_root", lambda: app_root)
    monkeypatch.setattr(core_manager, "get_data_dir", lambda: data_dir)
    monkeypatch.setattr(core_manager.shutil, "which", lambda _name: None)

    assert core_manager.find_singbox_binary() == fallback_exe


def test_main_window_auto_downloads_when_singbox_missing(tmp_path: Path, monkeypatch) -> None:
    import sys
    import time

    from PySide6.QtWidgets import QApplication

    from ppv.ui import main_window

    app = QApplication.instance() or QApplication(sys.argv)
    downloaded_exe = tmp_path / "sing-box.exe"
    state = {"exists": False}

    monkeypatch.setattr(main_window, "find_singbox_binary", lambda: downloaded_exe if state["exists"] else None)

    def fake_download(progress_cb=None):
        if progress_cb is not None:
            progress_cb(50, 100)
            progress_cb(100, 100)
        downloaded_exe.write_bytes(b"fake-exe")
        state["exists"] = True
        return downloaded_exe

    monkeypatch.setattr(main_window, "download_singbox_binary", fake_download)

    win = main_window.MainWindow(auto_connect=False, start_minimized=False, single_instance=None)
    deadline = time.monotonic() + 3.0
    while (not state["exists"] or win._downloading_singbox) and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.02)

    assert state["exists"]
    assert "sing-box.exe" in win.monitor_page.log_box.toPlainText()
    win._force_quit = True
    win.close()
