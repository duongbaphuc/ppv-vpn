"""Automatic downloader and SHA-256 verifier for the official sing-box core."""

from __future__ import annotations

import contextlib
import hashlib
import zipfile
from collections.abc import Callable
from pathlib import Path

import requests

from ppv.storage import get_app_root, get_data_dir

SINGBOX_VERSION = "1.14.4"
SINGBOX_ZIP_URL = (
    f"https://github.com/SagerNet/sing-box/releases/download/"
    f"v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-windows-amd64.zip"
)
SINGBOX_EXE_SHA256 = "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9"


class SingBoxDownloadError(RuntimeError):
    """Raised when downloading or verifying sing-box fails."""


def get_download_target_path() -> Path:
    """Return writable destination path for sing-box.exe (`bin/` if writable, else data dir)."""
    app_bin = get_app_root() / "bin"
    try:
        app_bin.mkdir(parents=True, exist_ok=True)
        probe = app_bin / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return app_bin / "sing-box.exe"
    except OSError:
        data_bin = get_data_dir() / "bin"
        data_bin.mkdir(parents=True, exist_ok=True)
        return data_bin / "sing-box.exe"


def _extract_singbox_from_zip(zip_path: Path, exe_tmp: Path) -> str:
    """Extract `sing-box.exe` safely from a release zip archive and return its SHA-256."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        exe_member = next(
            (info for info in zf.infolist() if not info.is_dir() and Path(info.filename).name.lower() == "sing-box.exe"),
            None,
        )
        if exe_member is None:
            raise SingBoxDownloadError("Không tìm thấy sing-box.exe bên trong gói tải về.")

        hasher = hashlib.sha256()
        with zf.open(exe_member, "r") as src, exe_tmp.open("wb") as dst:
            while True:
                chunk = src.read(256 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
                hasher.update(chunk)
        return hasher.hexdigest().lower()


def download_singbox_binary(
    target_path: Path | None = None,
    progress_cb: Callable[[int, int], None] | None = None,
    url: str = SINGBOX_ZIP_URL,
    expected_sha256: str = SINGBOX_EXE_SHA256,
) -> Path:
    """Download, extract, and SHA-256 verify sing-box.exe for Windows amd64."""
    dest = target_path or get_download_target_path()
    dest.parent.mkdir(parents=True, exist_ok=True)

    tmp_zip = dest.with_suffix(".zip.tmp")
    tmp_exe = dest.with_suffix(".exe.tmp")
    try:
        try:
            resp = requests.get(
                url,
                stream=True,
                timeout=30,
                headers={"User-Agent": "PPV-VPN/1.0"},
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise SingBoxDownloadError(f"Không thể tải sing-box v{SINGBOX_VERSION}: {exc}") from exc

        total_bytes = int(resp.headers.get("content-length") or 0)
        downloaded = 0
        with tmp_zip.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=128 * 1024):
                if not chunk:
                    continue
                f.write(chunk)
                downloaded += len(chunk)
                if progress_cb is not None:
                    progress_cb(downloaded, total_bytes)

        try:
            digest = _extract_singbox_from_zip(tmp_zip, tmp_exe)
        except zipfile.BadZipFile as exc:
            raise SingBoxDownloadError("File nén sing-box tải về bị hỏng.") from exc

        if expected_sha256 and digest != expected_sha256.lower():
            raise SingBoxDownloadError(
                f"Mã kiểm tra SHA-256 của sing-box.exe không khớp ({digest})."
            )

        tmp_exe.replace(dest)
        return dest
    finally:
        with contextlib.suppress(OSError):
            tmp_zip.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            tmp_exe.unlink(missing_ok=True)
