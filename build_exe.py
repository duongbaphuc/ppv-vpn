"""Build standalone Windows distribution (`dist/PPV-VPN/PPV-VPN.exe`) with PyInstaller."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from PySide6.QtGui import QImage
from PySide6.QtWidgets import QApplication

from ppv import __version__
from ppv.singbox_downloader import download_singbox_binary
from ppv.theme import create_app_pixmap

ROOT = Path(__file__).resolve().parent


def generate_ico(out_path: Path) -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    _ = app
    px = create_app_pixmap(connected=True, size=256)
    img: QImage = px.toImage()
    img.save(str(out_path), "ICO")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build standalone PPV-VPN distribution")
    parser.add_argument(
        "--distpath",
        default=str(ROOT / "dist"),
        help="Destination dist root folder (default: ./dist)",
    )
    parser.add_argument(
        "--clean-release",
        action="store_true",
        help="Omit local private warpplus.conf; include warpplus.conf.example and README.md instead",
    )
    parser.add_argument(
        "--zip",
        action="store_true",
        help="Create a distributable PPV-VPN-v<version>-win64.zip archive next to dist_dir",
    )
    args = parser.parse_args(argv)
    dist_root = Path(args.distpath).resolve()

    singbox_src = ROOT / "bin" / "sing-box.exe"
    if not singbox_src.exists():
        print("bin/sing-box.exe not found locally; downloading official v1.14.4 release...")
        download_singbox_binary(target_path=singbox_src)

    build_assets = ROOT / "build"
    build_assets.mkdir(parents=True, exist_ok=True)
    ico_path = build_assets / "ppv.ico"
    generate_ico(ico_path)

    excludes = [
        "PySide6.QtWebEngine",
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtPdf",
        "PySide6.QtPdfWidgets",
        "PySide6.Qt3DCore",
        "PySide6.Qt3DRender",
        "PySide6.Qt3DInput",
        "PySide6.Qt3DLogic",
        "PySide6.Qt3DAnimation",
        "PySide6.Qt3DExtras",
        "PySide6.QtQuick",
        "PySide6.QtQml",
        "PySide6.QtMultimedia",
        "PySide6.QtMultimediaWidgets",
        "PySide6.QtSql",
        "PySide6.QtTest",
        "tkinter",
    ]

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onedir",
        "--name",
        "PPV-VPN",
        "--distpath",
        str(dist_root),
        "--icon",
        str(ico_path),
        "--add-binary",
        f"{singbox_src};bin",
    ]
    for mod in excludes:
        cmd.extend(["--exclude-module", mod])
    cmd.append(str(ROOT / "ppv" / "__main__.py"))

    print("Running:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=str(ROOT))
    if res.returncode != 0:
        return res.returncode

    dist_dir = dist_root / "PPV-VPN"
    if args.clean_release:
        example_conf = ROOT / "warpplus.conf.example"
        if example_conf.exists():
            shutil.copy2(example_conf, dist_dir / "warpplus.conf.example")
        readme = ROOT / "README.md"
        if readme.exists():
            shutil.copy2(readme, dist_dir / "README.md")
    else:
        warp_sample = ROOT / "warpplus.conf"
        if warp_sample.exists():
            shutil.copy2(warp_sample, dist_dir / "warpplus.conf")

    print(f"Build complete: {dist_dir / 'PPV-VPN.exe'}")

    if args.zip:
        zip_path = dist_root / f"PPV-VPN-v{__version__}-win64.zip"
        if zip_path.exists():
            zip_path.unlink()
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for item in sorted(dist_dir.rglob("*")):
                if item.is_file():
                    zf.write(item, item.relative_to(dist_root).as_posix())
        sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        print(f"Archive ready: {zip_path} ({zip_path.stat().st_size} bytes)")
        print(f"SHA256: {sha256}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
