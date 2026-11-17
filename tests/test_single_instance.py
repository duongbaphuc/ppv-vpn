"""Tests for SingleInstanceController and VpnCoreManager error extraction."""

from __future__ import annotations

import sys
import threading
import time
import uuid
from pathlib import Path

from PySide6.QtWidgets import QApplication

from ppv.core_manager import VpnCoreManager, strip_ansi
from ppv.single_instance import SingleInstanceController


def test_single_instance_notify_and_lock() -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    name = f"PPV_Test_{uuid.uuid4().hex[:8]}"

    primary = SingleInstanceController(server_name=name, parent=app)
    assert primary.start_listening()

    notified: list[bool] = []
    primary.show_requested.connect(lambda: notified.append(True))

    results: dict[str, bool] = {}

    def _secondary_proc() -> None:
        secondary = SingleInstanceController(server_name=name)
        results["listen"] = secondary.start_listening()
        results["notify"] = secondary.try_notify_existing()
        secondary.close()

    t = threading.Thread(target=_secondary_proc, daemon=True)
    t.start()

    deadline = time.monotonic() + 2.5
    while (t.is_alive() or not notified) and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.02)
    t.join(timeout=1.0)

    assert results == {"listen": False, "notify": True}
    assert notified == [True]

    primary.close()
    app.processEvents()


def test_core_manager_extract_error_detail(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    _ = app
    mgr = VpnCoreManager(tmp_path)
    mgr._recent_logs.append("INFO[0000] starting")
    mgr._recent_logs.append("FATAL[0000] configure tun interface: Access is denied.")
    assert "Access is denied" in mgr._extract_error_detail()


def test_strip_ansi_sequences() -> None:
    raw = "+0700 2026-11-17 08:53:18 \x1b[36mINFO\x1b[0m [\x1b[38;5;87m3362189712\x1b[0m 1ms] dns: cached"
    assert strip_ansi(raw) == "+0700 2026-11-17 08:53:18 INFO [3362189712 1ms] dns: cached"
