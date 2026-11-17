"""WireGuard & Cloudflare WARP+ profile management page."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ppv.core_manager import (
    WireGuardProbeResult,
    find_working_warp_endpoint,
    probe_wireguard_profile,
)
from ppv.models import AppSettings, WireGuardProfile
from ppv.process_helper import find_conflicting_vpns
from ppv.warp_api import WarpRegistrationError, register_warp_profile
from ppv.wg_parser import WireGuardParseError, parse_wireguard_conf, profile_to_conf


class _ProfileProbeWorker(QThread):
    progress = Signal(int, int, str, int)
    finished_probe = Signal(str, object, bool, bool)  # prof_id, result, scan_mode, other_vpn_active

    def __init__(
        self,
        profile: WireGuardProfile,
        scan_alternatives: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.profile = profile
        self.scan_alternatives = scan_alternatives
        self.cancel_event = threading.Event()

    def run(self) -> None:
        other_active = bool(find_conflicting_vpns())
        if self.scan_alternatives:
            res = find_working_warp_endpoint(
                self.profile,
                timeout_per_try=3.5,
                cancel_event=self.cancel_event,
                progress_cb=lambda idx, total, host, port: self.progress.emit(
                    idx, total, host, port
                ),
            )
        else:
            res = probe_wireguard_profile(self.profile, timeout=4.5)
        self.finished_probe.emit(self.profile.id, res, self.scan_alternatives, other_active)


class _WarpRegWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, profile_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.profile_name = profile_name

    def run(self) -> None:
        try:
            prof = register_warp_profile(name=self.profile_name)
            self.succeeded.emit(prof)
        except WarpRegistrationError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Lỗi không xác định khi tạo WARP: {exc}")


class _PasteConfDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Dán cấu hình WireGuard (.conf)")
        self.resize(520, 400)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        lay.addWidget(QLabel("Dán nội dung file WireGuard .conf vào ô dưới đây:"))
        self.editor = QPlainTextEdit()
        self.editor.setPlaceholderText("[Interface]\nPrivateKey = ...\nAddress = ...\n\n[Peer]\nPublicKey = ...\nEndpoint = ...")
        lay.addWidget(self.editor, 1)

        row = QHBoxLayout()
        row.addStretch()
        cancel_btn = QPushButton("Hủy")
        cancel_btn.clicked.connect(self.reject)
        ok_btn = QPushButton("Nhập cấu hình")
        ok_btn.setObjectName("PrimaryButton")
        ok_btn.clicked.connect(self.accept)
        row.addWidget(cancel_btn)
        row.addWidget(ok_btn)
        lay.addLayout(row)


class ProfilesPage(QWidget):
    """Manage WireGuard .conf profiles and generate free Cloudflare WARP configs."""

    profiles_changed = Signal()
    active_profile_changed = Signal(str)

    def __init__(
        self,
        settings: AppSettings,
        profiles: list[WireGuardProfile],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = settings
        self.profiles = profiles
        self._warp_worker: _WarpRegWorker | None = None
        self._probe_worker: _ProfileProbeWorker | None = None
        self._auto_activate_next_warp = False
        self._reveal_private = False

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        title = QLabel("Quản lý Profile WireGuard & WARP+")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        toolbar = QHBoxLayout()
        self.gen_warp_btn = QPushButton("+ Tạo Cloudflare WARP miễn phí")
        self.gen_warp_btn.setObjectName("SuccessButton")
        self.gen_warp_btn.clicked.connect(self._create_warp_profile)
        toolbar.addWidget(self.gen_warp_btn)

        import_btn = QPushButton("+ Nhập file .conf")
        import_btn.setObjectName("PrimaryButton")
        import_btn.clicked.connect(self._import_conf_file)
        toolbar.addWidget(import_btn)

        paste_btn = QPushButton("+ Dán nội dung .conf")
        paste_btn.clicked.connect(self._paste_conf)
        toolbar.addWidget(paste_btn)
        toolbar.addStretch()
        root.addLayout(toolbar)

        split = QHBoxLayout()
        split.setSpacing(14)

        # Left list
        self.list_widget = QListWidget()
        self.list_widget.setMinimumWidth(250)
        self.list_widget.currentRowChanged.connect(self._on_row_changed)
        split.addWidget(self.list_widget, 1)

        # Right inspector card
        detail_card = QFrame()
        detail_card.setObjectName("Card")
        d_lay = QVBoxLayout(detail_card)
        d_lay.setContentsMargins(18, 16, 18, 16)
        d_lay.setSpacing(10)

        self.detail_title = QLabel("Chưa chọn profile")
        self.detail_title.setObjectName("SectionTitle")
        d_lay.addWidget(self.detail_title)

        self.detail_text = QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        mono = QFont("Consolas", 10)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.detail_text.setFont(mono)
        self.detail_text.setStyleSheet('font-family: "Consolas", "Courier New", monospace; font-size: 12px;')
        d_lay.addWidget(self.detail_text, 1)

        action_row_top = QHBoxLayout()
        action_row_top.setSpacing(8)
        self.set_active_btn = QPushButton("Đặt làm mặc định")
        self.set_active_btn.setObjectName("PrimaryButton")
        self.set_active_btn.clicked.connect(self._set_selected_active)

        self.probe_btn = QPushButton("Kiểm tra / Tìm Endpoint")
        self.probe_btn.clicked.connect(self._probe_selected)

        action_row_top.addWidget(self.set_active_btn)
        action_row_top.addWidget(self.probe_btn)
        action_row_top.addStretch()
        d_lay.addLayout(action_row_top)

        action_row_bottom = QHBoxLayout()
        action_row_bottom.setSpacing(8)
        self.reveal_btn = QPushButton("Hiện PrivateKey")
        self.reveal_btn.clicked.connect(self._toggle_reveal)

        self.export_btn = QPushButton("Xuất .conf")
        self.export_btn.clicked.connect(self._export_selected)

        self.delete_btn = QPushButton("Xóa")
        self.delete_btn.setObjectName("DangerButton")
        self.delete_btn.clicked.connect(self._delete_selected)

        action_row_bottom.addWidget(self.reveal_btn)
        action_row_bottom.addWidget(self.export_btn)
        action_row_bottom.addStretch()
        action_row_bottom.addWidget(self.delete_btn)
        d_lay.addLayout(action_row_bottom)

        split.addWidget(detail_card, 2)
        root.addLayout(split, 1)

        self.refresh_list()

    def refresh_list(self) -> None:
        current_id = self._current_profile_id()
        self.list_widget.blockSignals(True)
        self.list_widget.clear()
        select_row = 0
        for idx, prof in enumerate(self.profiles):
            active_tag = " [Đang chọn]" if prof.id == self.settings.active_profile_id else ""
            item = QListWidgetItem(f"{prof.name}{active_tag}\n{prof.endpoint}")
            item.setData(Qt.ItemDataRole.UserRole, prof.id)
            self.list_widget.addItem(item)
            if current_id and prof.id == current_id or not current_id and prof.id == self.settings.active_profile_id:
                select_row = idx
        self.list_widget.blockSignals(False)

        if self.profiles:
            self.list_widget.setCurrentRow(select_row)
            self._render_details(self.profiles[select_row])
        else:
            self._render_details(None)

    def _current_profile_id(self) -> str | None:
        item = self.list_widget.currentItem()
        return str(item.data(Qt.ItemDataRole.UserRole)) if item else None

    def _selected_profile(self) -> WireGuardProfile | None:
        pid = self._current_profile_id()
        return next((p for p in self.profiles if p.id == pid), None)

    def _on_row_changed(self, row: int) -> None:
        if 0 <= row < len(self.profiles):
            self._render_details(self.profiles[row])
        else:
            self._render_details(None)

    def _render_details(self, prof: WireGuardProfile | None) -> None:
        has_prof = prof is not None
        self.set_active_btn.setEnabled(has_prof)
        if self._probe_worker is None or not self._probe_worker.isRunning():
            self.probe_btn.setEnabled(has_prof)
        self.reveal_btn.setEnabled(has_prof)
        self.export_btn.setEnabled(has_prof)
        self.delete_btn.setEnabled(has_prof)

        if prof is None:
            self.detail_title.setText("Chưa có profile nào")
            self.detail_text.setPlainText("")
            return

        is_active = prof.id == self.settings.active_profile_id
        self.set_active_btn.setEnabled(not is_active)
        self.detail_title.setText(f"{prof.name}  ({prof.source.upper()})")

        conf_text = profile_to_conf(prof)
        if not self._reveal_private:
            conf_text = conf_text.replace(prof.private_key, "<Đã ẩn - bấm 'Hiện PrivateKey' để xem>")
        self.detail_text.setPlainText(conf_text)

    def _toggle_reveal(self) -> None:
        self._reveal_private = not self._reveal_private
        self.reveal_btn.setText("Ẩn PrivateKey" if self._reveal_private else "Hiện PrivateKey")
        self._render_details(self._selected_profile())

    def _create_warp_profile(self) -> None:
        self._start_warp_registration(auto_activate=False, prompt_name=True)

    def _start_warp_registration(self, auto_activate: bool = False, prompt_name: bool = True) -> None:
        default_name = f"Cloudflare WARP #{len(self.profiles) + 1}"
        if prompt_name:
            name, ok = QInputDialog.getText(
                self, "Tạo Cloudflare WARP miễn phí", "Tên profile:", text=default_name
            )
            if not ok:
                return
            chosen = name.strip() or default_name
        else:
            chosen = default_name
        self._auto_activate_next_warp = auto_activate
        self.gen_warp_btn.setEnabled(False)
        self.gen_warp_btn.setText("Đang đăng ký WARP...")
        self._warp_worker = _WarpRegWorker(chosen, self)
        self._warp_worker.succeeded.connect(self._on_warp_created)
        self._warp_worker.failed.connect(self._on_warp_failed)
        self._warp_worker.start()

    def _on_warp_created(self, prof: WireGuardProfile) -> None:
        self.gen_warp_btn.setEnabled(True)
        self.gen_warp_btn.setText("+ Tạo Cloudflare WARP miễn phí")
        self.profiles.append(prof)
        if self._auto_activate_next_warp or not self.settings.active_profile_id:
            self.settings.active_profile_id = prof.id
        self._auto_activate_next_warp = False
        self.profiles_changed.emit()
        self.refresh_list()
        QMessageBox.information(
            self,
            "Thành công",
            f"Đã tạo profile '{prof.name}' với Endpoint {prof.endpoint}!\n"
            "Bạn có thể bấm 'Kiểm tra / Tìm Endpoint' hoặc 'KẾT NỐI' ngay.",
        )

    def _on_warp_failed(self, err: str) -> None:
        self._auto_activate_next_warp = False
        self.gen_warp_btn.setEnabled(True)
        self.gen_warp_btn.setText("+ Tạo Cloudflare WARP miễn phí")
        QMessageBox.warning(self, "Không thể tạo WARP", err)

    def _import_conf_file(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Chọn file cấu hình WireGuard (.conf)",
            "",
            "WireGuard Config (*.conf);;All Files (*.*)",
        )
        if not files:
            return
        imported = 0
        for file_path in files:
            p = Path(file_path)
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
                prof = parse_wireguard_conf(text, name=p.stem, source="imported")
                self.profiles.append(prof)
                if not self.settings.active_profile_id:
                    self.settings.active_profile_id = prof.id
                imported += 1
            except WireGuardParseError as exc:
                QMessageBox.warning(self, f"Lỗi đọc {p.name}", str(exc))
        if imported:
            self.profiles_changed.emit()
            self.refresh_list()

    def _paste_conf(self) -> None:
        dlg = _PasteConfDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        raw = dlg.editor.toPlainText().strip()
        if not raw:
            return
        name, ok = QInputDialog.getText(
            self, "Đặt tên profile", "Tên profile:", text=f"WireGuard #{len(self.profiles) + 1}"
        )
        if not ok:
            return
        try:
            prof = parse_wireguard_conf(raw, name=name.strip() or "WireGuard", source="manual")
        except WireGuardParseError as exc:
            QMessageBox.warning(self, "Cấu hình không hợp lệ", str(exc))
            return
        self.profiles.append(prof)
        if not self.settings.active_profile_id:
            self.settings.active_profile_id = prof.id
        self.profiles_changed.emit()
        self.refresh_list()

    def _set_selected_active(self) -> None:
        prof = self._selected_profile()
        if prof:
            self.active_profile_changed.emit(prof.id)

    def _probe_selected(self) -> None:
        prof = self._selected_profile()
        if prof is None:
            return
        if self._probe_worker is not None and self._probe_worker.isRunning():
            return
        self._start_profile_probe(prof, scan_alternatives=False)

    def _start_profile_probe(self, prof: WireGuardProfile, scan_alternatives: bool) -> None:
        self.probe_btn.setEnabled(False)
        self.probe_btn.setText(
            "Đang dò Endpoint WARP..." if scan_alternatives else "Đang kiểm tra..."
        )
        self._probe_worker = _ProfileProbeWorker(
            prof, scan_alternatives=scan_alternatives, parent=self
        )
        self._probe_worker.progress.connect(self._on_probe_progress)
        self._probe_worker.finished_probe.connect(self._on_probe_finished)
        self._probe_worker.start()

    def _on_probe_progress(self, idx: int, total: int, host: str, port: int) -> None:
        self.probe_btn.setText(f"Đang dò ({idx}/{total})...")

    def _on_probe_finished(
        self,
        prof_id: str,
        res: WireGuardProbeResult,
        scan_mode: bool,
        other_vpn_active: bool,
    ) -> None:
        prof = next((p for p in self.profiles if p.id == prof_id), None)
        self.probe_btn.setEnabled(self._selected_profile() is not None)
        self.probe_btn.setText("Kiểm tra / Tìm Endpoint")
        if prof is None:
            return

        note = (
            "\n\nLưu ý: VPN hệ thống khác đang bật, nên kiểm tra đang đi qua VPN đó. "
            "Hãy tắt VPN khác để kiểm tra mạng vật lý trực tiếp."
            if other_vpn_active
            else ""
        )
        if res.ok:
            changed = (
                res.endpoint_host != prof.endpoint_host
                or int(res.endpoint_port) != int(prof.endpoint_port)
            )
            detail_msg = (
                f"Tunnel WireGuard hoạt động!\n"
                f"Endpoint: {res.endpoint_host}:{res.endpoint_port}\n"
                f"IP thoát: {res.exit_ip or '?'} ({res.loc or '?'})\n"
                f"Trạng thái WARP: {res.warp_status or 'ok'}\n"
                f"Độ trễ: {res.latency_ms} ms{note}"
            )
            if scan_mode and changed:
                reply = QMessageBox.question(
                    self,
                    "Tìm thấy Endpoint WARP hoạt động",
                    f"{detail_msg}\n\nÁp dụng Endpoint {res.endpoint_host}:{res.endpoint_port} "
                    f"cho profile '{prof.name}' ngay?",
                )
                if reply == QMessageBox.StandardButton.Yes:
                    prof.endpoint_host = res.endpoint_host
                    prof.endpoint_port = int(res.endpoint_port)
                    self.profiles_changed.emit()
                    self.refresh_list()
            else:
                QMessageBox.information(self, f"Kiểm tra {prof.name}", detail_msg)
            return

        if not scan_mode:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Question)
            box.setWindowTitle(f"Endpoint {prof.name} không phản hồi")
            extra_hint = (
                "\n• Nếu đang dùng file .conf cũ (như warpplus.conf), key WireGuard có thể đã hết hạn trên Cloudflare — "
                "bấm 'Tạo WARP mới' để lấy key hoạt động ngay."
                if prof.source != "warp"
                else ""
            )
            box.setText(
                f"Kiểm tra tới {res.endpoint_host}:{res.endpoint_port} thất bại:\n"
                f"{res.error}{note}{extra_hint}\n\n"
                "Chọn cách xử lý:"
            )
            new_warp_btn = box.addButton(
                "Tạo Cloudflare WARP mới (Khuyên dùng)", QMessageBox.ButtonRole.AcceptRole
            )
            scan_btn = box.addButton(
                "Dò Endpoint/Port khác", QMessageBox.ButtonRole.ActionRole
            )
            box.addButton("Đóng", QMessageBox.ButtonRole.RejectRole)
            box.exec()
            if box.clickedButton() == new_warp_btn:
                self._start_warp_registration(auto_activate=True, prompt_name=False)
            elif box.clickedButton() == scan_btn:
                self._start_profile_probe(prof, scan_alternatives=True)
            return

        box2 = QMessageBox(self)
        box2.setIcon(QMessageBox.Icon.Warning)
        box2.setWindowTitle("Không tìm thấy Endpoint phản hồi")
        box2.setText(
            f"Đã thử các Endpoint/Port Cloudflare WARP cho '{prof.name}' nhưng không nhận được phản hồi bắt tay.\n\n"
            f"Chi tiết cuối: {res.error}{note}\n\n"
            "Nguyên nhân thường gặp:\n"
            "• Key WireGuard của file .conf đã hết hạn hoặc bị Cloudflare thu hồi.\n"
            "• Hoặc firewall ngoài (simplewall / mạng công ty) đang chặn sing-box.exe gửi UDP."
        )
        new_warp_btn2 = box2.addButton(
            "Tạo Cloudflare WARP mới ngay", QMessageBox.ButtonRole.AcceptRole
        )
        box2.addButton("Đóng", QMessageBox.ButtonRole.RejectRole)
        box2.exec()
        if box2.clickedButton() == new_warp_btn2:
            self._start_warp_registration(auto_activate=True, prompt_name=False)

    def stop_workers(self) -> None:
        if self._probe_worker is not None and self._probe_worker.isRunning():
            self._probe_worker.cancel_event.set()
            self._probe_worker.wait(2000)
        if self._warp_worker is not None and self._warp_worker.isRunning():
            self._warp_worker.wait(1500)

    def _export_selected(self) -> None:
        prof = self._selected_profile()
        if not prof:
            return
        safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in prof.name).strip() or "profile"
        path, _ = QFileDialog.getSaveFileName(
            self, "Xuất file WireGuard .conf", f"{safe_name}.conf", "WireGuard Config (*.conf)"
        )
        if path:
            Path(path).write_text(profile_to_conf(prof), encoding="utf-8")

    def _delete_selected(self) -> None:
        prof = self._selected_profile()
        if not prof:
            return
        reply = QMessageBox.question(
            self,
            "Xác nhận xóa",
            f"Bạn có chắc muốn xóa profile '{prof.name}'?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.profiles[:] = [p for p in self.profiles if p.id != prof.id]
        if self.settings.active_profile_id == prof.id:
            self.settings.active_profile_id = self.profiles[0].id if self.profiles else None
        self.profiles_changed.emit()
        self.refresh_list()
