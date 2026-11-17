"""WireGuard & Cloudflare WARP+ profile management page."""

from __future__ import annotations

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

from ppv.models import AppSettings, WireGuardProfile
from ppv.warp_api import WarpRegistrationError, register_warp_profile
from ppv.wg_parser import WireGuardParseError, parse_wireguard_conf, profile_to_conf


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

        action_row = QHBoxLayout()
        self.set_active_btn = QPushButton("Đặt làm mặc định")
        self.set_active_btn.setObjectName("PrimaryButton")
        self.set_active_btn.clicked.connect(self._set_selected_active)

        self.reveal_btn = QPushButton("Hiện PrivateKey")
        self.reveal_btn.clicked.connect(self._toggle_reveal)

        self.export_btn = QPushButton("Xuất .conf")
        self.export_btn.clicked.connect(self._export_selected)

        self.delete_btn = QPushButton("Xóa")
        self.delete_btn.setObjectName("DangerButton")
        self.delete_btn.clicked.connect(self._delete_selected)

        action_row.addWidget(self.set_active_btn)
        action_row.addWidget(self.reveal_btn)
        action_row.addWidget(self.export_btn)
        action_row.addStretch()
        action_row.addWidget(self.delete_btn)
        d_lay.addLayout(action_row)

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
        default_name = f"Cloudflare WARP #{len(self.profiles) + 1}"
        name, ok = QInputDialog.getText(
            self, "Tạo Cloudflare WARP miễn phí", "Tên profile:", text=default_name
        )
        if not ok:
            return
        self.gen_warp_btn.setEnabled(False)
        self.gen_warp_btn.setText("Đang đăng ký WARP...")
        self._warp_worker = _WarpRegWorker(name.strip() or default_name, self)
        self._warp_worker.succeeded.connect(self._on_warp_created)
        self._warp_worker.failed.connect(self._on_warp_failed)
        self._warp_worker.start()

    def _on_warp_created(self, prof: WireGuardProfile) -> None:
        self.gen_warp_btn.setEnabled(True)
        self.gen_warp_btn.setText("+ Tạo Cloudflare WARP miễn phí")
        self.profiles.append(prof)
        if not self.settings.active_profile_id:
            self.settings.active_profile_id = prof.id
        self.profiles_changed.emit()
        self.refresh_list()
        QMessageBox.information(
            self,
            "Thành công",
            f"Đã tạo profile '{prof.name}' với Endpoint {prof.endpoint}!",
        )

    def _on_warp_failed(self, err: str) -> None:
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
