"""Application and tunnel engine settings page."""

from __future__ import annotations

import json

from PySide6.QtCore import Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ppv.models import AppSettings, WireGuardProfile
from ppv.singbox_config import build_singbox_config


class SettingsPage(QWidget):
    """Configures DNS behavior, MTU, LAN bypass, strict route, and tray options."""

    settings_changed = Signal()

    def __init__(
        self,
        settings: AppSettings,
        profiles: list[WireGuardProfile],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = settings
        self.profiles = profiles

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        title = QLabel("Cài đặt nâng cao")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        card = QFrame()
        card.setObjectName("Card")
        form = QFormLayout(card)
        form.setContentsMargins(20, 18, 20, 18)
        form.setSpacing(14)

        self.dns_combo = QComboBox()
        self.dns_combo.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.dns_combo.setMinimumContentsLength(24)
        self.dns_combo.addItem("Tách DNS theo từng ứng dụng (Khuyên dùng)", "split")
        self.dns_combo.addItem("Toàn bộ DNS đi qua VPN (chống nhà mạng chặn DNS)", "vpn_all")
        self.dns_combo.addItem("Giữ DNS hệ thống mặc định", "local")
        idx = self.dns_combo.findData(self.settings.dns_mode)
        if idx >= 0:
            self.dns_combo.setCurrentIndex(idx)
        self.dns_combo.currentIndexChanged.connect(self._save_from_ui)
        form.addRow("Chế độ DNS:", self.dns_combo)

        self.mtu_spin = QSpinBox()
        self.mtu_spin.setRange(1000, 1500)
        self.mtu_spin.setValue(self.settings.default_mtu)
        self.mtu_spin.valueChanged.connect(self._save_from_ui)
        form.addRow("MTU mặc định (khi .conf không ghi):", self.mtu_spin)

        self.bypass_lan_chk = QCheckBox("Bỏ qua mạng nội bộ (LAN / IP riêng tư đi trực tiếp)")
        self.bypass_lan_chk.setChecked(self.settings.bypass_lan)
        self.bypass_lan_chk.toggled.connect(self._save_from_ui)
        form.addRow("", self.bypass_lan_chk)

        self.strict_route_chk = QCheckBox("Strict Route (siết route Windows TUN — tắt nếu gặp lỗi mạng nội bộ)")
        self.strict_route_chk.setChecked(self.settings.strict_route)
        self.strict_route_chk.toggled.connect(self._save_from_ui)
        form.addRow("", self.strict_route_chk)

        self.ipv6_chk = QCheckBox("Bật IPv6 trong TUN (chỉ bật nếu mạng của bạn hỗ trợ IPv6)")
        self.ipv6_chk.setChecked(self.settings.ipv6_enabled)
        self.ipv6_chk.toggled.connect(self._save_from_ui)
        form.addRow("", self.ipv6_chk)

        self.tray_chk = QCheckBox("Thu nhỏ xuống khay hệ thống (System Tray) khi bấm đóng cửa sổ")
        self.tray_chk.setChecked(self.settings.minimize_to_tray)
        self.tray_chk.toggled.connect(self._save_from_ui)
        form.addRow("", self.tray_chk)

        self.auto_stop_vpn_chk = QCheckBox(
            "Tự động tắt các app/dịch vụ VPN khác (APKCombo VPN, WireGuard...) khi bấm Kết nối"
        )
        self.auto_stop_vpn_chk.setChecked(self.settings.auto_stop_other_vpns)
        self.auto_stop_vpn_chk.toggled.connect(self._save_from_ui)
        form.addRow("", self.auto_stop_vpn_chk)

        self.auto_connect_chk = QCheckBox("Tự động kết nối VPN khi mở ứng dụng (nếu đã có quyền Admin)")
        self.auto_connect_chk.setChecked(self.settings.auto_connect_on_start)
        self.auto_connect_chk.toggled.connect(self._save_from_ui)
        form.addRow("", self.auto_connect_chk)

        root.addWidget(card)

        btn_row = QHBoxLayout()
        preview_btn = QPushButton("Xem trước cấu hình sing-box.json")
        preview_btn.clicked.connect(self._preview_singbox_json)
        btn_row.addWidget(preview_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)
        root.addStretch()

    def _save_from_ui(self) -> None:
        self.settings.dns_mode = str(self.dns_combo.currentData())  # type: ignore[assignment]
        self.settings.default_mtu = int(self.mtu_spin.value())
        self.settings.bypass_lan = self.bypass_lan_chk.isChecked()
        self.settings.strict_route = self.strict_route_chk.isChecked()
        self.settings.ipv6_enabled = self.ipv6_chk.isChecked()
        self.settings.minimize_to_tray = self.tray_chk.isChecked()
        self.settings.auto_stop_other_vpns = self.auto_stop_vpn_chk.isChecked()
        self.settings.auto_connect_on_start = self.auto_connect_chk.isChecked()
        self.settings_changed.emit()

    def _preview_singbox_json(self) -> None:
        prof = next((p for p in self.profiles if p.id == self.settings.active_profile_id), None)
        if prof is None:
            QMessageBox.information(self, "Chưa có profile", "Vui lòng chọn hoặc tạo một profile VPN trước.")
            return
        cfg = build_singbox_config(prof, self.settings, api_port=19090, api_secret="<hidden>")
        cfg["endpoints"][0]["private_key"] = "<REDACTED>"

        dlg = QDialog(self)
        dlg.setWindowTitle("Xem trước cấu hình sing-box 1.14")
        dlg.resize(660, 520)
        lay = QVBoxLayout(dlg)
        ed = QPlainTextEdit()
        ed.setReadOnly(True)
        mono = QFont("Consolas", 10)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        ed.setFont(mono)
        ed.setStyleSheet('font-family: "Consolas", "Courier New", monospace; font-size: 12px;')
        ed.setPlainText(json.dumps(cfg, indent=2, ensure_ascii=False))
        lay.addWidget(ed)
        dlg.exec()
