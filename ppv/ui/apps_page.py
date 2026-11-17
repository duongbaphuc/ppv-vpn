"""Simplewall-inspired Per-App Firewall (Allow/Block) & VPN Split-Tunneling page."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QSize, Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ppv.firewall_manager import is_simplewall_running
from ppv.models import AppRule, AppSettings, FirewallMode, RuleAction, utc_now_iso
from ppv.process_helper import DiscoveredApp, extract_exe_icon, is_admin, list_running_apps
from ppv.ui.app_picker_dialog import AppPickerDialog

_ROW_BG: dict[str, str] = {
    "vpn": "#172554",     # Deep blue tint for VPN apps
    "allow": "#064e3b",   # Deep green tint (Simplewall Allow style)
    "block": "#4c0519",   # Deep rose/red tint (Simplewall Block style)
}

_ROW_FG: dict[str, str] = {
    "vpn": "#dbeafe",
    "allow": "#d1fae5",
    "block": "#ffe4e6",
}


@dataclass
class _DisplayRow:
    rule: AppRule | None
    running_app: DiscoveredApp | None
    display_name: str
    exe_name: str
    exe_path: str
    is_running: bool
    pid: int | None


class _ProcessScanWorker(QThread):
    scan_ready = Signal(list)

    def __init__(self, include_system32: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.include_system32 = include_system32

    def run(self) -> None:
        apps = list_running_apps(
            include_background=True,
            include_system_binaries=self.include_system32,
        )
        self.scan_ready.emit(apps)


def _format_added_time(iso_ts: str) -> str:
    if not iso_ts:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_ts).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso_ts[:16]


class AppsPage(QWidget):
    """Unified Simplewall-style per-app Firewall (VPN / Allow / Block) and live process list."""

    rules_changed = Signal()
    apply_requested = Signal()
    firewall_sync_requested = Signal()
    elevate_requested = Signal()

    def __init__(self, settings: AppSettings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self._connected = False
        self._dirty_while_connected = False
        self._running_apps: list[DiscoveredApp] = []
        self._display_rows: list[_DisplayRow] = []
        self._scan_worker: _ProcessScanWorker | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title = QLabel("Tường lửa & Chia tách ứng dụng")
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        # Firewall master control card
        fw_card = QFrame()
        fw_card.setObjectName("Card")
        fw_lay = QVBoxLayout(fw_card)
        fw_lay.setContentsMargins(16, 12, 16, 12)
        fw_lay.setSpacing(8)

        fw_top = QHBoxLayout()
        fw_top.setSpacing(10)

        self.fw_toggle_btn = QPushButton("Bật Firewall")
        self.fw_toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.fw_toggle_btn.clicked.connect(self._toggle_firewall)
        fw_top.addWidget(self.fw_toggle_btn)

        mode_lbl = QLabel("Chế độ lọc:")
        mode_lbl.setStyleSheet("font-weight: 600;")
        fw_top.addWidget(mode_lbl)

        self.fw_mode_combo = QComboBox()
        self.fw_mode_combo.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.fw_mode_combo.setMinimumContentsLength(26)
        self.fw_mode_combo.addItem(
            "Chặn app chưa gán quyền — Chỉ mở app đã chọn (Allowlist giống Simplewall)",
            "allowlist",
        )
        self.fw_mode_combo.addItem(
            "Mặc định mở — Chỉ chặn app đặt Block (Blacklist An toàn)",
            "blacklist",
        )
        self.fw_mode_combo.currentIndexChanged.connect(self._on_fw_mode_changed)
        fw_top.addWidget(self.fw_mode_combo, 1)
        fw_lay.addLayout(fw_top)

        self.vpn_allowlist_chk = QCheckBox(
            "Chặn app chưa gán khi bật VPN (áp dụng ngay trong tunnel dù Windows Firewall tắt)"
        )
        self.vpn_allowlist_chk.setToolTip(
            "Khi bật, mọi ứng dụng ở trạng thái 'Chưa gán' sẽ bị sing-box reject khi kết nối VPN, "
            "chỉ các app đặt 'Qua VPN' hoặc 'Cho phép' được truy cập mạng."
        )
        self.vpn_allowlist_chk.toggled.connect(self._on_vpn_allowlist_toggled)
        fw_lay.addWidget(self.vpn_allowlist_chk)

        self.mode_hint = QLabel()
        self.mode_hint.setWordWrap(True)
        self.mode_hint.setObjectName("MutedText")
        fw_lay.addWidget(self.mode_hint)
        layout.addWidget(fw_card)

        # Warning if simplewall.exe is also active
        self.simplewall_banner = QFrame()
        self.simplewall_banner.setObjectName("InfoBanner")
        sw_lay = QHBoxLayout(self.simplewall_banner)
        sw_lay.setContentsMargins(12, 8, 12, 8)
        sw_lbl = QLabel(
            "Phát hiện simplewall.exe đang chạy song song. Nếu bật Firewall của PPV VPN ở chế độ Allowlist, "
            "cần đảm bảo simplewall không chặn các app bạn muốn mở."
        )
        sw_lbl.setWordWrap(True)
        sw_lbl.setStyleSheet("color: #dbeafe;")
        sw_lay.addWidget(sw_lbl)
        self.simplewall_banner.setVisible(False)
        layout.addWidget(self.simplewall_banner)

        # Admin notice banner when firewall is enabled without Admin
        self.admin_fw_banner = QFrame()
        self.admin_fw_banner.setObjectName("WarningBanner")
        af_lay = QHBoxLayout(self.admin_fw_banner)
        af_lay.setContentsMargins(12, 8, 12, 8)
        af_lbl = QLabel(
            "Cần quyền Administrator để áp dụng luật Windows Firewall (WFP) xuống hệ thống."
        )
        af_lbl.setWordWrap(True)
        af_lbl.setStyleSheet("color: #fef3c7; font-weight: 600;")
        af_btn = QPushButton("Cấp quyền Admin ngay")
        af_btn.setObjectName("PrimaryButton")
        af_btn.clicked.connect(self.elevate_requested.emit)
        af_lay.addWidget(af_lbl, 1)
        af_lay.addWidget(af_btn)
        self.admin_fw_banner.setVisible(False)
        layout.addWidget(self.admin_fw_banner)

        # Pending apply banner when VPN tunnel is running
        self.apply_banner = QFrame()
        self.apply_banner.setObjectName("InfoBanner")
        banner_lay = QHBoxLayout(self.apply_banner)
        banner_lay.setContentsMargins(12, 8, 12, 8)
        banner_lbl = QLabel("Danh sách quy tắc đã thay đổi trong lúc VPN đang bật.")
        banner_lbl.setStyleSheet("color: #dbeafe; font-weight: 600;")
        self.apply_now_btn = QPushButton("Áp dụng lại VPN ngay")
        self.apply_now_btn.setObjectName("PrimaryButton")
        self.apply_now_btn.clicked.connect(self._on_apply_clicked)
        banner_lay.addWidget(banner_lbl, 1)
        banner_lay.addWidget(self.apply_now_btn)
        self.apply_banner.setVisible(False)
        layout.addWidget(self.apply_banner)

        # Reminder banner when block rules exist while Windows Firewall is OFF
        self.fw_off_block_banner = QFrame()
        self.fw_off_block_banner.setObjectName("WarningBanner")
        fob_lay = QHBoxLayout(self.fw_off_block_banner)
        fob_lay.setContentsMargins(12, 8, 12, 8)
        self.fw_off_block_lbl = QLabel()
        self.fw_off_block_lbl.setWordWrap(True)
        self.fw_off_block_lbl.setStyleSheet("color: #fef3c7;")
        fob_btn = QPushButton("Bật Firewall ngay")
        fob_btn.setObjectName("PrimaryButton")
        fob_btn.clicked.connect(self._toggle_firewall)
        fob_lay.addWidget(self.fw_off_block_lbl, 1)
        fob_lay.addWidget(fob_btn)
        self.fw_off_block_banner.setVisible(False)
        layout.addWidget(self.fw_off_block_banner)

        # Row 1: Search + State Filter + Permission Filter + System32
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(8)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Tìm theo tên, .exe hoặc đường dẫn... (Ctrl+F)")
        self.search_edit.textChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.search_edit, 1)

        self.view_filter_combo = QComboBox()
        self.view_filter_combo.addItem("Tất cả trạng thái", "all")
        self.view_filter_combo.addItem("Đang chạy lúc này", "running")
        self.view_filter_combo.addItem("Đã lưu quy tắc", "rules")
        self.view_filter_combo.currentIndexChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.view_filter_combo)

        perm_lbl = QLabel("Quyền:")
        perm_lbl.setStyleSheet("font-weight: 600;")
        filter_bar.addWidget(perm_lbl)

        self.perm_filter_combo = QComboBox()
        self.perm_filter_combo.addItem("Tất cả quyền", "all")
        self.perm_filter_combo.addItem("Chưa gán", "none")
        self.perm_filter_combo.addItem("Qua VPN (wg-out)", "vpn")
        self.perm_filter_combo.addItem("Cho phép (Mở)", "allow")
        self.perm_filter_combo.addItem("Chặn (Block)", "block")
        self.perm_filter_combo.addItem("Đang tạm tắt", "disabled")
        self.perm_filter_combo.currentIndexChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.perm_filter_combo)

        self.show_sys32_chk = QCheckBox("System32")
        self.show_sys32_chk.setToolTip("Hiển thị thêm các tiến trình nền trong C:\\Windows\\System32")
        self.show_sys32_chk.toggled.connect(self.refresh_running_processes)
        filter_bar.addWidget(self.show_sys32_chk)
        layout.addLayout(filter_bar)

        # Row 2: Refresh / Add + color legend
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.refresh_btn = QPushButton("Làm mới tiến trình")
        self.refresh_btn.clicked.connect(self.refresh_running_processes)
        toolbar.addWidget(self.refresh_btn)

        self.pick_btn = QPushButton("+ App đã cài")
        self.pick_btn.setObjectName("PrimaryButton")
        self.pick_btn.clicked.connect(self._open_app_picker)
        toolbar.addWidget(self.pick_btn)

        self.browse_btn = QPushButton("+ Chọn file .exe...")
        self.browse_btn.clicked.connect(self._browse_exe)
        toolbar.addWidget(self.browse_btn)

        toolbar.addStretch()
        legend_vpn = QLabel("■ Qua VPN")
        legend_vpn.setStyleSheet("color: #60a5fa; font-weight: 600; font-size: 12px;")
        legend_allow = QLabel("■ Cho phép")
        legend_allow.setStyleSheet("color: #34d399; font-weight: 600; font-size: 12px;")
        legend_block = QLabel("■ Chặn (Block)")
        legend_block.setStyleSheet("color: #fb7185; font-weight: 600; font-size: 12px;")
        toolbar.addWidget(legend_vpn)
        toolbar.addWidget(legend_allow)
        toolbar.addWidget(legend_block)
        layout.addLayout(toolbar)

        # Row 3: Multi-select & Batch-Set permission bar
        batch_bar = QHBoxLayout()
        batch_bar.setSpacing(6)
        batch_lbl = QLabel("Đặt quyền hàng loạt:")
        batch_lbl.setStyleSheet("font-weight: 600; font-size: 12px;")
        batch_bar.addWidget(batch_lbl)

        self.select_visible_btn = QPushButton("Chọn hết đang lọc")
        self.select_visible_btn.setToolTip("Chọn tất cả dòng đang hiển thị theo bộ lọc để đặt quyền hàng loạt")
        self.select_visible_btn.clicked.connect(self._select_all_visible)
        batch_bar.addWidget(self.select_visible_btn)

        self.batch_vpn_btn = QPushButton("Set -> Qua VPN")
        self.batch_vpn_btn.setObjectName("PrimaryButton")
        self.batch_vpn_btn.clicked.connect(lambda: self._batch_set_action("vpn"))
        batch_bar.addWidget(self.batch_vpn_btn)

        self.batch_allow_btn = QPushButton("Set -> Cho phép")
        self.batch_allow_btn.setObjectName("SuccessButton")
        self.batch_allow_btn.clicked.connect(lambda: self._batch_set_action("allow"))
        batch_bar.addWidget(self.batch_allow_btn)

        self.batch_block_btn = QPushButton("Set -> Chặn (Block)")
        self.batch_block_btn.setObjectName("DangerButton")
        self.batch_block_btn.clicked.connect(lambda: self._batch_set_action("block"))
        batch_bar.addWidget(self.batch_block_btn)

        self.batch_clear_btn = QPushButton("Bỏ quy tắc")
        self.batch_clear_btn.clicked.connect(lambda: self._batch_set_action("none"))
        batch_bar.addWidget(self.batch_clear_btn)
        batch_bar.addStretch()
        layout.addLayout(batch_bar)

        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._focus_search)

        # Simplewall-style unified table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Bật", "Ứng dụng / Tiến trình", "Quyền mạng", "Khớp", "Đường dẫn", "Thêm lúc", "Xóa"]
        )
        self.table.setIconSize(QSize(20, 20))
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(44)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 42)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(1, 225)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, 170)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(3, 116)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(5, 122)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(6, 70)
        layout.addWidget(self.table, 1)

        # Bottom summary bar
        self.summary_label = QLabel()
        self.summary_label.setObjectName("MutedText")
        layout.addWidget(self.summary_label)

        self.refresh_view()
        self.refresh_running_processes()

    def _focus_search(self) -> None:
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def set_connection_state(self, state: str) -> None:
        self._connected = state in ("connected", "connecting")
        if not self._connected:
            self._dirty_while_connected = False
            self.apply_banner.setVisible(False)

    def refresh_view(self) -> None:
        self._sync_firewall_controls()
        self._rebuild_table()

    def refresh_running_processes(self) -> None:
        if self._scan_worker is not None and self._scan_worker.isRunning():
            return
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("Đang quét...")
        self._scan_worker = _ProcessScanWorker(
            include_system32=self.show_sys32_chk.isChecked(),
            parent=self,
        )
        self._scan_worker.scan_ready.connect(self._on_scan_ready)
        self._scan_worker.start()

    def stop_workers(self) -> None:
        if self._scan_worker is not None and self._scan_worker.isRunning():
            self._scan_worker.wait(1500)

    def _on_scan_ready(self, apps: list[DiscoveredApp]) -> None:
        self._running_apps = apps
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("Làm mới tiến trình")
        self._rebuild_table()

    def _sync_firewall_controls(self) -> None:
        fw_on = self.settings.firewall_enabled
        if fw_on:
            self.fw_toggle_btn.setText("Đang bật Firewall • Bấm để tắt")
            self.fw_toggle_btn.setObjectName("SuccessButton")
        else:
            self.fw_toggle_btn.setText("Bật Firewall (Đang tắt)")
            self.fw_toggle_btn.setObjectName("PrimaryButton")
        self.fw_toggle_btn.style().unpolish(self.fw_toggle_btn)
        self.fw_toggle_btn.style().polish(self.fw_toggle_btn)

        self.fw_mode_combo.blockSignals(True)
        idx = self.fw_mode_combo.findData(self.settings.firewall_mode)
        if idx >= 0:
            self.fw_mode_combo.setCurrentIndex(idx)
        self.fw_mode_combo.blockSignals(False)

        is_allowlist = self.settings.firewall_mode == "allowlist"
        self.vpn_allowlist_chk.setVisible(is_allowlist)
        self.vpn_allowlist_chk.blockSignals(True)
        self.vpn_allowlist_chk.setChecked(bool(self.settings.block_unassigned_in_vpn))
        self.vpn_allowlist_chk.blockSignals(False)

        split_desc = (
            "VPN Include (chỉ app 'Qua VPN' đi tunnel)"
            if self.settings.split_mode == "include"
            else "VPN Exclude (app không chọn đi tunnel; 'Cho phép' đi trực tiếp)"
        )
        if fw_on:
            if is_allowlist:
                fw_desc = (
                    "Firewall ĐANG BẬT (Allowlist chặt như Simplewall): chặn toàn bộ app chưa gán, "
                    "chỉ cho phép các app đặt 'Qua VPN' hoặc 'Cho phép'."
                )
            else:
                fw_desc = (
                    "Firewall ĐANG BẬT (Blacklist An toàn): chặn hoàn toàn mọi app đặt 'Chặn (Block)' ngay cả khi tắt VPN; "
                    "app khác kết nối bình thường."
                )
        elif is_allowlist and self.settings.block_unassigned_in_vpn:
            fw_desc = (
                "Đang chặn app 'Chưa gán' khi bật VPN (Windows Firewall đang TẮT): "
                "lúc kết nối VPN, mọi app 'Chưa gán' bị từ chối mạng trong tunnel; bấm 'Bật Firewall' để chặn cả lúc tắt VPN."
            )
        elif is_allowlist:
            fw_desc = (
                "Firewall đang TẮT và chưa tích chặn app chưa gán trong VPN: "
                "bấm 'Bật Firewall' để chặn triệt để cả khi tắt VPN, hoặc tích 'Chặn app chưa gán khi bật VPN'."
            )
        else:
            fw_desc = (
                "Firewall đang TẮT (Blacklist — Mặc định mở): quy tắc 'Chặn (Block)' chỉ chặn lúc đang bật VPN. "
                "Bấm 'Bật Firewall' để chặn triệt để ở tầng Windows Firewall ngay cả khi tắt VPN."
            )
        self.mode_hint.setText(f"{fw_desc}\nĐịnh tuyến VPN hiện tại: {split_desc}.")

        self.simplewall_banner.setVisible(is_simplewall_running())
        self.admin_fw_banner.setVisible(fw_on and not is_admin())
        block_count = sum(1 for r in self.settings.app_rules if r.enabled and r.action == "block")
        if not fw_on and (block_count > 0 or self.settings.firewall_mode == "allowlist"):
            if self.settings.firewall_mode == "allowlist" and not self.settings.block_unassigned_in_vpn:
                self.fw_off_block_lbl.setText(
                    "Chế độ Allowlist đang chọn (chặn app chưa gán), nhưng Windows Firewall đang TẮT — "
                    "bấm 'Bật Firewall ngay' hoặc tích 'Chặn app chưa gán khi bật VPN'."
                )
            elif self.settings.firewall_mode == "allowlist":
                self.fw_off_block_lbl.setText(
                    "Chế độ Allowlist đang chọn nhưng Windows Firewall đang TẮT "
                    "(hiện chỉ chặn app chưa gán khi VPN kết nối). Bấm 'Bật Firewall ngay' để chặn cả khi tắt VPN."
                )
            else:
                self.fw_off_block_lbl.setText(
                    f"Bạn đang đặt {block_count} app ở chế độ 'Chặn (Block)' nhưng Windows Firewall đang TẮT "
                    "(hiện chỉ chặn lúc VPN bật). Bấm 'Bật Firewall ngay' để chặn triệt để ở tầng Windows."
                )
            self.fw_off_block_banner.setVisible(True)
        else:
            self.fw_off_block_banner.setVisible(False)

    def _on_vpn_allowlist_toggled(self, checked: bool) -> None:
        self.settings.block_unassigned_in_vpn = bool(checked)
        self._sync_firewall_controls()
        self._mark_rules_changed(sync_firewall=False)

    def _toggle_firewall(self) -> None:
        target = not self.settings.firewall_enabled
        if target and self.settings.firewall_mode == "allowlist":
            allowed_count = sum(
                1
                for r in self.settings.app_rules
                if r.enabled and r.action in ("vpn", "allow")
            )
            warn_empty = (
                "\nCảnh báo: Hiện chưa có ứng dụng nào được đặt 'Qua VPN' hoặc 'Cho phép' — "
                "bật lên sẽ chặn toàn bộ app người dùng!\n"
                if allowed_count == 0
                else ""
            )
            reply = QMessageBox.question(
                self,
                "Bật Firewall chế độ Allowlist chặt",
                f"Chế độ Allowlist (giống Simplewall) sẽ chặn kết nối ra ngoài của tất cả ứng dụng "
                f"CHƯA được đánh dấu 'Qua VPN' hoặc 'Cho phép' (hiện đã cấp phép {allowed_count} app; "
                f"PPV VPN vẫn tự mở sing-box.exe và DNS/DHCP).{warn_empty}\n\n"
                "Bạn có chắc muốn bật chế độ này không?",
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        self.settings.firewall_enabled = target
        self._sync_firewall_controls()
        if self._connected and self.settings.firewall_mode == "allowlist":
            self._dirty_while_connected = True
            self.apply_banner.setVisible(True)
        self.rules_changed.emit()
        self.firewall_sync_requested.emit()
        self._update_summary()

    def _on_fw_mode_changed(self) -> None:
        new_mode: FirewallMode = str(self.fw_mode_combo.currentData())  # type: ignore[assignment]
        if new_mode == self.settings.firewall_mode:
            return
        if new_mode == "allowlist" and self.settings.firewall_enabled:
            allowed_count = sum(
                1
                for r in self.settings.app_rules
                if r.enabled and r.action in ("vpn", "allow")
            )
            reply = QMessageBox.question(
                self,
                "Chuyển sang chế độ Allowlist (giống Simplewall)",
                f"Khi chuyển sang Allowlist, mọi ứng dụng chưa đặt 'Qua VPN' hoặc 'Cho phép' "
                f"(hiện đang mở {allowed_count} app) sẽ bị chặn mạng.\n\n"
                "Tiếp tục chuyển sang chế độ Allowlist?",
            )
            if reply != QMessageBox.StandardButton.Yes:
                self._sync_firewall_controls()
                return
        self.settings.firewall_mode = new_mode
        self._sync_firewall_controls()
        if self._connected and (
            self.settings.firewall_enabled or self.settings.block_unassigned_in_vpn
        ):
            self._dirty_while_connected = True
            self.apply_banner.setVisible(True)
        self.rules_changed.emit()
        if self.settings.firewall_enabled:
            self.firewall_sync_requested.emit()
        self._update_summary()

    def _mark_rules_changed(self, sync_firewall: bool = True) -> None:
        if self._connected:
            self._dirty_while_connected = True
            self.apply_banner.setVisible(True)
        self.rules_changed.emit()
        if sync_firewall and self.settings.firewall_enabled:
            self.firewall_sync_requested.emit()
        self._update_summary()

    def _on_apply_clicked(self) -> None:
        self._dirty_while_connected = False
        self.apply_banner.setVisible(False)
        self.apply_requested.emit()

    def _build_display_rows(self) -> list[_DisplayRow]:
        running_by_path: dict[str, DiscoveredApp] = {}
        running_by_name: dict[str, DiscoveredApp] = {}
        for app in self._running_apps:
            running_by_path[os.path.normpath(app.exe_path).lower()] = app
            running_by_name.setdefault(app.exe_name.lower(), app)

        rows: list[_DisplayRow] = []
        covered_paths: set[str] = set()
        covered_names: set[str] = set()

        for rule in self.settings.app_rules:
            norm_path = os.path.normpath(rule.exe_path).lower()
            exe_low = rule.exe_name.lower()
            matched_proc = running_by_path.get(norm_path)
            if matched_proc is None and rule.match_type == "name":
                matched_proc = running_by_name.get(exe_low)
            covered_paths.add(norm_path)
            if rule.match_type == "name":
                covered_names.add(exe_low)

            rows.append(
                _DisplayRow(
                    rule=rule,
                    running_app=matched_proc,
                    display_name=rule.display_name,
                    exe_name=rule.exe_name,
                    exe_path=rule.exe_path,
                    is_running=matched_proc is not None,
                    pid=matched_proc.pid if matched_proc else None,
                )
            )

        for app in self._running_apps:
            norm_path = os.path.normpath(app.exe_path).lower()
            if norm_path in covered_paths or app.exe_name.lower() in covered_names:
                continue
            rows.append(
                _DisplayRow(
                    rule=None,
                    running_app=app,
                    display_name=app.display_name,
                    exe_name=app.exe_name,
                    exe_path=app.exe_path,
                    is_running=True,
                    pid=app.pid,
                )
            )

        return rows

    def _row_colors(self, rule: AppRule | None) -> tuple[str | None, str | None]:
        if rule is None or not rule.enabled:
            return None, None
        return _ROW_BG.get(rule.action), _ROW_FG.get(rule.action)

    def _rebuild_table(self) -> None:
        vbar = self.table.verticalScrollBar()
        prev_scroll = vbar.value() if vbar is not None else 0
        self._display_rows = self._build_display_rows()
        self.table.clearContents()
        self.table.setRowCount(0)
        self.table.setRowCount(len(self._display_rows))

        for row_idx, entry in enumerate(self._display_rows):
            rule = entry.rule
            bg_hex, fg_hex = self._row_colors(rule)
            cell_style = (
                f"QWidget#RowCell {{ background-color: {bg_hex}; }}"
                if bg_hex
                else "QWidget#RowCell { background-color: transparent; }"
            )

            # Col 0: Active checkbox
            chk_wrap = QWidget()
            chk_wrap.setObjectName("RowCell")
            chk_wrap.setStyleSheet(cell_style)
            chk_lay = QHBoxLayout(chk_wrap)
            chk_lay.setContentsMargins(0, 0, 0, 0)
            chk_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chk = QCheckBox()
            chk.setChecked(bool(rule and rule.enabled))
            chk.stateChanged.connect(
                lambda state_val, r_idx=row_idx: self._on_checkbox_toggled(
                    r_idx, state_val == Qt.CheckState.Checked.value
                )
            )
            chk_lay.addWidget(chk)
            self.table.setCellWidget(row_idx, 0, chk_wrap)

            # Col 1: Icon + App Name + Running indicator
            running_tag = " [Đang chạy]" if entry.is_running else ""
            name_item = QTableWidgetItem(f"{entry.display_name} ({entry.exe_name}){running_tag}")
            px = extract_exe_icon(entry.exe_path, 22)
            if px is not None:
                name_item.setIcon(QIcon(px))
            if bg_hex:
                name_item.setBackground(QBrush(QColor(bg_hex)))
            if fg_hex:
                name_item.setForeground(QBrush(QColor(fg_hex)))
            elif not entry.is_running:
                name_item.setForeground(QBrush(QColor("#94a3b8")))
            self.table.setItem(row_idx, 1, name_item)

            # Col 2: Action selector (Unassigned / VPN / Allow / Block)
            act_wrap = QWidget()
            act_wrap.setObjectName("RowCell")
            act_wrap.setStyleSheet(cell_style)
            act_lay = QHBoxLayout(act_wrap)
            act_lay.setContentsMargins(4, 4, 4, 4)
            act_combo = QComboBox()
            act_combo.addItem("Chưa gán", "none")
            act_combo.addItem("Qua VPN", "vpn")
            act_combo.addItem("Cho phép (Mở)", "allow")
            act_combo.addItem("Chặn (Block)", "block")
            if rule is not None:
                act_idx = act_combo.findData(rule.action)
                act_combo.setCurrentIndex(act_idx if act_idx >= 0 else 1)
            else:
                act_combo.setCurrentIndex(0)
            act_combo.currentIndexChanged.connect(
                lambda _i, r_idx=row_idx, cb=act_combo: self._on_action_changed(
                    r_idx, str(cb.currentData())
                )
            )
            act_lay.addWidget(act_combo)
            self.table.setCellWidget(row_idx, 2, act_wrap)

            # Col 3: Match type
            match_wrap = QWidget()
            match_wrap.setObjectName("RowCell")
            match_wrap.setStyleSheet(cell_style)
            match_lay = QHBoxLayout(match_wrap)
            match_lay.setContentsMargins(4, 4, 4, 4)
            match_combo = QComboBox()
            match_combo.addItem("Tên .exe", "name")
            match_combo.addItem("Đường dẫn", "path")
            if rule is not None:
                match_combo.setCurrentIndex(0 if rule.match_type == "name" else 1)
                match_combo.currentIndexChanged.connect(
                    lambda _i, rid=rule.id, cb=match_combo: self._change_match_type(
                        rid, str(cb.currentData())
                    )
                )
            else:
                match_combo.setEnabled(False)
            match_lay.addWidget(match_combo)
            self.table.setCellWidget(row_idx, 3, match_wrap)

            # Col 4: Path
            path_item = QTableWidgetItem(entry.exe_path)
            path_item.setToolTip(entry.exe_path)
            if bg_hex:
                path_item.setBackground(QBrush(QColor(bg_hex)))
            if fg_hex:
                path_item.setForeground(QBrush(QColor(fg_hex)))
            self.table.setItem(row_idx, 4, path_item)

            # Col 5: Added timestamp (or Running status)
            added_text = _format_added_time(rule.added_at) if rule else "Đang mở"
            added_item = QTableWidgetItem(added_text)
            added_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if bg_hex:
                added_item.setBackground(QBrush(QColor(bg_hex)))
            if fg_hex:
                added_item.setForeground(QBrush(QColor(fg_hex)))
            else:
                added_item.setForeground(QBrush(QColor("#94a3b8")))
            self.table.setItem(row_idx, 5, added_item)

            # Col 6: Delete button (for saved rules)
            del_wrap = QWidget()
            del_wrap.setObjectName("RowCell")
            del_wrap.setStyleSheet(cell_style)
            del_lay = QHBoxLayout(del_wrap)
            del_lay.setContentsMargins(4, 5, 4, 5)
            if rule is not None:
                del_btn = QPushButton("Xóa")
                del_btn.setObjectName("DangerButton")
                del_btn.setStyleSheet("padding: 4px 8px;")
                del_btn.clicked.connect(
                    lambda _checked=False, rid=rule.id: self._delete_rule(rid)
                )
                del_lay.addWidget(del_btn)
            self.table.setCellWidget(row_idx, 6, del_wrap)

        self._apply_filters()
        self._update_summary()
        if vbar is not None:
            vbar.setValue(prev_scroll)

    def _apply_filters(self) -> None:
        query = self.search_edit.text().strip().lower()
        view_mode = str(self.view_filter_combo.currentData() or "all")
        perm_mode = str(self.perm_filter_combo.currentData() or "all")

        for row_idx, entry in enumerate(self._display_rows):
            text_ok = (
                not query
                or query in entry.display_name.lower()
                or query in entry.exe_name.lower()
                or query in entry.exe_path.lower()
            )
            rule = entry.rule
            if view_mode == "running":
                state_ok = entry.is_running
            elif view_mode == "rules":
                state_ok = rule is not None
            else:
                state_ok = True

            if perm_mode == "none":
                perm_ok = rule is None
            elif perm_mode in ("vpn", "allow", "block"):
                perm_ok = rule is not None and rule.enabled and rule.action == perm_mode
            elif perm_mode == "disabled":
                perm_ok = rule is not None and not rule.enabled
            else:
                perm_ok = True

            self.table.setRowHidden(row_idx, not (text_ok and state_ok and perm_ok))

    def _select_all_visible(self) -> None:
        self.table.clearSelection()
        sel_model = self.table.selectionModel()
        model = self.table.model()
        if sel_model is None or model is None:
            return
        from PySide6.QtCore import QItemSelectionModel

        for row_idx in range(self.table.rowCount()):
            if not self.table.isRowHidden(row_idx):
                sel_model.select(
                    model.index(row_idx, 0),
                    QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
                )

    def _batch_set_action(self, action_val: str) -> None:
        sel_model = self.table.selectionModel()
        selected_rows = (
            sorted({idx.row() for idx in sel_model.selectedRows() if not self.table.isRowHidden(idx.row())})
            if sel_model is not None
            else []
        )
        if not selected_rows:
            visible_rows = [r for r in range(self.table.rowCount()) if not self.table.isRowHidden(r)]
            if not visible_rows:
                return
            action_labels = {
                "vpn": "Qua VPN",
                "allow": "Cho phép (Mở)",
                "block": "Chặn (Block)",
                "none": "Bỏ quy tắc",
            }
            reply = QMessageBox.question(
                self,
                "Đặt quyền hàng loạt",
                f"Bạn chưa bôi chọn dòng nào.\nÁp dụng '{action_labels.get(action_val, action_val)}' "
                f"cho toàn bộ {len(visible_rows)} dòng đang hiển thị?",
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            selected_rows = visible_rows

        self._apply_action_to_rows(selected_rows, action_val)

    def _apply_action_to_rows(self, row_indices: list[int], action_val: str) -> None:
        if not row_indices:
            return
        if action_val == "none":
            remove_ids = {
                self._display_rows[r_idx].rule.id
                for r_idx in row_indices
                if 0 <= r_idx < len(self._display_rows) and self._display_rows[r_idx].rule is not None
            }
            if not remove_ids:
                return
            self.settings.app_rules = [r for r in self.settings.app_rules if r.id not in remove_ids]
        elif action_val in ("vpn", "allow", "block"):
            for r_idx in row_indices:
                if not (0 <= r_idx < len(self._display_rows)):
                    continue
                rule = self._ensure_rule_for_row(r_idx, action_val)  # type: ignore[arg-type]
                if rule is not None:
                    rule.action = action_val  # type: ignore[assignment]
                    rule.enabled = True
                    if not rule.added_at:
                        rule.added_at = utc_now_iso()
        else:
            return

        self._rebuild_table()
        self._sync_firewall_controls()
        self._mark_rules_changed()

    def _update_summary(self) -> None:
        rules = self.settings.app_rules
        vpn_n = sum(1 for r in rules if r.enabled and r.action == "vpn")
        allow_n = sum(1 for r in rules if r.enabled and r.action == "allow")
        block_n = sum(1 for r in rules if r.enabled and r.action == "block")
        strict_unassigned = self.settings.is_unassigned_blocked_in_vpn
        unassigned_txt = "Chưa gán: Chặn mạng" if strict_unassigned else "Chưa gán: Mở"
        fw_txt = (
            f"Đang bật ({'Allowlist chặt' if self.settings.firewall_mode == 'allowlist' else 'Blacklist'})"
            if self.settings.firewall_enabled
            else "Đang tắt"
        )
        self.summary_label.setText(
            f"Tiến trình đang chạy: {len(self._running_apps)}  |  "
            f"Quy tắc bật — Qua VPN: {vpn_n} • Cho phép: {allow_n} • Chặn (Block): {block_n}  |  "
            f"{unassigned_txt}  |  Firewall: {fw_txt}"
        )

    def _ensure_rule_for_row(self, row_idx: int, action: RuleAction) -> AppRule | None:
        if not (0 <= row_idx < len(self._display_rows)):
            return None
        entry = self._display_rows[row_idx]
        if entry.rule is not None:
            return entry.rule
        new_rule = AppRule(
            display_name=entry.display_name,
            exe_name=entry.exe_name,
            exe_path=entry.exe_path,
            enabled=True,
            match_type="name",
            action=action,
            added_at=utc_now_iso(),
        )
        self.settings.app_rules.append(new_rule)
        return new_rule

    def _on_checkbox_toggled(self, row_idx: int, checked: bool) -> None:
        if not (0 <= row_idx < len(self._display_rows)):
            return
        entry = self._display_rows[row_idx]
        if entry.rule is None:
            if not checked:
                return
            default_action: RuleAction = (
                "allow"
                if self.settings.is_unassigned_blocked_in_vpn
                else "vpn"
            )
            self._ensure_rule_for_row(row_idx, default_action)
        else:
            entry.rule.enabled = checked
        self._rebuild_table()
        self._sync_firewall_controls()
        self._mark_rules_changed()

    def _on_action_changed(self, row_idx: int, action_val: str) -> None:
        if not (0 <= row_idx < len(self._display_rows)):
            return
        entry = self._display_rows[row_idx]
        if action_val == "none":
            if entry.rule is not None:
                self._delete_rule(entry.rule.id)
            return
        if action_val not in ("vpn", "allow", "block"):
            return
        rule = self._ensure_rule_for_row(row_idx, action_val)  # type: ignore[arg-type]
        if rule is not None:
            rule.action = action_val  # type: ignore[assignment]
            rule.enabled = True
            if not rule.added_at:
                rule.added_at = utc_now_iso()
        self._rebuild_table()
        self._sync_firewall_controls()
        self._mark_rules_changed()

    def _change_match_type(self, rule_id: str, match_type: str) -> None:
        for r in self.settings.app_rules:
            if r.id == rule_id and match_type in ("name", "path"):
                r.match_type = match_type  # type: ignore[assignment]
                break
        self._mark_rules_changed()

    def _delete_rule(self, rule_id: str) -> None:
        self.settings.app_rules = [r for r in self.settings.app_rules if r.id != rule_id]
        self._rebuild_table()
        self._sync_firewall_controls()
        self._mark_rules_changed()

    def _show_context_menu(self, pos) -> None:
        row_idx = self.table.rowAt(pos.y())
        if not (0 <= row_idx < len(self._display_rows)):
            return
        entry = self._display_rows[row_idx]
        sel_model = self.table.selectionModel()
        selected_rows = (
            sorted({idx.row() for idx in sel_model.selectedRows()})
            if sel_model is not None and row_idx in {idx.row() for idx in sel_model.selectedRows()}
            else [row_idx]
        )
        suffix = f" ({len(selected_rows)} mục)" if len(selected_rows) > 1 else ""

        menu = QMenu(self)
        act_vpn = menu.addAction(f"Cho qua VPN (wg-out){suffix}")
        act_allow = menu.addAction(f"Cho phép mạng trực tiếp (Allow){suffix}")
        act_block = menu.addAction(f"Chặn mạng hoàn toàn (Block){suffix}")
        menu.addSeparator()
        act_open_dir = menu.addAction("Mở thư mục chứa file .exe")
        act_delete = menu.addAction(f"Xóa quy tắc{suffix}")
        act_delete.setEnabled(
            any(
                0 <= r < len(self._display_rows) and self._display_rows[r].rule is not None
                for r in selected_rows
            )
        )

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == act_vpn:
            self._apply_action_to_rows(selected_rows, "vpn")
        elif chosen == act_allow:
            self._apply_action_to_rows(selected_rows, "allow")
        elif chosen == act_block:
            self._apply_action_to_rows(selected_rows, "block")
        elif chosen == act_open_dir:
            self._open_exe_folder(entry.exe_path)
        elif chosen == act_delete:
            self._apply_action_to_rows(selected_rows, "none")

    def _open_exe_folder(self, exe_path: str) -> None:
        norm = os.path.normpath(exe_path)
        if os.path.exists(norm):
            subprocess.Popen(["explorer.exe", f"/select,{norm}"])
        elif os.path.isdir(os.path.dirname(norm)):
            subprocess.Popen(["explorer.exe", os.path.dirname(norm)])

    def _open_app_picker(self) -> None:
        existing = {r.exe_path.lower() for r in self.settings.app_rules}
        dlg = AppPickerDialog(existing_paths=existing, parent=self)
        if dlg.exec() == AppPickerDialog.DialogCode.Accepted:
            picked = dlg.selected_apps()
            if not picked:
                return
            for app in picked:
                if app.exe_path.lower() not in existing:
                    self.settings.app_rules.append(
                        AppRule(
                            display_name=app.display_name,
                            exe_name=app.exe_name,
                            exe_path=app.exe_path,
                            enabled=True,
                            match_type="name",
                            action="vpn",
                            added_at=utc_now_iso(),
                        )
                    )
                    existing.add(app.exe_path.lower())
            self._rebuild_table()
            self._mark_rules_changed()

    def _browse_exe(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Chọn tệp thực thi ứng dụng (.exe)",
            os.environ.get("PROGRAMFILES", "C:\\"),
            "Executable Files (*.exe)",
        )
        if not files:
            return
        existing = {r.exe_path.lower() for r in self.settings.app_rules}
        added = False
        for file_path in files:
            norm = os.path.normpath(file_path)
            if norm.lower() in existing:
                continue
            p = Path(norm)
            self.settings.app_rules.append(
                AppRule(
                    display_name=p.stem,
                    exe_name=p.name,
                    exe_path=norm,
                    enabled=True,
                    match_type="name",
                    action="vpn",
                    added_at=utc_now_iso(),
                )
            )
            existing.add(norm.lower())
            added = True
        if added:
            self._rebuild_table()
            self._mark_rules_changed()
