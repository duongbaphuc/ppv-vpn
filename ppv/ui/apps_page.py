"""Per-App split-tunneling rules management page."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QIcon
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
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ppv.models import AppRule, AppSettings
from ppv.process_helper import extract_exe_icon
from ppv.ui.app_picker_dialog import AppPickerDialog


class AppsPage(QWidget):
    """Allows adding, toggling, searching, and removing per-app VPN rules."""

    rules_changed = Signal()
    apply_requested = Signal()

    def __init__(self, settings: AppSettings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self._connected = False
        self._dirty_while_connected = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        title = QLabel("Ứng dụng qua VPN (Split Tunneling)")
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        self.mode_hint = QLabel()
        self.mode_hint.setWordWrap(True)
        self.mode_hint.setObjectName("MutedText")
        layout.addWidget(self.mode_hint)

        # Pending apply banner when tunnel is running
        self.apply_banner = QFrame()
        self.apply_banner.setObjectName("InfoBanner")
        banner_lay = QHBoxLayout(self.apply_banner)
        banner_lay.setContentsMargins(12, 8, 12, 8)
        banner_lbl = QLabel("Danh sách ứng dụng đã thay đổi trong lúc VPN đang bật.")
        banner_lbl.setStyleSheet("color: #dbeafe; font-weight: 600;")
        self.apply_now_btn = QPushButton("Áp dụng lại ngay")
        self.apply_now_btn.setObjectName("PrimaryButton")
        self.apply_now_btn.clicked.connect(self._on_apply_clicked)
        banner_lay.addWidget(banner_lbl, 1)
        banner_lay.addWidget(self.apply_now_btn)
        self.apply_banner.setVisible(False)
        layout.addWidget(self.apply_banner)

        # Toolbar
        toolbar = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Lọc danh sách ứng dụng đã thêm...")
        self.search_edit.textChanged.connect(self._filter_table)
        toolbar.addWidget(self.search_edit, 1)

        self.pick_btn = QPushButton("+ Chọn app đang chạy / đã cài")
        self.pick_btn.setObjectName("PrimaryButton")
        self.pick_btn.clicked.connect(self._open_app_picker)
        toolbar.addWidget(self.pick_btn)

        self.browse_btn = QPushButton("+ Chọn file .exe...")
        self.browse_btn.clicked.connect(self._browse_exe)
        toolbar.addWidget(self.browse_btn)
        layout.addLayout(toolbar)

        # Table
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Bật", "Ứng dụng", "Kiểu khớp", "Đường dẫn", "Xóa"]
        )
        self.table.setIconSize(QSize(22, 22))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(44)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 54)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, 175)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(4, 72)
        layout.addWidget(self.table, 1)

        self.empty_hint = QLabel(
            "Chưa có ứng dụng nào. Hãy bấm '+ Chọn app đang chạy / đã cài' hoặc '+ Chọn file .exe...' để thêm."
        )
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint.setObjectName("MutedText")
        layout.addWidget(self.empty_hint)

        self.refresh_view()

    def set_connection_state(self, state: str) -> None:
        self._connected = state in ("connected", "connecting")
        if not self._connected:
            self._dirty_while_connected = False
            self.apply_banner.setVisible(False)

    def refresh_view(self) -> None:
        if self.settings.split_mode == "include":
            self.mode_hint.setText(
                "Chế độ hiện tại: INCLUDE — Chỉ các ứng dụng được BẬT bên dưới mới đi qua VPN; "
                "các ứng dụng khác và hệ thống giữ nguyên mạng trực tiếp."
            )
        else:
            self.mode_hint.setText(
                "Chế độ hiện tại: EXCLUDE — Toàn bộ máy đi qua VPN NGOẠI TRỪ các ứng dụng được BẬT bên dưới."
            )
        self._rebuild_table()

    def _mark_changed(self) -> None:
        if self._connected:
            self._dirty_while_connected = True
            self.apply_banner.setVisible(True)
        self.rules_changed.emit()

    def _on_apply_clicked(self) -> None:
        self._dirty_while_connected = False
        self.apply_banner.setVisible(False)
        self.apply_requested.emit()

    def _rebuild_table(self) -> None:
        rules = self.settings.app_rules
        self.empty_hint.setVisible(len(rules) == 0)
        self.table.setRowCount(len(rules))

        for row_idx, rule in enumerate(rules):
            # Col 0: Enable checkbox
            chk_wrap = QWidget()
            chk_lay = QHBoxLayout(chk_wrap)
            chk_lay.setContentsMargins(0, 0, 0, 0)
            chk_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chk = QCheckBox()
            chk.setChecked(rule.enabled)
            chk.stateChanged.connect(
                lambda state_val, rid=rule.id: self._toggle_rule(
                    rid, state_val == Qt.CheckState.Checked.value
                )
            )
            chk_lay.addWidget(chk)
            self.table.setCellWidget(row_idx, 0, chk_wrap)

            # Col 1: Icon + name
            name_item = QTableWidgetItem(f"{rule.display_name} ({rule.exe_name})")
            px = extract_exe_icon(rule.exe_path, 24)
            if px is not None:
                name_item.setIcon(QIcon(px))
            self.table.setItem(row_idx, 1, name_item)

            # Col 2: Match type combo
            combo = QComboBox()
            combo.addItem("Theo tên .exe (khuyên dùng)", "name")
            combo.addItem("Đường dẫn chính xác", "path")
            combo.setCurrentIndex(0 if rule.match_type == "name" else 1)
            combo.currentIndexChanged.connect(
                lambda _idx, rid=rule.id, cb=combo: self._change_match_type(
                    rid, str(cb.currentData())
                )
            )
            self.table.setCellWidget(row_idx, 2, combo)

            # Col 3: Full path
            path_item = QTableWidgetItem(rule.exe_path)
            path_item.setToolTip(rule.exe_path)
            self.table.setItem(row_idx, 3, path_item)

            # Col 4: Delete button
            del_wrap = QWidget()
            del_lay = QHBoxLayout(del_wrap)
            del_lay.setContentsMargins(4, 4, 4, 4)
            del_btn = QPushButton("Xóa")
            del_btn.setObjectName("DangerButton")
            del_btn.clicked.connect(lambda _checked=False, rid=rule.id: self._delete_rule(rid))
            del_lay.addWidget(del_btn)
            self.table.setCellWidget(row_idx, 4, del_wrap)

        self._filter_table(self.search_edit.text())

    def _filter_table(self, text: str) -> None:
        query = text.strip().lower()
        for row_idx, rule in enumerate(self.settings.app_rules):
            match = (
                not query
                or query in rule.display_name.lower()
                or query in rule.exe_name.lower()
                or query in rule.exe_path.lower()
            )
            self.table.setRowHidden(row_idx, not match)

    def _toggle_rule(self, rule_id: str, enabled: bool) -> None:
        for r in self.settings.app_rules:
            if r.id == rule_id:
                r.enabled = enabled
                break
        self._mark_changed()

    def _change_match_type(self, rule_id: str, match_type: str) -> None:
        for r in self.settings.app_rules:
            if r.id == rule_id and match_type in ("name", "path"):
                r.match_type = match_type  # type: ignore[assignment]
                break
        self._mark_changed()

    def _delete_rule(self, rule_id: str) -> None:
        self.settings.app_rules = [r for r in self.settings.app_rules if r.id != rule_id]
        self._rebuild_table()
        self._mark_changed()

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
                        )
                    )
                    existing.add(app.exe_path.lower())
            self._rebuild_table()
            self._mark_changed()

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
                )
            )
            existing.add(norm.lower())
            added = True
        if added:
            self._rebuild_table()
            self._mark_changed()
