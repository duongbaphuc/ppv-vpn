"""Dialog for picking running or installed Windows applications."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, QThread, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ppv.process_helper import (
    DiscoveredApp,
    extract_exe_icon,
    list_installed_apps,
    list_running_apps,
)


class _AppScanWorker(QThread):
    finished_scan = Signal(list, list)

    def run(self) -> None:
        running = list_running_apps(include_background=True)
        installed = list_installed_apps()
        self.finished_scan.emit(running, installed)


class AppPickerDialog(QDialog):
    """Multi-select dialog listing running processes and Start Menu installed apps."""

    def __init__(
        self,
        existing_paths: set[str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Chọn ứng dụng")
        self.resize(640, 520)
        self._existing_paths = {p.lower() for p in existing_paths}
        self._running: list[DiscoveredApp] = []
        self._installed: list[DiscoveredApp] = []
        self._selected: list[DiscoveredApp] = []

        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(16, 16, 16, 16)

        header = QLabel("Chọn một hoặc nhiều ứng dụng muốn thêm vào danh sách")
        header.setObjectName("SectionTitle")
        root.addWidget(header)

        search_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Tìm theo tên ứng dụng hoặc tên file .exe...")
        self.search_input.textChanged.connect(self._apply_filter)
        search_row.addWidget(self.search_input)

        self.refresh_btn = QPushButton("Làm mới")
        self.refresh_btn.clicked.connect(self._start_scan)
        search_row.addWidget(self.refresh_btn)
        root.addLayout(search_row)

        self.tabs = QTabWidget()
        self.running_list = QListWidget()
        self.running_list.setIconSize(QSize(24, 24))
        self.installed_list = QListWidget()
        self.installed_list.setIconSize(QSize(24, 24))
        self.tabs.addTab(self.running_list, "Đang chạy")
        self.tabs.addTab(self.installed_list, "Đã cài đặt (Start Menu)")
        root.addWidget(self.tabs, 1)

        self.status_label = QLabel("Đang quét danh sách ứng dụng...")
        self.status_label.setObjectName("MutedText")
        root.addWidget(self.status_label)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("Hủy")
        cancel_btn.clicked.connect(self.reject)
        self.add_btn = QPushButton("Thêm các app đã chọn")
        self.add_btn.setObjectName("PrimaryButton")
        self.add_btn.clicked.connect(self._accept_selected)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self.add_btn)
        root.addLayout(btn_row)

        self._worker: _AppScanWorker | None = None
        self._start_scan()

    def selected_apps(self) -> list[DiscoveredApp]:
        return self._selected

    def _start_scan(self) -> None:
        self.refresh_btn.setEnabled(False)
        self.status_label.setText("Đang quét các tiến trình đang chạy và ứng dụng đã cài đặt...")
        self._worker = _AppScanWorker(self)
        self._worker.finished_scan.connect(self._on_scan_finished)
        self._worker.start()

    def _on_scan_finished(self, running: list[DiscoveredApp], installed: list[DiscoveredApp]) -> None:
        self._running = running
        self._installed = installed
        self.refresh_btn.setEnabled(True)
        self.status_label.setText(
            f"Tìm thấy {len(running)} tiến trình đang chạy và {len(installed)} ứng dụng đã cài đặt."
        )
        self._populate_list(self.running_list, self._running)
        self._populate_list(self.installed_list, self._installed)
        self._apply_filter(self.search_input.text())

    def _populate_list(self, widget: QListWidget, apps: list[DiscoveredApp]) -> None:
        widget.clear()
        for app in apps:
            already = app.exe_path.lower() in self._existing_paths
            tag = " [Đang mở]" if app.has_window else ""
            suffix = " (Đã có)" if already else ""
            item = QListWidgetItem(f"{app.display_name} ({app.exe_name}){tag}{suffix}")
            item.setToolTip(app.exe_path)
            item.setData(Qt.ItemDataRole.UserRole, app)
            px = extract_exe_icon(app.exe_path, 24)
            if px is not None:
                item.setIcon(QIcon(px))
            item.setFlags(
                (item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                if not already
                else (item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            )
            item.setCheckState(Qt.CheckState.Unchecked)
            widget.addItem(item)

    def _apply_filter(self, text: str) -> None:
        query = text.strip().lower()
        for widget in (self.running_list, self.installed_list):
            for idx in range(widget.count()):
                item = widget.item(idx)
                app: DiscoveredApp = item.data(Qt.ItemDataRole.UserRole)
                visible = (
                    not query
                    or query in app.display_name.lower()
                    or query in app.exe_name.lower()
                    or query in app.exe_path.lower()
                )
                item.setHidden(not visible)

    def _accept_selected(self) -> None:
        picked: dict[str, DiscoveredApp] = {}
        for widget in (self.running_list, self.installed_list):
            for idx in range(widget.count()):
                item = widget.item(idx)
                if item.checkState() == Qt.CheckState.Checked:
                    app: DiscoveredApp = item.data(Qt.ItemDataRole.UserRole)
                    picked.setdefault(app.exe_path.lower(), app)
        self._selected = list(picked.values())
        self.accept()
