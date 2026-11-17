"""Live per-app connection monitor and sing-box runtime log viewer."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ppv.core_manager import ConnectionRow
from ppv.theme import format_bytes


class MonitorPage(QWidget):
    """Displays real-time per-app connections (VPN vs Direct vs Blocked) and sing-box logs."""

    logs_cleared = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._latest_rows: list[ConnectionRow] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        title = QLabel("Giám sát kết nối & Nhật ký")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Top pane: Live connections
        conn_widget = QWidget()
        conn_lay = QVBoxLayout(conn_widget)
        conn_lay.setContentsMargins(0, 0, 0, 6)
        conn_lay.setSpacing(8)

        filter_row = QHBoxLayout()
        sec1 = QLabel("Kết nối đang hoạt động theo ứng dụng")
        sec1.setObjectName("SectionTitle")
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Lọc theo tên .exe hoặc domain/IP...")
        self.filter_edit.textChanged.connect(self._render_connections)
        self.outbound_filter = QComboBox()
        self.outbound_filter.addItem("Tất cả luồng", "all")
        self.outbound_filter.addItem("Chỉ qua VPN (wg-out)", "vpn")
        self.outbound_filter.addItem("Chỉ trực tiếp (direct)", "direct")
        self.outbound_filter.addItem("Chỉ bị chặn (reject)", "reject")
        self.outbound_filter.currentIndexChanged.connect(self._render_connections)
        filter_row.addWidget(sec1, 1)
        filter_row.addWidget(self.filter_edit)
        filter_row.addWidget(self.outbound_filter)
        conn_lay.addLayout(filter_row)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Ứng dụng", "Đích (Host / IP:Port)", "Giao thức", "Luồng đi", "Tải lên", "Tải xuống"]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, 85)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(3, 145)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(4, 90)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(5, 90)
        conn_lay.addWidget(self.table, 1)
        splitter.addWidget(conn_widget)

        # Bottom pane: Logs
        log_widget = QWidget()
        log_lay = QVBoxLayout(log_widget)
        log_lay.setContentsMargins(0, 6, 0, 0)
        log_lay.setSpacing(8)

        log_bar = QHBoxLayout()
        sec2 = QLabel("Nhật ký sing-box")
        sec2.setObjectName("SectionTitle")
        copy_btn = QPushButton("Sao chép log")
        copy_btn.clicked.connect(self._copy_logs)
        clear_btn = QPushButton("Xóa log")
        clear_btn.clicked.connect(self._clear_logs)
        log_bar.addWidget(sec2, 1)
        log_bar.addWidget(copy_btn)
        log_bar.addWidget(clear_btn)
        log_lay.addLayout(log_bar)

        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumBlockCount(1500)
        mono = QFont("Consolas", 10)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.log_box.setFont(mono)
        self.log_box.setStyleSheet('font-family: "Consolas", "Courier New", monospace; font-size: 12px;')
        log_lay.addWidget(self.log_box, 1)
        splitter.addWidget(log_widget)

        splitter.setSizes([320, 220])
        root.addWidget(splitter, 1)

    def append_log(self, line: str) -> None:
        self.log_box.appendPlainText(line)

    def update_connections(self, rows: list[ConnectionRow]) -> None:
        self._latest_rows = rows
        self._render_connections()

    def _render_connections(self) -> None:
        query = self.filter_edit.text().strip().lower()
        mode = str(self.outbound_filter.currentData())

        filtered: list[ConnectionRow] = []
        for r in self._latest_rows:
            out_low = r.rule_outbound.lower()
            is_vpn = "wg-out" in out_low
            is_reject = "reject" in out_low or "block" in out_low
            if mode == "vpn" and not is_vpn:
                continue
            if mode == "direct" and (is_vpn or is_reject):
                continue
            if mode == "reject" and not is_reject:
                continue
            if query and query not in r.process_name.lower() and query not in r.destination.lower():
                continue
            filtered.append(r)

        self.table.setRowCount(len(filtered))
        for idx, r in enumerate(filtered):
            out_low = r.rule_outbound.lower()
            is_vpn = "wg-out" in out_low
            is_reject = "reject" in out_low or "block" in out_low
            self.table.setItem(idx, 0, QTableWidgetItem(r.process_name))
            self.table.setItem(idx, 1, QTableWidgetItem(r.destination))
            self.table.setItem(idx, 2, QTableWidgetItem(r.network))

            if is_reject:
                out_item = QTableWidgetItem("Bị chặn (Block)")
                out_item.setForeground(QColor("#fb7185"))
                self.table.setItem(idx, 3, out_item)
                count_txt = f"Chặn ({r.blocked_count or 1}x)"
                self.table.setItem(idx, 4, QTableWidgetItem(count_txt))
                self.table.setItem(idx, 5, QTableWidgetItem(r.timestamp or "—"))
            else:
                if is_vpn:
                    out_item = QTableWidgetItem("VPN (wg-out)")
                    out_item.setForeground(QColor("#34d399"))
                else:
                    out_item = QTableWidgetItem("Trực tiếp (direct)")
                    out_item.setForeground(QColor("#94a3b8"))
                self.table.setItem(idx, 3, out_item)
                self.table.setItem(idx, 4, QTableWidgetItem(format_bytes(r.upload_bytes)))
                self.table.setItem(idx, 5, QTableWidgetItem(format_bytes(r.download_bytes)))

    def _copy_logs(self) -> None:
        QApplication.clipboard().setText(self.log_box.toPlainText())

    def _clear_logs(self) -> None:
        self.log_box.clear()
        self.logs_cleared.emit()
