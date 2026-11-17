"""Main connection dashboard page."""

from __future__ import annotations

import requests
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ppv.models import AppSettings, WireGuardProfile
from ppv.process_helper import (
    find_conflicting_vpns,
    is_admin,
    stop_conflicting_vpns,
)
from ppv.theme import format_bytes, format_speed


class _IpCheckWorker(QThread):
    result_ready = Signal(str)

    def run(self) -> None:
        try:
            r = requests.get("https://ipinfo.io/json", timeout=8)
            if r.ok:
                d = r.json()
                ip = d.get("ip", "?")
                country = d.get("country", "")
                org = d.get("org", "")
                self.result_ready.emit(f"{ip} ({country}) {org}".strip())
                return
        except Exception:
            pass
        try:
            r2 = requests.get("https://api.ipify.org", timeout=6)
            if r2.ok:
                self.result_ready.emit(r2.text.strip())
                return
        except Exception:
            pass
        self.result_ready.emit("Không thể kiểm tra IP (kiểm tra mạng)")


class DashboardPage(QWidget):
    """Hero connect/disconnect view with split mode, profile selection, and live stats."""

    toggle_connect_requested = Signal()
    profile_selected = Signal(str)
    split_mode_changed = Signal(str)
    elevate_requested = Signal()
    open_apps_requested = Signal()
    open_profiles_requested = Signal()

    def __init__(
        self,
        settings: AppSettings,
        profiles: list[WireGuardProfile],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = settings
        self.profiles = profiles
        self._state = "disconnected"
        self._ip_worker: _IpCheckWorker | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        content = QWidget()
        content.setObjectName("ScrollContent")
        scroll.setWidget(content)

        root = QVBoxLayout(content)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        title = QLabel("Bảng điều khiển VPN")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        # Conflict banner (e.g. APKCombo VPN WireGuardTunnel$warpplus active)
        self.conflict_banner = QFrame()
        self.conflict_banner.setObjectName("WarningBanner")
        c_lay = QHBoxLayout(self.conflict_banner)
        c_lay.setContentsMargins(14, 10, 14, 10)
        self.conflict_label = QLabel()
        self.conflict_label.setWordWrap(True)
        self.conflict_label.setStyleSheet("color: #fef3c7; font-weight: 600;")
        self.stop_conflict_btn = QPushButton("Tắt VPN khác")
        self.stop_conflict_btn.setObjectName("DangerButton")
        self.stop_conflict_btn.clicked.connect(self._stop_conflicting_tunnels)
        c_lay.addWidget(self.conflict_label, 1)
        c_lay.addWidget(self.stop_conflict_btn)
        self.conflict_banner.setVisible(False)
        root.addWidget(self.conflict_banner)

        # Admin status banner
        self.admin_banner = QFrame()
        self.admin_banner.setObjectName("InfoBanner")
        a_lay = QHBoxLayout(self.admin_banner)
        a_lay.setContentsMargins(14, 8, 14, 8)
        self.admin_label = QLabel(
            "App đang chạy với quyền User thường. Khi bấm Kết nối, Windows sẽ hỏi quyền Admin (UAC) để tạo card mạng TUN."
        )
        self.admin_label.setWordWrap(True)
        self.admin_label.setStyleSheet("color: #dbeafe;")
        self.elevate_btn = QPushButton("Cấp quyền Admin ngay")
        self.elevate_btn.setObjectName("PrimaryButton")
        self.elevate_btn.clicked.connect(self.elevate_requested.emit)
        a_lay.addWidget(self.admin_label, 1)
        a_lay.addWidget(self.elevate_btn)
        self.admin_banner.setVisible(not is_admin())
        root.addWidget(self.admin_banner)

        # Hero connection card
        hero = QFrame()
        hero.setObjectName("Card")
        hero.setMinimumHeight(178)
        hero.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        hero_lay = QVBoxLayout(hero)
        hero_lay.setContentsMargins(24, 22, 24, 22)
        hero_lay.setSpacing(14)

        top_row = QHBoxLayout()
        top_row.setSpacing(24)

        self.connect_btn = QPushButton("KẾT NỐI")
        self.connect_btn.setObjectName("ConnectHeroButton")
        self.connect_btn.setProperty("state", "disconnected")
        self.connect_btn.setFixedSize(130, 130)
        self.connect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_btn.clicked.connect(self.toggle_connect_requested.emit)
        top_row.addWidget(self.connect_btn)

        info_col = QVBoxLayout()
        info_col.setSpacing(8)
        self.status_heading = QLabel("Chưa kết nối")
        self.status_heading.setStyleSheet("font-size: 20px; font-weight: 700; color: #f8fafc;")
        self.status_sub = QLabel("Chọn Profile và danh sách ứng dụng rồi bấm Kết nối.")
        self.status_sub.setWordWrap(True)
        self.status_sub.setObjectName("MutedText")

        prof_row = QHBoxLayout()
        prof_lbl = QLabel("Profile VPN:")
        prof_lbl.setStyleSheet("font-weight: 600;")
        self.profile_combo = QComboBox()
        self.profile_combo.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.profile_combo.setMinimumContentsLength(18)
        self.profile_combo.setMinimumWidth(160)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        manage_prof_btn = QPushButton("Quản lý Profile")
        manage_prof_btn.clicked.connect(self.open_profiles_requested.emit)
        prof_row.addWidget(prof_lbl)
        prof_row.addWidget(self.profile_combo, 1)
        prof_row.addWidget(manage_prof_btn)

        info_col.addWidget(self.status_heading)
        info_col.addWidget(self.status_sub)
        info_col.addLayout(prof_row)
        top_row.addLayout(info_col, 1)
        hero_lay.addLayout(top_row)
        root.addWidget(hero)

        # Split mode + app count card
        mode_card = QFrame()
        mode_card.setObjectName("Card")
        mode_card.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        mode_lay = QVBoxLayout(mode_card)
        mode_lay.setContentsMargins(18, 14, 18, 14)
        mode_lay.setSpacing(10)

        mode_header = QHBoxLayout()
        mode_title = QLabel("Chế độ chia tách ứng dụng (Per-App Routing)")
        mode_title.setObjectName("SectionTitle")
        self.apps_count_btn = QPushButton("Cấu hình ứng dụng")
        self.apps_count_btn.clicked.connect(self.open_apps_requested.emit)
        mode_header.addWidget(mode_title, 1)
        mode_header.addWidget(self.apps_count_btn)
        mode_lay.addLayout(mode_header)

        self.radio_include = QRadioButton(
            "Chỉ app đã chọn dùng VPN (Include) — Còn lại dùng mạng gốc"
        )
        self.radio_exclude = QRadioButton(
            "Tất cả dùng VPN trừ ứng dụng được chọn (Exclude)"
        )
        self.radio_include.toggled.connect(self._on_mode_toggled)
        mode_lay.addWidget(self.radio_include)
        mode_lay.addWidget(self.radio_exclude)

        self.apps_summary_label = QLabel()
        self.apps_summary_label.setObjectName("MutedText")
        self.apps_summary_label.setWordWrap(True)
        mode_lay.addWidget(self.apps_summary_label)
        root.addWidget(mode_card)

        # Live stats cards row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)

        self.up_card, self.up_value, self.up_total_lbl = self._make_stat_card("Tốc độ tải lên", "0 B/s", "Tổng: 0 B")
        self.down_card, self.down_value, self.down_total_lbl = self._make_stat_card("Tốc độ tải xuống", "0 B/s", "Tổng: 0 B")
        self.conn_card, self.conn_value, self.conn_sub_lbl = self._make_stat_card("Kết nối đang theo dõi", "0", "Qua VPN: 0 | Trực tiếp: 0")

        stats_row.addWidget(self.up_card, 1)
        stats_row.addWidget(self.down_card, 1)
        stats_row.addWidget(self.conn_card, 1)
        root.addLayout(stats_row)

        # Bottom IP check bar
        ip_card = QFrame()
        ip_card.setObjectName("Card")
        ip_lay = QHBoxLayout(ip_card)
        ip_lay.setContentsMargins(16, 10, 16, 10)
        self.ip_label = QLabel("Mẹo kiểm tra: thêm trình duyệt vào tab Ứng dụng rồi mở ipinfo.io để xem IP VPN; mở tab Giám sát để xem từng kết nối.")
        self.ip_label.setWordWrap(True)
        self.ip_label.setObjectName("MutedText")
        self.check_ip_btn = QPushButton("Kiểm tra IP mạng gốc")
        self.check_ip_btn.clicked.connect(self._check_direct_ip)
        ip_lay.addWidget(self.ip_label, 1)
        ip_lay.addWidget(self.check_ip_btn)
        root.addWidget(ip_card)

        root.addStretch()
        self.refresh_data()
        self.refresh_conflicts()

    def _make_stat_card(self, label_text: str, value_text: str, sub_text: str) -> tuple[QFrame, QLabel, QLabel]:
        card = QFrame()
        card.setObjectName("Card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(4)
        lbl = QLabel(label_text)
        lbl.setObjectName("MutedText")
        val = QLabel(value_text)
        val.setStyleSheet("font-size: 18px; font-weight: 700; color: #f8fafc;")
        sub = QLabel(sub_text)
        sub.setObjectName("MutedText")
        lay.addWidget(lbl)
        lay.addWidget(val)
        lay.addWidget(sub)
        return card, val, sub

    def refresh_conflicts(self) -> None:
        conflicts = find_conflicting_vpns()
        if conflicts:
            labels = list(dict.fromkeys(f"{c.display_name} ({c.identifier})" for c in conflicts))
            preview = ", ".join(labels[:4])
            if len(labels) > 4:
                preview += f" (+{len(labels) - 4})"
            if self.settings.auto_stop_other_vpns:
                hint = "Khi bấm KẾT NỐI, PPV VPN sẽ tự động tắt các VPN này trước."
            else:
                hint = "Nên tắt trước khi bật PPV VPN để tránh xung đột định tuyến."
            self.conflict_label.setText(f"Phát hiện VPN khác đang mở: {preview}. {hint}")
            self.conflict_banner.setVisible(True)
        else:
            self.conflict_banner.setVisible(False)

    def _stop_conflicting_tunnels(self) -> None:
        if not is_admin():
            QMessageBox.information(
                self,
                "Cần quyền Admin",
                "Vui lòng cấp quyền Admin cho app (bấm 'Cấp quyền Admin ngay') hoặc bấm 'KẾT NỐI' để app tự xin quyền Admin và tắt VPN khác.",
            )
            return
        _stopped, errors = stop_conflicting_vpns()
        self.refresh_conflicts()
        if errors:
            QMessageBox.warning(self, "Không thể dừng hoàn toàn", "\n".join(errors))

    def refresh_data(self) -> None:
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        for prof in self.profiles:
            self.profile_combo.addItem(f"{prof.name}  ({prof.endpoint})", prof.id)
        idx = self.profile_combo.findData(self.settings.active_profile_id)
        if idx >= 0:
            self.profile_combo.setCurrentIndex(idx)
        self.profile_combo.blockSignals(False)

        self.radio_include.blockSignals(True)
        self.radio_exclude.blockSignals(True)
        self.radio_include.setChecked(self.settings.split_mode == "include")
        self.radio_exclude.setChecked(self.settings.split_mode == "exclude")
        self.radio_include.blockSignals(False)
        self.radio_exclude.blockSignals(False)

        enabled_apps = [r for r in self.settings.app_rules if r.enabled]
        if enabled_apps:
            preview = ", ".join(r.exe_name for r in enabled_apps[:6])
            if len(enabled_apps) > 6:
                preview += f" (+{len(enabled_apps) - 6} app nữa)"
            self.apps_summary_label.setText(
                f"Đang bật {len(enabled_apps)} ứng dụng: {preview}"
            )
        else:
            self.apps_summary_label.setText(
                "Chưa bật ứng dụng nào trong danh sách."
            )
        self.apps_count_btn.setText(f"Quản lý ứng dụng ({len(enabled_apps)})")

    def set_connection_state(self, state: str) -> None:
        self._state = state
        visual_state = "connecting" if state in ("stopping_others", "downloading_core") else state
        self.connect_btn.setProperty("state", visual_state)
        self.connect_btn.style().unpolish(self.connect_btn)
        self.connect_btn.style().polish(self.connect_btn)

        active = next(
            (p for p in self.profiles if p.id == self.settings.active_profile_id), None
        )
        prof_label = active.name if active else "Chưa chọn profile"

        if state == "connected":
            self.connect_btn.setText("NGẮT\nKẾT NỐI")
            self.status_heading.setText("Đã kết nối Per-App VPN")
            self.status_heading.setStyleSheet("font-size: 20px; font-weight: 700; color: #34d399;")
            mode_txt = "Include (Chỉ app đã chọn)" if self.settings.split_mode == "include" else "Exclude"
            self.status_sub.setText(f"Profile: {prof_label}  •  Chế độ: {mode_txt}")
        elif state == "downloading_core":
            self.connect_btn.setText("ĐANG TẢI\nCORE...")
            self.status_heading.setText("Đang tải sing-box.exe...")
            self.status_heading.setStyleSheet("font-size: 20px; font-weight: 700; color: #fbbf24;")
            self.status_sub.setText("Chưa có sing-box.exe — đang tự động tải bản chính thức từ GitHub...")
        elif state == "stopping_others":
            self.connect_btn.setText("ĐANG TẮT\nVPN KHÁC...")
            self.status_heading.setText("Đang tắt các VPN khác...")
            self.status_heading.setStyleSheet("font-size: 20px; font-weight: 700; color: #fbbf24;")
            self.status_sub.setText("Đang dừng APKCombo VPN / các dịch vụ VPN khác trước khi kết nối...")
        elif state == "connecting":
            self.connect_btn.setText("ĐANG\nKẾT NỐI...")
            self.status_heading.setText("Đang thiết lập tunnel...")
            self.status_heading.setStyleSheet("font-size: 20px; font-weight: 700; color: #fbbf24;")
            self.status_sub.setText(f"Đang khởi tạo interface Wintun cho {prof_label}...")
        elif state == "error":
            self.connect_btn.setText("THỬ LẠI")
            self.status_heading.setText("Lỗi kết nối")
            self.status_heading.setStyleSheet("font-size: 20px; font-weight: 700; color: #f87171;")
            self.status_sub.setText("Hãy kiểm tra quyền Admin, profile WireGuard hoặc xem tab Giám sát.")
        else:
            self.connect_btn.setText("KẾT NỐI")
            self.status_heading.setText("Chưa kết nối")
            self.status_heading.setStyleSheet("font-size: 20px; font-weight: 700; color: #f8fafc;")
            self.status_sub.setText("Sẵn sàng kết nối VPN theo từng ứng dụng.")

    def set_core_download_progress(self, downloaded: int, total: int) -> None:
        dl_mb = downloaded / (1024 * 1024)
        if total > 0:
            total_mb = total / (1024 * 1024)
            pct = min(100, int(downloaded * 100 / total))
            self.status_sub.setText(
                f"Đang tải sing-box.exe: {pct}% ({dl_mb:.1f} / {total_mb:.1f} MB)..."
            )
        else:
            self.status_sub.setText(f"Đang tải sing-box.exe: {dl_mb:.1f} MB...")

    def update_stats(
        self, up_bps: int, down_bps: int, up_total: int, down_total: int, conns: list
    ) -> None:
        self.up_value.setText(format_speed(up_bps))
        self.up_total_lbl.setText(f"Tổng: {format_bytes(up_total)}")
        self.down_value.setText(format_speed(down_bps))
        self.down_total_lbl.setText(f"Tổng: {format_bytes(down_total)}")
        vpn_count = sum(1 for c in conns if "wg-out" in c.rule_outbound.lower())
        direct_count = max(0, len(conns) - vpn_count)
        self.conn_value.setText(str(len(conns)))
        self.conn_sub_lbl.setText(f"Qua VPN: {vpn_count} | Trực tiếp: {direct_count}")

    def _on_profile_changed(self) -> None:
        prof_id = self.profile_combo.currentData()
        if prof_id:
            self.profile_selected.emit(str(prof_id))

    def _on_mode_toggled(self, checked: bool) -> None:
        if checked:
            self.split_mode_changed.emit("include")
        else:
            self.split_mode_changed.emit("exclude")

    def _check_direct_ip(self) -> None:
        self.check_ip_btn.setEnabled(False)
        self.check_ip_btn.setText("Đang kiểm tra...")
        self._ip_worker = _IpCheckWorker(self)
        self._ip_worker.result_ready.connect(self._on_ip_checked)
        self._ip_worker.start()

    def _on_ip_checked(self, result: str) -> None:
        self.check_ip_btn.setEnabled(True)
        self.check_ip_btn.setText("Kiểm tra IP mạng gốc")
        self.ip_label.setText(f"IP trực tiếp của máy: {result}")
