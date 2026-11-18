"""Main application window, sidebar navigation, and system tray integration."""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from ppv import __app_name__, __version__
from ppv.core_manager import VpnCoreManager, find_singbox_binary
from ppv.firewall_manager import FirewallSyncResult, sync_windows_firewall
from ppv.models import AppSettings
from ppv.process_helper import (
    cleanup_stale_ppv_instances,
    find_conflicting_vpns,
    is_admin,
    relaunch_as_admin,
    stop_conflicting_vpns,
)
from ppv.singbox_downloader import SingBoxDownloadError, download_singbox_binary
from ppv.single_instance import SingleInstanceController
from ppv.storage import AppStorage
from ppv.theme import create_app_icon
from ppv.ui.apps_page import AppsPage
from ppv.ui.dashboard_page import DashboardPage
from ppv.ui.monitor_page import MonitorPage
from ppv.ui.profiles_page import ProfilesPage
from ppv.ui.settings_page import SettingsPage


class _StopOtherVpnsWorker(QThread):
    finished_cleanup = Signal(list, list)

    def run(self) -> None:
        cleanup_stale_ppv_instances()
        stopped, errors = stop_conflicting_vpns()
        self.finished_cleanup.emit(stopped, errors)


class _DownloadSingboxWorker(QThread):
    progress = Signal(int, int)
    succeeded = Signal(str)
    failed = Signal(str)

    def run(self) -> None:
        try:
            path = download_singbox_binary(
                progress_cb=lambda done, total: self.progress.emit(done, total)
            )
            self.succeeded.emit(str(path))
        except SingBoxDownloadError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Không thể tải sing-box.exe: {exc}")


class _FirewallSyncWorker(QThread):
    finished_sync = Signal(object)

    def __init__(self, settings: AppSettings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings

    def run(self) -> None:
        res = sync_windows_firewall(self.settings)
        self.finished_sync.emit(res)


class MainWindow(QMainWindow):
    """Main window hosting sidebar navigation, pages, core manager, and system tray."""

    def __init__(
        self,
        auto_connect: bool = False,
        start_minimized: bool = False,
        single_instance: SingleInstanceController | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle(f"{__app_name__} v{__version__} — Per-App WireGuard VPN & Simple Firewall")
        self.resize(1080, 700)
        self.setMinimumSize(900, 600)

        self.storage = AppStorage()
        self.settings = self.storage.load_settings()
        self.profiles = self.storage.load_profiles()
        self.storage.ensure_active_profile(self.settings, self.profiles)

        self.core = VpnCoreManager(self.storage.runtime_dir, parent=self)
        self._single_instance = single_instance
        self._force_quit = False
        self._tray_notified = False
        self._stopping_other_vpns = False
        self._cancel_pending_connect = False
        self._pending_connect_profile = None
        self._stop_vpns_worker: _StopOtherVpnsWorker | None = None
        self._downloading_singbox = False
        self._connect_after_download = False
        self._download_worker: _DownloadSingboxWorker | None = None
        self._fw_worker: _FirewallSyncWorker | None = None

        self._icon_idle = create_app_icon(state="disconnected")
        self._icon_connecting = create_app_icon(state="connecting")
        self._icon_active = create_app_icon(state="connected")
        self._icon_error = create_app_icon(state="error")
        self.setWindowIcon(self._icon_idle)

        # Central layout
        central = QWidget()
        self.setCentralWidget(central)
        root_lay = QHBoxLayout(central)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(228)
        side_lay = QVBoxLayout(sidebar)
        side_lay.setContentsMargins(14, 18, 14, 16)
        side_lay.setSpacing(6)

        brand = QLabel(__app_name__)
        brand.setObjectName("BrandTitle")
        sub = QLabel("Per-App Split Tunnel")
        sub.setObjectName("BrandSubtitle")
        side_lay.addWidget(brand)
        side_lay.addWidget(sub)
        side_lay.addSpacing(14)

        self.nav_buttons: list[QPushButton] = []
        nav_items = [
            "Bảng điều khiển",
            "Tường lửa && Ứng dụng",
            "Profiles (.conf / WARP)",
            "Giám sát && Nhật ký",
            "Cài đặt",
        ]
        for idx, text in enumerate(nav_items):
            btn = QPushButton(text)
            btn.setObjectName("NavButton")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _checked=False, i=idx: self._switch_page(i))
            side_lay.addWidget(btn)
            self.nav_buttons.append(btn)

        side_lay.addStretch()

        role_txt = "Quyền: Administrator" if is_admin() else "Quyền: User thường"
        self.admin_badge = QLabel(role_txt)
        self.admin_badge.setObjectName("MutedText")
        self.ver_badge = QLabel(f"v{__version__} • sing-box TUN")
        self.ver_badge.setObjectName("MutedText")
        side_lay.addWidget(self.admin_badge)
        side_lay.addWidget(self.ver_badge)

        root_lay.addWidget(sidebar)

        # Pages
        self.stack = QStackedWidget()
        self.dashboard_page = DashboardPage(self.settings, self.profiles)
        self.apps_page = AppsPage(self.settings)
        self.profiles_page = ProfilesPage(self.settings, self.profiles)
        self.monitor_page = MonitorPage()
        self.settings_page = SettingsPage(self.settings, self.profiles)

        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.apps_page)
        self.stack.addWidget(self.profiles_page)
        self.stack.addWidget(self.monitor_page)
        self.stack.addWidget(self.settings_page)
        root_lay.addWidget(self.stack, 1)

        self._wire_signals()
        self._setup_tray()
        self._switch_page(0)

        # Periodic conflict check when disconnected
        self._conflict_timer = QTimer(self)
        self._conflict_timer.setInterval(5000)
        self._conflict_timer.timeout.connect(self._on_periodic_refresh)
        self._conflict_timer.start()

        if start_minimized and QSystemTrayIcon.isSystemTrayAvailable():
            QTimer.singleShot(0, self.hide)

        self._download_startup_timer = QTimer(self)
        self._download_startup_timer.setSingleShot(True)
        self._download_startup_timer.timeout.connect(lambda: self._start_singbox_download(connect_after=False))
        if find_singbox_binary() is None:
            self._download_startup_timer.start(150)

        self._fw_startup_timer = QTimer(self)
        self._fw_startup_timer.setSingleShot(True)
        self._fw_startup_timer.timeout.connect(lambda: self._sync_firewall(prompt_uac=False))
        if self.settings.firewall_enabled and is_admin():
            self._fw_startup_timer.start(200)

        if auto_connect or (self.settings.auto_connect_on_start and is_admin()):
            QTimer.singleShot(250, self._start_connection)

    def _wire_signals(self) -> None:
        self.dashboard_page.toggle_connect_requested.connect(self._toggle_connection)
        self.dashboard_page.profile_selected.connect(self._on_profile_selected)
        self.dashboard_page.split_mode_changed.connect(self._on_split_mode_changed)
        self.dashboard_page.elevate_requested.connect(self._elevate_app)
        self.dashboard_page.open_apps_requested.connect(lambda: self._switch_page(1))
        self.dashboard_page.open_profiles_requested.connect(lambda: self._switch_page(2))

        self.apps_page.rules_changed.connect(self._on_apps_changed)
        self.apps_page.apply_requested.connect(self._restart_if_running)
        self.apps_page.firewall_sync_requested.connect(lambda: self._sync_firewall(prompt_uac=True))
        self.apps_page.elevate_requested.connect(self._elevate_app)

        self.profiles_page.profiles_changed.connect(self._on_profiles_changed)
        self.profiles_page.active_profile_changed.connect(self._on_profile_selected)

        self.settings_page.settings_changed.connect(self._on_settings_changed)

        self.core.state_changed.connect(self._on_core_state_changed)
        self.core.log_received.connect(self.monitor_page.append_log)
        self.core.stats_updated.connect(self._on_stats_updated)
        self.core.error_occurred.connect(self._on_core_error)
        self.core.tunnel_warning.connect(self._on_tunnel_warning)
        self.monitor_page.logs_cleared.connect(self.core.clear_blocked_history)

    def _setup_tray(self) -> None:
        self.tray = QSystemTrayIcon(self._icon_idle, self)
        self.tray.setToolTip(f"{__app_name__} — Chưa kết nối")
        menu = QMenu(self)

        self.tray_show_act = QAction("Mở PPV VPN", self)
        self.tray_show_act.triggered.connect(self._restore_from_tray)
        self.tray_toggle_act = QAction("Kết nối VPN", self)
        self.tray_toggle_act.triggered.connect(self._toggle_connection)
        self.tray_fw_off_act = QAction("Tắt nhanh Firewall (Mở lại mạng)", self)
        self.tray_fw_off_act.triggered.connect(self._emergency_disable_firewall)
        self.tray_fw_off_act.setEnabled(self.settings.firewall_enabled)
        self.tray_quit_act = QAction("Thoát hoàn toàn", self)
        self.tray_quit_act.triggered.connect(self.quit_completely)

        menu.addAction(self.tray_show_act)
        menu.addAction(self.tray_toggle_act)
        menu.addAction(self.tray_fw_off_act)
        menu.addSeparator()
        menu.addAction(self.tray_quit_act)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            if self.isVisible() and not self.isMinimized():
                self.hide()
            else:
                self._restore_from_tray()

    def bring_to_front(self) -> None:
        self._restore_from_tray()

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _switch_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for idx, btn in enumerate(self.nav_buttons):
            btn.setProperty("active", idx == index)
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        if index == 0:
            self.dashboard_page.refresh_conflicts()

    def _on_periodic_refresh(self) -> None:
        if self.stack.currentIndex() == 0 and not self._stopping_other_vpns:
            self.dashboard_page.refresh_conflicts()

    def _active_profile(self):
        return next(
            (p for p in self.profiles if p.id == self.settings.active_profile_id),
            None,
        )

    def _start_singbox_download(self, connect_after: bool = False) -> None:
        if connect_after:
            self._connect_after_download = True
        if self._downloading_singbox:
            if connect_after:
                self.dashboard_page.set_connection_state("downloading_core")
            return
        if find_singbox_binary() is not None:
            if connect_after:
                self._connect_after_download = False
                self._start_connection()
            return

        self._downloading_singbox = True
        self.monitor_page.append_log(
            "[PPV] Chưa có sing-box.exe — đang tự động tải sing-box v1.14.4 chính thức..."
        )
        if self._connect_after_download:
            self.dashboard_page.set_connection_state("downloading_core")
            self.setWindowIcon(self._icon_connecting)
            self.tray.setIcon(self._icon_connecting)
            self.tray.setToolTip(f"{__app_name__} — Đang tải sing-box...")
            self.tray_toggle_act.setText("Hủy tải / kết nối")
        else:
            self.dashboard_page.status_sub.setText(
                "Chưa có sing-box.exe — đang tự động tải xuống ở nền..."
            )

        self._download_worker = _DownloadSingboxWorker(self)
        self._download_worker.progress.connect(self._on_singbox_download_progress)
        self._download_worker.succeeded.connect(self._on_singbox_downloaded)
        self._download_worker.failed.connect(self._on_singbox_download_failed)
        self._download_worker.start()

    def _on_singbox_download_progress(self, downloaded: int, total: int) -> None:
        if self.core.state == "disconnected" and not self._stopping_other_vpns:
            self.dashboard_page.set_core_download_progress(downloaded, total)

    def _on_singbox_downloaded(self, path_str: str) -> None:
        self._downloading_singbox = False
        should_connect = self._connect_after_download
        self._connect_after_download = False
        self.monitor_page.append_log(f"[PPV] Đã tải và xác thực sing-box.exe tại: {path_str}")
        if should_connect:
            self._start_connection()
        elif self.core.state == "disconnected" and not self._stopping_other_vpns:
            self.dashboard_page.set_connection_state("disconnected")

    def _on_singbox_download_failed(self, err: str) -> None:
        self._downloading_singbox = False
        was_connecting = self._connect_after_download
        self._connect_after_download = False
        self.monitor_page.append_log(f"[PPV] Lỗi tải sing-box.exe: {err}")
        if was_connecting:
            self._on_core_state_changed("error")
            if not self.isVisible():
                self._restore_from_tray()
            QMessageBox.warning(self, "Không thể tải sing-box.exe", err)
        elif self.core.state == "disconnected":
            self.dashboard_page.status_sub.setText(
                "Chưa tải được sing-box.exe. Kiểm tra mạng rồi bấm Kết nối để thử lại."
            )

    def _toggle_connection(self) -> None:
        if self._downloading_singbox:
            self._connect_after_download = not self._connect_after_download
            if self._connect_after_download:
                self.dashboard_page.set_connection_state("downloading_core")
            else:
                self.dashboard_page.set_connection_state("disconnected")
                self.dashboard_page.status_sub.setText("Đang tiếp tục tải sing-box.exe ở nền...")
            return
        if self._stopping_other_vpns:
            self._cancel_pending_connect = True
            self.dashboard_page.status_sub.setText("Đang hủy chờ kết nối...")
            return
        if self.core.is_running or self.core.state in ("connected", "connecting"):
            self.core.stop_sync()
        else:
            self._start_connection()

    def _start_connection(self) -> None:
        if self._stopping_other_vpns:
            return
        if find_singbox_binary() is None:
            self._start_singbox_download(connect_after=True)
            return

        profile = self._active_profile()
        if profile is None:
            QMessageBox.warning(
                self,
                "Chưa có profile VPN",
                "Hãy nhập file WireGuard .conf hoặc tạo profile Cloudflare WARP miễn phí trước.",
            )
            self._switch_page(2)
            return

        if not is_admin():
            self.storage.save_settings(self.settings)
            self.storage.save_profiles(self.profiles)
            if self._single_instance is not None:
                self._single_instance.close()
            if relaunch_as_admin(["--connect", "--elevated"]):
                self._force_quit = True
                self.tray.hide()
                QApplication.quit()
            else:
                if self._single_instance is not None:
                    self._single_instance.start_listening()
                QMessageBox.information(
                    self,
                    "Cần quyền Administrator",
                    "Windows cần quyền Administrator để tạo card mạng ảo TUN cho Per-App VPN.",
                )
            return

        if self.settings.split_mode == "include":
            enabled_count = sum(1 for r in self.settings.app_rules if r.enabled)
            if enabled_count == 0:
                box = QMessageBox(self)
                box.setWindowTitle("Chưa chọn ứng dụng nào")
                box.setText(
                    "Bạn đang ở chế độ Include (chỉ app được chọn mới dùng VPN) nhưng chưa bật ứng dụng nào."
                )
                pick_btn = box.addButton("Đi tới chọn ứng dụng", QMessageBox.ButtonRole.AcceptRole)
                cont_btn = box.addButton("Vẫn kết nối", QMessageBox.ButtonRole.ActionRole)
                box.addButton("Hủy", QMessageBox.ButtonRole.RejectRole)
                box.exec()
                if box.clickedButton() == pick_btn:
                    self._switch_page(1)
                    return
                if box.clickedButton() != cont_btn:
                    return

        self.storage.save_settings(self.settings)

        if self.settings.auto_stop_other_vpns and find_conflicting_vpns():
            self._stopping_other_vpns = True
            self._cancel_pending_connect = False
            self._pending_connect_profile = profile
            self.dashboard_page.set_connection_state("stopping_others")
            self.apps_page.set_connection_state("connecting")
            self.setWindowIcon(self._icon_connecting)
            self.tray.setIcon(self._icon_connecting)
            self.tray.setToolTip(f"{__app_name__} — Đang tắt VPN khác...")
            self.tray_toggle_act.setText("Hủy kết nối")

            self._stop_vpns_worker = _StopOtherVpnsWorker(self)
            self._stop_vpns_worker.finished_cleanup.connect(self._on_other_vpns_stopped)
            self._stop_vpns_worker.start()
            return

        cleanup_stale_ppv_instances()
        self.core.start(profile, self.settings)

    def _on_other_vpns_stopped(self, stopped: list[str], errors: list[str]) -> None:
        self._stopping_other_vpns = False
        profile = self._pending_connect_profile
        self._pending_connect_profile = None

        unique_stopped = list(dict.fromkeys(stopped))
        if unique_stopped:
            self.monitor_page.append_log(
                f"[PPV] Đã tắt các VPN khác: {', '.join(unique_stopped)}"
            )
        for err in errors:
            self.monitor_page.append_log(f"[PPV] Cảnh báo khi tắt VPN khác: {err}")

        self.dashboard_page.refresh_conflicts()

        if self._cancel_pending_connect or profile is None:
            self._cancel_pending_connect = False
            self._on_core_state_changed("disconnected")
            return

        self.core.start(profile, self.settings)

    def _restart_if_running(self) -> None:
        if self.core.is_running:
            profile = self._active_profile()
            if profile is not None:
                self.storage.save_settings(self.settings)
                self.core.start(profile, self.settings)

    def _elevate_app(self) -> None:
        self.storage.save_settings(self.settings)
        self.storage.save_profiles(self.profiles)
        if self._single_instance is not None:
            self._single_instance.close()
        if relaunch_as_admin(["--elevated"]):
            self._force_quit = True
            self.tray.hide()
            QApplication.quit()
        elif self._single_instance is not None:
            self._single_instance.start_listening()

    def _on_profile_selected(self, profile_id: str) -> None:
        self.settings.active_profile_id = profile_id
        self.storage.save_settings(self.settings)
        self.dashboard_page.refresh_data()
        self.profiles_page.refresh_list()
        if self.core.is_running:
            self._restart_if_running()

    def _on_split_mode_changed(self, mode: str) -> None:
        if mode in ("include", "exclude"):
            self.settings.split_mode = mode  # type: ignore[assignment]
            self.storage.save_settings(self.settings)
            self.dashboard_page.refresh_data()
            self.apps_page.refresh_view()
            if self.core.is_running:
                self._restart_if_running()

    def _on_apps_changed(self) -> None:
        self.storage.save_settings(self.settings)
        self.dashboard_page.refresh_data()
        self.tray_fw_off_act.setEnabled(self.settings.firewall_enabled)

    def _sync_firewall(self, prompt_uac: bool = True) -> None:
        if self.settings.firewall_enabled and not is_admin():
            if prompt_uac:
                box = QMessageBox(self)
                box.setWindowTitle("Cần quyền Administrator")
                box.setText(
                    "Windows cần quyền Administrator để áp dụng bộ lọc Windows Firewall (Simple Firewall)."
                )
                elev_btn = box.addButton("Cấp quyền Admin ngay", QMessageBox.ButtonRole.AcceptRole)
                box.addButton("Để sau", QMessageBox.ButtonRole.RejectRole)
                box.exec()
                if box.clickedButton() == elev_btn:
                    self._elevate_app()
                else:
                    self.settings.firewall_enabled = False
                    self.storage.save_settings(self.settings)
                    self.apps_page.refresh_view()
                    self.dashboard_page.refresh_data()
            return

        if not self.settings.firewall_enabled and not is_admin():
            self.tray_fw_off_act.setEnabled(False)
            self.dashboard_page.refresh_data()
            return

        if self._fw_worker is not None and self._fw_worker.isRunning():
            self._fw_worker.wait(1500)
        self._fw_worker = _FirewallSyncWorker(self.settings, self)
        self._fw_worker.finished_sync.connect(self._on_firewall_synced)
        self._fw_worker.start()

    def _on_firewall_synced(self, result: FirewallSyncResult) -> None:
        self.storage.save_settings(self.settings)
        self.tray_fw_off_act.setEnabled(result.enabled)
        self.apps_page._sync_firewall_controls()
        self.dashboard_page.refresh_data()

        if result.enabled:
            self.monitor_page.append_log(
                f"[PPV Firewall] Đã bật ({result.mode}): {result.applied_block} app bị chặn, "
                f"{result.applied_allow} rule cho phép."
            )
        else:
            self.monitor_page.append_log(
                f"[PPV Firewall] Đã tắt bộ lọc & khôi phục cấu hình gốc ({result.removed} rule đã gỡ)."
            )
        for err in result.errors:
            self.monitor_page.append_log(f"[PPV Firewall] Cảnh báo: {err}")
        if result.errors:
            QMessageBox.warning(self, "Lỗi Windows Firewall", "\n".join(result.errors[:5]))

    def _emergency_disable_firewall(self) -> None:
        self.settings.firewall_enabled = False
        self.storage.save_settings(self.settings)
        self.apps_page.refresh_view()
        self.dashboard_page.refresh_data()
        self._sync_firewall(prompt_uac=True)

    def _on_profiles_changed(self) -> None:
        self.storage.save_profiles(self.profiles)
        self.storage.ensure_active_profile(self.settings, self.profiles)
        self.storage.save_settings(self.settings)
        self.dashboard_page.refresh_data()
        self.profiles_page.refresh_list()

    def _on_settings_changed(self) -> None:
        self.storage.save_settings(self.settings)
        self.dashboard_page.refresh_conflicts()

    def _on_core_state_changed(self, state: str) -> None:
        if state != "connected":
            self.dashboard_page.set_tunnel_warning("")
        self.dashboard_page.set_connection_state(state)
        self.apps_page.set_connection_state(state)

        icon_map = {
            "connected": self._icon_active,
            "connecting": self._icon_connecting,
            "error": self._icon_error,
        }
        icon = icon_map.get(state, self._icon_idle)
        self.setWindowIcon(icon)
        self.tray.setIcon(icon)

        prof = self._active_profile()
        prof_name = prof.name if prof else "No Profile"
        if state == "connected":
            self.tray.setToolTip(f"{__app_name__} — Đã kết nối ({prof_name})")
            self.tray_toggle_act.setText("Ngắt kết nối VPN")
        elif state == "connecting":
            self.tray.setToolTip(f"{__app_name__} — Đang kết nối...")
            self.tray_toggle_act.setText("Hủy kết nối")
        elif state == "error":
            self.tray.setToolTip(f"{__app_name__} — Lỗi kết nối")
            self.tray_toggle_act.setText("Thử lại kết nối")
        else:
            self.tray.setToolTip(f"{__app_name__} — Chưa kết nối")
            self.tray_toggle_act.setText("Kết nối VPN")

        if state in ("connected", "disconnected"):
            self.dashboard_page.refresh_conflicts()

    def _on_stats_updated(
        self, up_bps: int, down_bps: int, up_total: int, down_total: int, conns: list
    ) -> None:
        self.dashboard_page.update_stats(up_bps, down_bps, up_total, down_total, conns)
        self.monitor_page.update_connections(conns)

    def _on_core_error(self, msg: str) -> None:
        if not self.isVisible():
            self._restore_from_tray()
        QMessageBox.warning(self, "Lỗi VPN", msg)

    def _on_tunnel_warning(self, message: str) -> None:
        self.dashboard_page.set_tunnel_warning(message)
        if message:
            self.monitor_page.append_log(f"[PPV CẢNH BÁO] {message}")
            if self.core.state == "connected":
                self.setWindowIcon(self._icon_connecting)
                self.tray.setIcon(self._icon_connecting)
                self.tray.setToolTip(f"{__app_name__} — Tunnel chưa bắt tay được")
        elif self.core.state == "connected":
            prof = self._active_profile()
            prof_name = prof.name if prof else "No Profile"
            self.setWindowIcon(self._icon_active)
            self.tray.setIcon(self._icon_active)
            self.tray.setToolTip(f"{__app_name__} — Đã kết nối ({prof_name})")

    def closeEvent(self, event: QCloseEvent) -> None:
        if (
            not self._force_quit
            and self.settings.minimize_to_tray
            and QSystemTrayIcon.isSystemTrayAvailable()
        ):
            event.ignore()
            self.hide()
            if not self._tray_notified:
                self._tray_notified = True
                self.tray.showMessage(
                    __app_name__,
                    "Ứng dụng đang chạy ngầm ở khay hệ thống. Nhấp chuột phải vào biểu tượng để thoát hoàn toàn.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )
            return

        self._cancel_pending_connect = True
        self._connect_after_download = False
        self._conflict_timer.stop()
        self._download_startup_timer.stop()
        self._fw_startup_timer.stop()
        self.core.stop_sync()
        self.dashboard_page.stop_workers()
        self.profiles_page.stop_workers()
        self.apps_page.stop_workers()
        if self._stop_vpns_worker is not None and self._stop_vpns_worker.isRunning():
            self._stop_vpns_worker.wait(1500)
        if self._download_worker is not None and self._download_worker.isRunning():
            self._download_worker.wait(1500)
        if self._fw_worker is not None and self._fw_worker.isRunning():
            self._fw_worker.wait(1500)
        if self._single_instance is not None:
            self._single_instance.close()
        self.tray.hide()
        event.accept()

    def quit_completely(self) -> None:
        self._force_quit = True
        self._cancel_pending_connect = True
        self._connect_after_download = False
        self._conflict_timer.stop()
        self._download_startup_timer.stop()
        self._fw_startup_timer.stop()
        self.core.stop_sync()
        self.dashboard_page.stop_workers()
        self.profiles_page.stop_workers()
        self.apps_page.stop_workers()
        if self._stop_vpns_worker is not None and self._stop_vpns_worker.isRunning():
            self._stop_vpns_worker.wait(1500)
        if self._download_worker is not None and self._download_worker.isRunning():
            self._download_worker.wait(1500)
        if self._fw_worker is not None and self._fw_worker.isRunning():
            self._fw_worker.wait(1500)
        if self._single_instance is not None:
            self._single_instance.close()
        self.tray.hide()
        QApplication.quit()
