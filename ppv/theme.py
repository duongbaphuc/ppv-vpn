"""Theme styling, formatting helpers, and vector icons for PPV VPN."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter, QPainterPath, QPalette, QPen, QPixmap

DARK_STYLESHEET = """
QMainWindow, QDialog, QStackedWidget, QSplitter {
    background-color: #0b1120;
    color: #e2e8f0;
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    font-size: 13px;
}

QWidget {
    color: #e2e8f0;
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    font-size: 13px;
}

QLabel, QCheckBox, QRadioButton {
    background-color: transparent;
}

QScrollArea, QWidget#ScrollContent {
    background-color: transparent;
    border: none;
}

QTableWidget QWidget {
    background-color: transparent;
}

QMessageBox {
    background-color: #0f172a;
}

QToolTip {
    background-color: #0f172a;
    color: #f1f5f9;
    border: 1px solid #334155;
    padding: 4px 8px;
}

QMenu {
    background-color: #0f172a;
    color: #e2e8f0;
    border: 1px solid #334155;
    padding: 4px;
}

QMenu::item {
    padding: 6px 18px;
    border-radius: 6px;
}

QMenu::item:selected {
    background-color: #1d4ed8;
    color: #ffffff;
}

QFrame#Sidebar {
    background-color: #0f172a;
    border-right: 1px solid #1e293b;
}

QLabel#BrandTitle {
    font-size: 17px;
    font-weight: 700;
    color: #f8fafc;
}

QLabel#BrandSubtitle {
    font-size: 11px;
    color: #94a3b8;
}

QPushButton#NavButton {
    text-align: left;
    padding: 10px 14px;
    border-radius: 8px;
    border: none;
    background-color: transparent;
    color: #94a3b8;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#NavButton:hover {
    background-color: #1e293b;
    color: #f1f5f9;
}

QPushButton#NavButton[active="true"] {
    background-color: #1d4ed8;
    color: #ffffff;
}

QFrame#Card {
    background-color: #111c33;
    border: 1px solid #1e293b;
    border-radius: 12px;
}

QFrame#WarningBanner {
    background-color: #422006;
    border: 1px solid #b45309;
    border-radius: 10px;
}

QFrame#InfoBanner {
    background-color: #0c243c;
    border: 1px solid #1d4ed8;
    border-radius: 10px;
}

QLabel#PageTitle {
    font-size: 20px;
    font-weight: 700;
    color: #f8fafc;
}

QLabel#SectionTitle {
    font-size: 14px;
    font-weight: 700;
    color: #f1f5f9;
}

QLabel#MutedText {
    color: #94a3b8;
    font-size: 12px;
}

QPushButton {
    background-color: #1e293b;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 7px 14px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #283548;
    border-color: #475569;
}

QPushButton:pressed {
    background-color: #0f172a;
}

QPushButton:disabled {
    background-color: #162032;
    color: #64748b;
    border-color: #1e293b;
}

QPushButton#PrimaryButton {
    background-color: #2563eb;
    border: 1px solid #3b82f6;
    color: #ffffff;
}

QPushButton#PrimaryButton:hover {
    background-color: #1d4ed8;
}

QPushButton#SuccessButton {
    background-color: #059669;
    border: 1px solid #10b981;
    color: #ffffff;
}

QPushButton#SuccessButton:hover {
    background-color: #047857;
}

QPushButton#DangerButton {
    background-color: #991b1b;
    border: 1px solid #dc2626;
    color: #ffffff;
}

QPushButton#DangerButton:hover {
    background-color: #7f1d1d;
}

QPushButton#ConnectHeroButton {
    border-radius: 65px;
    font-size: 15px;
    font-weight: 700;
    background-color: #1e293b;
    border: 3px solid #3b82f6;
    color: #f8fafc;
}

QPushButton#ConnectHeroButton[state="disconnected"]:hover {
    background-color: #1e3a5f;
    border-color: #60a5fa;
}

QPushButton#ConnectHeroButton[state="connecting"] {
    background-color: #422006;
    border-color: #f59e0b;
    color: #fde68a;
}

QPushButton#ConnectHeroButton[state="connected"] {
    background-color: #064e3b;
    border-color: #10b981;
    color: #d1fae5;
}

QPushButton#ConnectHeroButton[state="connected"]:hover {
    background-color: #065f46;
    border-color: #34d399;
}

QPushButton#ConnectHeroButton[state="error"] {
    background-color: #450a0a;
    border-color: #ef4444;
    color: #fecaca;
}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 6px 10px;
    color: #f1f5f9;
    selection-background-color: #2563eb;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {
    border-color: #3b82f6;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox QAbstractItemView {
    background-color: #0f172a;
    color: #f1f5f9;
    border: 1px solid #334155;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
    outline: none;
}

QTableWidget, QListWidget {
    background-color: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    gridline-color: #1e293b;
    outline: none;
}

QHeaderView::section {
    background-color: #162032;
    color: #94a3b8;
    border: none;
    border-bottom: 1px solid #1e293b;
    padding: 8px 10px;
    font-weight: 600;
}

QTableWidget::item, QListWidget::item {
    padding: 6px 8px;
    border-bottom: 1px solid #152033;
}

QTableWidget::item:selected, QListWidget::item:selected {
    background-color: #1e3a5f;
    color: #ffffff;
}

QTabWidget::pane {
    border: 1px solid #1e293b;
    border-radius: 8px;
    background-color: #111c33;
}

QTabBar::tab {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 8px 16px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 4px;
}

QTabBar::tab:selected {
    background-color: #1e293b;
    color: #f8fafc;
    font-weight: 600;
}

QCheckBox, QRadioButton {
    spacing: 8px;
    color: #e2e8f0;
}

QScrollBar:vertical {
    background: #0b1120;
    width: 8px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #334155;
    border-radius: 4px;
    min-height: 24px;
}
"""


def create_dark_palette() -> QPalette:
    """Create a dark slate QPalette so native widgets never flash Windows light-mode chrome."""
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#0b1120"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#e2e8f0"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#0f172a"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#111c33"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#0f172a"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#f1f5f9"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#e2e8f0"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#1e293b"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#e2e8f0"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#2563eb"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#64748b"))
    return palette


def format_bytes(num_bytes: int) -> str:
    value = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return "0 B"


def format_speed(bps: int) -> str:
    return f"{format_bytes(bps)}/s"


_ICON_COLORS: dict[str, tuple[str, str]] = {
    "connected": ("#10b981", "#a7f3d0"),
    "connecting": ("#d97706", "#fde68a"),
    "stopping_others": ("#d97706", "#fde68a"),
    "error": ("#dc2626", "#fca5a5"),
    "disconnected": ("#64748b", "#cbd5e1"),
}


def create_app_pixmap(
    connected: bool = False,
    size: int = 64,
    state: str | None = None,
) -> QPixmap:
    """Render a crisp vector shield icon colored by VPN connection state."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    s = float(size)
    shield = QPainterPath()
    shield.moveTo(s * 0.50, s * 0.08)
    shield.lineTo(s * 0.86, s * 0.22)
    shield.quadTo(s * 0.86, s * 0.64, s * 0.50, s * 0.92)
    shield.quadTo(s * 0.14, s * 0.64, s * 0.14, s * 0.22)
    shield.closeSubpath()

    resolved_state = state if state is not None else ("connected" if connected else "disconnected")
    fill_hex, stroke_hex = _ICON_COLORS.get(resolved_state, _ICON_COLORS["disconnected"])
    fill_color = QColor(fill_hex)
    stroke_color = QColor(stroke_hex)

    painter.setBrush(QBrush(fill_color))
    painter.setPen(QPen(stroke_color, max(1.5, s * 0.05)))
    painter.drawPath(shield)

    # Inner split-tunnel fork symbol
    painter.setPen(
        QPen(QColor("#ffffff"), max(2.0, s * 0.08), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
    )
    painter.drawLine(QPointF(s * 0.50, s * 0.72), QPointF(s * 0.50, s * 0.48))
    painter.drawLine(QPointF(s * 0.50, s * 0.48), QPointF(s * 0.34, s * 0.33))
    painter.drawLine(QPointF(s * 0.50, s * 0.48), QPointF(s * 0.66, s * 0.33))

    painter.setBrush(QBrush(QColor("#ffffff")))
    painter.setPen(Qt.PenStyle.NoPen)
    r = s * 0.06
    painter.drawEllipse(QPointF(s * 0.34, s * 0.33), r, r)
    painter.drawEllipse(QPointF(s * 0.66, s * 0.33), r, r)

    painter.end()
    return pixmap


def create_app_icon(connected: bool = False, state: str | None = None) -> QIcon:
    icon = QIcon()
    for sz in (16, 24, 32, 48, 64):
        icon.addPixmap(create_app_pixmap(connected=connected, size=sz, state=state))
    return icon
