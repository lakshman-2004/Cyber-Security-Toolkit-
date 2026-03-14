"""
Cyber Security Toolkit - A GUI-Based Multi Security Utility Platform
Main application entry point.
"""

import sys
import os

# -- Ensure the project root is on sys.path ------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QSizePolicy, QScrollArea,
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette

# -- Page imports --------------------------------------------------------------
from gui.page_port_scanner    import PortScannerPage
from gui.page_password        import PasswordCheckerPage
from gui.page_hash            import HashGeneratorPage
from gui.page_url_scanner     import URLScannerPage
from gui.page_network_info    import NetworkInfoPage
from gui.page_threat_detector import ThreatDetectorPage


# =============================================================================
#  Colour palette
# =============================================================================
DARK_BG      = "#0d1117"
SIDEBAR_BG   = "#161b22"
CARD_BG      = "#1c2128"
ACCENT       = "#58a6ff"
ACCENT_HOVER = "#79b8ff"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
BORDER       = "#30363d"
SUCCESS      = "#2ecc71"
WARNING      = "#f1c40f"
DANGER       = "#e74c3c"


# =============================================================================
#  Sidebar nav button
# =============================================================================
class NavButton(QPushButton):
    def __init__(self, icon_text: str, label: str, parent=None):
        super().__init__(parent)
        self.icon_text = icon_text
        self.label_text = label
        self._active = False
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(52)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._refresh_style()

    def set_active(self, active: bool):
        self._active = active
        self._refresh_style()

    def _refresh_style(self):
        if self._active:
            bg      = ACCENT
            fg      = "#ffffff"
            border  = "none"
            weight  = "bold"
        else:
            bg      = "transparent"
            fg      = TEXT_MUTED
            border  = "none"
            weight  = "normal"

        self.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {fg};
                border: {border};
                border-radius: 8px;
                padding: 0 16px;
                font-size: 14px;
                font-weight: {weight};
                text-align: left;
            }}
            QPushButton:hover {{
                background: {"#1f6feb" if self._active else "#21262d"};
                color: {TEXT_PRIMARY};
            }}
        """)
        self.setText(f"  {self.icon_text}   {self.label_text}")


# =============================================================================
#  Main Window
# =============================================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Security Toolkit")
        self.setMinimumSize(1100, 720)
        self.resize(1280, 800)
        self._apply_global_style()

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # -- Sidebar -----------------------------------------------------------
        self.sidebar = self._build_sidebar()
        root_layout.addWidget(self.sidebar)

        # -- Content area ------------------------------------------------------
        self.stack = QStackedWidget()
        self.stack.setStyleSheet(f"background: {DARK_BG};")
        root_layout.addWidget(self.stack, 1)

        # -- Pages -------------------------------------------------------------
        self.pages = [
            PortScannerPage(),
            PasswordCheckerPage(),
            HashGeneratorPage(),
            URLScannerPage(),
            NetworkInfoPage(),
            ThreatDetectorPage(),
        ]
        for page in self.pages:
            self.stack.addWidget(page)

        # Show first page
        self._switch_page(0)

    # -- Sidebar builder -------------------------------------------------------
    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet(f"""
            QFrame {{
                background: {SIDEBAR_BG};
                border-right: 1px solid {BORDER};
            }}
        """)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 20, 12, 20)
        layout.setSpacing(4)

        # Logo / title
        logo_label = QLabel("SEC  CyberSec Toolkit")
        logo_label.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 16px;
            font-weight: bold;
            padding: 8px 4px 20px 4px;
        """)
        logo_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(logo_label)

        # Divider
        layout.addWidget(self._divider())

        # Nav items: (icon, label)
        nav_items = [
            ("SCAN", "Port Scanner"),
            ("KEY", "Password Checker"),
            ("LOCK", "Hash Generator"),
            ("URL", "URL Scanner"),
            ("NET", "Network Info"),
            ("AI", "Threat Detector"),
        ]

        self.nav_buttons: list[NavButton] = []
        for idx, (icon, label) in enumerate(nav_items):
            btn = NavButton(icon, label)
            btn.clicked.connect(lambda checked, i=idx: self._switch_page(i))
            self.nav_buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        # Footer
        layout.addWidget(self._divider())
        footer = QLabel("v1.0  *  Educational Use Only")
        footer.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; padding: 8px 4px 0 4px;")
        footer.setAlignment(Qt.AlignCenter)
        layout.addWidget(footer)

        return sidebar

    # -- Page switcher ---------------------------------------------------------
    def _switch_page(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.set_active(i == index)

    # -- Helpers ---------------------------------------------------------------
    @staticmethod
    def _divider() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFixedHeight(1)
        line.setStyleSheet(f"background: {BORDER}; border: none; margin: 4px 0;")
        return line

    def _apply_global_style(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background: {DARK_BG};
                color: {TEXT_PRIMARY};
                font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif;
            }}
            QScrollBar:vertical {{
                background: {CARD_BG};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER};
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {TEXT_MUTED};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar:horizontal {{
                background: {CARD_BG};
                height: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:horizontal {{
                background: {BORDER};
                border-radius: 4px;
            }}
            QToolTip {{
                background: {CARD_BG};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER};
                padding: 4px 8px;
                border-radius: 4px;
            }}
        """)


# =============================================================================
#  Entry point
# =============================================================================
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Cyber Security Toolkit")
    app.setOrganizationName("CyberSecToolkit")

    # High-DPI support
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
