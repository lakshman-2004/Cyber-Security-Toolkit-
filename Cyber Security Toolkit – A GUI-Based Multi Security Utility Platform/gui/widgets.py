"""
Shared reusable widgets for all GUI pages.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QTextEdit, QProgressBar, QSizePolicy,
    QScrollArea,
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QCursor

# -- Colour palette (mirrors main.py) -----------------------------------------
DARK_BG      = "#0d1117"
SIDEBAR_BG   = "#161b22"
CARD_BG      = "#1c2128"
ACCENT       = "#58a6ff"
ACCENT_HOVER = "#1f6feb"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
BORDER       = "#30363d"
SUCCESS      = "#2ecc71"
WARNING      = "#f1c40f"
DANGER       = "#e74c3c"
INPUT_BG     = "#0d1117"


# =============================================================================
#  Page base - scrollable content area with a header
# =============================================================================
class BasePage(QWidget):
    """
    Every tool page inherits from this.
    Provides:
      * A styled page header (icon + title + subtitle)
      * A scrollable content area  (self.content_layout)
    """

    def __init__(self, icon: str, title: str, subtitle: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background: {DARK_BG};")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # -- Header ------------------------------------------------------------
        header = QFrame()
        header.setFixedHeight(80)
        header.setStyleSheet(f"""
            QFrame {{
                background: {SIDEBAR_BG};
                border-bottom: 1px solid {BORDER};
            }}
        """)
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(28, 0, 28, 0)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"font-size: 28px; background: transparent;")
        h_layout.addWidget(icon_lbl)

        h_layout.addSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        t_lbl = QLabel(title)
        t_lbl.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {TEXT_PRIMARY}; background: transparent;")
        s_lbl = QLabel(subtitle)
        s_lbl.setStyleSheet(f"font-size: 12px; color: {TEXT_MUTED}; background: transparent;")
        title_col.addWidget(t_lbl)
        title_col.addWidget(s_lbl)
        h_layout.addLayout(title_col)
        h_layout.addStretch()

        outer.addWidget(header)

        # -- Scrollable body ---------------------------------------------------
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(f"background: {DARK_BG}; border: none;")

        body = QWidget()
        body.setStyleSheet(f"background: {DARK_BG};")
        self.content_layout = QVBoxLayout(body)
        self.content_layout.setContentsMargins(28, 24, 28, 24)
        self.content_layout.setSpacing(20)

        scroll.setWidget(body)
        outer.addWidget(scroll, 1)


# =============================================================================
#  Card widget
# =============================================================================
class Card(QFrame):
    """A rounded dark card container."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background: {CARD_BG};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}
        """)
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(20, 16, 20, 16)
        self.layout_.setSpacing(12)

    def add(self, widget):
        self.layout_.addWidget(widget)
        return widget

    def add_layout(self, layout):
        self.layout_.addLayout(layout)
        return layout


# =============================================================================
#  Section label
# =============================================================================
def section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"""
        color: {TEXT_MUTED};
        font-size: 11px;
        font-weight: bold;
        letter-spacing: 1px;
        text-transform: uppercase;
        background: transparent;
    """)
    return lbl


# =============================================================================
#  Styled input
# =============================================================================
def styled_input(placeholder: str = "", password: bool = False) -> QLineEdit:
    inp = QLineEdit()
    inp.setPlaceholderText(placeholder)
    if password:
        inp.setEchoMode(QLineEdit.Password)
    inp.setFixedHeight(40)
    inp.setStyleSheet(f"""
        QLineEdit {{
            background: {INPUT_BG};
            color: {TEXT_PRIMARY};
            border: 1px solid {BORDER};
            border-radius: 6px;
            padding: 0 12px;
            font-size: 14px;
        }}
        QLineEdit:focus {{
            border: 1px solid {ACCENT};
        }}
        QLineEdit::placeholder {{
            color: {TEXT_MUTED};
        }}
    """)
    return inp


# =============================================================================
#  Primary action button
# =============================================================================
def primary_button(text: str, icon: str = "") -> QPushButton:
    btn = QPushButton(f"{icon}  {text}" if icon else text)
    btn.setFixedHeight(42)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setStyleSheet(f"""
        QPushButton {{
            background: {ACCENT};
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 0 24px;
            font-size: 14px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background: {ACCENT_HOVER};
        }}
        QPushButton:pressed {{
            background: #1158c7;
        }}
        QPushButton:disabled {{
            background: #21262d;
            color: {TEXT_MUTED};
        }}
    """)
    return btn


# =============================================================================
#  Danger / stop button
# =============================================================================
def danger_button(text: str, icon: str = "") -> QPushButton:
    btn = QPushButton(f"{icon}  {text}" if icon else text)
    btn.setFixedHeight(42)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setStyleSheet(f"""
        QPushButton {{
            background: {DANGER};
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 0 24px;
            font-size: 14px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background: #c0392b;
        }}
        QPushButton:pressed {{
            background: #a93226;
        }}
        QPushButton:disabled {{
            background: #21262d;
            color: {TEXT_MUTED};
        }}
    """)
    return btn


# =============================================================================
#  Results text area
# =============================================================================
def results_area(min_height: int = 200) -> QTextEdit:
    ta = QTextEdit()
    ta.setReadOnly(True)
    ta.setMinimumHeight(min_height)
    ta.setStyleSheet(f"""
        QTextEdit {{
            background: {INPUT_BG};
            color: {TEXT_PRIMARY};
            border: 1px solid {BORDER};
            border-radius: 6px;
            padding: 10px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
        }}
    """)
    return ta


# =============================================================================
#  Styled progress bar
# =============================================================================
def styled_progress(color: str = ACCENT) -> QProgressBar:
    pb = QProgressBar()
    pb.setFixedHeight(8)
    pb.setTextVisible(False)
    pb.setStyleSheet(f"""
        QProgressBar {{
            background: {BORDER};
            border-radius: 4px;
            border: none;
        }}
        QProgressBar::chunk {{
            background: {color};
            border-radius: 4px;
        }}
    """)
    return pb


# =============================================================================
#  Badge / pill label
# =============================================================================
def badge(text: str, color: str = ACCENT) -> QLabel:
    lbl = QLabel(text)
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setStyleSheet(f"""
        background: {color}22;
        color: {color};
        border: 1px solid {color}55;
        border-radius: 10px;
        padding: 2px 10px;
        font-size: 12px;
        font-weight: bold;
    """)
    return lbl


# =============================================================================
#  Horizontal divider
# =============================================================================
def h_divider() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: {BORDER}; border: none;")
    return line


# =============================================================================
#  Info row  (label : value)
# =============================================================================
def info_row(label: str, value: str, value_color: str = TEXT_PRIMARY) -> QWidget:
    row = QWidget()
    row.setStyleSheet("background: transparent;")
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)

    lbl = QLabel(label)
    lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 13px; background: transparent;")
    lbl.setFixedWidth(160)

    val = QLabel(value)
    val.setStyleSheet(f"color: {value_color}; font-size: 13px; font-weight: bold; background: transparent;")
    val.setWordWrap(True)
    val.setTextInteractionFlags(Qt.TextSelectableByMouse)

    layout.addWidget(lbl)
    layout.addWidget(val, 1)
    return row
