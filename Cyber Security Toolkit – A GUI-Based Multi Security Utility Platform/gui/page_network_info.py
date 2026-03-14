"""
GUI Page - Network Information Tool
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QApplication, QSizePolicy,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from gui.widgets import (
    BasePage, Card, section_label, primary_button,
    h_divider, info_row,
    ACCENT, SUCCESS, DANGER, WARNING, TEXT_PRIMARY, TEXT_MUTED,
    CARD_BG, BORDER, INPUT_BG,
)
from modules.network_info import get_network_info


# -- Worker thread -------------------------------------------------------------
class NetworkInfoThread(QThread):
    done = pyqtSignal(dict)

    def run(self):
        self.done.emit(get_network_info())


class NetworkInfoPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(
            icon="NET",
            title="Network Information",
            subtitle="Display system network details: IP, MAC, interfaces, DNS, gateway",
            parent=parent,
        )
        self._thread = None
        self._build_ui()
        # Auto-load on open
        self._refresh()

    # -- UI construction -------------------------------------------------------
    def _build_ui(self):
        cl = self.content_layout

        # Refresh button row
        btn_row = QHBoxLayout()
        self.refresh_btn = primary_button("Refresh")
        self.refresh_btn.setFixedWidth(140)
        self.refresh_btn.clicked.connect(self._refresh)
        self.copy_btn = primary_button("Copy All")
        self.copy_btn.setFixedWidth(130)
        self.copy_btn.setStyleSheet(
            self.copy_btn.styleSheet()
            .replace(ACCENT, "#21262d")
            .replace("#1f6feb", "#30363d")
        )
        self.copy_btn.clicked.connect(self._copy_all)
        self.status_lbl = QLabel("Loading...")
        self.status_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        btn_row.addWidget(self.refresh_btn)
        btn_row.addWidget(self.copy_btn)
        btn_row.addSpacing(12)
        btn_row.addWidget(self.status_lbl)
        btn_row.addStretch()
        cl.addLayout(btn_row)

        # -- Primary info card -------------------------------------------------
        primary_card = Card()
        primary_card.add(section_label("SYSTEM NETWORK INFO"))

        self._rows = {}
        fields = [
            ("hostname",        "Hostname"),
            ("local_ip",        "Local IP Address"),
            ("public_ip",       "Public IP Address"),
            ("mac_address",     "MAC Address"),
            ("default_gateway", "Default Gateway"),
            ("os_info",         "Operating System"),
        ]
        for key, label in fields:
            row_w = info_row(label, "-")
            # Keep reference to the value label (second child)
            val_lbl = row_w.layout().itemAt(1).widget()
            self._rows[key] = val_lbl
            primary_card.add(row_w)

        cl.addWidget(primary_card)

        # -- DNS servers card --------------------------------------------------
        dns_card = Card()
        dns_card.add(section_label("DNS SERVERS"))
        self.dns_lbl = QLabel("-")
        self.dns_lbl.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:13px; background:transparent;")
        self.dns_lbl.setWordWrap(True)
        dns_card.add(self.dns_lbl)
        cl.addWidget(dns_card)

        # -- Interfaces table card ---------------------------------------------
        iface_card = Card()
        iface_card.add(section_label("NETWORK INTERFACES"))

        self.iface_table = QTableWidget(0, 3)
        self.iface_table.setHorizontalHeaderLabels(["Interface", "IP Address", "MAC Address"])
        self.iface_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.iface_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.iface_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.iface_table.verticalHeader().setVisible(False)
        self.iface_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.iface_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.iface_table.setAlternatingRowColors(True)
        self.iface_table.setMinimumHeight(160)
        self.iface_table.setStyleSheet(f"""
            QTableWidget {{
                background: {INPUT_BG};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER};
                border-radius: 6px;
                gridline-color: {BORDER};
                font-size: 13px;
            }}
            QTableWidget::item {{
                padding: 6px 10px;
            }}
            QTableWidget::item:selected {{
                background: {ACCENT}33;
                color: {TEXT_PRIMARY};
            }}
            QHeaderView::section {{
                background: {CARD_BG};
                color: {TEXT_MUTED};
                border: none;
                border-bottom: 1px solid {BORDER};
                padding: 6px 10px;
                font-size: 12px;
                font-weight: bold;
            }}
            QTableWidget::item:alternate {{
                background: #161b22;
            }}
        """)
        iface_card.add(self.iface_table)
        cl.addWidget(iface_card)
        cl.addStretch()

    # -- Logic -----------------------------------------------------------------
    def _refresh(self):
        self.refresh_btn.setEnabled(False)
        self.status_lbl.setText("Gathering network information...")
        self.status_lbl.setStyleSheet(f"color:{ACCENT}; font-size:13px; background:transparent;")

        self._thread = NetworkInfoThread()
        self._thread.done.connect(self._on_result)
        self._thread.start()

    def _on_result(self, info: dict):
        self.refresh_btn.setEnabled(True)
        self.status_lbl.setText("OK  Information updated")
        self.status_lbl.setStyleSheet(f"color:{SUCCESS}; font-size:13px; background:transparent;")

        # Primary fields
        for key, lbl in self._rows.items():
            val = info.get(key, "-") or "-"
            lbl.setText(str(val))

        # DNS
        dns = info.get("dns_servers", ["-"])
        self.dns_lbl.setText("  *  " + "\n  *  ".join(dns))

        # Interfaces table
        interfaces = info.get("interfaces", [])
        self.iface_table.setRowCount(0)
        for iface in interfaces:
            row = self.iface_table.rowCount()
            self.iface_table.insertRow(row)
            self.iface_table.setItem(row, 0, QTableWidgetItem(iface.get("name", "-")))
            self.iface_table.setItem(row, 1, QTableWidgetItem(iface.get("ip",   "-")))
            self.iface_table.setItem(row, 2, QTableWidgetItem(iface.get("mac",  "-")))

    def _copy_all(self):
        lines = []
        for key, lbl in self._rows.items():
            lines.append(f"{key}: {lbl.text()}")
        lines.append(f"DNS: {self.dns_lbl.text()}")
        QApplication.clipboard().setText("\n".join(lines))
