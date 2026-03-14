"""
GUI Page – Port Scanner
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QSizePolicy,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from gui.widgets import (
    BasePage, Card, section_label, styled_input,
    primary_button, danger_button, styled_progress,
    h_divider, ACCENT, SUCCESS, DANGER, WARNING,
    TEXT_PRIMARY, TEXT_MUTED, CARD_BG, BORDER, INPUT_BG,
)
from modules.port_scanner import PortScannerThread


class PortScannerPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(
            icon="🔍",
            title="Port Scanner",
            subtitle="Scan a target host to detect open ports and running services",
            parent=parent,
        )
        self._thread = None
        self._open_count = 0
        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        cl = self.content_layout

        # ── Input card ────────────────────────────────────────────────────────
        input_card = Card()
        input_card.add(section_label("SCAN TARGET"))

        # Target IP row
        row1 = QHBoxLayout()
        row1.setSpacing(12)
        self.ip_input = styled_input("e.g.  192.168.1.1  or  scanme.nmap.org")
        self.ip_input.returnPressed.connect(self._start_scan)
        row1.addWidget(QLabel("Target Host", styleSheet=f"color:{TEXT_MUTED}; font-size:13px; background:transparent;"))
        row1.addWidget(self.ip_input, 1)
        input_card.add_layout(row1)

        # Port range row
        row2 = QHBoxLayout()
        row2.setSpacing(12)
        self.start_port = styled_input("1")
        self.start_port.setFixedWidth(120)
        self.end_port   = styled_input("1024")
        self.end_port.setFixedWidth(120)
        lbl_range = QLabel("Port Range", styleSheet=f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        lbl_range.setFixedWidth(90)
        lbl_to    = QLabel("to", styleSheet=f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        row2.addWidget(lbl_range)
        row2.addWidget(self.start_port)
        row2.addWidget(lbl_to)
        row2.addWidget(self.end_port)
        row2.addStretch()
        input_card.add_layout(row2)

        # Buttons row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.scan_btn = primary_button("Start Scan", "🔍")
        self.scan_btn.setFixedWidth(160)
        self.scan_btn.clicked.connect(self._start_scan)

        self.stop_btn = danger_button("Stop", "⏹")
        self.stop_btn.setFixedWidth(120)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)

        self.clear_btn = primary_button("Clear", "🗑")
        self.clear_btn.setFixedWidth(120)
        self.clear_btn.setStyleSheet(self.clear_btn.styleSheet().replace(ACCENT, "#21262d").replace("#1f6feb", "#30363d"))
        self.clear_btn.clicked.connect(self._clear)

        btn_row.addWidget(self.scan_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch()
        input_card.add_layout(btn_row)

        cl.addWidget(input_card)

        # ── Progress card ─────────────────────────────────────────────────────
        prog_card = Card()
        prog_row = QHBoxLayout()
        prog_row.setSpacing(12)
        self.status_lbl = QLabel("Ready to scan")
        self.status_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        self.open_count_lbl = QLabel("Open ports: 0")
        self.open_count_lbl.setStyleSheet(f"color:{SUCCESS}; font-size:13px; font-weight:bold; background:transparent;")
        prog_row.addWidget(self.status_lbl, 1)
        prog_row.addWidget(self.open_count_lbl)
        prog_card.add_layout(prog_row)

        self.progress_bar = styled_progress(ACCENT)
        self.progress_bar.setValue(0)
        prog_card.add(self.progress_bar)
        cl.addWidget(prog_card)

        # ── Results table ─────────────────────────────────────────────────────
        results_card = Card()
        results_card.add(section_label("SCAN RESULTS"))

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Port", "Status", "Service"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 100)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(300)
        self.table.setStyleSheet(f"""
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
                letter-spacing: 1px;
            }}
            QTableWidget::item:alternate {{
                background: #161b22;
            }}
        """)
        results_card.add(self.table)
        cl.addWidget(results_card)
        cl.addStretch()

    # ── Scan logic ────────────────────────────────────────────────────────────
    def _start_scan(self):
        target = self.ip_input.text().strip()
        if not target:
            self.status_lbl.setText("⚠  Please enter a target host.")
            self.status_lbl.setStyleSheet(f"color:{WARNING}; font-size:13px; background:transparent;")
            return

        try:
            sp = int(self.start_port.text().strip() or "1")
            ep = int(self.end_port.text().strip() or "1024")
        except ValueError:
            self.status_lbl.setText("⚠  Port range must be integers.")
            self.status_lbl.setStyleSheet(f"color:{WARNING}; font-size:13px; background:transparent;")
            return

        if sp < 1 or ep > 65535 or sp > ep:
            self.status_lbl.setText("⚠  Invalid port range (1–65535, start ≤ end).")
            self.status_lbl.setStyleSheet(f"color:{WARNING}; font-size:13px; background:transparent;")
            return

        # Reset UI
        self.table.setRowCount(0)
        self._open_count = 0
        self.open_count_lbl.setText("Open ports: 0")
        self.progress_bar.setValue(0)
        self.status_lbl.setText(f"Scanning {target}  ({sp}–{ep})…")
        self.status_lbl.setStyleSheet(f"color:{ACCENT}; font-size:13px; background:transparent;")
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self._thread = PortScannerThread(target, sp, ep)
        self._thread.result_signal.connect(self._on_result)
        self._thread.progress_signal.connect(self.progress_bar.setValue)
        self._thread.finished_signal.connect(self._on_finished)
        self._thread.error_signal.connect(self._on_error)
        self._thread.start()

    def _stop_scan(self):
        if self._thread:
            self._thread.stop()
        self.stop_btn.setEnabled(False)

    def _clear(self):
        self.table.setRowCount(0)
        self._open_count = 0
        self.open_count_lbl.setText("Open ports: 0")
        self.progress_bar.setValue(0)
        self.status_lbl.setText("Ready to scan")
        self.status_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")

    # ── Thread callbacks ──────────────────────────────────────────────────────
    def _on_result(self, port: int, status: str, service: str):
        row = self.table.rowCount()
        self.table.insertRow(row)

        port_item    = QTableWidgetItem(str(port))
        status_item  = QTableWidgetItem(status)
        service_item = QTableWidgetItem(service)

        port_item.setTextAlignment(Qt.AlignCenter)
        status_item.setTextAlignment(Qt.AlignCenter)

        status_item.setForeground(QColor(SUCCESS))

        self.table.setItem(row, 0, port_item)
        self.table.setItem(row, 1, status_item)
        self.table.setItem(row, 2, service_item)
        self.table.scrollToBottom()

        self._open_count += 1
        self.open_count_lbl.setText(f"Open ports: {self._open_count}")

    def _on_finished(self, summary: str):
        self.status_lbl.setText(f"✅  {summary}")
        self.status_lbl.setStyleSheet(f"color:{SUCCESS}; font-size:13px; background:transparent;")
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)

    def _on_error(self, msg: str):
        self.status_lbl.setText(f"❌  {msg}")
        self.status_lbl.setStyleSheet(f"color:{DANGER}; font-size:13px; background:transparent;")
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
