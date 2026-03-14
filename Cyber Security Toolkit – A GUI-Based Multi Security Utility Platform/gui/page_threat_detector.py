"""
GUI Page - AI Threat Detection Dashboard (Bonus)
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QSizePolicy, QApplication,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor

from gui.widgets import (
    BasePage, Card, section_label, styled_input,
    primary_button, styled_progress, results_area,
    h_divider, badge,
    ACCENT, SUCCESS, DANGER, WARNING, TEXT_PRIMARY, TEXT_MUTED,
    CARD_BG, BORDER, INPUT_BG,
)
from modules.threat_detector import analyse_threats, THREAT_LEVELS


# -- Worker thread -------------------------------------------------------------
class ThreatThread(QThread):
    done = pyqtSignal(dict)

    def __init__(self, open_ports, password, url):
        super().__init__()
        self.open_ports = open_ports
        self.password   = password
        self.url        = url

    def run(self):
        result = analyse_threats(
            open_ports=self.open_ports or None,
            password=self.password or None,
            url=self.url or None,
        )
        self.done.emit(result)


# -- Severity colour map -------------------------------------------------------
_SEV_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#2ecc71",
    "NONE":     "#8b949e",
}


class ThreatDetectorPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(
            icon="AI",
            title="AI Threat Detector",
            subtitle="Aggregate findings from all modules into a unified threat assessment",
            parent=parent,
        )
        self._thread = None
        self._build_ui()

    # -- UI construction -------------------------------------------------------
    def _build_ui(self):
        cl = self.content_layout

        # -- Inputs card -------------------------------------------------------
        inputs_card = Card()
        inputs_card.add(section_label("INPUTS  (leave blank to skip)"))

        # Open ports
        ports_row = QHBoxLayout()
        ports_row.setSpacing(10)
        ports_lbl = QLabel("Open Ports")
        ports_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        ports_lbl.setFixedWidth(120)
        self.ports_input = styled_input("e.g.  21, 22, 80, 443, 3389")
        ports_row.addWidget(ports_lbl)
        ports_row.addWidget(self.ports_input, 1)
        inputs_card.add_layout(ports_row)

        # Password
        pw_row = QHBoxLayout()
        pw_row.setSpacing(10)
        pw_lbl = QLabel("Password")
        pw_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        pw_lbl.setFixedWidth(120)
        self.pw_input = styled_input("Enter a password to evaluate...", password=True)
        pw_row.addWidget(pw_lbl)
        pw_row.addWidget(self.pw_input, 1)
        inputs_card.add_layout(pw_row)

        # URL
        url_row = QHBoxLayout()
        url_row.setSpacing(10)
        url_lbl = QLabel("URL")
        url_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        url_lbl.setFixedWidth(120)
        self.url_input = styled_input("Enter a URL to evaluate...")
        url_row.addWidget(url_lbl)
        url_row.addWidget(self.url_input, 1)
        inputs_card.add_layout(url_row)

        # Analyse button
        btn_row = QHBoxLayout()
        self.analyse_btn = primary_button("Analyse Threats")
        self.analyse_btn.setFixedWidth(200)
        self.analyse_btn.clicked.connect(self._analyse)
        btn_row.addWidget(self.analyse_btn)
        btn_row.addStretch()
        inputs_card.add_layout(btn_row)
        cl.addWidget(inputs_card)

        # -- Threat level card -------------------------------------------------
        level_card = Card()
        level_row = QHBoxLayout()
        level_row.setSpacing(16)

        self.threat_icon_lbl = QLabel("AI")
        self.threat_icon_lbl.setStyleSheet("font-size:44px; background:transparent;")

        level_text = QVBoxLayout()
        level_text.setSpacing(4)
        self.threat_level_lbl = QLabel("-")
        self.threat_level_lbl.setStyleSheet(
            f"font-size:28px; font-weight:bold; color:{TEXT_MUTED}; background:transparent;"
        )
        self.threat_score_lbl = QLabel("Threat Score: -")
        self.threat_score_lbl.setStyleSheet(f"font-size:13px; color:{TEXT_MUTED}; background:transparent;")
        level_text.addWidget(self.threat_level_lbl)
        level_text.addWidget(self.threat_score_lbl)

        level_row.addWidget(self.threat_icon_lbl)
        level_row.addLayout(level_text)
        level_row.addStretch()
        level_card.add_layout(level_row)

        self.threat_bar = styled_progress(ACCENT)
        self.threat_bar.setFixedHeight(14)
        self.threat_bar.setMaximum(100)
        self.threat_bar.setValue(0)
        level_card.add(self.threat_bar)

        self.summary_lbl = QLabel("Run an analysis to see the threat summary.")
        self.summary_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        self.summary_lbl.setWordWrap(True)
        level_card.add(self.summary_lbl)
        cl.addWidget(level_card)

        # -- Findings table card -----------------------------------------------
        findings_card = Card()
        findings_card.add(section_label("DETAILED FINDINGS"))

        self.findings_table = QTableWidget(0, 4)
        self.findings_table.setHorizontalHeaderLabels(
            ["Category", "Severity", "Finding", "Recommendation"]
        )
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.findings_table.setWordWrap(True)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setMinimumHeight(260)
        self.findings_table.setStyleSheet(f"""
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
        findings_card.add(self.findings_table)
        cl.addWidget(findings_card)
        cl.addStretch()

    # -- Logic -----------------------------------------------------------------
    def _analyse(self):
        # Parse ports
        ports_text = self.ports_input.text().strip()
        open_ports = []
        if ports_text:
            for part in ports_text.replace(" ", "").split(","):
                try:
                    open_ports.append(int(part))
                except ValueError:
                    pass

        password = self.pw_input.text().strip()
        url      = self.url_input.text().strip()

        self.analyse_btn.setEnabled(False)
        self.analyse_btn.setText("Analysing...")
        self.summary_lbl.setText("Running threat analysis, please wait...")

        self._thread = ThreatThread(open_ports, password, url)
        self._thread.done.connect(self._on_result)
        self._thread.start()

    def _on_result(self, result: dict):
        self.analyse_btn.setEnabled(True)
        self.analyse_btn.setText("Analyse Threats")

        color = result["threat_color"]
        level = result["threat_level"]
        score = result["threat_score"]
        icon  = result["threat_icon"]

        # Threat level display
        self.threat_icon_lbl.setText(icon)
        level_info = THREAT_LEVELS[level]
        self.threat_level_lbl.setText(f"Threat Level: {level_info['label']}")
        self.threat_level_lbl.setStyleSheet(
            f"font-size:28px; font-weight:bold; color:{color}; background:transparent;"
        )
        self.threat_score_lbl.setText(f"Threat Score: {score}/100")
        self.threat_score_lbl.setStyleSheet(f"font-size:13px; color:{color}; background:transparent;")

        # Progress bar
        self.threat_bar.setStyleSheet(f"""
            QProgressBar {{
                background: #30363d;
                border-radius: 4px;
                border: none;
            }}
            QProgressBar::chunk {{
                background: {color};
                border-radius: 4px;
            }}
        """)
        self.threat_bar.setValue(score)

        # Summary
        self.summary_lbl.setText(result["summary"])
        self.summary_lbl.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:13px; background:transparent;")

        # Findings table
        findings = result["findings"]
        self.findings_table.setRowCount(0)
        if not findings:
            self.findings_table.insertRow(0)
            item = QTableWidgetItem("OK  No threats detected.")
            item.setForeground(QColor(SUCCESS))
            self.findings_table.setItem(0, 0, item)
            self.findings_table.setSpan(0, 0, 1, 4)
        else:
            for f in findings:
                row = self.findings_table.rowCount()
                self.findings_table.insertRow(row)

                cat_item  = QTableWidgetItem(f["category"])
                sev_item  = QTableWidgetItem(f["severity"])
                msg_item  = QTableWidgetItem(f["message"])
                rec_item  = QTableWidgetItem(f["recommendation"])

                sev_color = _SEV_COLORS.get(f["severity"], TEXT_MUTED)
                sev_item.setForeground(QColor(sev_color))
                sev_item.setTextAlignment(Qt.AlignCenter)

                self.findings_table.setItem(row, 0, cat_item)
                self.findings_table.setItem(row, 1, sev_item)
                self.findings_table.setItem(row, 2, msg_item)
                self.findings_table.setItem(row, 3, rec_item)

            self.findings_table.resizeRowsToContents()
