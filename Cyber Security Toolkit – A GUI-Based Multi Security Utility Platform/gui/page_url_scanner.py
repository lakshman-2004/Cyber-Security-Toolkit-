"""
GUI Page - URL Security Scanner
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QSizePolicy, QApplication,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from gui.widgets import (
    BasePage, Card, section_label, styled_input,
    primary_button, results_area, h_divider, badge,
    styled_progress,
    ACCENT, SUCCESS, DANGER, WARNING, TEXT_PRIMARY, TEXT_MUTED,
    CARD_BG, BORDER,
)
from modules.url_scanner import scan_url


# -- Worker thread so the GUI stays responsive ---------------------------------
class URLScanThread(QThread):
    done = pyqtSignal(dict)

    def __init__(self, url: str):
        super().__init__()
        self.url = url

    def run(self):
        result = scan_url(self.url)
        self.done.emit(result)


class URLScannerPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(
            icon="URL",
            title="URL Security Scanner",
            subtitle="Detect phishing, suspicious domains, and unsafe URLs",
            parent=parent,
        )
        self._thread = None
        self._build_ui()

    # -- UI construction -------------------------------------------------------
    def _build_ui(self):
        cl = self.content_layout

        # -- Input card --------------------------------------------------------
        input_card = Card()
        input_card.add(section_label("ENTER URL"))

        url_row = QHBoxLayout()
        url_row.setSpacing(10)
        self.url_input = styled_input("e.g.  https://example.com  or  http://login-paypal.xyz")
        self.url_input.returnPressed.connect(self._scan)
        self.scan_btn = primary_button("Scan URL")
        self.scan_btn.setFixedWidth(150)
        self.scan_btn.clicked.connect(self._scan)
        url_row.addWidget(self.url_input, 1)
        url_row.addWidget(self.scan_btn)
        input_card.add_layout(url_row)
        cl.addWidget(input_card)

        # -- Risk level card ---------------------------------------------------
        risk_card = Card()
        risk_row = QHBoxLayout()
        risk_row.setSpacing(16)

        self.risk_icon_lbl = QLabel("URL")
        self.risk_icon_lbl.setStyleSheet("font-size:40px; background:transparent;")

        risk_text_col = QVBoxLayout()
        risk_text_col.setSpacing(4)
        self.risk_level_lbl = QLabel("-")
        self.risk_level_lbl.setStyleSheet(
            f"font-size:26px; font-weight:bold; color:{TEXT_MUTED}; background:transparent;"
        )
        self.risk_score_lbl = QLabel("Risk Score: -")
        self.risk_score_lbl.setStyleSheet(f"font-size:13px; color:{TEXT_MUTED}; background:transparent;")
        risk_text_col.addWidget(self.risk_level_lbl)
        risk_text_col.addWidget(self.risk_score_lbl)

        risk_row.addWidget(self.risk_icon_lbl)
        risk_row.addLayout(risk_text_col)
        risk_row.addStretch()
        risk_card.add_layout(risk_row)

        self.risk_bar = styled_progress(ACCENT)
        self.risk_bar.setFixedHeight(12)
        self.risk_bar.setMaximum(100)
        self.risk_bar.setValue(0)
        risk_card.add(self.risk_bar)
        cl.addWidget(risk_card)

        # -- Details card ------------------------------------------------------
        details_card = Card()
        details_card.add(section_label("URL DETAILS"))

        self.domain_lbl  = self._detail_row(details_card, "Domain")
        self.scheme_lbl  = self._detail_row(details_card, "Scheme")
        self.ip_lbl      = self._detail_row(details_card, "Resolved IP")
        self.redir_lbl   = self._detail_row(details_card, "Redirects To")
        cl.addWidget(details_card)

        # -- Findings card -----------------------------------------------------
        findings_card = Card()
        findings_card.add(section_label("FINDINGS & REASONS"))
        self.findings_area = results_area(120)
        findings_card.add(self.findings_area)
        cl.addWidget(findings_card)

        # -- Suggestions card --------------------------------------------------
        sugg_card = Card()
        sugg_card.add(section_label("RECOMMENDATIONS"))
        self.sugg_area = results_area(80)
        sugg_card.add(self.sugg_area)
        cl.addWidget(sugg_card)
        cl.addStretch()

    # -- Helpers ---------------------------------------------------------------
    def _detail_row(self, card: Card, label: str) -> QLabel:
        row = QHBoxLayout()
        row.setSpacing(8)
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        lbl.setFixedWidth(130)
        val = QLabel("-")
        val.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:13px; font-weight:bold; background:transparent;")
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        val.setWordWrap(True)
        row.addWidget(lbl)
        row.addWidget(val, 1)
        card.add_layout(row)
        return val

    # -- Logic -----------------------------------------------------------------
    def _scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.findings_area.setPlainText("!  Please enter a URL.")
            return

        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")
        self.findings_area.setPlainText("Scanning URL, please wait...")
        self.sugg_area.setPlainText("")

        self._thread = URLScanThread(url)
        self._thread.done.connect(self._on_result)
        self._thread.start()

    def _on_result(self, result: dict):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan URL")

        if not result["success"]:
            self.findings_area.setPlainText(f"X  Error: {result['error']}")
            return

        color = result["risk_color"]
        level = result["risk_level"]
        score = result["risk_score"]

        # Risk level display
        icons = {"LOW": "LOW", "MEDIUM": "MED", "HIGH": "HIGH", "CRITICAL": "CRIT"}
        self.risk_icon_lbl.setText(icons.get(level, "URL"))
        self.risk_level_lbl.setText(f"Risk Level: {level}")
        self.risk_level_lbl.setStyleSheet(
            f"font-size:26px; font-weight:bold; color:{color}; background:transparent;"
        )
        self.risk_score_lbl.setText(f"Risk Score: {score}/100")
        self.risk_score_lbl.setStyleSheet(f"font-size:13px; color:{color}; background:transparent;")

        # Progress bar
        self.risk_bar.setStyleSheet(f"""
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
        self.risk_bar.setValue(score)

        # Details
        self.domain_lbl.setText(result["domain"] or "-")
        self.scheme_lbl.setText(result["scheme"].upper())
        self.ip_lbl.setText(result["ip_address"] or "Could not resolve")
        self.redir_lbl.setText(result["redirected_to"] or "None detected")

        # Findings
        reasons = result["reasons"]
        if reasons:
            self.findings_area.setPlainText("\n".join(f"  *  {r}" for r in reasons))
        else:
            self.findings_area.setPlainText("  OK  No threats detected.")

        # Suggestions
        suggestions = result["suggestions"]
        if suggestions:
            self.sugg_area.setPlainText("\n".join(f"  TIP  {s}" for s in suggestions))
        else:
            self.sugg_area.setPlainText("  OK  URL appears safe.")
