"""
GUI Page - Password Strength Checker
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QCheckBox, QSizePolicy,
)
from PyQt5.QtCore import Qt, QTimer

from gui.widgets import (
    BasePage, Card, section_label, styled_input,
    primary_button, styled_progress, h_divider, badge,
    ACCENT, SUCCESS, DANGER, WARNING, TEXT_PRIMARY, TEXT_MUTED,
    CARD_BG, BORDER,
)
from modules.password_checker import check_password_strength


class PasswordCheckerPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(
            icon="KEY",
            title="Password Strength Checker",
            subtitle="Analyse password complexity and get improvement suggestions",
            parent=parent,
        )
        self._build_ui()

    # -- UI construction -------------------------------------------------------
    def _build_ui(self):
        cl = self.content_layout

        # -- Input card --------------------------------------------------------
        input_card = Card()
        input_card.add(section_label("ENTER PASSWORD"))

        pw_row = QHBoxLayout()
        pw_row.setSpacing(10)
        self.pw_input = styled_input("Type a password to analyse...", password=True)
        self.pw_input.textChanged.connect(self._on_text_changed)

        self.show_cb = QCheckBox("Show")
        self.show_cb.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        self.show_cb.toggled.connect(
            lambda checked: self.pw_input.setEchoMode(
                self.pw_input.Normal if checked else self.pw_input.Password
            )
        )

        pw_row.addWidget(self.pw_input, 1)
        pw_row.addWidget(self.show_cb)
        input_card.add_layout(pw_row)

        self.check_btn = primary_button("Check Strength")
        self.check_btn.clicked.connect(self._analyse)
        input_card.add(self.check_btn)
        cl.addWidget(input_card)

        # -- Strength meter card -----------------------------------------------
        meter_card = Card()
        meter_card.add(section_label("STRENGTH METER"))

        # Level badge + score
        top_row = QHBoxLayout()
        self.level_lbl = QLabel("-")
        self.level_lbl.setStyleSheet(f"font-size:28px; font-weight:bold; color:{TEXT_MUTED}; background:transparent;")
        self.score_lbl = QLabel("Score: -")
        self.score_lbl.setStyleSheet(f"font-size:13px; color:{TEXT_MUTED}; background:transparent;")
        self.entropy_lbl = QLabel("Entropy: -")
        self.entropy_lbl.setStyleSheet(f"font-size:13px; color:{TEXT_MUTED}; background:transparent;")
        top_row.addWidget(self.level_lbl)
        top_row.addStretch()
        top_row.addWidget(self.score_lbl)
        top_row.addSpacing(16)
        top_row.addWidget(self.entropy_lbl)
        meter_card.add_layout(top_row)

        self.strength_bar = styled_progress(ACCENT)
        self.strength_bar.setFixedHeight(14)
        self.strength_bar.setMaximum(100)
        self.strength_bar.setValue(0)
        meter_card.add(self.strength_bar)
        cl.addWidget(meter_card)

        # -- Checks card -------------------------------------------------------
        checks_card = Card()
        checks_card.add(section_label("SECURITY CHECKS"))

        self.check_labels = {}
        check_defs = [
            ("length_8",      "At least 8 characters"),
            ("length_12",     "At least 12 characters"),
            ("length_16",     "At least 16 characters"),
            ("has_lowercase", "Contains lowercase letters"),
            ("has_uppercase", "Contains uppercase letters"),
            ("has_digit",     "Contains numbers"),
            ("has_special",   "Contains special characters"),
            ("no_repeat",     "No repeated characters (3+)"),
            ("no_common",     "Not a common password"),
        ]

        # Two-column grid
        grid_row = QHBoxLayout()
        grid_row.setSpacing(20)
        col1 = QVBoxLayout()
        col1.setSpacing(8)
        col2 = QVBoxLayout()
        col2.setSpacing(8)

        for i, (key, text) in enumerate(check_defs):
            lbl = QLabel(f"-  {text}")
            lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
            self.check_labels[key] = lbl
            if i < 5:
                col1.addWidget(lbl)
            else:
                col2.addWidget(lbl)

        col1.addStretch()
        col2.addStretch()
        grid_row.addLayout(col1)
        grid_row.addLayout(col2)
        checks_card.add_layout(grid_row)
        cl.addWidget(checks_card)

        # -- Suggestions card --------------------------------------------------
        sugg_card = Card()
        sugg_card.add(section_label("SUGGESTIONS"))
        self.suggestions_lbl = QLabel("Enter a password above to see suggestions.")
        self.suggestions_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        self.suggestions_lbl.setWordWrap(True)
        sugg_card.add(self.suggestions_lbl)
        cl.addWidget(sugg_card)
        cl.addStretch()

    # -- Logic -----------------------------------------------------------------
    def _on_text_changed(self, text: str):
        """Live analysis as user types."""
        if text:
            self._analyse()
        else:
            self._reset_ui()

    def _analyse(self):
        pw = self.pw_input.text()
        if not pw:
            return

        result = check_password_strength(pw)
        score  = result["score"]
        level  = result["level"]
        color  = result["color"]
        checks = result["checks"]
        suggestions = result["suggestions"]
        entropy = result["entropy"]

        # Level label
        self.level_lbl.setText(level)
        self.level_lbl.setStyleSheet(
            f"font-size:28px; font-weight:bold; color:{color}; background:transparent;"
        )

        # Score / entropy
        self.score_lbl.setText(f"Score: {score}/100")
        self.score_lbl.setStyleSheet(f"font-size:13px; color:{color}; background:transparent;")
        self.entropy_lbl.setText(f"Entropy: ~{entropy} bits")
        self.entropy_lbl.setStyleSheet(f"font-size:13px; color:{TEXT_MUTED}; background:transparent;")

        # Progress bar colour
        self.strength_bar.setStyleSheet(
            self.strength_bar.styleSheet().replace(
                "background: #58a6ff", f"background: {color}"
            )
        )
        # Rebuild chunk colour properly
        self.strength_bar.setStyleSheet(f"""
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
        self.strength_bar.setValue(score)

        # Check labels
        for key, lbl in self.check_labels.items():
            passed = checks.get(key, False)
            icon   = "OK" if passed else "X"
            text   = lbl.text().split("  ", 1)[1]
            clr    = SUCCESS if passed else DANGER
            lbl.setText(f"{icon}  {text}")
            lbl.setStyleSheet(f"color:{clr}; font-size:13px; background:transparent;")

        # Suggestions
        bullet_list = "\n".join(f"  *  {s}" for s in suggestions)
        self.suggestions_lbl.setText(bullet_list)
        self.suggestions_lbl.setStyleSheet(
            f"color:{TEXT_PRIMARY}; font-size:13px; background:transparent;"
        )

    def _reset_ui(self):
        self.level_lbl.setText("-")
        self.level_lbl.setStyleSheet(f"font-size:28px; font-weight:bold; color:{TEXT_MUTED}; background:transparent;")
        self.score_lbl.setText("Score: -")
        self.entropy_lbl.setText("Entropy: -")
        self.strength_bar.setValue(0)
        for lbl in self.check_labels.values():
            text = lbl.text().split("  ", 1)[1]
            lbl.setText(f"-  {text}")
            lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        self.suggestions_lbl.setText("Enter a password above to see suggestions.")
        self.suggestions_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
