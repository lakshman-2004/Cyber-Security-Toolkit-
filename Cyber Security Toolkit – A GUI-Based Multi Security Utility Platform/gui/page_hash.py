"""
GUI Page - Hash Generator
"""

import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QButtonGroup, QRadioButton, QFileDialog,
    QApplication, QSizePolicy, QTabWidget,
)
from PyQt5.QtCore import Qt

from gui.widgets import (
    BasePage, Card, section_label, styled_input,
    primary_button, results_area, h_divider, badge,
    ACCENT, SUCCESS, DANGER, WARNING, TEXT_PRIMARY, TEXT_MUTED,
    CARD_BG, BORDER, INPUT_BG,
)
from modules.hash_generator import (
    hash_text, hash_file, hash_text_all, hash_file_all,
    SUPPORTED_ALGORITHMS,
)


class HashGeneratorPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(
            icon="LOCK",
            title="Hash Generator",
            subtitle="Generate cryptographic hash values for text or files",
            parent=parent,
        )
        self._selected_file = None
        self._build_ui()

    # -- UI construction -------------------------------------------------------
    def _build_ui(self):
        cl = self.content_layout

        # -- Algorithm selector card -------------------------------------------
        alg_card = Card()
        alg_card.add(section_label("HASH ALGORITHM"))

        alg_row = QHBoxLayout()
        alg_row.setSpacing(16)
        self.alg_group = QButtonGroup(self)
        self._alg_radios = {}

        for alg in SUPPORTED_ALGORITHMS:
            rb = QRadioButton(alg)
            rb.setStyleSheet(f"""
                QRadioButton {{
                    color: {TEXT_PRIMARY};
                    font-size: 13px;
                    background: transparent;
                    spacing: 6px;
                }}
                QRadioButton::indicator {{
                    width: 16px;
                    height: 16px;
                    border-radius: 8px;
                    border: 2px solid {BORDER};
                    background: {INPUT_BG};
                }}
                QRadioButton::indicator:checked {{
                    background: {ACCENT};
                    border: 2px solid {ACCENT};
                }}
            """)
            self.alg_group.addButton(rb)
            self._alg_radios[alg] = rb
            alg_row.addWidget(rb)

        self._alg_radios["SHA256"].setChecked(True)
        alg_row.addStretch()
        alg_card.add_layout(alg_row)
        cl.addWidget(alg_card)

        # -- Text input card ---------------------------------------------------
        text_card = Card()
        text_card.add(section_label("HASH TEXT"))

        self.text_input = styled_input("Enter text to hash...")
        self.text_input.returnPressed.connect(self._hash_text)
        text_card.add(self.text_input)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.hash_text_btn = primary_button("Generate Hash")
        self.hash_text_btn.setFixedWidth(180)
        self.hash_text_btn.clicked.connect(self._hash_text)

        self.hash_all_btn = primary_button("All Algorithms")
        self.hash_all_btn.setFixedWidth(180)
        self.hash_all_btn.setStyleSheet(
            self.hash_all_btn.styleSheet()
            .replace(ACCENT, "#21262d")
            .replace("#1f6feb", "#30363d")
        )
        self.hash_all_btn.clicked.connect(self._hash_text_all)

        btn_row.addWidget(self.hash_text_btn)
        btn_row.addWidget(self.hash_all_btn)
        btn_row.addStretch()
        text_card.add_layout(btn_row)
        cl.addWidget(text_card)

        # -- File input card ---------------------------------------------------
        file_card = Card()
        file_card.add(section_label("HASH FILE"))

        file_row = QHBoxLayout()
        file_row.setSpacing(10)
        self.file_lbl = QLabel("No file selected")
        self.file_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:13px; background:transparent;")
        self.file_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        browse_btn = primary_button("Browse...")
        browse_btn.setFixedWidth(130)
        browse_btn.clicked.connect(self._browse_file)

        file_row.addWidget(self.file_lbl, 1)
        file_row.addWidget(browse_btn)
        file_card.add_layout(file_row)

        file_btn_row = QHBoxLayout()
        file_btn_row.setSpacing(10)
        self.hash_file_btn = primary_button("Hash File")
        self.hash_file_btn.setFixedWidth(160)
        self.hash_file_btn.setEnabled(False)
        self.hash_file_btn.clicked.connect(self._hash_file)

        self.hash_file_all_btn = primary_button("All Algorithms")
        self.hash_file_all_btn.setFixedWidth(180)
        self.hash_file_all_btn.setEnabled(False)
        self.hash_file_all_btn.setStyleSheet(
            self.hash_file_all_btn.styleSheet()
            .replace(ACCENT, "#21262d")
            .replace("#1f6feb", "#30363d")
        )
        self.hash_file_all_btn.clicked.connect(self._hash_file_all)

        file_btn_row.addWidget(self.hash_file_btn)
        file_btn_row.addWidget(self.hash_file_all_btn)
        file_btn_row.addStretch()
        file_card.add_layout(file_btn_row)
        cl.addWidget(file_card)

        # -- Results card ------------------------------------------------------
        res_card = Card()
        res_header = QHBoxLayout()
        res_header.setSpacing(10)
        res_header.addWidget(section_label("RESULT"))
        res_header.addStretch()

        self.copy_btn = primary_button("Copy")
        self.copy_btn.setFixedWidth(100)
        self.copy_btn.setFixedHeight(32)
        self.copy_btn.clicked.connect(self._copy_result)
        res_header.addWidget(self.copy_btn)
        res_card.add_layout(res_header)

        self.result_area = results_area(120)
        res_card.add(self.result_area)
        cl.addWidget(res_card)
        cl.addStretch()

    # -- Logic -----------------------------------------------------------------
    def _selected_alg(self) -> str:
        for alg, rb in self._alg_radios.items():
            if rb.isChecked():
                return alg
        return "SHA256"

    def _hash_text(self):
        text = self.text_input.text()
        if not text:
            self.result_area.setPlainText("!  Please enter some text.")
            return
        alg = self._selected_alg()
        r   = hash_text(text, alg)
        if r["success"]:
            self.result_area.setPlainText(
                f"Algorithm : {r['algorithm']}\n"
                f"Input     : {text[:80]}{'...' if len(text) > 80 else ''}\n"
                f"Digest    : {r['digest']}\n"
                f"Bit length: {r['digest_length']} bits"
            )
        else:
            self.result_area.setPlainText(f"X  Error: {r['error']}")

    def _hash_text_all(self):
        text = self.text_input.text()
        if not text:
            self.result_area.setPlainText("!  Please enter some text.")
            return
        results = hash_text_all(text)
        lines = [f"Input: {text[:80]}{'...' if len(text) > 80 else ''}\n"]
        for alg, digest in results.items():
            lines.append(f"{alg:<8}: {digest}")
        self.result_area.setPlainText("\n".join(lines))

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if path:
            self._selected_file = path
            name = os.path.basename(path)
            size = os.path.getsize(path)
            self.file_lbl.setText(f"{name}  ({self._human_size(size)})")
            self.file_lbl.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:13px; background:transparent;")
            self.hash_file_btn.setEnabled(True)
            self.hash_file_all_btn.setEnabled(True)

    def _hash_file(self):
        if not self._selected_file:
            return
        alg = self._selected_alg()
        r   = hash_file(self._selected_file, alg)
        if r["success"]:
            self.result_area.setPlainText(
                f"Algorithm : {r['algorithm']}\n"
                f"File      : {r['filename']}\n"
                f"Size      : {self._human_size(r['filesize'])}\n"
                f"Digest    : {r['digest']}\n"
                f"Bit length: {r['digest_length']} bits"
            )
        else:
            self.result_area.setPlainText(f"X  Error: {r['error']}")

    def _hash_file_all(self):
        if not self._selected_file:
            return
        results = hash_file_all(self._selected_file)
        name = os.path.basename(self._selected_file)
        lines = [f"File: {name}\n"]
        for alg, digest in results.items():
            lines.append(f"{alg:<8}: {digest}")
        self.result_area.setPlainText("\n".join(lines))

    def _copy_result(self):
        text = self.result_area.toPlainText()
        if text:
            QApplication.clipboard().setText(text)

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
