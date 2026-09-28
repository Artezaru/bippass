"""
bippass - Local python password manager with Qt-GUI based on Artezaru/pyaescbc.
Copyright (C) 2026 Artezaru, artezaru.github@proton.me

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations

from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ...core.password_generator import (
    DEFAULT_SPECIAL_CHARACTERS,
    GeneratorType,
    WORDLIST_LANGUAGES,
    generate_memorable_password,
    generate_random_password,
)
from ..translate import LANGUAGE_NAME_KEYS, translator

_LENGTH_RANGE = (1, 256)
_DEFAULT_LENGTH = 20

_WORD_COUNT_RANGE = (1, 12)
_DEFAULT_WORD_COUNT = 4
_DIGIT_COUNT_RANGE = (0, 12)
_DEFAULT_DIGIT_COUNT = 2
_DEFAULT_SEPARATOR = "-"

_WORDLIST_CHOICES = ("en", "fr", "es")
_FALLBACK_WORDLIST = "en"


class GeneratorDialog(QDialog):
    """
    Dialog to generate a password (random or memorable), preview it,
    copy it, and optionally hand it back to the caller.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    Generation only happens when :attr:`generate_button` is pressed.
    "Use this password", "Cancel" and "Copy" stay hidden or disabled
    until a password exists, so :meth:`get_password` is guaranteed
    non-empty once :meth:`exec_` returned ``QDialog.Accepted``.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("generator.dialog_title"))
        self._generated_password = ""

        layout = QVBoxLayout(self)

        # Combo entries and stack pages share the same order, so the
        # combo's index is also the page index.
        type_row = QHBoxLayout()
        type_row.addWidget(QLabel(translator.translate("common.type_label")))
        self.type_combo = QComboBox()
        self.type_combo.addItem(translator.translate("generator.type_random"), GeneratorType.RANDOM)
        self.type_combo.addItem(
            translator.translate("generator.type_memorable"), GeneratorType.MEMORABLE
        )
        type_row.addWidget(self.type_combo, stretch=1)
        layout.addLayout(type_row)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_random_panel())
        self.stack.addWidget(self._build_memorable_panel())
        self.type_combo.currentIndexChanged.connect(self.stack.setCurrentIndex)
        layout.addWidget(self.stack)

        result_row = QHBoxLayout()
        self.result_edit = QLineEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setPlaceholderText(translator.translate("generator.result_placeholder"))
        result_row.addWidget(self.result_edit, stretch=1)

        self.copy_button = QPushButton(translator.translate("generator.copy_button"))
        self.copy_button.setAutoDefault(False)
        self.copy_button.clicked.connect(self._on_copy)
        result_row.addWidget(self.copy_button)
        layout.addLayout(result_row)

        self.generate_button = QPushButton(translator.translate("generator.generate_button"))
        self.generate_button.setDefault(True)
        self.generate_button.clicked.connect(self._on_generate)
        layout.addWidget(self.generate_button)

        self.result_separator = QFrame()
        self.result_separator.setFrameShape(QFrame.HLine)
        self.result_separator.setFrameShadow(QFrame.Sunken)
        layout.addWidget(self.result_separator)

        buttons = QDialogButtonBox()
        self.use_button = buttons.addButton(
            translator.translate("generator.use_button"), QDialogButtonBox.AcceptRole
        )
        self.use_button.setAutoDefault(False)
        self.cancel_button = buttons.addButton(
            translator.translate("common.cancel"), QDialogButtonBox.RejectRole
        )
        # Red through the `QPushButton#dangerButton` rule of `theme.py`.
        self.cancel_button.setObjectName("dangerButton")
        self.cancel_button.setAutoDefault(False)
        buttons.accepted.connect(self._on_use)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._update_widgets()

    def _build_random_panel(self) -> QWidget:
        """
        Build the options panel of the random generator.

        Returns
        -------
        QWidget
            Panel with the length, the character classes and the
            custom set of special characters.
        """
        panel = QWidget()
        form = QFormLayout(panel)

        self.length_spin = QSpinBox()
        self.length_spin.setRange(*_LENGTH_RANGE)
        self.length_spin.setValue(_DEFAULT_LENGTH)
        form.addRow(translator.translate("generator.length_label"), self.length_spin)

        self.lowercase_check = self._add_checkbox(form, "generator.lowercase_label", checked=True)
        self.uppercase_check = self._add_checkbox(form, "generator.uppercase_label", checked=True)
        self.digits_check = self._add_checkbox(form, "generator.digits_label", checked=True)

        self.special_check = QCheckBox(translator.translate("generator.special_characters_label"))
        self.special_characters_edit = QLineEdit(DEFAULT_SPECIAL_CHARACTERS)
        self.special_reset_button = QPushButton("↺")
        self.special_reset_button.setFixedWidth(28)
        self.special_reset_button.setAutoDefault(False)
        self.special_reset_button.setToolTip(
            translator.translate("generator.special_characters_reset_tooltip")
        )
        self.special_reset_button.clicked.connect(
            lambda: self.special_characters_edit.setText(DEFAULT_SPECIAL_CHARACTERS)
        )
        special_row = QHBoxLayout()
        special_row.addWidget(self.special_characters_edit, stretch=1)
        special_row.addWidget(self.special_reset_button)
        form.addRow(self.special_check, special_row)

        self.special_check.toggled.connect(self.special_characters_edit.setEnabled)
        self.special_check.toggled.connect(self.special_reset_button.setEnabled)
        self.special_characters_edit.setEnabled(False)
        self.special_reset_button.setEnabled(False)

        return panel

    def _build_memorable_panel(self) -> QWidget:
        """
        Build the options panel of the memorable generator.

        Returns
        -------
        QWidget
            Panel with the wordlist language, the word and digit
            counts, the separator and the capitalization.
        """
        panel = QWidget()
        form = QFormLayout(panel)

        self.language_combo = QComboBox()
        for code in _WORDLIST_CHOICES:
            self.language_combo.addItem(translator.translate(LANGUAGE_NAME_KEYS[code]), code)
        default = (
            translator.language if translator.language in WORDLIST_LANGUAGES else _FALLBACK_WORDLIST
        )
        self.language_combo.setCurrentIndex(max(0, self.language_combo.findData(default)))
        form.addRow(translator.translate("generator.word_language_label"), self.language_combo)

        self.word_count_spin = QSpinBox()
        self.word_count_spin.setRange(*_WORD_COUNT_RANGE)
        self.word_count_spin.setValue(_DEFAULT_WORD_COUNT)
        form.addRow(translator.translate("generator.word_count_label"), self.word_count_spin)

        self.digit_count_spin = QSpinBox()
        self.digit_count_spin.setRange(*_DIGIT_COUNT_RANGE)
        self.digit_count_spin.setValue(_DEFAULT_DIGIT_COUNT)
        form.addRow(translator.translate("generator.digit_count_label"), self.digit_count_spin)

        self.separator_edit = QLineEdit(_DEFAULT_SEPARATOR)
        form.addRow(translator.translate("generator.separator_label"), self.separator_edit)

        self.capitalize_check = self._add_checkbox(form, "generator.capitalize_label", checked=True)

        return panel

    @staticmethod
    def _add_checkbox(form: QFormLayout, label_key: str, checked: bool) -> QCheckBox:
        """
        Add a full-width checkbox row to a form.

        Parameters
        ----------
        form : QFormLayout
            Form the row is added to.
        label_key : str
            Translation key of the checkbox label.
        checked : bool
            Initial state of the checkbox.

        Returns
        -------
        QCheckBox
            The new checkbox.
        """
        check = QCheckBox(translator.translate(label_key))
        check.setChecked(checked)
        form.addRow(check)
        return check

    def _generate(self) -> str:
        """
        Generate a password from the options of the selected generator.

        Returns
        -------
        str
            The generated password.

        Raises
        ------
        ValueError
            If the options can't produce a password (e.g. no character
            class selected).
        OSError
            If the wordlist can't be read.
        """
        if self.type_combo.currentData() is GeneratorType.RANDOM:
            return generate_random_password(
                self.length_spin.value(),
                use_lowercase=self.lowercase_check.isChecked(),
                use_uppercase=self.uppercase_check.isChecked(),
                use_digits=self.digits_check.isChecked(),
                use_special=self.special_check.isChecked(),
                special_characters=self.special_characters_edit.text(),
            )
        return generate_memorable_password(
            self.word_count_spin.value(),
            language=self.language_combo.currentData(),
            digit_count=self.digit_count_spin.value(),
            separator=self.separator_edit.text(),
            capitalize=self.capitalize_check.isChecked(),
        )

    def _on_generate(self) -> None:
        """Generate a password and show it, or show the error."""
        try:
            password = self._generate()
        except (ValueError, OSError) as exc:
            QMessageBox.critical(
                self,
                translator.translate("common.error_title"),
                translator.translate("generator.generation_error", error=str(exc)),
            )
            return
        self._generated_password = password
        self.result_edit.setText(password)
        self._update_widgets()

    def _update_widgets(self) -> None:
        """Show and enable the result actions only once a password exists."""
        has_password = bool(self._generated_password)
        self.copy_button.setEnabled(has_password)
        self.result_separator.setVisible(has_password)
        self.use_button.setVisible(has_password)
        self.cancel_button.setVisible(has_password)

    def _on_copy(self) -> None:
        """Copy the generated password to the clipboard."""
        if self._generated_password:
            QApplication.clipboard().setText(self._generated_password)

    def _on_use(self) -> None:
        """Accept the dialog if a password was generated."""
        if self._generated_password:
            self.accept()

    def get_password(self) -> str:
        """
        Return the generated password.

        Returns
        -------
        str
            The last password generated in this dialog; only
            meaningful once :meth:`exec_` returned ``QDialog.Accepted``.
        """
        return self._generated_password