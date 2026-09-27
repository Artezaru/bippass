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

from PyQt5.QtCore import Qt
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

from ..core.password_generator import (
    DEFAULT_SPECIAL_CHARACTERS,
    GeneratorType,
    WORDLIST_LANGUAGES,
    generate_memorable_password,
    generate_random_password,
)

from .translate import translator, generator_translation

def _t(key: str, **kwargs: str) -> str:
    """Shorthand for ``translator.translate(key, generator_translation, **kwargs)``."""
    return translator.translate(key, generator_translation, **kwargs)


class GeneratorDialog(QDialog):
    """
    Dialog to generate a password (random or memorable), preview it,
    copy it, and optionally hand it back to the caller.

    Parameters
    ----------
    parent : QWidget, optional

    Notes
    -----
    Generation never happens implicitly (e.g. while the user is still
    adjusting options): the user always presses
    :attr:`generate_button` explicitly, and the "Use this password"
    button (see :meth:`_on_use`) only accepts the dialog once at least
    one password has actually been generated, so a caller reading
    :meth:`get_password` after :meth:`exec_` returns
    ``QDialog.Accepted`` is guaranteed a non-empty result.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_t("dialog_title"))
        self._generated_password: str = ""

        layout = QVBoxLayout(self)

        # -- Type selector ---------------------------------------------------

        type_row = QHBoxLayout()
        type_row.addWidget(QLabel(_t("type_label")))
        self.type_combo = QComboBox()
        self.type_combo.addItem(_t("type_random"), GeneratorType.RANDOM)
        self.type_combo.addItem(_t("type_memorable"), GeneratorType.MEMORABLE)
        self.type_combo.currentIndexChanged.connect(self._on_type_changed)
        type_row.addWidget(self.type_combo, stretch=1)
        layout.addLayout(type_row)

        # -- Per-type option panels -------------------------------------------

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_random_panel())
        self.stack.addWidget(self._build_memorable_panel())
        layout.addWidget(self.stack)

        # -- Result ------------------------------------------------------------

        result_row = QHBoxLayout()
        self.result_edit = QLineEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setPlaceholderText(_t("result_placeholder"))
        result_row.addWidget(self.result_edit, stretch=1)

        self.copy_button = QPushButton(_t("copy_button"))
        self.copy_button.clicked.connect(self._on_copy)
        result_row.addWidget(self.copy_button)
        layout.addLayout(result_row)

        self.generate_button = QPushButton(_t("generate_button"))
        self.generate_button.clicked.connect(self._on_generate)
        layout.addWidget(self.generate_button)

        # Separates "Generate" from "Use this password"/"Cancel"
        # below: shown only alongside those two (see `_update_widgets`),
        # never on its own.
        self.result_separator = QFrame()
        self.result_separator.setFrameShape(QFrame.HLine)
        self.result_separator.setFrameShadow(QFrame.Sunken)
        layout.addWidget(self.result_separator)

        # -- Use / Cancel --------------------------------------------------------
        #
        # Both, and the separator above, stay hidden until a password
        # has actually been generated (see `_update_widgets`): before
        # that, there is nothing to use, and closing the dialog is
        # still possible through its title bar. `use_button` keeps the
        # default button color; `cancel_button` is styled red via the
        # `dangerButton` object name (see `theme.py`'s
        # `QPushButton#dangerButton` rule), the same convention
        # already used for the "Cancel" button in `ItemViewer`.

        buttons = QDialogButtonBox()
        self.use_button = buttons.addButton(_t("use_button"), QDialogButtonBox.AcceptRole)
        self.use_button.clicked.connect(self._on_use)

        self.cancel_button = buttons.addButton(_t("cancel_button"), QDialogButtonBox.RejectRole)
        self.cancel_button.setObjectName("dangerButton")
        self.cancel_button.clicked.connect(self.reject)

        layout.addWidget(buttons)

        self._on_type_changed()
        self._on_special_toggled()
        self._update_widgets()

    # -- Panels --------------------------------------------------------------

    def _build_random_panel(self) -> QWidget:
        panel = QWidget()
        form = QFormLayout(panel)

        self.length_spin = QSpinBox()
        self.length_spin.setRange(1, 256)
        self.length_spin.setValue(20)
        form.addRow(_t("length_label"), self.length_spin)

        self.lowercase_check = QCheckBox(_t("lowercase_label"))
        self.lowercase_check.setChecked(True)
        form.addRow(self.lowercase_check)

        self.uppercase_check = QCheckBox(_t("uppercase_label"))
        self.uppercase_check.setChecked(True)
        form.addRow(self.uppercase_check)

        self.digits_check = QCheckBox(_t("digits_label"))
        self.digits_check.setChecked(True)
        form.addRow(self.digits_check)

        self.special_check = QCheckBox()
        self.special_check.toggled.connect(self._on_special_toggled)
        special_row = QHBoxLayout()
        self.special_characters_edit = QLineEdit(DEFAULT_SPECIAL_CHARACTERS)
        special_row.addWidget(self.special_characters_edit, stretch=1)
        self.special_reset_button = QPushButton("↺")
        self.special_reset_button.setFixedWidth(28)
        self.special_reset_button.setToolTip(_t("special_characters_reset_tooltip"))
        self.special_reset_button.clicked.connect(self._on_reset_special_characters)
        special_row.addWidget(self.special_reset_button)
        form.addRow(self.special_check, special_row)

        return panel

    def _build_memorable_panel(self) -> QWidget:
        panel = QWidget()
        form = QFormLayout(panel)

        self.language_combo = QComboBox()
        self.language_combo.addItem(_t("language_en"), "en")
        self.language_combo.addItem(_t("language_fr"), "fr")
        self.language_combo.addItem(_t("language_es"), "es")
        # Default to the display language when it is one of the
        # bundled wordlist languages, English otherwise.
        default_language = translator.language if translator.language in WORDLIST_LANGUAGES else "en"
        self.language_combo.setCurrentIndex(self.language_combo.findData(default_language))
        form.addRow(_t("language_label"), self.language_combo)

        self.word_count_spin = QSpinBox()
        self.word_count_spin.setRange(1, 12)
        self.word_count_spin.setValue(4)
        form.addRow(_t("word_count_label"), self.word_count_spin)

        self.digit_count_spin = QSpinBox()
        self.digit_count_spin.setRange(0, 12)
        self.digit_count_spin.setValue(2)
        form.addRow(_t("digit_count_label"), self.digit_count_spin)

        self.separator_edit = QLineEdit("-")
        form.addRow(_t("separator_label"), self.separator_edit)

        self.capitalize_check = QCheckBox(_t("capitalize_label"))
        self.capitalize_check.setChecked(True)
        form.addRow(self.capitalize_check)

        return panel

    # -- Behavior --------------------------------------------------------------

    def _on_type_changed(self) -> None:
        generator_type = self.type_combo.currentData()
        self.stack.setCurrentIndex(0 if generator_type is GeneratorType.RANDOM else 1)

    def _on_special_toggled(self) -> None:
        self.special_check.setText(_t("special_characters_label"))
        enabled = self.special_check.isChecked()
        self.special_characters_edit.setEnabled(enabled)
        self.special_reset_button.setEnabled(enabled)

    def _on_reset_special_characters(self) -> None:
        self.special_characters_edit.setText(DEFAULT_SPECIAL_CHARACTERS)

    def _on_generate(self) -> None:
        generator_type = self.type_combo.currentData()

        try:
            if generator_type is GeneratorType.RANDOM:
                password = generate_random_password(
                    self.length_spin.value(),
                    use_lowercase=self.lowercase_check.isChecked(),
                    use_uppercase=self.uppercase_check.isChecked(),
                    use_digits=self.digits_check.isChecked(),
                    use_special=self.special_check.isChecked(),
                    special_characters=self.special_characters_edit.text(),
                )
            else:
                password = generate_memorable_password(
                    self.word_count_spin.value(),
                    language=self.language_combo.currentData(),
                    digit_count=self.digit_count_spin.value(),
                    separator=self.separator_edit.text(),
                    capitalize=self.capitalize_check.isChecked(),
                )
        except (ValueError, OSError) as exc:
            QMessageBox.critical(self, _t("error_title"), _t("generation_error", error=exc))
            return

        self._generated_password = password
        self.result_edit.setText(password)
        self._update_widgets()

    def _update_widgets(self) -> None:
        """
        Show the separator and the Use/Cancel buttons if and only if
        :attr:`_generated_password` is non-empty, hide them otherwise.

        Called once at construction time (nothing generated yet, so
        everything starts hidden) and again after every
        :meth:`_on_generate` call.
        """
        has_password = bool(self._generated_password)
        self.result_separator.setVisible(has_password)
        self.use_button.setVisible(has_password)
        self.cancel_button.setVisible(has_password)

    def _on_copy(self) -> None:
        if not self._generated_password:
            return
        QApplication.clipboard().setText(self._generated_password)

    def _on_use(self) -> None:
        if not self._generated_password:
            QMessageBox.information(self, _t("error_title"), _t("nothing_generated"))
            return
        self.accept()

    # -- Result ------------------------------------------------------------

    def get_password(self) -> str:
        """
        Return the generated password.

        Returns
        -------
        str
            The last password generated in this dialog. Only
            meaningful after :meth:`exec_` returned
            ``QDialog.Accepted`` (see the class docstring's Notes).
        """
        return self._generated_password