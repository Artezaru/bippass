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

from typing import Callable

from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QWidget,
)

from .translate import LANGUAGE_NAME_KEYS, translator


def refresh_style(widget: QWidget) -> None:
    """
    Re-apply the QSS of a widget after one of its dynamic properties
    changed.

    Parameters
    ----------
    widget : QWidget
        Widget whose style must be re-evaluated.
    """
    widget.style().unpolish(widget)
    widget.style().polish(widget)


class PasswordField(QWidget):
    """
    Masked :class:`QLineEdit` with a "Show"/"Hide" toggle button.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    edit : QLineEdit
        The password input, masked by default.
    toggle_button : QPushButton
        Button switching :attr:`edit` between masked and plain text.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.Password)

        self.toggle_button = QPushButton()
        self.toggle_button.setObjectName("smallButton")
        # Otherwise Enter in the field would toggle instead of hitting OK.
        self.toggle_button.setAutoDefault(False)
        self.toggle_button.clicked.connect(self._toggle_mask)

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self.edit, stretch=1)
        row.addWidget(self.toggle_button)

        self.retranslate()
        translator.language_changed.connect(self.retranslate)

    @pyqtSlot()
    def retranslate(self) -> None:
        """Refresh the toggle button's text and tooltip."""
        masked = self.edit.echoMode() == QLineEdit.Password
        self.toggle_button.setText(translator.translate("common.show" if masked else "common.hide"))
        self.toggle_button.setToolTip(translator.translate("common.show_hide_tooltip"))

    def _toggle_mask(self) -> None:
        """Switch :attr:`edit` between masked and plain text."""
        masked = self.edit.echoMode() == QLineEdit.Password
        self.edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.retranslate()

    def clear(self) -> None:
        """Erase the entered password."""
        self.edit.clear()

    def text(self) -> str:
        """
        Return the entered password.

        Returns
        -------
        str
            The password as typed, without stripping.
        """
        return self.edit.text()

    def to_bytearray(self) -> bytearray:
        """
        Return the entered password as a mutable buffer.

        Returns
        -------
        bytearray
            The UTF-8 encoded password, so the caller can wipe it
            after use.
        """
        return bytearray(self.edit.text().encode("utf-8"))


class LanguageComboBox(QComboBox):
    """
    Combo box of the supported languages, each named in the current
    display language.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    Starts on the current display language. Picking an entry doesn't
    change the language by itself: the owner reacts to
    ``currentIndexChanged``, since a settings dialog only applies it
    once accepted.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        for code, name_key in LANGUAGE_NAME_KEYS.items():
            self.addItem(translator.translate(name_key), code)
        self.set_language(translator.language)
        translator.language_changed.connect(self.retranslate)

    def language(self) -> str:
        """
        Return the selected language.

        Returns
        -------
        str
            Language code.
        """
        return self.currentData()

    def set_language(self, language: str) -> None:
        """
        Select a language without emitting ``currentIndexChanged``.

        Parameters
        ----------
        language : str
            Language code; nothing is selected if unsupported.
        """
        self.blockSignals(True)
        self.setCurrentIndex(self.findData(language))
        self.blockSignals(False)

    @pyqtSlot()
    def retranslate(self) -> None:
        """Rename every language in the current display language."""
        for index, name_key in enumerate(LANGUAGE_NAME_KEYS.values()):
            self.setItemText(index, translator.translate(name_key))


def ok_cancel_buttons(
    dialog: QDialog,
    on_accept: Callable[[], None] | None = None,
) -> QDialogButtonBox:
    """
    Build a translated OK/Cancel button box wired to a dialog.

    Parameters
    ----------
    dialog : QDialog
        Dialog the buttons belong to; Cancel calls its ``reject``.
    on_accept : callable, optional
        Called on OK, typically to validate the fields before calling
        ``dialog.accept()``. Default is ``dialog.accept``.

    Returns
    -------
    QDialogButtonBox
        The button box, to be added to the dialog's layout.
    """
    buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    buttons.button(QDialogButtonBox.Ok).setText(translator.translate("common.ok"))
    buttons.button(QDialogButtonBox.Cancel).setText(translator.translate("common.cancel"))
    buttons.accepted.connect(on_accept or dialog.accept)
    buttons.rejected.connect(dialog.reject)
    return buttons