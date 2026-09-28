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

from typing import TYPE_CHECKING

from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QLineEdit,
    QMessageBox,
)

from ..translate import translator
from ..widgets import LanguageComboBox, ok_cancel_buttons

if TYPE_CHECKING:
    from ...core.manager import PasswordManager


class AccountSettingsDialog(QDialog):
    """
    Dialog to edit the theme, the language and the inactivity
    auto-close delay, all stored in the manager's metadata.

    Parameters
    ----------
    manager : PasswordManager
        Manager whose metadata is edited, read to pre-fill the fields.
    current_theme : str
        Currently active theme (``"light"`` or ``"dark"``), used to
        pre-select the theme, in case it drifted from the metadata
        value within the session.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, manager: PasswordManager, current_theme: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("settings.dialog_title"))
        self._close_timer_s = manager.get_close_timer_s()

        layout = QFormLayout(self)

        self.theme_combo = QComboBox()
        self.theme_combo.addItem(translator.translate("settings.theme_light"), "light")
        self.theme_combo.addItem(translator.translate("settings.theme_dark"), "dark")
        self.theme_combo.setCurrentIndex(self.theme_combo.findData(current_theme))
        layout.addRow(translator.translate("settings.theme_label"), self.theme_combo)

        self.language_combo = LanguageComboBox()
        layout.addRow(translator.translate("settings.language_label"), self.language_combo)

        self.close_timer_edit = QLineEdit(str(self._close_timer_s))
        layout.addRow(translator.translate("settings.close_timer_label"), self.close_timer_edit)

        layout.addRow(ok_cancel_buttons(self, self._on_accept))

    def _on_accept(self) -> None:
        """Accept the dialog if the delay is a positive integer, warn otherwise."""
        try:
            close_timer_s = int(self.close_timer_edit.text().strip())
        except ValueError:
            close_timer_s = 0
        if close_timer_s <= 0:
            QMessageBox.warning(
                self,
                translator.translate("common.error_title"),
                translator.translate("settings.invalid_close_timer"),
            )
            return
        self._close_timer_s = close_timer_s
        self.accept()

    def apply_to(self, manager: PasswordManager) -> tuple[str, str, int]:
        """
        Write the dialog's fields back into the manager's metadata.

        Parameters
        ----------
        manager : PasswordManager
            Manager to update.

        Returns
        -------
        tuple of (str, str, int)
            ``(theme, language, close_timer_s)``, for the caller to
            apply right away rather than on next launch.
        """
        theme = self.theme_combo.currentData()
        language = self.language_combo.language()

        manager.set_theme(theme)
        manager.set_language(language)
        manager.set_close_timer_s(self._close_timer_s)

        return theme, language, self._close_timer_s