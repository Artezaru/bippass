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

from PyQt5.QtWidgets import QComboBox, QDialog, QFormLayout, QMessageBox

from ..translate import translator
from ..widgets import PasswordField, ok_cancel_buttons


class ChangeCredentialsDialog(QDialog):
    """
    Dialog to change either the primary or the secondary password.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    Only the side being changed is collected here: the caller
    (`window.PasswordManagerWindow._open_change_credentials`) carries
    the other side over unchanged from the manager's current
    :class:`Credentials`.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("credentials.dialog_title"))

        layout = QFormLayout(self)

        self.target_combo = QComboBox()
        self.target_combo.addItem(translator.translate("credentials.change_primary"), "primary")
        self.target_combo.addItem(translator.translate("credentials.change_secondary"), "secondary")
        layout.addRow(self.target_combo)

        self.password_field = PasswordField()
        self.confirm_password_field = PasswordField()
        layout.addRow(translator.translate("credentials.password_label"), self.password_field)
        layout.addRow(
            translator.translate("credentials.confirm_password_label"),
            self.confirm_password_field,
        )

        layout.addRow(ok_cancel_buttons(self, self._on_accept))

    def _on_accept(self) -> None:
        """Accept the dialog if the password is set and confirmed, warn otherwise."""
        password = self.password_field.text()
        if not password:
            message_key = "credentials.empty_password"
        elif password != self.confirm_password_field.text():
            message_key = "credentials.password_mismatch"
        else:
            self.accept()
            return
        QMessageBox.warning(
            self, translator.translate("common.error_title"), translator.translate(message_key)
        )

    def get_data(self) -> dict:
        """
        Return the side to change and its new password.

        Returns
        -------
        dict
            ``{"target": "primary" or "secondary", "password": bytearray}``.
        """
        return {
            "target": self.target_combo.currentData(),
            "password": self.password_field.to_bytearray(),
        }