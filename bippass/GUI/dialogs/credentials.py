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

from PyQt5.QtWidgets import QComboBox, QDialog, QFormLayout, QLabel

from ..translate import translator
from ..widgets import NewPasswordFields, PasswordField, ok_cancel_buttons, warn


class ChangePasswordDialog(QDialog):
    """
    Dialog to change either the primary or the secondary password.

    Asks for the current password of the chosen side, and the new one
    twice. Nothing is checked against the profile here: the caller
    passes both to :meth:`PasswordManager.change_primary_password` or
    :meth:`PasswordManager.change_secondary_password`, which check the
    current one.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("credentials.dialog_title"))
        layout = QFormLayout(self)

        self.target_combo = QComboBox()
        self.target_combo.addItem(tr("credentials.change_primary"), "primary")
        self.target_combo.addItem(tr("credentials.change_secondary"), "secondary")
        layout.addRow(self.target_combo)

        hint = QLabel(tr("credentials.hint"))
        hint.setObjectName("mutedLabel")
        hint.setWordWrap(True)
        layout.addRow(hint)

        self.current_field = PasswordField()
        layout.addRow(tr("credentials.current_password_label"), self.current_field)
        self.new_fields = NewPasswordFields(
            layout, tr("credentials.password_label"), tr("credentials.confirm_password_label")
        )
        layout.addRow(ok_cancel_buttons(self, self._on_accept))

    def _on_accept(self) -> None:
        """Accept if every field is filled and the new password confirmed, warn otherwise."""
        problem = "empty" if not self.current_field.text() else self.new_fields.problem()
        if problem == "empty":
            warn(self, "credentials.empty_password")
        elif problem == "mismatch":
            warn(self, "credentials.password_mismatch")
        elif self.new_fields.text() == self.current_field.text():
            warn(self, "credentials.same_password")
        else:
            self.accept()

    def _clear(self) -> None:
        """Erase every typed password."""
        self.current_field.clear()
        self.new_fields.clear()

    def reject(self) -> None:
        """Erase the typed passwords, then close."""
        self._clear()
        super().reject()

    def get_data(self) -> dict:
        """
        Return the side to change and both passwords, then erase the fields.

        Returns
        -------
        dict
            ``{"target": "primary" or "secondary", "current": bytearray,
            "new": bytearray}``. The caller owns (and must erase) both
            buffers; passing them to the manager does.
        """
        data = {
            "target": self.target_combo.currentData(),
            "current": self.current_field.to_bytearray(),
            "new": self.new_fields.to_bytearray(),
        }
        self._clear()
        return data
