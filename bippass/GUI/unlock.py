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

# Asking for the secondary password once the profile is open, on demand
# (the primary one is asked by the start page).

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QWidget

from ..core.exceptions import SecondaryPasswordError
from .tasks import run_blocking
from .translate import translator
from .widgets import PasswordField, ok_cancel_buttons, warn

if TYPE_CHECKING:
    from ..core.manager import PasswordManager


class SecondaryPasswordDialog(QDialog):
    """
    Dialog asking for the secondary password.

    It only collects the password: :func:`ensure_decrypted` closes it,
    then decrypts behind the "please wait" veil of the main window,
    which a small dialog would hide.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("unlock.secondary_title"))

        layout = QFormLayout(self)
        message = QLabel(translator.translate("unlock.secondary_message"))
        message.setWordWrap(True)
        layout.addRow(message)

        self.password_field = PasswordField()
        layout.addRow(translator.translate("unlock.secondary_label"), self.password_field)
        layout.addRow(ok_cancel_buttons(self, self._on_accept))
        self.password_field.edit.setFocus()

    def _on_accept(self) -> None:
        """Accept once a password is typed."""
        if self.password_field.text():
            self.accept()

    def take_password(self) -> bytearray:
        """
        Return the typed password, and erase the field.

        Returns
        -------
        bytearray
            The UTF-8 encoded password, owned (and to be erased) by the
            caller.
        """
        password = self.password_field.to_bytearray()
        self.password_field.clear()
        return password

    def reject(self) -> None:
        """Erase the typed password, then close."""
        self.password_field.clear()
        super().reject()


def ensure_decrypted(manager: PasswordManager, parent: QWidget | None = None) -> bool:
    """
    Make sure the data key is available, asking for the secondary password if needed.

    Parameters
    ----------
    manager : PasswordManager
        Unlocked manager.

    parent : QWidget, optional
        Widget of the main window: parent of the password dialog, and
        window covered by the "please wait" veil while decrypting.

    Returns
    -------
    bool
        ``True`` if the manager is decrypted (already, or now);
        ``False`` if the user cancelled.

    Notes
    -----
    Call it right before any operation needing the data key: showing,
    copying or editing a secret, duplicating an item, exporting,
    importing, changing the secondary password.

    The dialog is closed before the derivation, which runs behind the
    veil of the main window (see :func:`tasks.run_blocking`). A wrong
    password is reported, then the dialog is shown again.
    """
    while not manager.is_decrypted:
        dialog = SecondaryPasswordDialog(parent)
        if dialog.exec_() != QDialog.Accepted:
            return False
        password = dialog.take_password()
        try:
            run_blocking(
                parent,
                translator.translate("unlock.decrypting"),
                lambda: manager.decrypt(password),
            )
        except SecondaryPasswordError:
            warn(parent, "unlock.wrong_secondary_message", "unlock.wrong_password_title")
        finally:
            password[:] = bytes(len(password))
    return True
