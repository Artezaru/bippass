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

from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit

from ..translate import translator
from ..widgets import ok_cancel_buttons

if TYPE_CHECKING:
    from ...core.manager import PasswordManager


class MetadataDialog(QDialog):
    """
    Dialog to edit the manager's account metadata (username).

    Parameters
    ----------
    manager : PasswordManager
        Manager whose metadata is edited, read to pre-fill the fields.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("metadata.dialog_title"))

        layout = QFormLayout(self)

        self.username_edit = QLineEdit(manager.get_username() or "")
        layout.addRow(translator.translate("common.username_label"), self.username_edit)
        layout.addRow(
            translator.translate("metadata.version_label"), QLabel(str(manager.get_version()))
        )

        layout.addRow(ok_cancel_buttons(self))

    def get_username(self) -> str | None:
        """
        Return the entered username.

        Returns
        -------
        str or None
            The username, stripped, or ``None`` if left empty.
        """
        return self.username_edit.text().strip() or None

    def apply_to(self, manager: PasswordManager) -> None:
        """
        Write the dialog's fields back into the manager's metadata.

        Parameters
        ----------
        manager : PasswordManager
            Manager to update. An empty username is stored as ``None``.
        """
        manager.set_username(self.get_username())