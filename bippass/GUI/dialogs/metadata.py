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
    Dialog to edit the profile's username and label.

    Also shows, read-only, the profile's UUID (which names its file)
    and its dates.

    Parameters
    ----------
    manager : PasswordManager
        Unlocked manager whose metadata is edited, read to pre-fill the
        fields.
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    The username is stored encrypted. The label is the only text
    readable without a password: it is what the profile list of the
    start page shows. Either may be left empty.
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("metadata.dialog_title"))
        layout = QFormLayout(self)

        self.username_edit = QLineEdit(manager.get_username() or "")
        layout.addRow(tr("common.username_label"), self.username_edit)

        self.label_edit = QLineEdit(manager.label or "")
        layout.addRow(tr("common.label_label"), self.label_edit)
        hint = QLabel(tr("metadata.label_hint"))
        hint.setObjectName("mutedLabel")
        hint.setWordWrap(True)
        layout.addRow(hint)

        for label_key, value in (
            ("metadata.uuid_label", manager.uuid),
            ("metadata.creation_date_label", manager.creation_date),
            ("metadata.modification_date_label", manager.modification_date),
        ):
            value_label = QLabel(value)
            value_label.setObjectName("mutedLabel")
            layout.addRow(tr(label_key), value_label)

        layout.addRow(ok_cancel_buttons(self))

    def apply_to(self, manager: PasswordManager) -> None:
        """
        Write the dialog's fields back into the manager.

        Parameters
        ----------
        manager : PasswordManager
            Manager to update. Empty fields are stored as ``None``.
        """
        username = self.username_edit.text().strip() or None
        label = self.label_edit.text().strip() or None
        if username != manager.get_username():
            manager.set_username(username)
        if label != manager.label:
            manager.set_label(label)
