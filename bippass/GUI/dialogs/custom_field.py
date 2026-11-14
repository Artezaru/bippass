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

from PyQt5.QtWidgets import QComboBox, QDialog, QFormLayout, QLabel, QLineEdit

from ...core.item import FieldKind
from ..translate import translator
from ..widgets import ok_cancel_buttons, warn


class CustomFieldDialog(QDialog):
    """
    Dialog to create a new custom field on an item.

    Asks for a name and a kind: *clear* (stored like a login) or
    *encrypted* (stored like a password, behind the secondary
    password). Values are entered afterwards in the item viewer; a
    custom field may hold several of them.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    Several custom fields may share a name: each has its own id. Only
    a blank name is refused.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("custom_field.dialog_title"))
        self.setModal(True)
        layout = QFormLayout(self)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText(tr("custom_field.field_name_placeholder"))
        layout.addRow(tr("common.name_label"), self.name_edit)

        self.kind_combo = QComboBox()
        self.kind_combo.addItem(tr("custom_field.kind_clear"), FieldKind.CLEAR)
        self.kind_combo.addItem(tr("custom_field.kind_encrypted"), FieldKind.ENCRYPTED)
        layout.addRow(tr("common.type_label"), self.kind_combo)

        hint = QLabel(tr("custom_field.kind_hint"))
        hint.setObjectName("mutedLabel")
        hint.setWordWrap(True)
        layout.addRow(hint)
        layout.addRow(ok_cancel_buttons(self, self._on_accept))

    def _on_accept(self) -> None:
        """Accept the dialog if the name is set, warn otherwise."""
        if self.name_edit.text().strip():
            self.accept()
            return
        warn(self, "custom_field.field_name_required")

    def get_data(self) -> dict:
        """
        Return the new field's name and kind.

        Returns
        -------
        dict
            ``{"name": str, "kind": FieldKind}``, the name stripped.
        """
        return {"name": self.name_edit.text().strip(), "kind": self.kind_combo.currentData()}
