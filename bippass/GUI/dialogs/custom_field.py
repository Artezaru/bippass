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

from PyQt5.QtWidgets import QComboBox, QDialog, QFormLayout, QLineEdit, QMessageBox

from ..translate import translator
from ..widgets import ok_cancel_buttons

# Custom field kinds offered: multi-value custom fields aren't supported.
_CUSTOM_FIELD_KINDS = ("SCALAR", "ENCRYPTED")


class CustomFieldDialog(QDialog):
    """
    Dialog to create a new custom field on an item.

    Parameters
    ----------
    existing_names : tuple of str, optional
        Names of the item's current custom fields, refused as the new
        field's name.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, existing_names: tuple[str, ...] = (), parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("custom_field.dialog_title"))
        self.setModal(True)
        self._existing_names = existing_names

        layout = QFormLayout(self)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText(
            translator.translate("custom_field.field_name_placeholder")
        )
        layout.addRow(translator.translate("common.name_label"), self.name_edit)

        self.kind_combo = QComboBox()
        self.kind_combo.addItems(_CUSTOM_FIELD_KINDS)
        layout.addRow(translator.translate("common.type_label"), self.kind_combo)

        layout.addRow(ok_cancel_buttons(self, self._on_accept))

    def _on_accept(self) -> None:
        """Accept the dialog if the name is set and not taken, warn otherwise."""
        name = self.name_edit.text().strip()
        if not name:
            message = translator.translate("custom_field.field_name_required")
        elif name in self._existing_names:
            message = translator.translate("custom_field.field_already_exists", name=name)
        else:
            self.accept()
            return
        QMessageBox.warning(self, translator.translate("common.error_title"), message)

    def get_data(self) -> dict:
        """
        Return the new field's name and kind.

        Returns
        -------
        dict
            ``{"name": str, "kind": "SCALAR" or "ENCRYPTED"}``.
        """
        return {
            "name": self.name_edit.text().strip(),
            "kind": self.kind_combo.currentText(),
        }