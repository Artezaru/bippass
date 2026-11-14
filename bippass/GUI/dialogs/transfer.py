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

from pathlib import Path
from typing import TYPE_CHECKING, Callable

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
)

from ...core.profiles import PROFILE_EXTENSION
from ..common import item_display_name, vault_display_name
from ..translate import translator
from ..widgets import NewPasswordFields, PasswordField, ok_cancel_buttons, small_button, warn

if TYPE_CHECKING:
    from ...core.manager import PasswordManager


_DEFAULT_EXPORT_FILENAME = f"export{PROFILE_EXTENSION}"


def _path_row(edit: QLineEdit, on_browse: Callable[[], None]) -> QHBoxLayout:
    """
    Build a path field with a "Browse..." button next to it.

    Parameters
    ----------
    edit : QLineEdit
        Field holding the path.
    on_browse : callable
        Called when "Browse..." is clicked.

    Returns
    -------
    QHBoxLayout
        The row, to be added to the dialog's layout.
    """
    browse_button = small_button(translator.translate("common.browse"))
    browse_button.clicked.connect(on_browse)
    row = QHBoxLayout()
    row.addWidget(edit, stretch=1)
    row.addWidget(browse_button)
    return row


# ---------------------------------------------------------------------------
# Export dialog
# ---------------------------------------------------------------------------

class ExportItemsDialog(QDialog):
    """
    Dialog to export a selection of items to a new, standalone profile
    file, protected by two freshly chosen passwords.

    Parameters
    ----------
    manager : PasswordManager
        Unlocked manager whose items are listed for selection.
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    The items are read once, at construction time. The passwords are
    meant to be shared with the recipient: they are not this profile's
    own.
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("export.dialog_title"))
        self.resize(480, 560)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(tr("export.items_label")))
        self.items_list = QListWidget()
        for vault in manager.get_vaults():
            for item in vault.sorted_items():
                entry = QListWidgetItem(f"{vault_display_name(vault)} / {item_display_name(item)}")
                entry.setFlags(entry.flags() | Qt.ItemIsUserCheckable)
                entry.setCheckState(Qt.Unchecked)
                entry.setData(Qt.UserRole, item.uuid)
                self.items_list.addItem(entry)
        layout.addWidget(self.items_list, stretch=1)

        form = QFormLayout()
        self.vault_name_edit = QLineEdit(tr("export.default_vault_name"))
        form.addRow(tr("export.vault_name_label"), self.vault_name_edit)
        self.primary_fields = NewPasswordFields(
            form, tr("export.primary_password_label"), tr("export.confirm_primary_password_label")
        )
        self.secondary_fields = NewPasswordFields(
            form, tr("export.secondary_password_label"), tr("export.confirm_secondary_password_label")
        )
        layout.addLayout(form)

        self.destination_edit = QLineEdit()
        self.destination_edit.setPlaceholderText(tr("export.destination_label"))
        layout.addLayout(_path_row(self.destination_edit, self._browse_destination))
        layout.addWidget(ok_cancel_buttons(self, self._on_accept))

    def _clear(self) -> None:
        """Erase every typed password."""
        self.primary_fields.clear()
        self.secondary_fields.clear()

    def _checked_uuids(self) -> list[str]:
        """
        Return the items checked for export.

        Returns
        -------
        list of str
            UUIDs of every checked row, in list order.
        """
        return [
            self.items_list.item(row).data(Qt.UserRole)
            for row in range(self.items_list.count())
            if self.items_list.item(row).checkState() == Qt.Checked
        ]

    def _browse_destination(self) -> None:
        """Pick the destination file, starting in the user's home folder."""
        start = self.destination_edit.text().strip() or str(Path.home() / _DEFAULT_EXPORT_FILENAME)
        path, _filter = QFileDialog.getSaveFileName(
            self,
            translator.translate("export.select_file_title"),
            start,
            translator.translate("common.profile_files_filter"),
        )
        if path:
            if not Path(path).suffix:
                path += PROFILE_EXTENSION
            self.destination_edit.setText(path)

    def _on_accept(self) -> None:
        """Accept the dialog if every field is valid, warn otherwise."""
        problems = {self.primary_fields.problem(), self.secondary_fields.problem()}
        if not self._checked_uuids():
            warn(self, "export.no_items_selected")
        elif "empty" in problems:
            warn(self, "export.missing_password")
        elif "mismatch" in problems:
            warn(self, "export.password_mismatch")
        elif not self.destination_edit.text().strip():
            warn(self, "export.missing_destination")
        else:
            self.accept()

    def reject(self) -> None:
        """Erase the typed passwords, then close."""
        self._clear()
        super().reject()

    def get_data(self) -> dict:
        """
        Return the export settings, then erase the password fields.

        Returns
        -------
        dict
            ``{"item_uuids": list[str], "vault_name": str or None,
            "primary": bytearray, "secondary": bytearray, "path": str}``.
            The caller owns both password buffers; passing them to
            :meth:`PasswordManager.export_items` erases them.
        """
        data = {
            "item_uuids": self._checked_uuids(),
            "vault_name": self.vault_name_edit.text().strip() or None,
            "primary": self.primary_fields.to_bytearray(),
            "secondary": self.secondary_fields.to_bytearray(),
            "path": self.destination_edit.text().strip(),
        }
        self._clear()
        return data


# ---------------------------------------------------------------------------
# Import dialog
# ---------------------------------------------------------------------------

class ImportItemsDialog(QDialog):
    """
    Dialog to import every item of another profile file (typically
    written by :class:`ExportItemsDialog`) into a vault of the manager.

    Parameters
    ----------
    manager : PasswordManager
        Unlocked manager receiving the items; its vaults are listed as
        possible targets, after the default "new vault" entry.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("import.dialog_title"))
        layout = QFormLayout(self)

        self.file_edit = QLineEdit()
        layout.addRow(tr("import.file_label"), _path_row(self.file_edit, self._browse_file))

        self.primary_field = PasswordField()
        self.secondary_field = PasswordField()
        layout.addRow(tr("import.primary_password_label"), self.primary_field)
        layout.addRow(tr("import.secondary_password_label"), self.secondary_field)

        # Several vaults may share a name: each entry carries its UUID.
        self.vault_combo = QComboBox()
        self.vault_combo.addItem(
            tr("import.new_vault_entry", name=tr("import.new_vault_name")), None
        )
        for vault in manager.get_vaults():
            self.vault_combo.addItem(vault_display_name(vault), vault.uuid)
        layout.addRow(tr("import.vault_label"), self.vault_combo)
        layout.addRow(ok_cancel_buttons(self, self._on_accept))

    def _browse_file(self) -> None:
        """Pick the file to import, starting in the user's home folder."""
        start = self.file_edit.text().strip() or str(Path.home())
        path, _filter = QFileDialog.getOpenFileName(
            self,
            translator.translate("import.select_file_title"),
            start,
            translator.translate("common.profile_files_filter"),
        )
        if path:
            self.file_edit.setText(path)

    def _on_accept(self) -> None:
        """Accept the dialog if every field is filled, warn otherwise."""
        if not self.file_edit.text().strip():
            warn(self, "import.missing_file")
        elif not self.primary_field.text() or not self.secondary_field.text():
            warn(self, "import.missing_password")
        else:
            self.accept()

    def reject(self) -> None:
        """Erase the typed passwords, then close."""
        self.primary_field.clear()
        self.secondary_field.clear()
        super().reject()

    def get_data(self) -> dict:
        """
        Return the file to import, its passwords and the target vault,
        then erase the password fields.

        Returns
        -------
        dict
            ``{"path": str, "primary": bytearray, "secondary": bytearray,
            "vault_uuid": str or None}``, ``None`` meaning a new vault.
            The caller owns both password buffers; passing them to
            :meth:`PasswordManager.import_items` erases them.
        """
        data = {
            "path": self.file_edit.text().strip(),
            "primary": self.primary_field.to_bytearray(),
            "secondary": self.secondary_field.to_bytearray(),
            "vault_uuid": self.vault_combo.currentData(),
        }
        self.primary_field.clear()
        self.secondary_field.clear()
        return data
