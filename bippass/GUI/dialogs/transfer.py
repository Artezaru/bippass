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
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from ...core.credentials import Credentials
from ..translate import translator
from ..widgets import PasswordField, ok_cancel_buttons

if TYPE_CHECKING:
    from ...core.manager import PasswordManager


_DEFAULT_EXPORT_FILENAME = "export.encrypted"


def _build_credentials(primary: PasswordField, secondary: PasswordField) -> Credentials:
    """
    Build fresh credentials from two password fields.

    Parameters
    ----------
    primary : PasswordField
        Field holding the primary password.
    secondary : PasswordField
        Field holding the secondary password.

    Returns
    -------
    Credentials
        New credentials holding both passwords.
    """
    credentials = Credentials()
    credentials.set_primary_password(primary.to_bytearray())
    credentials.set_secondary_password(secondary.to_bytearray())
    return credentials


def _warn(parent: QDialog, message_key: str) -> None:
    """
    Show a translated validation warning.

    Parameters
    ----------
    parent : QDialog
        Dialog the message box is attached to.
    message_key : str
        Translation key of the message.
    """
    QMessageBox.warning(
        parent, translator.translate("common.error_title"), translator.translate(message_key)
    )


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
    browse_button = QPushButton(translator.translate("common.browse"))
    browse_button.setAutoDefault(False)
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
    Dialog to export a selection of items to a new, standalone vault
    file, encrypted with its own, freshly entered credentials.

    Parameters
    ----------
    manager : PasswordManager
        Manager whose vaults and items are listed for selection.
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    The items are read once, at construction time; the dialog does not
    refresh them while it is open.
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("export.dialog_title"))
        self.resize(480, 520)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(translator.translate("export.items_label")))
        self.items_list = QListWidget()
        for vault in manager.get_vaults():
            for item in vault.get_items():
                item_name = item.get("item_name") or translator.translate("common.unnamed_item")
                entry = QListWidgetItem(f"{vault.name} / {item_name}")
                entry.setFlags(entry.flags() | Qt.ItemIsUserCheckable)
                entry.setCheckState(Qt.Unchecked)
                entry.setData(Qt.UserRole, (item.uuid, vault.name))
                self.items_list.addItem(entry)
        layout.addWidget(self.items_list, stretch=1)

        self.primary_field = PasswordField()
        self.confirm_primary_field = PasswordField()
        self.secondary_field = PasswordField()
        self.confirm_secondary_field = PasswordField()

        form = QFormLayout()
        form.addRow(translator.translate("export.primary_password_label"), self.primary_field)
        form.addRow(
            translator.translate("export.confirm_primary_password_label"),
            self.confirm_primary_field,
        )
        form.addRow(translator.translate("export.secondary_password_label"), self.secondary_field)
        form.addRow(
            translator.translate("export.confirm_secondary_password_label"),
            self.confirm_secondary_field,
        )
        layout.addLayout(form)

        self.destination_edit = QLineEdit()
        self.destination_edit.setPlaceholderText(translator.translate("export.destination_label"))
        layout.addLayout(_path_row(self.destination_edit, self._browse_destination))

        layout.addWidget(ok_cancel_buttons(self, self._on_accept))

    def _checked_items(self) -> list[tuple[str, str]]:
        """
        Return the items checked for export.

        Returns
        -------
        list of (str, str)
            ``(item_uuid, vault_name)`` of every checked row.
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
            translator.translate("common.vault_files_filter"),
        )
        if path:
            self.destination_edit.setText(path)

    def _on_accept(self) -> None:
        """Accept the dialog if every field is valid, warn otherwise."""
        if not self._checked_items():
            _warn(self, "export.no_items_selected")
        elif not self.primary_field.text() or not self.secondary_field.text():
            _warn(self, "export.missing_password")
        elif (
            self.primary_field.text() != self.confirm_primary_field.text()
            or self.secondary_field.text() != self.confirm_secondary_field.text()
        ):
            _warn(self, "export.password_mismatch")
        elif not self.destination_edit.text().strip():
            _warn(self, "export.missing_destination")
        else:
            self.accept()

    def get_data(self) -> dict:
        """
        Return the selected items, the export credentials and the
        destination path.

        Returns
        -------
        dict
            ``{"items": list[(item_uuid, vault_name)], "credentials":
            Credentials, "path": str}``.
        """
        return {
            "items": self._checked_items(),
            "credentials": _build_credentials(self.primary_field, self.secondary_field),
            "path": self.destination_edit.text().strip(),
        }


# ---------------------------------------------------------------------------
# Import dialog
# ---------------------------------------------------------------------------

class ImportItemsDialog(QDialog):
    """
    Dialog to import the items of a standalone vault file (as written
    by :class:`ExportItemsDialog`) into the manager.

    Parameters
    ----------
    manager : PasswordManager
        Manager the items will be imported into; only used to list its
        vault names in :attr:`vault_combo`.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("import.dialog_title"))

        layout = QFormLayout(self)

        self.file_edit = QLineEdit()
        layout.addRow(
            translator.translate("import.file_label"),
            _path_row(self.file_edit, self._browse_file),
        )

        self.primary_field = PasswordField()
        self.secondary_field = PasswordField()
        layout.addRow(translator.translate("import.primary_password_label"), self.primary_field)
        layout.addRow(translator.translate("import.secondary_password_label"), self.secondary_field)

        # Editable, so a new vault can be named.
        self.vault_combo = QComboBox()
        self.vault_combo.setEditable(True)
        self.vault_combo.addItems([vault.name for vault in manager.get_vaults()])
        self.vault_combo.setEditText(translator.translate("import.default_vault_name"))
        layout.addRow(translator.translate("import.vault_label"), self.vault_combo)

        layout.addRow(ok_cancel_buttons(self, self._on_accept))

    def _browse_file(self) -> None:
        """Pick the file to import, starting in the user's home folder."""
        start = self.file_edit.text().strip() or str(Path.home())
        path, _filter = QFileDialog.getOpenFileName(
            self,
            translator.translate("import.select_file_title"),
            start,
            translator.translate("common.vault_files_filter"),
        )
        if path:
            self.file_edit.setText(path)

    def _on_accept(self) -> None:
        """Accept the dialog if every field is filled, warn otherwise."""
        if not self.file_edit.text().strip():
            _warn(self, "import.missing_file")
        elif not self.primary_field.text() or not self.secondary_field.text():
            _warn(self, "import.missing_password")
        elif not self.vault_combo.currentText().strip():
            _warn(self, "import.missing_vault")
        else:
            self.accept()

    def get_data(self) -> dict:
        """
        Return the file to import, its credentials and the target vault.

        Returns
        -------
        dict
            ``{"path": str, "credentials": Credentials, "vault": str}``.
        """
        return {
            "path": self.file_edit.text().strip(),
            "credentials": _build_credentials(self.primary_field, self.secondary_field),
            "vault": self.vault_combo.currentText().strip(),
        }