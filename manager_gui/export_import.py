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

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
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

from ...core.manager import PasswordManager
from ...core.credentials import Credentials

from .common import _t


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
        Manager whose vaults/items are listed for selection.
    parent : QWidget, optional

    Notes
    -----
    The listed items are read once, at construction time
    (:meth:`PasswordManager.get_vaults`/:meth:`Vault.get_items`); the
    dialog does not refresh them while it is open.
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_t("export_dialog_title"))
        self.resize(480, 520)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(_t("export_items_label")))

        self.items_list = QListWidget()
        for vault in manager.get_vaults():
            for item in vault.get_items():
                item_name = item.get("item_name") or _t("unnamed_item")
                list_item = QListWidgetItem(f"{vault.name} / {item_name}")
                list_item.setFlags(list_item.flags() | Qt.ItemIsUserCheckable)
                list_item.setCheckState(Qt.Unchecked)
                list_item.setData(Qt.UserRole, (item.uuid, vault.name))
                self.items_list.addItem(list_item)
        layout.addWidget(self.items_list, stretch=1)

        credentials_form = QFormLayout()

        self.primary_password_edit = QLineEdit()
        self.primary_password_edit.setEchoMode(QLineEdit.Password)
        self.primary_toggle_btn = QPushButton(_t("show"))
        self.primary_toggle_btn.setObjectName("smallButton")
        self.primary_toggle_btn.clicked.connect(self._toggle_primary_mask)
        primary_row = QHBoxLayout()
        primary_row.addWidget(self.primary_password_edit)
        primary_row.addWidget(self.primary_toggle_btn)
        credentials_form.addRow(_t("export_primary_password_label"), primary_row)

        self.confirm_primary_password_edit = QLineEdit()
        self.confirm_primary_password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_primary_toggle_btn = QPushButton(_t("show"))
        self.confirm_primary_toggle_btn.setObjectName("smallButton")
        self.confirm_primary_toggle_btn.clicked.connect(self._toggle_confirm_primary_mask)
        confirm_primary_row = QHBoxLayout()
        confirm_primary_row.addWidget(self.confirm_primary_password_edit)
        confirm_primary_row.addWidget(self.confirm_primary_toggle_btn)
        credentials_form.addRow(_t("export_confirm_primary_password_label"), confirm_primary_row)

        self.secondary_password_edit = QLineEdit()
        self.secondary_password_edit.setEchoMode(QLineEdit.Password)
        self.secondary_toggle_btn = QPushButton(_t("show"))
        self.secondary_toggle_btn.setObjectName("smallButton")
        self.secondary_toggle_btn.clicked.connect(self._toggle_secondary_mask)
        secondary_row = QHBoxLayout()
        secondary_row.addWidget(self.secondary_password_edit)
        secondary_row.addWidget(self.secondary_toggle_btn)
        credentials_form.addRow(_t("export_secondary_password_label"), secondary_row)

        self.confirm_secondary_password_edit = QLineEdit()
        self.confirm_secondary_password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_secondary_toggle_btn = QPushButton(_t("show"))
        self.confirm_secondary_toggle_btn.setObjectName("smallButton")
        self.confirm_secondary_toggle_btn.clicked.connect(self._toggle_confirm_secondary_mask)
        confirm_secondary_row = QHBoxLayout()
        confirm_secondary_row.addWidget(self.confirm_secondary_password_edit)
        confirm_secondary_row.addWidget(self.confirm_secondary_toggle_btn)
        credentials_form.addRow(_t("export_confirm_secondary_password_label"), confirm_secondary_row)

        layout.addLayout(credentials_form)

        destination_row = QHBoxLayout()
        self.destination_edit = QLineEdit()
        self.destination_edit.setPlaceholderText(_t("export_destination_label"))
        self.browse_button = QPushButton(_t("browse_button"))
        self.browse_button.clicked.connect(self._browse_destination)
        destination_row.addWidget(self.destination_edit, stretch=1)
        destination_row.addWidget(self.browse_button)
        layout.addLayout(destination_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_t("ok_button"))
        buttons.button(QDialogButtonBox.Cancel).setText(_t("cancel_button"))
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _toggle_primary_mask(self) -> None:
        masked = self.primary_password_edit.echoMode() == QLineEdit.Password
        self.primary_password_edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.primary_toggle_btn.setText(_t("hide" if masked else "show"))

    def _toggle_confirm_primary_mask(self) -> None:
        masked = self.confirm_primary_password_edit.echoMode() == QLineEdit.Password
        self.confirm_primary_password_edit.setEchoMode(
            QLineEdit.Normal if masked else QLineEdit.Password
        )
        self.confirm_primary_toggle_btn.setText(_t("hide" if masked else "show"))

    def _toggle_secondary_mask(self) -> None:
        masked = self.secondary_password_edit.echoMode() == QLineEdit.Password
        self.secondary_password_edit.setEchoMode(
            QLineEdit.Normal if masked else QLineEdit.Password
        )
        self.secondary_toggle_btn.setText(_t("hide" if masked else "show"))

    def _toggle_confirm_secondary_mask(self) -> None:
        masked = self.confirm_secondary_password_edit.echoMode() == QLineEdit.Password
        self.confirm_secondary_password_edit.setEchoMode(
            QLineEdit.Normal if masked else QLineEdit.Password
        )
        self.confirm_secondary_toggle_btn.setText(_t("hide" if masked else "show"))

    def _browse_destination(self) -> None:
        """Prompt for the destination file, defaulting to the user's home directory."""
        default_dir = self.destination_edit.text().strip() or str(Path.home())
        path, _filter = QFileDialog.getSaveFileName(
            self,
            _t("select_export_file_dialog_title"),
            default_dir,
            _t("vault_files_filter"),
        )
        if path:
            self.destination_edit.setText(path)

    def _on_accept(self) -> None:
        if not any(
            self.items_list.item(row).checkState() == Qt.Checked
            for row in range(self.items_list.count())
        ):
            QMessageBox.warning(self, _t("error_title"), _t("export_no_items_selected"))
            return

        primary = self.primary_password_edit.text()
        secondary = self.secondary_password_edit.text()
        if not primary or not secondary:
            QMessageBox.warning(self, _t("error_title"), _t("export_missing_password"))
            return
        if primary != self.confirm_primary_password_edit.text():
            QMessageBox.warning(self, _t("error_title"), _t("export_password_mismatch"))
            return
        if secondary != self.confirm_secondary_password_edit.text():
            QMessageBox.warning(self, _t("error_title"), _t("export_password_mismatch"))
            return

        if not self.destination_edit.text().strip():
            QMessageBox.warning(self, _t("error_title"), _t("export_missing_destination"))
            return

        self.accept()

    def get_data(self) -> dict:
        """
        Return the selected items, freshly built export credentials,
        and the chosen destination path.

        Returns
        -------
        dict
            ``{"items": list[(item_uuid, vault_name)], "credentials":
            Credentials, "path": str}``.
        """
        items = [
            self.items_list.item(row).data(Qt.UserRole)
            for row in range(self.items_list.count())
            if self.items_list.item(row).checkState() == Qt.Checked
        ]

        credentials = Credentials()
        credentials.set_primary_password(
            bytearray(self.primary_password_edit.text().encode("utf-8"))
        )
        credentials.set_secondary_password(
            bytearray(self.secondary_password_edit.text().encode("utf-8"))
        )

        return {
            "items": items,
            "credentials": credentials,
            "path": self.destination_edit.text().strip(),
        }


# ---------------------------------------------------------------------------
# Import dialog
# ---------------------------------------------------------------------------


class ImportItemsDialog(QDialog):
    """
    Dialog to import the items from a standalone vault file (as
    written by :class:`ExportItemsDialog`/:meth:`PasswordManager._export_items`)
    into an existing manager.

    Parameters
    ----------
    manager : PasswordManager
        Manager the imported items will be added to; used only to
        pre-fill :attr:`vault_combo` with the current vault names.
    parent : QWidget, optional
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_t("import_dialog_title"))

        layout = QFormLayout(self)

        file_row = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.browse_button = QPushButton(_t("browse_button"))
        self.browse_button.clicked.connect(self._browse_file)
        file_row.addWidget(self.file_edit, stretch=1)
        file_row.addWidget(self.browse_button)
        layout.addRow(_t("import_file_label"), file_row)

        self.primary_password_edit = QLineEdit()
        self.primary_password_edit.setEchoMode(QLineEdit.Password)
        self.primary_toggle_btn = QPushButton(_t("show"))
        self.primary_toggle_btn.setObjectName("smallButton")
        self.primary_toggle_btn.clicked.connect(self._toggle_primary_mask)
        primary_row = QHBoxLayout()
        primary_row.addWidget(self.primary_password_edit)
        primary_row.addWidget(self.primary_toggle_btn)
        layout.addRow(_t("import_primary_password_label"), primary_row)

        self.secondary_password_edit = QLineEdit()
        self.secondary_password_edit.setEchoMode(QLineEdit.Password)
        self.secondary_toggle_btn = QPushButton(_t("show"))
        self.secondary_toggle_btn.setObjectName("smallButton")
        self.secondary_toggle_btn.clicked.connect(self._toggle_secondary_mask)
        secondary_row = QHBoxLayout()
        secondary_row.addWidget(self.secondary_password_edit)
        secondary_row.addWidget(self.secondary_toggle_btn)
        layout.addRow(_t("import_secondary_password_label"), secondary_row)

        self.vault_combo = QComboBox()
        self.vault_combo.setEditable(True)
        for vault in manager.get_vaults():
            self.vault_combo.addItem(vault.name)
        self.vault_combo.setEditText(_t("default_import_vault_name"))
        layout.addRow(_t("import_vault_label"), self.vault_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_t("ok_button"))
        buttons.button(QDialogButtonBox.Cancel).setText(_t("cancel_button"))
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _toggle_primary_mask(self) -> None:
        masked = self.primary_password_edit.echoMode() == QLineEdit.Password
        self.primary_password_edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.primary_toggle_btn.setText(_t("hide" if masked else "show"))

    def _toggle_secondary_mask(self) -> None:
        masked = self.secondary_password_edit.echoMode() == QLineEdit.Password
        self.secondary_password_edit.setEchoMode(
            QLineEdit.Normal if masked else QLineEdit.Password
        )
        self.secondary_toggle_btn.setText(_t("hide" if masked else "show"))

    def _browse_file(self) -> None:
        """Prompt for the file to import, defaulting to the user's home directory."""
        default_dir = self.file_edit.text().strip() or str(Path.home())
        path, _filter = QFileDialog.getOpenFileName(
            self,
            _t("select_import_file_dialog_title"),
            default_dir,
            _t("vault_files_filter"),
        )
        if path:
            self.file_edit.setText(path)

    def _on_accept(self) -> None:
        if not self.file_edit.text().strip():
            QMessageBox.warning(self, _t("error_title"), _t("import_missing_file"))
            return

        if not self.primary_password_edit.text() or not self.secondary_password_edit.text():
            QMessageBox.warning(self, _t("error_title"), _t("import_missing_password"))
            return

        if not self.vault_combo.currentText().strip():
            QMessageBox.warning(self, _t("error_title"), _t("import_missing_vault"))
            return

        self.accept()

    def get_data(self) -> dict:
        """
        Return the chosen file, freshly built import credentials, and
        target vault name.

        Returns
        -------
        dict
            ``{"path": str, "credentials": Credentials, "vault": str}``.
        """
        credentials = Credentials()
        credentials.set_primary_password(
            bytearray(self.primary_password_edit.text().encode("utf-8"))
        )
        credentials.set_secondary_password(
            bytearray(self.secondary_password_edit.text().encode("utf-8"))
        )

        return {
            "path": self.file_edit.text().strip(),
            "credentials": credentials,
            "vault": self.vault_combo.currentText().strip(),
        }
