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

from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
)

from ...core.manager import PasswordManager

from ..translate import translator, ENGLISH, FRENCH, SPANISH

from .common import _t


# ---------------------------------------------------------------------------
# Metadata dialog
# ---------------------------------------------------------------------------

class MetadataDialog(QDialog):
    """
    Small dialog to edit the manager's account metadata (username).

    Parameters
    ----------
    manager : PasswordManager
        Manager whose metadata is being edited, read to pre-fill the
        fields.
    parent : QWidget, optional
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_t("metadata_dialog_title"))

        layout = QFormLayout(self)

        self.username_edit = QLineEdit(manager.get_username() or "")
        layout.addRow(_t("username_label"), self.username_edit)

        version_label = QLabel(str(manager.get_version()))
        layout.addRow(_t("version_label"), version_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_t("ok_button"))
        buttons.button(QDialogButtonBox.Cancel).setText(_t("cancel_button"))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def apply_to(self, manager: PasswordManager) -> None:
        """Write the dialog's fields back into ``manager``'s metadata."""
        manager.set_username(self.username_edit.text().strip() or None)


# ---------------------------------------------------------------------------
# Account settings dialog
# ---------------------------------------------------------------------------

class AccountSettingsDialog(QDialog):
    """
    Dialog to edit theme, language and inactivity auto-close delay,
    all stored in the manager's metadata.

    Parameters
    ----------
    manager : PasswordManager
        Manager whose metadata is being edited, read to pre-fill the
        fields.
    current_theme : str
        Currently active theme ("light"/"dark"), used to pre-select
        the theme combo (kept separate from the metadata value in
        case the two have drifted apart within the session).
    parent : QWidget, optional
    """

    def __init__(self, manager: PasswordManager, current_theme: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_t("settings_dialog_title"))

        layout = QFormLayout(self)

        self.theme_combo = QComboBox()
        self.theme_combo.addItem(_t("theme_light"), "light")
        self.theme_combo.addItem(_t("theme_dark"), "dark")
        self.theme_combo.setCurrentIndex(
            self.theme_combo.findData(current_theme)
        )
        layout.addRow(_t("settings_theme_label"), self.theme_combo)

        self.language_combo = QComboBox()
        self.language_combo.addItem(_t("language_en"), ENGLISH)
        self.language_combo.addItem(_t("language_fr"), FRENCH)
        self.language_combo.addItem(_t("language_es"), SPANISH)
        self.language_combo.setCurrentIndex(
            self.language_combo.findData(translator.language)
        )
        layout.addRow(_t("settings_language_label"), self.language_combo)

        self.close_timer_edit = QLineEdit(str(manager.get_close_timer_s()))
        layout.addRow(_t("settings_close_timer_label"), self.close_timer_edit)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText(_t("ok_button"))
        self.buttons.button(QDialogButtonBox.Cancel).setText(_t("cancel_button"))
        self.buttons.accepted.connect(self._on_accept)
        self.buttons.rejected.connect(self.reject)
        layout.addRow(self.buttons)

    def _on_accept(self) -> None:
        try:
            close_timer_s = int(self.close_timer_edit.text().strip())
            if close_timer_s <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, _t("error_title"), _t("invalid_close_timer"))
            return
        self._close_timer_s = close_timer_s
        self.accept()

    def apply_to(self, manager: PasswordManager) -> tuple[str, str, int]:
        """
        Write the dialog's fields back into ``manager``'s metadata.

        Returns
        -------
        tuple of (str, str, int)
            ``(theme, language, close_timer_s)`` chosen, for the
            caller to apply immediately (theme/language take effect
            application-wide right away, not just on next launch).
        """
        theme = self.theme_combo.currentData()
        language = self.language_combo.currentData()
        close_timer_s = self._close_timer_s

        manager.set_theme(theme)
        manager.set_language(language)
        manager.set_close_timer_s(close_timer_s)

        return theme, language, close_timer_s


# ---------------------------------------------------------------------------
# Change credentials dialog
# ---------------------------------------------------------------------------

class ChangeCredentialsDialog(QDialog):
    """
    Dialog to change either the primary or the secondary password.

    Parameters
    ----------
    parent : QWidget, optional

    Notes
    -----
    Only the side being changed is collected here: the caller
    (`window.PasswordManagerWindow._open_change_credentials`) is
    responsible for carrying the other side over unchanged, using the
    manager's current :class:`Credentials` (see that method's Notes).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_t("credentials_dialog_title"))

        layout = QFormLayout(self)

        self.target_combo = QComboBox()
        self.target_combo.addItem(_t("credentials_change_primary"), "primary")
        self.target_combo.addItem(_t("credentials_change_secondary"), "secondary")
        layout.addRow(self.target_combo)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_toggle_btn = QPushButton(_t("show"))
        self.password_toggle_btn.setObjectName("smallButton")
        self.password_toggle_btn.setToolTip(_t("show_hide_tooltip"))
        self.password_toggle_btn.clicked.connect(self._toggle_password_mask)
        password_row = QHBoxLayout()
        password_row.addWidget(self.password_edit)
        password_row.addWidget(self.password_toggle_btn)
        layout.addRow(_t("credentials_password_label"), password_row)

        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_password_toggle_btn = QPushButton(_t("show"))
        self.confirm_password_toggle_btn.setObjectName("smallButton")
        self.confirm_password_toggle_btn.setToolTip(_t("show_hide_tooltip"))
        self.confirm_password_toggle_btn.clicked.connect(self._toggle_confirm_password_mask)
        confirm_password_row = QHBoxLayout()
        confirm_password_row.addWidget(self.confirm_password_edit)
        confirm_password_row.addWidget(self.confirm_password_toggle_btn)
        layout.addRow(_t("credentials_confirm_password_label"), confirm_password_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_t("ok_button"))
        buttons.button(QDialogButtonBox.Cancel).setText(_t("cancel_button"))
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _toggle_password_mask(self) -> None:
        masked = self.password_edit.echoMode() == QLineEdit.Password
        self.password_edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.password_toggle_btn.setText(_t("hide" if masked else "show"))

    def _toggle_confirm_password_mask(self) -> None:
        masked = self.confirm_password_edit.echoMode() == QLineEdit.Password
        self.confirm_password_edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.confirm_password_toggle_btn.setText(_t("hide" if masked else "show"))

    def _on_accept(self) -> None:
        password = self.password_edit.text()

        if not password:
            QMessageBox.warning(self, _t("error_title"), _t("credentials_empty_password"))
            return
        if password != self.confirm_password_edit.text():
            QMessageBox.warning(self, _t("error_title"), _t("credentials_password_mismatch"))
            return

        self.accept()

    def get_data(self) -> dict:
        """
        Return the collected side and password.

        Returns
        -------
        dict
            ``{"target": "primary" or "secondary", "password": bytearray}``.
        """
        return {
            "target": self.target_combo.currentData(),
            "password": bytearray(self.password_edit.text().encode("utf-8")),
        }
