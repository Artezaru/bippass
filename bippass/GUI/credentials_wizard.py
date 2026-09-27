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

import json
from pathlib import Path

import pyaescbc

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
    QRadioButton,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

from ..core.manager import PasswordManager
from ..core.credentials import Credentials
from ..core.types import Metadata
from ..core.exceptions import (
    PrimaryPasswordError,
    SecondaryPasswordError,
    CorruptedBase64Error,
)
from ..core.profiles import profile_path, list_existing_profiles

from .manager_window import PasswordManagerWindow
from .translate import translator, credentials_gui_translation, ENGLISH, FRENCH, SPANISH


def _t(key: str, **kwargs: str) -> str:
    """Shorthand for ``translator.translate(key, credentials_gui_translation, **kwargs)``."""
    return translator.translate(key, credentials_gui_translation, **kwargs)

MEMORY_FILE_PATH = Path.home() / ".bippass" / "recent.json"

def _load_last_file_path() -> Path | None:
    """
    Return the last vault file path remembered in the memory file.

    Returns
    -------
    Path or None
        The remembered path, or ``None`` if there is no memory file
        yet, or it cannot be read/parsed.

    Notes
    -----
    Deliberately silent on any failure (missing file, corrupted JSON,
    permission error): this is only a convenience pre-fill, never
    something the rest of the app depends on.
    """
    try:
        raw = json.loads(MEMORY_FILE_PATH.read_text(encoding="utf-8"))
        return Path(raw["last_file"])
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        return None


def _remember_file_path(path: Path) -> None:
    """
    Record ``path`` as the last vault file opened or created.

    Parameters
    ----------
    path : Path
        Vault file path to remember for next time.

    Notes
    -----
    Best-effort: write failures (e.g. a read-only home directory) are
    silently ignored, for the same reason as :func:`_load_last_file_path`.
    """
    try:
        MEMORY_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        MEMORY_FILE_PATH.write_text(
            json.dumps({"last_file": str(path)}), encoding="utf-8",
        )
    except OSError:
        pass


def _build_language_combo(combo: QComboBox) -> None:
    """
    (Re)fill ``combo`` with the three supported languages, translated
    to the current display language, keeping the current selection.

    Shared by every page that carries its own language switcher (here,
    just :class:`_FilePage`), so they can't drift apart.
    """
    combo.blockSignals(True)
    combo.clear()
    combo.addItem(_t("language_en"), ENGLISH)
    combo.addItem(_t("language_fr"), FRENCH)
    combo.addItem(_t("language_es"), SPANISH)
    combo.setCurrentIndex(combo.findData(translator.language))
    combo.blockSignals(False)


# ---------------------------------------------------------------------------
# Unlock / create wizard
# ---------------------------------------------------------------------------

class _FilePage(QWizardPage):
    """
    Step 1: the launch screen -- pick an existing profile or vault
    file to open, or choose a username for a new profile. Also carries
    the wizard's language switcher (see :attr:`language_combo`), since
    this is the very first thing shown.

    Builds the :class:`PasswordManager` for the rest of the wizard,
    with an empty :class:`Credentials` instance that the next two
    pages fill in, but does not decrypt or authenticate anything yet.

    Notes
    -----
    A "profile" is simply a vault file living at the well-known
    location ``~/bippass/<username>.encrypted`` (see
    :mod:`core.profiles`). In OPEN mode, this page lists every such
    profile currently on disk as one-click choices, alongside a
    "Browse..." option for a vault file stored elsewhere. In CREATE
    mode, only a username is asked for: the destination is always
    ``~/bippass/<username>.encrypted``, and creation is refused if a
    profile with that username already exists -- there is no manual
    "choose where to save" step anymore, and no silent overwrite.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)

        top_layout = QHBoxLayout()
        mode_layout = QHBoxLayout()
        self.open_radio = QRadioButton()
        self.create_radio = QRadioButton()
        self.open_radio.setChecked(True)
        self.open_radio.toggled.connect(self._on_mode_changed)
        mode_layout.addWidget(self.open_radio)
        mode_layout.addWidget(self.create_radio)
        top_layout.addLayout(mode_layout)
        top_layout.addStretch()

        self.language_label = QLabel()
        self.language_combo = QComboBox()
        self.language_combo.currentIndexChanged.connect(self._on_language_changed)
        top_layout.addWidget(self.language_label)
        top_layout.addWidget(self.language_combo)
        layout.addLayout(top_layout)

        # -- OPEN mode: existing profiles, or browse for a file ------------

        self.profiles_label = QLabel()
        layout.addWidget(self.profiles_label)

        self.profiles_list = QListWidget()
        self.profiles_list.setMaximumHeight(140)
        self.profiles_list.itemClicked.connect(self._on_profile_clicked)
        layout.addWidget(self.profiles_list)

        self.browse_label = QLabel()
        layout.addWidget(self.browse_label)

        file_layout = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.textEdited.connect(self._on_file_edited)
        self.browse_button = QPushButton()
        self.browse_button.clicked.connect(self._browse)
        file_layout.addWidget(self.file_edit)
        file_layout.addWidget(self.browse_button)
        layout.addLayout(file_layout)

        # -- CREATE mode: username only (destination is derived) -----------

        self.username_label = QLabel()
        self.username_edit = QLineEdit()
        self.username_edit.textChanged.connect(self._update_destination_label)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_edit)

        self.destination_label = QLabel()
        self.destination_label.setObjectName("mutedLabel")
        self.destination_label.setWordWrap(True)
        layout.addWidget(self.destination_label)

        layout.addStretch()

        _build_language_combo(self.language_combo)
        self._retranslate_ui()

    def initializePage(self) -> None:
        self._refresh_profiles_list()
        if self.open_radio.isChecked() and not self.file_edit.text():
            last_path = _load_last_file_path()
            if last_path is not None:
                self.file_edit.setText(str(last_path))

    def _refresh_profiles_list(self) -> None:
        """(Re)populate :attr:`profiles_list` from what's currently on disk."""
        self.profiles_list.clear()
        for username in list_existing_profiles():
            item = QListWidgetItem(username)
            item.setData(Qt.UserRole, str(profile_path(username)))
            self.profiles_list.addItem(item)

    def _on_profile_clicked(self, item: QListWidgetItem) -> None:
        """Fill the file field from a clicked profile row."""
        self.file_edit.setText(item.data(Qt.UserRole))

    def _on_file_edited(self, _text: str) -> None:
        """A manual edit to the file field no longer matches a profile row."""
        self.profiles_list.clearSelection()

    def _on_language_changed(self, index: int) -> None:
        """Switch the display language and retranslate the whole wizard."""
        language = self.language_combo.itemData(index)
        if language is None or language == translator.language:
            return
        translator.set_language(language)
        wizard = self.wizard()
        if wizard is not None:
            wizard.retranslate_all()

    def _on_mode_changed(self) -> None:
        creating = self.create_radio.isChecked()
        self.setSubTitle(
            _t("file_page_subtitle_create") if creating
            else _t("file_page_subtitle_open")
        )

        self.profiles_label.setVisible(not creating)
        self.profiles_list.setVisible(not creating)
        self.browse_label.setVisible(not creating)
        self.file_edit.setVisible(not creating)
        self.browse_button.setVisible(not creating)

        self.username_label.setVisible(creating)
        self.username_edit.setVisible(creating)
        self.destination_label.setVisible(creating)
        if creating:
            self._update_destination_label()

    def _update_destination_label(self) -> None:
        """Show where a new profile would be saved, as the username is typed."""
        username = self.username_edit.text().strip()
        if not username:
            self.destination_label.setText("")
            return
        self.destination_label.setText(_t("destination_label", path=str(profile_path(username))))

    def _retranslate_ui(self) -> None:
        """Refresh every translated string on this page after a language change."""
        self.setTitle(_t("file_page_title"))
        self.open_radio.setText(_t("open_radio"))
        self.create_radio.setText(_t("create_radio"))

        self.language_label.setText(_t("language_label"))
        _build_language_combo(self.language_combo)

        self.profiles_label.setText(_t("existing_profiles_label"))
        self.browse_label.setText(_t("browse_label"))
        self.file_edit.setPlaceholderText(_t("file_path_placeholder"))
        self.browse_button.setText(_t("browse_button"))

        self.username_label.setText(_t("username_label"))
        self._update_destination_label()

        self._on_mode_changed()

    def _browse(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, _t("select_vault_file_dialog_title"), "",
            _t("vault_files_filter"),
        )
        if filename:
            self.file_edit.setText(filename)
            self.profiles_list.clearSelection()

    def validatePage(self) -> bool:
        wizard: CredentialsWizard = self.wizard()

        if self.create_radio.isChecked():
            return self._create_manager(wizard)
        return self._open_manager(wizard)

    def _create_manager(self, wizard: 'CredentialsWizard') -> bool:
        username = self.username_edit.text().strip()
        if not username:
            QMessageBox.warning(self, _t("missing_username_title"), _t("missing_username_message"))
            return False

        path = profile_path(username)
        if path.exists():
            QMessageBox.warning(
                self, _t("profile_exists_title"),
                _t("profile_exists_message", username=username),
            )
            return False

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.critical(
                self, _t("folder_error_title"),
                _t("folder_error_message", error=exc),
            )
            return False

        metadata: Metadata = {
            "username": username,
            "version": 1,
        }

        wizard.mode = "create"
        wizard.file_path = path
        wizard.credentials = Credentials()
        try:
            wizard.manager = PasswordManager.new(metadata, wizard.credentials)
        except Exception as exc:
            QMessageBox.critical(
                self, _t("unexpected_error_title"),
                _t("unexpected_error_message", error_type=type(exc).__name__, error=exc),
            )
            return False
        return True

    def _open_manager(self, wizard: 'CredentialsWizard') -> bool:
        path_text = self.file_edit.text().strip()
        if not path_text:
            QMessageBox.warning(self, _t("missing_file_title"), _t("missing_file_message"))
            return False
        path = Path(path_text)

        if not path.is_file():
            QMessageBox.warning(
                self, _t("file_not_found_title"),
                _t("file_not_found_message", path=str(path)),
            )
            return False

        try:
            data = bytearray(path.read_bytes())
        except OSError as exc:
            QMessageBox.critical(
                self, _t("read_error_title"),
                _t("read_error_message", error=exc),
            )
            return False

        wizard.mode = "open"
        wizard.file_path = path
        wizard.credentials = Credentials()
        wizard.manager = PasswordManager(data, wizard.credentials)
        return True


class _PrimaryPage(QWizardPage):
    """
    Step 2: primary password.
 
    In "open" mode, entering it attempts
    :meth:`PasswordManager.decrypt_data`; a wrong password keeps the
    user on this page. In "create" mode, it is simply recorded (with
    a confirmation field) as the new vault's primary password.
    """
 
    def __init__(self, parent=None):
        super().__init__(parent)
 
        layout = QFormLayout(self)
 
        self.password_label = QLabel()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_toggle_btn = QPushButton()
        self.password_toggle_btn.setObjectName("smallButton")
        self.password_toggle_btn.clicked.connect(self._toggle_password_mask)
        password_row = QHBoxLayout()
        password_row.addWidget(self.password_edit)
        password_row.addWidget(self.password_toggle_btn)
        layout.addRow(self.password_label, password_row)
 
        self.confirm_password_label = QLabel()
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_password_toggle_btn = QPushButton()
        self.confirm_password_toggle_btn.setObjectName("smallButton")
        self.confirm_password_toggle_btn.clicked.connect(self._toggle_confirm_password_mask)
        confirm_password_row = QHBoxLayout()
        confirm_password_row.addWidget(self.confirm_password_edit)
        confirm_password_row.addWidget(self.confirm_password_toggle_btn)
        layout.addRow(self.confirm_password_label, confirm_password_row)
 
        self._retranslate_ui()
 
    def initializePage(self) -> None:
        self._update_mode_texts()
 
    def _toggle_password_mask(self) -> None:
        masked = self.password_edit.echoMode() == QLineEdit.Password
        self.password_edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.password_toggle_btn.setText(_t("hide" if masked else "show"))
 
    def _toggle_confirm_password_mask(self) -> None:
        masked = self.confirm_password_edit.echoMode() == QLineEdit.Password
        self.confirm_password_edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.confirm_password_toggle_btn.setText(_t("hide" if masked else "show"))
 
    def _update_mode_texts(self) -> None:
        creating = self.wizard().mode == "create"
        self.setSubTitle(
            _t("primary_subtitle_create") if creating else _t("primary_subtitle_open")
        )
        self.confirm_password_label.setVisible(creating)
        self.confirm_password_edit.setVisible(creating)
        self.confirm_password_toggle_btn.setVisible(creating)
 
    def _retranslate_ui(self) -> None:
        """Refresh every translated string on this page after a language change."""
        self.setTitle(_t("primary_page_title"))
        self.password_label.setText(_t("password_label"))
        self.confirm_password_label.setText(_t("confirm_password_label"))
        self.password_toggle_btn.setToolTip(_t("show_hide_tooltip"))
        self.password_toggle_btn.setText(
            _t("hide" if self.password_edit.echoMode() == QLineEdit.Normal else "show")
        )
        self.confirm_password_toggle_btn.setToolTip(_t("show_hide_tooltip"))
        self.confirm_password_toggle_btn.setText(
            _t("hide" if self.confirm_password_edit.echoMode() == QLineEdit.Normal else "show")
        )
        # `self.wizard()` is still None at construction time (before
        # `addPage` inserts this page into the wizard), and
        # `_update_mode_texts` needs `wizard().mode`: skip it then --
        # `initializePage` (called by Qt right before this page is
        # actually shown) runs it with a real wizard in place.
        if self.wizard() is not None:
            self._update_mode_texts()
 
    def validatePage(self) -> bool:
        wizard: CredentialsWizard = self.wizard()
        password = self.password_edit.text()
 
        if not password:
            QMessageBox.warning(self, _t("missing_fields_title"), _t("missing_fields_message"))
            return False
 
        if wizard.mode == "create":
            if password != self.confirm_password_edit.text():
                QMessageBox.warning(self, _t("mismatch_title"), _t("mismatch_message"))
                return False
            wizard.credentials.set_primary_password(bytearray(password.encode("utf-8")))
            return True
 
        # Open mode: try to actually decrypt with this password.
        wizard.credentials.set_primary_password(bytearray(password.encode("utf-8")))
        try:
            wizard.manager.decrypt_data()
        except PrimaryPasswordError:
            QMessageBox.critical(
                self, _t("wrong_credentials_title"),
                _t("wrong_primary_credentials_message"),
            )
            return False
        except ValueError as exc:
            QMessageBox.critical(
                self, _t("invalid_vault_title"),
                _t("invalid_vault_message", error=exc),
            )
            return False
        except Exception as exc:
            QMessageBox.critical(
                self, _t("unexpected_error_title"),
                _t("unexpected_error_message", error_type=type(exc).__name__, error=exc),
            )
            return False
        return True
 
 
class _SecondaryPage(QWizardPage):
    """
    Step 3: secondary password.
 
    In "open" mode, entering it attempts
    :meth:`PasswordManager.check_secondary`; a wrong password keeps
    the user on this page. In "create" mode, it is recorded (with
    confirmation fields), and the brand-new vault is written to disk
    right away via :meth:`PasswordManager.save_changes`, so nothing is
    lost even if the app closes before the user explicitly saves again.
    """
 
    def __init__(self, parent=None):
        super().__init__(parent)
 
        layout = QFormLayout(self)
 
        self.password_label = QLabel()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_toggle_btn = QPushButton()
        self.password_toggle_btn.setObjectName("smallButton")
        self.password_toggle_btn.clicked.connect(self._toggle_password_mask)
        password_row = QHBoxLayout()
        password_row.addWidget(self.password_edit)
        password_row.addWidget(self.password_toggle_btn)
        layout.addRow(self.password_label, password_row)
 
        self.confirm_password_label = QLabel()
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_password_toggle_btn = QPushButton()
        self.confirm_password_toggle_btn.setObjectName("smallButton")
        self.confirm_password_toggle_btn.clicked.connect(self._toggle_confirm_password_mask)
        confirm_password_row = QHBoxLayout()
        confirm_password_row.addWidget(self.confirm_password_edit)
        confirm_password_row.addWidget(self.confirm_password_toggle_btn)
        layout.addRow(self.confirm_password_label, confirm_password_row)
 
        self._retranslate_ui()
 
    def initializePage(self) -> None:
        self._update_mode_texts()
 
    def _toggle_password_mask(self) -> None:
        masked = self.password_edit.echoMode() == QLineEdit.Password
        self.password_edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.password_toggle_btn.setText(_t("hide" if masked else "show"))
 
    def _toggle_confirm_password_mask(self) -> None:
        masked = self.confirm_password_edit.echoMode() == QLineEdit.Password
        self.confirm_password_edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.confirm_password_toggle_btn.setText(_t("hide" if masked else "show"))
 
    def _update_mode_texts(self) -> None:
        creating = self.wizard().mode == "create"
        self.setSubTitle(
            _t("secondary_subtitle_create") if creating else _t("secondary_subtitle_open")
        )
        self.confirm_password_label.setVisible(creating)
        self.confirm_password_edit.setVisible(creating)
        self.confirm_password_toggle_btn.setVisible(creating)
 
    def _retranslate_ui(self) -> None:
        """Refresh every translated string on this page after a language change."""
        self.setTitle(_t("secondary_page_title"))
        self.password_label.setText(_t("password_label"))
        self.confirm_password_label.setText(_t("confirm_password_label"))
        self.password_toggle_btn.setToolTip(_t("show_hide_tooltip"))
        self.password_toggle_btn.setText(
            _t("hide" if self.password_edit.echoMode() == QLineEdit.Normal else "show")
        )
        self.confirm_password_toggle_btn.setToolTip(_t("show_hide_tooltip"))
        self.confirm_password_toggle_btn.setText(
            _t("hide" if self.confirm_password_edit.echoMode() == QLineEdit.Normal else "show")
        )
        # See the identical guard/comment in `_PrimaryPage._retranslate_ui`.
        if self.wizard() is not None:
            self._update_mode_texts()
 
    def validatePage(self) -> bool:
        wizard: CredentialsWizard = self.wizard()
        password = self.password_edit.text()
 
        if not password:
            QMessageBox.warning(self, _t("missing_fields_title"), _t("missing_fields_message"))
            return False
 
        if wizard.mode == "create":
            if password != self.confirm_password_edit.text():
                QMessageBox.warning(self, _t("mismatch_title"), _t("mismatch_message"))
                return False
            wizard.credentials.set_secondary_password(bytearray(password.encode("utf-8")))
            try:
                wizard.manager.save_changes(wizard.file_path)
            except OSError as exc:
                QMessageBox.critical(
                    self, _t("write_error_title"),
                    _t("write_error_message", error=exc),
                )
                return False
            _remember_file_path(wizard.file_path)
            return True
 
        # Open mode: try to actually validate this password.
        wizard.credentials.set_secondary_password(bytearray(password.encode("utf-8")))
        try:
            wizard.manager.check_secondary()
        except SecondaryPasswordError:
            QMessageBox.critical(
                self, _t("wrong_credentials_title"),
                _t("wrong_secondary_credentials_message"),
            )
            return False
        except CorruptedBase64Error:
            QMessageBox.critical(
                self, _t("corrupted_vault_title"),
                _t("corrupted_vault_message"),
            )
            return False
        except Exception as exc:
            QMessageBox.critical(
                self, _t("unexpected_error_title"),
                _t("unexpected_error_message", error_type=type(exc).__name__, error=exc),
            )
            return False
 
        _remember_file_path(wizard.file_path)
        return True


class CredentialsWizard(QWizard):
    """
    Three-step wizard to open an existing vault or create a new one.

    1. :class:`_FilePage`, the launch screen: pick an existing
       profile (or browse for a vault file stored elsewhere) to open,
       or choose a username for a new profile -- saved at
       ``~/bippass/<username>.encrypted`` -- and build an inert
       :class:`PasswordManager` with an empty :class:`Credentials`.
       Also carries the wizard's language switcher.

    2. :class:`_PrimaryPage`, enter (open) or choose (create) the
       primary password.

    3. :class:`_SecondaryPage`, enter (open) or choose (create) the
       secondary password.

    On success, opens the main :class:`PasswordManagerWindow` itself
    (see :attr:`window`) rather than leaving that to the caller.

    Attributes
    ----------
    mode : str
        ``"open"`` or ``"create"``, set by :class:`_FilePage`.

    file_path : Path or None
        The vault file being opened or created.

    credentials : Credentials
        Shared, filled in progressively by pages 2 and 3.

    manager : PasswordManager or None
        Built by :class:`_FilePage`; fully usable once all three
        pages have completed.

    window : PasswordManagerWindow or None
        The main window opened on success. Kept as an attribute so it
        is not garbage-collected once the wizard itself closes.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("BIPPASS")
        self.setOption(QWizard.NoBackButtonOnStartPage, True)

        self.mode: str = "open"
        self.file_path: Path | None = None
        self.credentials: Credentials = Credentials()
        self.manager: PasswordManager | None = None
        self.window: PasswordManagerWindow | None = None

        self._file_page = _FilePage(self)
        self._primary_page = _PrimaryPage(self)
        self._secondary_page = _SecondaryPage(self)

        self.addPage(self._file_page)
        self.addPage(self._primary_page)
        self.addPage(self._secondary_page)

        self.finished.connect(self._on_finished)

    def retranslate_all(self) -> None:
        """Refresh every translated string on every page, e.g. after a language change."""
        self._file_page._retranslate_ui()
        self._primary_page._retranslate_ui()
        self._secondary_page._retranslate_ui()

    def _on_finished(self, result: int) -> None:
        if result != QDialog.Accepted:
            return
        self.window = PasswordManagerWindow(self.manager, self.file_path)
        self.window.show()