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

from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtWidgets import (
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
    QWidget,
    QWizard,
    QWizardPage,
)

from ..core.credentials import Credentials
from ..core.exceptions import (
    CorruptedBase64Error,
    PrimaryPasswordError,
    SecondaryPasswordError,
)
from ..core.manager import PasswordManager
from ..core.profiles import list_existing_profiles, profile_path
from ..core.types import Metadata
from .translate import translator
from .widgets import LanguageComboBox, PasswordField
from .window import PasswordManagerWindow


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WIZARD_TITLE = "BIPPASS"

# Remembers the last vault file opened or created, to pre-fill the
# first page.
RECENT_FILE_PATH = Path.home() / ".bippass" / "recent.json"

MODE_OPEN = "open"
MODE_CREATE = "create"

_NEW_PROFILE_FORMAT_VERSION = 1
_PROFILES_LIST_MAX_HEIGHT_PX = 140


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_last_file_path() -> Path | None:
    """
    Return the last vault file opened or created.

    Returns
    -------
    Path or None
        The remembered path, or ``None`` if nothing is remembered or
        the file can't be read.

    Notes
    -----
    Failures are silent: this is only a convenience pre-fill.
    """
    try:
        recent = json.loads(RECENT_FILE_PATH.read_text(encoding="utf-8"))
        return Path(recent["last_file"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _remember_file_path(path: Path) -> None:
    """
    Remember a vault file as the last one opened or created.

    Parameters
    ----------
    path : Path
        Vault file to remember.

    Notes
    -----
    Best effort: a write failure (e.g. read-only home folder) is
    ignored.
    """
    try:
        RECENT_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        RECENT_FILE_PATH.write_text(json.dumps({"last_file": str(path)}), encoding="utf-8")
    except OSError:
        pass


def _warn(parent: QWidget, title_key: str, message: str) -> None:
    """
    Show a warning message box.

    Parameters
    ----------
    parent : QWidget
        Parent of the message box.
    title_key : str
        Translation key of the title.
    message : str
        Message, already translated.
    """
    QMessageBox.warning(parent, translator.translate(title_key), message)


def _error(parent: QWidget, title_key: str, message: str) -> None:
    """
    Show an error message box.

    Parameters
    ----------
    parent : QWidget
        Parent of the message box.
    title_key : str
        Translation key of the title.
    message : str
        Message, already translated.
    """
    QMessageBox.critical(parent, translator.translate(title_key), message)


def _unexpected_error(parent: QWidget, exc: Exception) -> None:
    """
    Show an unexpected error with its type.

    Parameters
    ----------
    parent : QWidget
        Parent of the message box.
    exc : Exception
        The error.
    """
    _error(
        parent,
        "wizard.unexpected_error_title",
        translator.translate(
            "wizard.unexpected_error_message", error_type=type(exc).__name__, error=str(exc)
        ),
    )


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

class _FilePage(QWizardPage):
    """
    Step 1: pick a profile or vault file to open, or a username for a
    new profile. Also holds the wizard's language switcher.

    Builds the wizard's :class:`PasswordManager` with empty
    :class:`Credentials`, filled by the next two pages; nothing is
    decrypted yet.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    A profile is a vault file at ``~/.bippass/profiles/<username>.encrypted``
    (see :mod:`core.profiles`). Opening lists the existing profiles
    and allows browsing for a file stored elsewhere; creating only asks
    for a username and refuses one that is already taken.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        top_row = QHBoxLayout()
        self.open_radio = QRadioButton()
        self.create_radio = QRadioButton()
        self.open_radio.setChecked(True)
        self.open_radio.toggled.connect(self._on_mode_changed)
        top_row.addWidget(self.open_radio)
        top_row.addWidget(self.create_radio)
        top_row.addStretch()

        self.language_label = QLabel()
        self.language_combo = LanguageComboBox()
        self.language_combo.currentIndexChanged.connect(self._on_language_changed)
        top_row.addWidget(self.language_label)
        top_row.addWidget(self.language_combo)
        layout.addLayout(top_row)

        # Open mode: existing profiles, or any vault file
        self.profiles_label = QLabel()
        layout.addWidget(self.profiles_label)

        self.profiles_list = QListWidget()
        self.profiles_list.setMaximumHeight(_PROFILES_LIST_MAX_HEIGHT_PX)
        self.profiles_list.itemClicked.connect(self._on_profile_clicked)
        layout.addWidget(self.profiles_list)

        self.browse_label = QLabel()
        layout.addWidget(self.browse_label)

        file_row = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.textEdited.connect(self.profiles_list.clearSelection)
        self.browse_button = QPushButton()
        self.browse_button.clicked.connect(self._browse)
        file_row.addWidget(self.file_edit)
        file_row.addWidget(self.browse_button)
        layout.addLayout(file_row)

        # Create mode: username only, the file path is derived from it
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

        self.retranslate()
        translator.language_changed.connect(self.retranslate)

    def initializePage(self) -> None:
        """List the profiles on disk and pre-fill the last file opened."""
        self._refresh_profiles_list()
        if self.open_radio.isChecked() and not self.file_edit.text():
            last_path = _load_last_file_path()
            if last_path is not None:
                self.file_edit.setText(str(last_path))

    @pyqtSlot()
    def retranslate(self) -> None:
        """Refresh every text of the page."""
        tr = translator.translate
        self.setTitle(tr("wizard.file_page_title"))
        self.open_radio.setText(tr("wizard.open_radio"))
        self.create_radio.setText(tr("wizard.create_radio"))
        self.language_label.setText(tr("wizard.language_label"))
        self.profiles_label.setText(tr("wizard.existing_profiles_label"))
        self.browse_label.setText(tr("wizard.browse_label"))
        self.file_edit.setPlaceholderText(tr("wizard.file_path_placeholder"))
        self.browse_button.setText(tr("common.browse"))
        self.username_label.setText(tr("common.username_label"))
        self._on_mode_changed()

    def _refresh_profiles_list(self) -> None:
        """Fill :attr:`profiles_list` with the profiles currently on disk."""
        self.profiles_list.clear()
        for username in list_existing_profiles():
            row = QListWidgetItem(username)
            row.setData(Qt.UserRole, str(profile_path(username)))
            self.profiles_list.addItem(row)

    def _on_profile_clicked(self, row: QListWidgetItem) -> None:
        """
        Fill the file field with a clicked profile's file.

        Parameters
        ----------
        row : QListWidgetItem
            The clicked profile row.
        """
        self.file_edit.setText(row.data(Qt.UserRole))

    def _on_language_changed(self) -> None:
        """Switch the display language to the one picked."""
        translator.set_language(self.language_combo.language())

    def _is_creating(self) -> bool:
        """
        Tell whether a new profile is being created.

        Returns
        -------
        bool
            ``True`` in create mode, ``False`` in open mode.
        """
        return self.create_radio.isChecked()

    def _on_mode_changed(self) -> None:
        """Show the widgets and subtitle of the selected mode."""
        creating = self._is_creating()
        self.setSubTitle(
            translator.translate(
                "wizard.file_page_subtitle_create" if creating else "wizard.file_page_subtitle_open"
            )
        )
        for widget in (
            self.profiles_label,
            self.profiles_list,
            self.browse_label,
            self.file_edit,
            self.browse_button,
        ):
            widget.setVisible(not creating)
        for widget in (self.username_label, self.username_edit, self.destination_label):
            widget.setVisible(creating)
        self._update_destination_label()

    def _update_destination_label(self) -> None:
        """Show where the new profile will be saved, as the username is typed."""
        username = self.username_edit.text().strip()
        self.destination_label.setText(
            translator.translate("wizard.destination_label", path=str(profile_path(username)))
            if username
            else ""
        )

    def _browse(self) -> None:
        """Pick a vault file, starting next to the current one or in the home folder."""
        current = Path(self.file_edit.text().strip() or Path.home())
        start = current.parent if current.is_file() else Path.home()
        filename, _filter = QFileDialog.getOpenFileName(
            self,
            translator.translate("wizard.select_vault_file_dialog_title"),
            str(start),
            translator.translate("common.vault_files_filter"),
        )
        if filename:
            self.file_edit.setText(filename)
            self.profiles_list.clearSelection()

    def validatePage(self) -> bool:
        """
        Prepare the wizard's manager for the selected mode.

        Returns
        -------
        bool
            ``True`` to go on to the next page, ``False`` after an
            error message.
        """
        wizard: CredentialsWizard = self.wizard()
        if self._is_creating():
            return self._prepare_new_profile(wizard)
        return self._prepare_existing_file(wizard)

    def _prepare_new_profile(self, wizard: CredentialsWizard) -> bool:
        """
        Build an empty manager for a new profile.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard, receiving the mode, file path and manager.

        Returns
        -------
        bool
            ``False`` if the username is empty or taken, or the
            profiles folder can't be created.

        Notes
        -----
        The new profile starts in the language chosen in the wizard.
        """
        username = self.username_edit.text().strip()
        if not username:
            _warn(
                self,
                "wizard.missing_username_title",
                translator.translate("wizard.missing_username_message"),
            )
            return False

        path = profile_path(username)
        if path.exists():
            _warn(
                self,
                "wizard.profile_exists_title",
                translator.translate("wizard.profile_exists_message", username=username),
            )
            return False

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _error(
                self,
                "wizard.folder_error_title",
                translator.translate("wizard.folder_error_message", error=str(exc)),
            )
            return False

        metadata: Metadata = {"username": username, "version": _NEW_PROFILE_FORMAT_VERSION}
        credentials = Credentials()
        try:
            manager = PasswordManager.new(metadata, credentials)
            manager.set_language(translator.language)
        except Exception as exc:
            _unexpected_error(self, exc)
            return False

        wizard.start(MODE_CREATE, path, manager, credentials)
        return True

    def _prepare_existing_file(self, wizard: CredentialsWizard) -> bool:
        """
        Read an existing vault file into a still-locked manager.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard, receiving the mode, file path and manager.

        Returns
        -------
        bool
            ``False`` if no file is given, it doesn't exist or can't be
            read.
        """
        path_text = self.file_edit.text().strip()
        if not path_text:
            _warn(
                self,
                "wizard.missing_file_title",
                translator.translate("wizard.missing_file_message"),
            )
            return False

        path = Path(path_text)
        if not path.is_file():
            _warn(
                self,
                "wizard.file_not_found_title",
                translator.translate("wizard.file_not_found_message", path=str(path)),
            )
            return False

        try:
            data = bytearray(path.read_bytes())
        except OSError as exc:
            _error(
                self,
                "wizard.read_error_title",
                translator.translate("wizard.read_error_message", error=str(exc)),
            )
            return False

        credentials = Credentials()
        try:
            manager = PasswordManager(data, credentials)
        except Exception as exc:
            _unexpected_error(self, exc)
            return False

        wizard.start(MODE_OPEN, path, manager, credentials)
        return True


class _PasswordPage(QWizardPage):
    """
    Base of the steps asking for one password: entered to unlock an
    existing vault, or chosen (with a confirmation) for a new one.

    Subclasses set the translation keys and implement
    :meth:`_apply_create` and :meth:`_apply_open`.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.
    """

    _title_key = ""
    _subtitle_create_key = ""
    _subtitle_open_key = ""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QFormLayout(self)

        self.password_label = QLabel()
        self.password_field = PasswordField()
        layout.addRow(self.password_label, self.password_field)

        self.confirm_label = QLabel()
        self.confirm_field = PasswordField()
        layout.addRow(self.confirm_label, self.confirm_field)

        self.retranslate()
        translator.language_changed.connect(self.retranslate)

    def _is_creating(self) -> bool:
        """
        Tell whether the wizard creates a new profile.

        Returns
        -------
        bool
            ``True`` in create mode; ``False`` in open mode, or before
            the page is added to the wizard.
        """
        wizard = self.wizard()
        return wizard is not None and wizard.mode == MODE_CREATE

    def initializePage(self) -> None:
        """Adapt the subtitle and confirmation field to the wizard's mode."""
        self._update_mode()

    @pyqtSlot()
    def retranslate(self) -> None:
        """Refresh every text of the page."""
        self.setTitle(translator.translate(self._title_key))
        self.password_label.setText(translator.translate("wizard.password_label"))
        self.confirm_label.setText(translator.translate("wizard.confirm_password_label"))
        self._update_mode()

    def _update_mode(self) -> None:
        """Show the subtitle of the mode, and the confirmation field when creating."""
        creating = self._is_creating()
        self.setSubTitle(
            translator.translate(self._subtitle_create_key if creating else self._subtitle_open_key)
        )
        self.confirm_label.setVisible(creating)
        self.confirm_field.setVisible(creating)

    def validatePage(self) -> bool:
        """
        Check the password, then apply it for the wizard's mode.

        Returns
        -------
        bool
            ``True`` to go on, ``False`` after an error message.
        """
        password = self.password_field.text()
        if not password:
            _warn(
                self,
                "wizard.missing_fields_title",
                translator.translate("wizard.missing_fields_message"),
            )
            return False

        wizard: CredentialsWizard = self.wizard()
        if not self._is_creating():
            return self._apply_open(wizard, self.password_field.to_bytearray())

        if password != self.confirm_field.text():
            _warn(self, "wizard.mismatch_title", translator.translate("wizard.mismatch_message"))
            return False
        return self._apply_create(wizard, self.password_field.to_bytearray())

    def clear(self) -> None:
        """Erase the entered passwords."""
        self.password_field.clear()
        self.confirm_field.clear()

    def _apply_create(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Use a chosen password for the new profile.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The confirmed password.

        Returns
        -------
        bool
            ``True`` to go on.
        """
        raise NotImplementedError

    def _apply_open(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Check an entered password against the opened vault.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The entered password.

        Returns
        -------
        bool
            ``True`` if the password is right.
        """
        raise NotImplementedError


class _PrimaryPage(_PasswordPage):
    """
    Step 2: the primary password, which decrypts the vault file.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.
    """

    _title_key = "wizard.primary_page_title"
    _subtitle_create_key = "wizard.primary_subtitle_create"
    _subtitle_open_key = "wizard.primary_subtitle_open"

    def _apply_create(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Record the primary password of the new profile.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The confirmed password.

        Returns
        -------
        bool
            Always ``True``.
        """
        wizard.credentials.set_primary_password(password)
        return True

    def _apply_open(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Decrypt the vault with the entered primary password.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The entered password.

        Returns
        -------
        bool
            ``False`` if the password is wrong or the vault invalid.
        """
        wizard.credentials.set_primary_password(password)
        try:
            wizard.manager.decrypt_data()
        except PrimaryPasswordError:
            _error(
                self,
                "wizard.wrong_credentials_title",
                translator.translate("wizard.wrong_primary_credentials_message"),
            )
            return False
        except ValueError as exc:
            _error(
                self,
                "wizard.invalid_vault_title",
                translator.translate("wizard.invalid_vault_message", error=str(exc)),
            )
            return False
        except Exception as exc:
            _unexpected_error(self, exc)
            return False
        return True


class _SecondaryPage(_PasswordPage):
    """
    Step 3: the secondary password, which encrypts individual secrets.

    When creating, the new vault is written to disk right away, so
    nothing is lost if the application closes before the next save.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.
    """

    _title_key = "wizard.secondary_page_title"
    _subtitle_create_key = "wizard.secondary_subtitle_create"
    _subtitle_open_key = "wizard.secondary_subtitle_open"

    def _apply_create(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Record the secondary password and write the new vault.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The confirmed password.

        Returns
        -------
        bool
            ``False`` if the vault file can't be written.
        """
        wizard.credentials.set_secondary_password(password)
        try:
            wizard.manager.save_changes(wizard.file_path)
        except OSError as exc:
            _error(
                self,
                "wizard.write_error_title",
                translator.translate("wizard.write_error_message", error=str(exc)),
            )
            return False
        except Exception as exc:
            _unexpected_error(self, exc)
            return False
        _remember_file_path(wizard.file_path)
        return True

    def _apply_open(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Check the entered secondary password against the vault.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The entered password.

        Returns
        -------
        bool
            ``False`` if the password is wrong or the vault corrupted.
        """
        wizard.credentials.set_secondary_password(password)
        try:
            wizard.manager.check_secondary()
        except SecondaryPasswordError:
            _error(
                self,
                "wizard.wrong_credentials_title",
                translator.translate("wizard.wrong_secondary_credentials_message"),
            )
            return False
        except CorruptedBase64Error:
            _error(
                self,
                "wizard.corrupted_vault_title",
                translator.translate("wizard.corrupted_vault_message"),
            )
            return False
        except Exception as exc:
            _unexpected_error(self, exc)
            return False
        _remember_file_path(wizard.file_path)
        return True


# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------

class CredentialsWizard(QWizard):
    """
    Three-step wizard opening an existing vault or creating a new one:

    1. :class:`_FilePage`: the profile or file to open, or the
       username of a new profile;
    2. :class:`_PrimaryPage`: the primary password;
    3. :class:`_SecondaryPage`: the secondary password.

    On success, the wizard opens the :class:`PasswordManagerWindow`
    itself.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    mode : str
        :data:`MODE_OPEN` or :data:`MODE_CREATE`, set by the first page.
    file_path : Path or None
        The vault file opened or created.
    credentials : Credentials
        Filled by the password pages.
    manager : PasswordManager or None
        Built by the first page, usable once every page is done.
    main_window : PasswordManagerWindow or None
        The window opened on success, kept so it isn't garbage
        collected once the wizard closes.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(WIZARD_TITLE)
        self.setOption(QWizard.NoBackButtonOnStartPage, True)

        self.mode = MODE_OPEN
        self.file_path: Path | None = None
        self.credentials = Credentials()
        self.manager: PasswordManager | None = None
        self.main_window: PasswordManagerWindow | None = None

        self._password_pages = (_PrimaryPage(self), _SecondaryPage(self))
        self.addPage(_FilePage(self))
        for page in self._password_pages:
            self.addPage(page)

        self.finished.connect(self._on_finished)

    def start(
        self,
        mode: str,
        file_path: Path,
        manager: PasswordManager,
        credentials: Credentials,
    ) -> None:
        """
        Record the vault chosen on the first page.

        Parameters
        ----------
        mode : str
            :data:`MODE_OPEN` or :data:`MODE_CREATE`.
        file_path : Path
            The vault file.
        manager : PasswordManager
            Manager built for that file, still locked.
        credentials : Credentials
            Empty credentials shared with ``manager``, filled by the
            password pages.
        """
        self.mode = mode
        self.file_path = file_path
        self.manager = manager
        self.credentials = credentials

    def _on_finished(self, result: int) -> None:
        """
        Erase the typed passwords and, on success, open the main window.

        Parameters
        ----------
        result : int
            ``QDialog.Accepted`` if every page was completed.
        """
        for page in self._password_pages:
            page.clear()
        if result != QDialog.Accepted:
            return
        self.main_window = PasswordManagerWindow(self.manager, self.file_path)
        self.main_window.show()