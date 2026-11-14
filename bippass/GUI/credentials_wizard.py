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

from ..core.exceptions import (
    CorruptedFileError,
    PrimaryPasswordError,
    TamperedDataError,
    UnsupportedVersionError,
)
from ..core.manager import PasswordManager
from ..core.profiles import ensure_profiles_dir, list_existing_profiles, profile_path
from .tasks import run_blocking
from .theme import load_theme
from .translate import translator
from .widgets import LanguageComboBox, PasswordField
from .window import PasswordManagerWindow


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WIZARD_TITLE = "BIPPASS"

# Remembers the last profile file opened or created, to pre-fill the
# first page.
RECENT_FILE_PATH = Path.home() / ".bippass" / "recent.json"

MODE_OPEN = "open"
MODE_CREATE = "create"

_PROFILES_LIST_MAX_HEIGHT_PX = 160

# Page ids, in order.
_FILE_PAGE, _PRIMARY_PAGE, _SECONDARY_PAGE = range(3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_last_file_path() -> Path | None:
    """
    Return the last profile file opened or created.

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
    Remember a profile file as the last one opened or created.

    Parameters
    ----------
    path : Path
        Profile file to remember.

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
    Step 1: pick a profile to open, or describe a new one. Also holds
    the wizard's language switcher.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    Opening lists the profiles of :data:`core.profiles.PROFILES_DIR`
    by their label, the only thing readable without a password, and
    allows browsing for a file stored elsewhere. Files of an older
    format are listed greyed out: they must be converted first.

    Creating asks for a username, stored encrypted, and a label, shown
    in this list. The label follows the username until edited; it may
    be left empty to keep the profile anonymous. The file is named
    after the profile's UUID, so nothing here can collide with an
    existing profile.
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

        # Open mode: existing profiles, or any profile file
        self.profiles_label = QLabel()
        layout.addWidget(self.profiles_label)

        self.profiles_list = QListWidget()
        self.profiles_list.setMaximumHeight(_PROFILES_LIST_MAX_HEIGHT_PX)
        self.profiles_list.itemClicked.connect(self._on_profile_clicked)
        self.profiles_list.itemDoubleClicked.connect(self._on_profile_double_clicked)
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

        # Create mode: username and label
        create_form = QFormLayout()
        self.username_label = QLabel()
        self.username_edit = QLineEdit()
        self.username_edit.textEdited.connect(self._on_username_edited)
        create_form.addRow(self.username_label, self.username_edit)

        self.label_label = QLabel()
        self.label_edit = QLineEdit()
        self.label_edit.textEdited.connect(self._on_label_edited)
        create_form.addRow(self.label_label, self.label_edit)
        self.create_widget = QWidget()
        self.create_widget.setLayout(create_form)
        layout.addWidget(self.create_widget)

        self.label_hint = QLabel()
        self.label_hint.setObjectName("mutedLabel")
        self.label_hint.setWordWrap(True)
        layout.addWidget(self.label_hint)
        layout.addStretch()

        # Whether the label still mirrors the username.
        self._label_follows_username = True

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
        self.label_label.setText(tr("common.label_label"))
        self.label_hint.setText(tr("wizard.label_hint"))
        self._on_mode_changed()
        self._refresh_profiles_list()

    def _refresh_profiles_list(self) -> None:
        """Fill :attr:`profiles_list` with the profiles currently on disk."""
        tr = translator.translate
        self.profiles_list.clear()
        for entry in list_existing_profiles():
            name = entry.label or tr("common.anonymous_profile")
            date = entry.modified.strftime("%Y-%m-%d %H:%M")
            text = tr("wizard.profile_row", name=name, date=date)
            row = QListWidgetItem(text)
            row.setData(Qt.UserRole, str(entry.path))
            row.setToolTip(str(entry.path))
            if not entry.supported:
                row.setText(tr("wizard.profile_row_unsupported", row=text))
                row.setFlags(row.flags() & ~Qt.ItemIsEnabled & ~Qt.ItemIsSelectable)
            self.profiles_list.addItem(row)

    def _on_profile_clicked(self, row: QListWidgetItem) -> None:
        """
        Fill the file field with a clicked profile's file.

        Parameters
        ----------
        row : QListWidgetItem
            The clicked profile row.
        """
        if row.flags() & Qt.ItemIsEnabled:
            self.file_edit.setText(row.data(Qt.UserRole))

    def _on_profile_double_clicked(self, row: QListWidgetItem) -> None:
        """
        Pick a profile and go on to the password page.

        Parameters
        ----------
        row : QListWidgetItem
            The double-clicked profile row.
        """
        if row.flags() & Qt.ItemIsEnabled:
            self.file_edit.setText(row.data(Qt.UserRole))
            self.wizard().next()

    def _on_language_changed(self) -> None:
        """Switch the display language to the one picked."""
        translator.set_language(self.language_combo.language())

    def _on_username_edited(self, text: str) -> None:
        """
        Mirror the username into the label, until the label is edited.

        Parameters
        ----------
        text : str
            The new username.
        """
        if self._label_follows_username:
            self.label_edit.setText(text)

    def _on_label_edited(self, text: str) -> None:
        """
        Stop mirroring the username once the label is edited by hand.

        Parameters
        ----------
        text : str
            The new label; clearing it mirrors the username again.
        """
        self._label_follows_username = not text

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
        self.create_widget.setVisible(creating)
        self.label_hint.setVisible(creating)

    def _browse(self) -> None:
        """Pick a profile file, starting next to the current one or in the home folder."""
        current = Path(self.file_edit.text().strip() or Path.home())
        start = current.parent if current.is_file() else Path.home()
        filename, _filter = QFileDialog.getOpenFileName(
            self,
            translator.translate("wizard.select_vault_file_dialog_title"),
            str(start),
            translator.translate("common.profile_files_filter"),
        )
        if filename:
            self.file_edit.setText(filename)
            self.profiles_list.clearSelection()

    def validatePage(self) -> bool:
        """
        Record the choice of this page in the wizard.

        Returns
        -------
        bool
            ``True`` to go on to the next page, ``False`` after an
            error message.
        """
        wizard: CredentialsWizard = self.wizard()
        if self._is_creating():
            wizard.start_create(
                self.username_edit.text().strip() or None,
                self.label_edit.text().strip() or None,
            )
            return True
        return self._read_existing_file(wizard)

    def _read_existing_file(self, wizard: CredentialsWizard) -> bool:
        """
        Read an existing profile file into a still-locked manager.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard, receiving the file path and manager.

        Returns
        -------
        bool
            ``False`` if no file is given, or it can't be read as a
            profile of the current format.
        """
        tr = translator.translate
        path_text = self.file_edit.text().strip()
        if not path_text:
            _warn(self, "wizard.missing_file_title", tr("wizard.missing_file_message"))
            return False

        path = Path(path_text)
        if not path.is_file():
            _warn(self, "wizard.file_not_found_title", tr("wizard.file_not_found_message", path=str(path)))
            return False

        try:
            manager = PasswordManager.read(path)
        except OSError as exc:
            _error(self, "wizard.read_error_title", tr("wizard.read_error_message", error=str(exc)))
            return False
        except UnsupportedVersionError as exc:
            _error(self, "wizard.invalid_vault_title", tr("wizard.unsupported_version_message", error=str(exc)))
            return False
        except CorruptedFileError as exc:
            _error(self, "wizard.invalid_vault_title", tr("wizard.invalid_vault_message", error=str(exc)))
            return False
        except Exception as exc:
            _unexpected_error(self, exc)
            return False

        wizard.start_open(path, manager)
        return True


class _PasswordPage(QWizardPage):
    """
    Base of the steps asking for one password: entered to unlock an
    existing profile, or chosen (with a confirmation) for a new one.

    Subclasses set the translation keys and implement
    :meth:`_apply_create` and, if they are part of the open mode,
    :meth:`_apply_open`.

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
        self.password_field.edit.setFocus()

    def cleanupPage(self) -> None:
        """Erase the typed passwords when going back."""
        self.clear()

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
            password_bytes = self.password_field.to_bytearray()
            self.clear()
            return self._apply_open(wizard, password_bytes)

        if password != self.confirm_field.text():
            _warn(self, "wizard.mismatch_title", translator.translate("wizard.mismatch_message"))
            return False
        password_bytes = self.password_field.to_bytearray()
        self.clear()
        return self._apply_create(wizard, password_bytes)

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
            The confirmed password, now owned by this method.

        Returns
        -------
        bool
            ``True`` to go on.
        """
        raise NotImplementedError

    def _apply_open(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Use an entered password on the opened profile.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The entered password, now owned by this method.

        Returns
        -------
        bool
            ``True`` if the password is right.
        """
        raise NotImplementedError


class _PrimaryPage(_PasswordPage):
    """
    Step 2: the primary password, which unlocks the profile.

    In open mode this is the last page: the secondary password is only
    asked later, the first time a secret is needed (see
    :func:`unlock.ensure_decrypted`).

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.
    """

    _title_key = "wizard.primary_page_title"
    _subtitle_create_key = "wizard.primary_subtitle_create"
    _subtitle_open_key = "wizard.primary_subtitle_open"

    def nextId(self) -> int:
        """
        Return the next page: none when opening, the secondary password when creating.

        Returns
        -------
        int
            ``-1`` (last page) in open mode, else the secondary page id.
        """
        return _SECONDARY_PAGE if self._is_creating() else -1

    def _apply_create(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Keep the primary password of the new profile until the next page.

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
        wizard.set_new_primary_password(password)
        return True

    def _apply_open(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Unlock the profile with the entered primary password.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The entered password, erased by the manager.

        Returns
        -------
        bool
            ``False`` if the password is wrong or the profile invalid.
        """
        tr = translator.translate
        try:
            run_blocking(self, tr("unlock.unlocking"), lambda: wizard.manager.unlock(password))
        except PrimaryPasswordError:
            _error(self, "wizard.wrong_credentials_title", tr("wizard.wrong_primary_credentials_message"))
            return False
        except (TamperedDataError, CorruptedFileError) as exc:
            _error(self, "wizard.invalid_vault_title", tr("wizard.invalid_vault_message", error=str(exc)))
            return False
        except Exception as exc:
            _unexpected_error(self, exc)
            return False
        _remember_file_path(wizard.file_path)
        return True


class _SecondaryPage(_PasswordPage):
    """
    Step 3, when creating only: the secondary password, which protects
    the secrets.

    The new profile is created and written to disk right away, so
    nothing is lost if the application closes before the next save.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.
    """

    _title_key = "wizard.secondary_page_title"
    _subtitle_create_key = "wizard.secondary_subtitle_create"
    _subtitle_open_key = "wizard.secondary_subtitle_create"

    def _apply_create(self, wizard: CredentialsWizard, password: bytearray) -> bool:
        """
        Create the new profile and write it.

        Parameters
        ----------
        wizard : CredentialsWizard
            The wizard.
        password : bytearray
            The confirmed secondary password, erased by the manager.

        Returns
        -------
        bool
            ``False`` if the profile can't be created or written.
        """
        tr = translator.translate
        try:
            manager = run_blocking(
                self,
                tr("wizard.creating"),
                lambda: PasswordManager.create(
                    wizard.new_username,
                    wizard.take_new_primary_password(),
                    password,
                    label=wizard.new_label,
                ),
            )
            manager.set_language(translator.language)
            manager.set_theme(load_theme())
        except Exception as exc:
            _unexpected_error(self, exc)
            # Both passwords are erased: start the passwords again.
            wizard.restart_passwords()
            return False

        try:
            ensure_profiles_dir()
            path = profile_path(manager.uuid)
            manager.save(path)
        except OSError as exc:
            manager.close()
            _error(self, "wizard.write_error_title", tr("wizard.write_error_message", error=str(exc)))
            wizard.restart_passwords()
            return False

        wizard.finish_create(path, manager)
        _remember_file_path(path)
        return True


# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------

class CredentialsWizard(QWizard):
    """
    Wizard opening an existing profile or creating a new one.

    Opening takes two steps: :class:`_FilePage` (the profile) then
    :class:`_PrimaryPage` (the primary password, which unlocks it).
    Creating takes three: the username and label, then both passwords,
    each confirmed (:class:`_PrimaryPage`, :class:`_SecondaryPage`).

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
        The profile file opened or created.
    manager : PasswordManager or None
        In open mode, read by the first page and unlocked by the
        second; in create mode, created by the last page.
    new_username, new_label : str or None
        In create mode, entered on the first page.
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
        self.manager: PasswordManager | None = None
        self.new_username: str | None = None
        self.new_label: str | None = None
        self.main_window: PasswordManagerWindow | None = None
        self._new_primary: bytearray | None = None

        self._password_pages = (_PrimaryPage(self), _SecondaryPage(self))
        self.setPage(_FILE_PAGE, _FilePage(self))
        self.setPage(_PRIMARY_PAGE, self._password_pages[0])
        self.setPage(_SECONDARY_PAGE, self._password_pages[1])

        self.finished.connect(self._on_finished)

    # -- open mode ----------------------------------------------------------

    def start_open(self, file_path: Path, manager: PasswordManager) -> None:
        """
        Record the profile picked on the first page.

        Parameters
        ----------
        file_path : Path
            The profile file.
        manager : PasswordManager
            Manager read from that file, still locked.
        """
        self._discard_manager()
        self.mode = MODE_OPEN
        self.file_path = file_path
        self.manager = manager

    # -- create mode --------------------------------------------------------

    def start_create(self, username: str | None, label: str | None) -> None:
        """
        Record the description of the new profile entered on the first page.

        Parameters
        ----------
        username : str or None
            Username, stored encrypted.
        label : str or None
            Label, readable without a password; ``None`` keeps the
            profile anonymous.
        """
        self._discard_manager()
        self.mode = MODE_CREATE
        self.new_username = username
        self.new_label = label

    def set_new_primary_password(self, password: bytearray) -> None:
        """
        Keep the chosen primary password until the profile is created.

        Parameters
        ----------
        password : bytearray
            The password; a previously kept one is erased.
        """
        self._erase_new_primary()
        self._new_primary = password

    def take_new_primary_password(self) -> bytearray:
        """
        Hand over the kept primary password.

        Returns
        -------
        bytearray
            The password, no longer kept by the wizard: the caller (the
            manager) erases it.
        """
        password, self._new_primary = self._new_primary, None
        if password is None:
            raise RuntimeError("No primary password was chosen.")
        return password

    def restart_passwords(self) -> None:
        """Go back to the primary password page after a failed creation."""
        self._erase_new_primary()
        self.back()

    def finish_create(self, file_path: Path, manager: PasswordManager) -> None:
        """
        Record the newly created profile.

        Parameters
        ----------
        file_path : Path
            Where it was written.
        manager : PasswordManager
            The created manager, unlocked and decrypted.
        """
        self.file_path = file_path
        self.manager = manager

    # -- end ----------------------------------------------------------------

    def _erase_new_primary(self) -> None:
        """Erase the kept primary password, if any."""
        if self._new_primary is not None:
            self._new_primary[:] = bytes(len(self._new_primary))
            self._new_primary = None

    def _discard_manager(self) -> None:
        """Close a manager read earlier, when the user goes back and picks again."""
        if self.manager is not None:
            self.manager.close()
            self.manager = None

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
        self._erase_new_primary()
        if result != QDialog.Accepted or self.manager is None or not self.manager.is_unlocked:
            self._discard_manager()
            return
        self.main_window = PasswordManagerWindow(self.manager, self.file_path)
        self.main_window.show()
