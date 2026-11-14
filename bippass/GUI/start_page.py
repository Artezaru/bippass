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

from PyQt5.QtCore import QFile, Qt, pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import (
    QButtonGroup,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..core.exceptions import (
    CorruptedFileError,
    PasswordManagerError,
    PrimaryPasswordError,
    TamperedDataError,
    UnsupportedVersionError,
)
from ..core.manager import PasswordManager
from ..core.profiles import ensure_profiles_dir, list_existing_profiles, profile_path
from .tasks import run_blocking
from .theme import load_theme
from .translate import translator
from .local_settings import read_setting, write_setting
from .widgets import NewPasswordFields, PasswordField, confirm, ok_cancel_buttons, warn


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_TITLE = "BIPPASS"

_CARD_MAX_WIDTH_PX = 600
# Inner margins (px) of the card, and spacing between its blocks.
_CARD_MARGINS_PX = (36, 28, 36, 28)
_CARD_SPACING_PX = 14
_PROFILES_LIST_MAX_HEIGHT_PX = 180
_OPEN_PAGE, _CREATE_PAGE = range(2)

# Steps of the "create" form: the primary password, then the secondary one.
_PRIMARY_STEP, _SECONDARY_STEP = range(2)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_last_file_path() -> Path | None:
    """
    Return the last profile file opened or created.

    Returns
    -------
    Path or None
        The remembered path (see :mod:`local_settings`), or ``None``.
    """
    value = read_setting("last_file")
    return Path(value) if isinstance(value, str) and value else None


def remember_file_path(path: Path) -> None:
    """
    Remember a profile file as the last one opened or created.

    Parameters
    ----------
    path : Path
        Profile file to remember (best effort, see :mod:`local_settings`).
    """
    write_setting("last_file", str(path))


def _same_file(a: Path | None, b: Path | None) -> bool:
    """
    Tell whether two paths designate the same file.

    Parameters
    ----------
    a, b : Path or None
        Paths to compare.

    Returns
    -------
    bool
        ``True`` if both are given and resolve to the same location.
    """
    if a is None or b is None:
        return False
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return a == b


# ---------------------------------------------------------------------------
# Start page
# ---------------------------------------------------------------------------

class _RenameProfileDialog(QDialog):
    """
    Dialog asking for the new name (label) of a profile and its primary
    password, needed to write the label: it is authenticated with the
    profile's content.

    Parameters
    ----------
    label : str
        Name pre-filled.

    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("start.rename_profile_title"))
        self.setMinimumWidth(420)
        layout = QFormLayout(self)
        hint = QLabel(tr("start.rename_profile_hint"))
        hint.setObjectName("mutedLabel")
        hint.setWordWrap(True)
        layout.addRow(hint)
        self.label_edit = QLineEdit(label)
        self.label_edit.selectAll()
        layout.addRow(tr("common.label_label"), self.label_edit)
        self.password_field = PasswordField()
        layout.addRow(tr("start.primary_label"), self.password_field)
        layout.addRow(ok_cancel_buttons(self, self._on_accept))
        self.label_edit.setFocus()

    def _on_accept(self) -> None:
        """Accept once the primary password is typed."""
        if self.password_field.text():
            self.accept()

    def take(self) -> tuple[str, bytearray]:
        """
        Return the new name (stripped, possibly empty) and the password, then erase the field.

        Returns
        -------
        tuple of (str, bytearray)
            The password is owned (and to be erased) by the caller.
        """
        password = self.password_field.to_bytearray()
        self.password_field.clear()
        return self.label_edit.text().strip(), password

    def reject(self) -> None:
        """Erase the typed password, then close."""
        self.password_field.clear()
        super().reject()


class StartPage(QWidget):
    """
    Start screen of the main window: open a profile, or create one.

    Shown when the application starts and whenever the profile is
    locked (which saves and closes it), so locking is also the way to
    switch to another profile or to create a new one. Everything sits in one centered card:

    - **Open**: the profiles of :data:`core.profiles.PROFILES_DIR`, by
      label (the only thing readable without a password) and date of
      last save, a "Browse…" field for a file stored elsewhere, and the
      primary password. The secondary password is asked later, only
      when a secret is needed.
    - **Create**: a username (stored encrypted), a label (shown in the
      list; it follows the username until edited, and may be left
      empty to stay anonymous) and the primary password, then, in a
      second step, the secondary password; each password confirmed.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    session_opened : pyqtSignal(object, object)
        Emitted with ``(manager, path)``: an unlocked
        :class:`PasswordManager` and its file.
    """

    session_opened = pyqtSignal(object, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._label_follows_username = True

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.addStretch(1)
        card = QFrame()
        card.setObjectName("startCard")
        card.setMaximumWidth(_CARD_MAX_WIDTH_PX)
        card.setFrameShape(QFrame.StyledPanel)
        outer.addWidget(card, alignment=Qt.AlignHCenter)
        outer.addStretch(2)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(*_CARD_MARGINS_PX)
        layout.setSpacing(_CARD_SPACING_PX)

        self.title_label = QLabel(APP_TITLE)
        self.title_label.setObjectName("sectionTitle")
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)

        # Mode switch: two exclusive checkable buttons.
        mode_row = QHBoxLayout()
        self.open_mode_btn = QPushButton()
        self.create_mode_btn = QPushButton()
        self._mode_group = QButtonGroup(self)
        for index, button in enumerate((self.open_mode_btn, self.create_mode_btn)):
            button.setCheckable(True)
            button.setAutoDefault(False)
            self._mode_group.addButton(button, index)
            mode_row.addWidget(button)
        self.open_mode_btn.setChecked(True)
        self._mode_group.buttonClicked.connect(self._on_mode_changed)
        layout.addLayout(mode_row)

        self.subtitle_label = QLabel()
        self.subtitle_label.setObjectName("mutedLabel")
        self.subtitle_label.setWordWrap(True)
        layout.addWidget(self.subtitle_label)

        self._pages = QStackedWidget()
        self._pages.insertWidget(_OPEN_PAGE, self._build_open_page())
        self._pages.insertWidget(_CREATE_PAGE, self._build_create_page())
        layout.addWidget(self._pages)

        self.retranslate()
        translator.language_changed.connect(self.retranslate)

    # -- construction -------------------------------------------------------

    def _build_open_page(self) -> QWidget:
        """
        Build the "open" form.

        Returns
        -------
        QWidget
            The form.
        """
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(_CARD_SPACING_PX // 2 + 2)

        self.profiles_label = QLabel()
        layout.addWidget(self.profiles_label)
        self.profiles_list = QListWidget()
        self.profiles_list.setMaximumHeight(_PROFILES_LIST_MAX_HEIGHT_PX)
        self.profiles_list.itemClicked.connect(self._on_profile_clicked)
        self.profiles_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.profiles_list.customContextMenuRequested.connect(self._profile_menu)
        layout.addWidget(self.profiles_list)

        self.browse_label = QLabel()
        layout.addWidget(self.browse_label)
        file_row = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.textEdited.connect(self.profiles_list.clearSelection)
        self.browse_button = QPushButton()
        self.browse_button.setAutoDefault(False)
        self.browse_button.clicked.connect(self._browse)
        file_row.addWidget(self.file_edit)
        file_row.addWidget(self.browse_button)
        layout.addLayout(file_row)

        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)
        self.open_password_label = QLabel()
        self.open_password = PasswordField()
        self.open_password.edit.returnPressed.connect(self._open)
        form.addRow(self.open_password_label, self.open_password)
        layout.addLayout(form)

        self.open_button = QPushButton()
        self.open_button.setDefault(True)
        self.open_button.clicked.connect(self._open)
        layout.addWidget(self.open_button)
        return page

    def _build_create_page(self) -> QWidget:
        """
        Build the "create" form, in two steps.

        Returns
        -------
        QWidget
            The form.

        Notes
        -----
        Step 1 asks the username, the label and the primary password;
        step 2 the secondary password. One step at a time keeps the
        card short enough for small windows, and lets each step explain
        what its password protects.
        """
        self._create_steps = QStackedWidget()
        self._create_steps.insertWidget(_PRIMARY_STEP, self._build_primary_step())
        self._create_steps.insertWidget(_SECONDARY_STEP, self._build_secondary_step())
        return self._create_steps

    @staticmethod
    def _step_layout(page: QWidget) -> QVBoxLayout:
        """Return the layout of a step of the "create" form."""
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(_CARD_SPACING_PX // 2 + 2)
        return layout

    @staticmethod
    def _form() -> QFormLayout:
        """Return a form layout with the spacing of the card."""
        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)
        return form

    def _build_primary_step(self) -> QWidget:
        """
        Build step 1: username, label and primary password.

        Returns
        -------
        QWidget
            The step.
        """
        page = QWidget()
        layout = self._step_layout(page)

        form = self._form()
        self.username_label = QLabel()
        self.username_edit = QLineEdit()
        self.username_edit.textEdited.connect(self._on_username_edited)
        form.addRow(self.username_label, self.username_edit)
        self.label_label = QLabel()
        self.label_edit = QLineEdit()
        self.label_edit.textEdited.connect(self._on_label_edited)
        form.addRow(self.label_label, self.label_edit)
        layout.addLayout(form)

        self.label_hint = QLabel()
        self.label_hint.setObjectName("mutedLabel")
        self.label_hint.setWordWrap(True)
        layout.addWidget(self.label_hint)

        passwords = self._form()
        # Labels set by `retranslate`.
        self.primary_fields = NewPasswordFields(passwords, "", "")
        self.primary_fields.confirmation.edit.returnPressed.connect(self._next_step)
        layout.addLayout(passwords)

        self.next_button = QPushButton()
        self.next_button.clicked.connect(self._next_step)
        layout.addWidget(self.next_button)
        return page

    def _build_secondary_step(self) -> QWidget:
        """
        Build step 2: secondary password.

        Returns
        -------
        QWidget
            The step.
        """
        page = QWidget()
        layout = self._step_layout(page)

        passwords = self._form()
        self.secondary_fields = NewPasswordFields(passwords, "", "")
        self.secondary_fields.confirmation.edit.returnPressed.connect(self._create)
        layout.addLayout(passwords)
        layout.addStretch()

        buttons = QHBoxLayout()
        self.back_button = QPushButton()
        self.back_button.setAutoDefault(False)
        self.back_button.clicked.connect(lambda: self._show_step(_PRIMARY_STEP))
        buttons.addWidget(self.back_button)
        self.create_button = QPushButton()
        self.create_button.clicked.connect(self._create)
        buttons.addWidget(self.create_button, stretch=1)
        layout.addLayout(buttons)
        return page

    # -- texts and state ----------------------------------------------------

    @pyqtSlot()
    def retranslate(self) -> None:
        """Refresh every text of the page."""
        tr = translator.translate
        self.open_mode_btn.setText(tr("start.open_mode"))
        self.create_mode_btn.setText(tr("start.create_mode"))
        self.profiles_label.setText(tr("start.profiles_label"))
        self.browse_label.setText(tr("start.browse_label"))
        self.file_edit.setPlaceholderText(tr("start.file_path_placeholder"))
        self.browse_button.setText(tr("common.browse"))
        self.open_password_label.setText(tr("start.primary_label"))
        self.open_button.setText(tr("start.open_button"))
        self.username_label.setText(tr("common.username_label"))
        self.label_label.setText(tr("common.label_label"))
        self.label_hint.setText(tr("start.label_hint"))
        self.primary_fields.label.setText(tr("start.primary_label"))
        self.secondary_fields.label.setText(tr("start.secondary_label"))
        for fields in (self.primary_fields, self.secondary_fields):
            fields.confirm_label.setText(tr("start.confirm_password_label"))
        self.next_button.setText(tr("start.next_button"))
        self.back_button.setText(tr("start.back_button"))
        self.create_button.setText(tr("start.create_button"))
        self._update_subtitle()
        self.refresh_profiles()

    def _is_creating(self) -> bool:
        """Tell whether the "create" form is shown."""
        return self.create_mode_btn.isChecked()

    def _update_subtitle(self) -> None:
        """Show the subtitle of the current mode (and step, when creating)."""
        if not self._is_creating():
            key = "start.subtitle_open"
        elif self._create_steps.currentIndex() == _PRIMARY_STEP:
            key = "start.step_primary"
        else:
            key = "start.step_secondary"
        self.subtitle_label.setText(translator.translate(key))

    def _on_mode_changed(self) -> None:
        """Show the form of the mode picked; creating starts at step 1."""
        self._pages.setCurrentIndex(_CREATE_PAGE if self._is_creating() else _OPEN_PAGE)
        self._show_step(_PRIMARY_STEP)

    def _show_step(self, step: int) -> None:
        """
        Show a step of the "create" form.

        Parameters
        ----------
        step : int
            :data:`_PRIMARY_STEP` or :data:`_SECONDARY_STEP`. Typed
            passwords are kept when going back and forth.
        """
        self._create_steps.setCurrentIndex(step)
        self._update_subtitle()
        self.focus_first_field()

    def _next_step(self) -> None:
        """Go to step 2 once the primary password is typed and confirmed."""
        problem = self.primary_fields.problem()
        if problem == "empty":
            warn(self, "start.missing_fields_message", "start.missing_fields_title")
        elif problem == "mismatch":
            warn(self, "start.mismatch_message", "start.mismatch_title")
        else:
            self._show_step(_SECONDARY_STEP)

    def focus_first_field(self) -> None:
        """Put the keyboard focus where the user starts typing."""
        if not self._is_creating():
            self.open_password.edit.setFocus()
        elif self._create_steps.currentIndex() == _PRIMARY_STEP:
            self.username_edit.setFocus()
        else:
            self.secondary_fields.password.edit.setFocus()

    def showEvent(self, event) -> None:
        """Refresh the profile list and focus the first field when shown."""
        super().showEvent(event)
        self.refresh_profiles()
        self.focus_first_field()

    def refresh_profiles(self) -> None:
        """
        Fill the profile list with the profiles currently on disk.

        Notes
        -----
        The last file opened is pre-selected. Files written by a newer
        version of bippass are listed greyed out.
        """
        tr = translator.translate
        self.profiles_list.clear()
        for entry in list_existing_profiles():
            name = entry.label or tr("common.anonymous_profile")
            text = tr("start.profile_row", name=name, date=entry.modified.strftime("%Y-%m-%d %H:%M"))
            row = QListWidgetItem(text)
            row.setData(Qt.UserRole, str(entry.path))
            row.setData(Qt.UserRole + 1, entry.label or "")
            row.setToolTip(str(entry.path))
            if not entry.supported:
                row.setText(tr("start.profile_row_unsupported", row=text))
                row.setFlags(row.flags() & ~Qt.ItemIsEnabled & ~Qt.ItemIsSelectable)
            self.profiles_list.addItem(row)

        if not self.file_edit.text():
            preselected = load_last_file_path()
            if preselected is not None:
                self.file_edit.setText(str(preselected))
        for index in range(self.profiles_list.count()):
            row = self.profiles_list.item(index)
            if _same_file(Path(row.data(Qt.UserRole)), Path(self.file_edit.text().strip() or ".")):
                row.setSelected(True)
                break

    def _selected_path(self) -> Path | None:
        """Return the path typed or picked, or ``None`` if empty."""
        text = self.file_edit.text().strip()
        return Path(text) if text else None

    def _on_profile_clicked(self, row: QListWidgetItem) -> None:
        """
        Use a clicked profile.

        Parameters
        ----------
        row : QListWidgetItem
            The clicked row.
        """
        if row.flags() & Qt.ItemIsEnabled:
            self.file_edit.setText(row.data(Qt.UserRole))
            self.open_password.edit.setFocus()

    # -- rename and delete ----

    def _profile_menu(self, pos) -> None:
        """
        Offer to rename or delete the profile under the cursor.

        Parameters
        ----------
        pos : QPoint
            Position of the right click, in the list's viewport.

        Notes
        -----
        A profile of a newer version can only be deleted.
        """
        row = self.profiles_list.itemAt(pos)
        if row is None:
            return
        tr = translator.translate
        path = Path(row.data(Qt.UserRole))
        name = row.data(Qt.UserRole + 1) or ""
        menu = QMenu(self)
        rename = menu.addAction(tr("start.rename_profile_action"))
        rename.setEnabled(bool(row.flags() & Qt.ItemIsEnabled))
        delete = menu.addAction(tr("start.delete_profile_action"))
        chosen = menu.exec_(self.profiles_list.viewport().mapToGlobal(pos))
        if chosen is rename:
            self._rename_profile(path, name)
        elif chosen is delete:
            self._delete_profile(path, name or tr("common.anonymous_profile"))

    def _rename_profile(self, path: Path, label: str) -> None:
        """
        Change the name (label) of a profile, with its primary password.

        Parameters
        ----------
        path : Path
            The profile file.

        label : str
            Its current name, pre-filled.

        Notes
        -----
        The profile is read, unlocked, renamed, saved and closed behind
        the "please wait" veil; it is never opened. A wrong password is
        reported, then the dialog is shown again.
        """
        tr = translator.translate
        while True:
            dialog = _RenameProfileDialog(label, self)
            if dialog.exec_() != QDialog.Accepted:
                return
            label, password = dialog.take()

            def rename(new_label: str = label, password: bytearray = password) -> None:
                manager = PasswordManager.read(path)
                try:
                    manager.unlock(password)
                    manager.set_label(new_label or None)
                    manager.save(path)
                finally:
                    manager.close()

            try:
                run_blocking(self, tr("start.renaming"), rename)
            except PrimaryPasswordError:
                warn(self, "start.wrong_primary_message", "start.wrong_password_title")
                continue
            except (PasswordManagerError, OSError, ValueError) as exc:
                warn(self, "start.rename_error_message", "start.rename_error_title", error=str(exc))
                return
            finally:
                password[:] = bytes(len(password))
            self.refresh_profiles()
            return

    def _delete_profile(self, path: Path, name: str) -> None:
        """
        Delete a profile file, after confirmation.

        Parameters
        ----------
        path : Path
            The profile file.

        name : str
            Its name, shown in the confirmation.

        Notes
        -----
        The file is moved to the trash when the system has one; if that
        fails, deleting it for good is asked separately.
        """
        tr = translator.translate
        if not confirm(self, "start.delete_profile_title",
                       tr("start.delete_profile_prompt", name=name, path=str(path))):
            return
        if not QFile.moveToTrash(str(path)):
            if not confirm(self, "start.delete_profile_title", tr("start.trash_failed_prompt")):
                return
            try:
                path.unlink()
            except OSError as exc:
                warn(self, "start.delete_error_message", "start.delete_error_title", error=str(exc))
                return
        if _same_file(self._selected_path(), path):
            self.file_edit.clear()
        self.refresh_profiles()

    def _browse(self) -> None:
        """Pick a profile file, starting next to the current one or in the home folder."""
        current = self._selected_path() or Path.home()
        start = current.parent if current.is_file() else Path.home()
        filename, _filter = QFileDialog.getOpenFileName(
            self,
            translator.translate("start.select_file_title"),
            str(start),
            translator.translate("common.profile_files_filter"),
        )
        if filename:
            self.file_edit.setText(filename)
            self.profiles_list.clearSelection()
            self.open_password.edit.setFocus()

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

    def clear_passwords(self) -> None:
        """Erase every typed password."""
        self.open_password.clear()
        self.primary_fields.clear()
        self.secondary_fields.clear()

    # -- open ---------------------------------------------------------------

    def _open(self) -> None:
        """Read the selected profile and unlock it with the typed primary password."""
        path = self._selected_path()
        if path is None:
            warn(self, "start.missing_file_message", "start.missing_file_title")
            return
        if not self.open_password.text():
            warn(self, "start.missing_fields_message", "start.missing_fields_title")
            return
        manager = self._read(path)
        if manager is None:
            return

        password = self.open_password.to_bytearray()
        self.open_password.clear()
        tr = translator.translate
        try:
            run_blocking(self, tr("start.unlocking"), lambda: manager.unlock(password))
        except PrimaryPasswordError:
            manager.close()
            warn(self, "start.wrong_primary_message", "start.wrong_password_title")
            return
        except (TamperedDataError, CorruptedFileError) as exc:
            manager.close()
            warn(self, "start.invalid_file_message", "start.invalid_file_title", error=str(exc))
            return
        self._finish(manager, path)

    def _read(self, path: Path) -> PasswordManager | None:
        """
        Read a profile file into a locked manager.

        Parameters
        ----------
        path : Path
            The file.

        Returns
        -------
        PasswordManager or None
            The manager, or ``None`` after an error message.
        """
        if not path.is_file():
            warn(self, "start.file_not_found_message", "start.file_not_found_title", path=str(path))
            return None
        try:
            return PasswordManager.read(path)
        except OSError as exc:
            warn(self, "start.read_error_message", "start.read_error_title", error=str(exc))
        except UnsupportedVersionError as exc:
            warn(self, "start.unsupported_version_message", "start.invalid_file_title", error=str(exc))
        except CorruptedFileError as exc:
            warn(self, "start.invalid_file_message", "start.invalid_file_title", error=str(exc))
        return None

    # -- create -------------------------------------------------------------

    def _create(self) -> None:
        """
        Create a new profile from the "create" form and write it.

        Notes
        -----
        Both passwords must be confirmed (the step at fault is shown
        again otherwise). The new profile starts in the
        current language and theme, and is written to
        :data:`core.profiles.PROFILES_DIR` right away, under its UUID.
        """
        for step, fields in ((_PRIMARY_STEP, self.primary_fields), (_SECONDARY_STEP, self.secondary_fields)):
            problem = fields.problem()
            if problem is not None:
                self._show_step(step)
                if problem == "empty":
                    warn(self, "start.missing_fields_message", "start.missing_fields_title")
                else:
                    warn(self, "start.mismatch_message", "start.mismatch_title")
                return
        username = self.username_edit.text().strip() or None
        label = self.label_edit.text().strip() or None
        primary_bytes = self.primary_fields.to_bytearray()
        secondary_bytes = self.secondary_fields.to_bytearray()
        self.clear_passwords()
        tr = translator.translate
        try:
            manager = run_blocking(
                self,
                tr("start.creating"),
                lambda: PasswordManager.create(username, primary_bytes, secondary_bytes, label=label),
            )
        except (PasswordManagerError, ValueError) as exc:
            warn(
                self,
                "start.create_error_message",
                "start.create_error_title",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            # The typed passwords are already erased: start again.
            self._show_step(_PRIMARY_STEP)
            return
        manager.set_language(translator.language)
        manager.set_theme(load_theme())

        try:
            ensure_profiles_dir()
            path = profile_path(manager.uuid)
            manager.save(path)
        except OSError as exc:
            manager.close()
            warn(self, "start.write_error_message", "start.write_error_title", error=str(exc))
            self._show_step(_PRIMARY_STEP)
            return

        self.username_edit.clear()
        self.label_edit.clear()
        self._label_follows_username = True
        self._finish(manager, path)

    def _finish(self, manager: PasswordManager, path: Path) -> None:
        """
        Hand an unlocked manager over to the window.

        Parameters
        ----------
        manager : PasswordManager
            The unlocked manager.
        path : Path
            Its file, remembered as the last one opened.
        """
        remember_file_path(path)
        self.clear_passwords()
        self.open_mode_btn.setChecked(True)
        self._on_mode_changed()
        self.session_opened.emit(manager, path)
