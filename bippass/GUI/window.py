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
from typing import TYPE_CHECKING, Callable, Optional

from PyQt5.QtCore import QEvent, QPoint, QSize, QTimer, pyqtSlot
from PyQt5.QtGui import QIcon, QKeySequence
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QMainWindow,
    QMenu,
    QPushButton,
    QShortcut,
    QStackedWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..__version__ import __version__
from ..core.exceptions import PasswordManagerError, VaultNotFoundError, WrongPasswordError
from .clipboard import clear_secret
from .common import _gui_icon, item_display_name
from .dialogs import (
    AccountSettingsDialog,
    ChangePasswordDialog,
    ExportItemsDialog,
    HelpDialog,
    ImportItemsDialog,
    MetadataDialog,
)
from .item_panel import ItemPanel
from .item_viewer import ItemViewer
from .save_worker import SaveWorker
from .tasks import is_busy, run_blocking
from .theme import DARK, LIGHT, apply_theme, load_theme, save_theme
from .translate import translator
from .start_page import APP_TITLE, StartPage
from .unlock import ensure_decrypted
from .vault_panel import VaultPanel
from ..backward.v2_to_v3_gui import menu_entries as _backward_menu_entries  # BACKWARD v2 -> v3, remove with bippass/backward/
from .widgets import (
    CANCEL,
    SAVE,
    LanguageComboBox,
    ask_unsaved,
    inform,
    refresh_style,
    show_error,
    show_rich_text,
    warn,
)

if TYPE_CHECKING:
    from ..core.item import Item
    from ..core.manager import PasswordManager
    from ..core.vault import Vault


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RELEASES_URL = "https://github.com/Artezaru/bippass/releases"

# User activity resetting the inactivity timer.
_ACTIVITY_EVENT_TYPES = (
    QEvent.MouseButtonPress,
    QEvent.MouseMove,
    QEvent.KeyPress,
    QEvent.Wheel,
)

_WINDOW_SIZE = (1300, 700)
_VAULT_LIST_WIDTH_PX = 400

# Zoom step and bounds, as a delta (pt) on the application's base font size.
_ZOOM_STEP_PT = 1
_ZOOM_MIN_DELTA_PT = -4
_ZOOM_MAX_DELTA_PT = 16

# Spacer width (px) before the theme toggle button, at the toolbar's left edge.
_TOOLBAR_LEFT_SPACING_PX = 16

# Padding (px) between the theme button's edge and its icon.
_THEME_BTN_ICON_PADDING_PX = 10

# Delay (ms) before retrying the auto-lock after cancelling a dialog.
_MODAL_RETRY_MS = 1000

# Pages of the central stack.
_START_PAGE, _CONTENT_PAGE = range(2)

# A menu entry: (translation key, slot or None for a greyed-out entry,
# shortcut shown or None); None stands for a separator.
MenuEntry = Optional[tuple[str, Optional[Callable[[], None]], Optional[str]]]


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class PasswordManagerWindow(QMainWindow):
    """
    Main window of the password manager.

    The toolbar holds the theme toggle, the language switcher, the Save
    button (highlighted while there are unsaved changes), the
    Decrypt/Encrypt toggle, the Lock button and a Settings menu.
    Below, three columns show the vaults (:class:`VaultPanel`), the
    items of the selected vault (:class:`ItemPanel`) and the embedded
    :class:`ItemViewer` of the open item. Until a profile is open, and
    whenever it is locked, the :class:`StartPage` replaces the three
    columns: the same window opens, creates and switches profiles.

    Attributes
    ----------
    manager : PasswordManager or None
        Manager of the open profile, ``None`` on the start page.
    file_path : Path or None
        File of the session.

    Notes
    -----
    **Profile states**, as in the command-line interface:

    - *unlocked*: names, logins and every clear field are shown;
    - *decrypted*: secrets can be shown, copied and edited too. The
      secondary password is asked the first time a secret is needed
      (:meth:`ensure_decrypted`), or with the Decrypt button; Encrypt
      forgets the data key again;
    - *locked*: the Lock button (``Ctrl+L``) or the inactivity timer
      save the profile, close it (erasing both keys) and bring back the
      start page, to open it again, open another profile or create one.
      If the save fails, the profile stays open.

    **Saving.** Changes are only written to disk when Save is pressed
    (or ``Ctrl+S``), when the window is closed after confirmation, when
    the profile is locked, or after a password change. Serializing
    happens in the GUI thread, writing in a :class:`SaveWorker`.

    Closing the window always erases both keys through
    :meth:`PasswordManager.close`.
    """

    def __init__(self):
        super().__init__()
        self.manager: PasswordManager | None = None
        self.file_path: Path | None = None

        self._viewer: ItemViewer | None = None
        self._viewer_uuid: str | None = None

        self._save_thread: SaveWorker | None = None
        self._dirty = False
        self._auto_closing = False
        self._closed = False

        self._theme = load_theme()

        self._base_font_pt = QApplication.font().pointSize()
        self._zoom_delta_pt = 0

        self.resize(*_WINDOW_SIZE)
        self._build_toolbar()
        self._build_ui()
        self._build_shortcuts()
        self._retranslate_ui()
        translator.language_changed.connect(self._retranslate_ui)

        apply_theme(QApplication.instance(), self._theme, self._text_scale)
        self._update_theme_button()
        self._update_toolbar_sizes()

        self._inactivity_timer = QTimer(self)
        self._inactivity_timer.setSingleShot(True)
        self._inactivity_timer.timeout.connect(self._on_inactivity_timeout)
        QApplication.instance().installEventFilter(self)
        self._reset_inactivity_timer()
        self._update_state_buttons()

    # =======================================================================
    # UI construction
    # =======================================================================

    def _build_toolbar(self) -> None:
        """Build the toolbar: theme, language, Save, Decrypt/Encrypt, Lock and Settings."""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        left_spacer = QWidget()
        left_spacer.setFixedWidth(_TOOLBAR_LEFT_SPACING_PX)
        toolbar.addWidget(left_spacer)

        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("smallButton")
        self.theme_btn.clicked.connect(self._toggle_theme)
        toolbar.addWidget(self.theme_btn)

        self.language_combo = LanguageComboBox()
        self.language_combo.currentIndexChanged.connect(self._on_language_changed)
        toolbar.addWidget(self.language_combo)

        toolbar.addSeparator()

        self.save_btn = QPushButton()
        self.save_btn.setObjectName("saveButton")
        self.save_btn.clicked.connect(self._on_save_requested)
        # QToolBar shows a widget through its action: hiding the widget
        # itself would leave it on screen, so the actions are kept.
        self._session_actions = [toolbar.addWidget(self.save_btn)]

        self.crypt_btn = QPushButton()
        self.crypt_btn.setObjectName("cryptButton")
        self.crypt_btn.clicked.connect(self._toggle_decrypted)
        self._session_actions.append(toolbar.addWidget(self.crypt_btn))

        self.lock_btn = QPushButton()
        self.lock_btn.clicked.connect(self.lock)
        self._session_actions.append(toolbar.addWidget(self.lock_btn))

        self.settings_btn = QPushButton()
        self.settings_btn.clicked.connect(self._open_settings_menu)
        toolbar.addWidget(self.settings_btn)

    def _build_ui(self) -> None:
        """Build the stack: the start page, and the three columns."""
        content = QWidget()
        layout = QHBoxLayout(content)

        self.vault_panel = VaultPanel(self)
        self.vault_panel.setMaximumWidth(_VAULT_LIST_WIDTH_PX)
        layout.addWidget(self.vault_panel, 1)

        self.item_panel = ItemPanel(self)
        layout.addWidget(self.item_panel, 2)

        self.vault_panel.vault_changed.connect(self.item_panel.show_vault)
        self.vault_panel.items_moved.connect(self.item_panel.refresh)

        # Item viewer, hidden until an item is opened
        self.viewer_panel = QWidget()
        self._viewer_layout = QVBoxLayout(self.viewer_panel)
        self._viewer_layout.setContentsMargins(0, 0, 0, 0)
        self._viewer_layout.setSpacing(0)
        self.viewer_panel.setVisible(False)
        layout.addWidget(self.viewer_panel, 3)

        self.start_page = StartPage()
        self.start_page.session_opened.connect(self.open_session)

        self._stack = QStackedWidget()
        self._stack.insertWidget(_START_PAGE, self.start_page)
        self._stack.insertWidget(_CONTENT_PAGE, content)
        self._stack.setCurrentIndex(_START_PAGE)
        self.setCentralWidget(self._stack)

    def _build_shortcuts(self) -> None:
        """
        Bind the window-wide keyboard shortcuts.

        Notes
        -----
        Both ``Ctrl+=`` and ``Ctrl++`` zoom in, since platforms report
        the "+"/"=" key differently. ``Ctrl+A`` belongs to the item
        list. ``Ctrl+F`` (search), ``Ctrl+N`` (new item) and ``Ctrl+E``
        (edit the open item) do nothing on the start page.
        """
        shortcuts = (
            ("Ctrl+=", self._zoom_in),
            ("Ctrl++", self._zoom_in),
            ("Ctrl+-", self._zoom_out),
            ("Ctrl+0", self._reset_zoom),
            ("Ctrl+S", self._on_save_requested),
            ("Ctrl+K", self._save_and_exit),
            ("Ctrl+L", self.lock),
            ("Ctrl+F", self._on_search_requested),
            ("Ctrl+N", self._on_new_item_requested),
            ("Ctrl+E", self._on_edit_requested),
        )
        for sequence, slot in shortcuts:
            QShortcut(QKeySequence(sequence), self).activated.connect(slot)

    def exec_menu(self, entries: list[MenuEntry], pos: QPoint) -> None:
        """
        Show a popup menu and run the slot of the chosen entry.

        Parameters
        ----------
        entries : list
            ``(translation key, slot, shortcut or None)`` per entry,
            ``None`` for a separator. A ``None`` slot shows the entry
            greyed out. The shortcut is only displayed; it is bound
            elsewhere.
        pos : QPoint
            Global position of the menu.
        """
        menu = QMenu(self)
        slots = []
        for entry in entries:
            if entry is None:
                menu.addSeparator()
                continue
            label_key, slot, shortcut = entry
            action = menu.addAction(translator.translate(label_key))
            action.setEnabled(slot is not None)
            if shortcut:
                action.setShortcut(QKeySequence(shortcut))
            slots.append((action, slot))

        chosen = menu.exec_(pos)
        for action, slot in slots:
            if chosen is action and slot is not None:
                slot()
                return

    def _open_settings_menu(self) -> None:
        """
        Show the Settings menu below its button.

        Notes
        -----
        On the start page, with no profile open, the menu only offers
        Updates and Help: every other entry needs a profile.
        """
        about: list[MenuEntry] = [
            ("window.menu_updates_action", self._show_updates, None),
            ("window.menu_help_action", self._open_help, None),
        ]
        if not self.has_profile:
            entries = [*_backward_menu_entries(self), *about]  # BACKWARD v2 -> v3, remove with bippass/backward/
        else:
            entries = [
                ("window.menu_metadata_action", self._open_metadata_dialog, None),
                ("window.menu_credentials_action", self._open_change_password, None),
                ("window.menu_preferences_action", self._open_account_settings, None),
                None,
                ("window.menu_export_action", self._open_export_items, None),
                ("window.menu_import_action", self._open_import_items, None),
                None,
                ("window.menu_zoom_in_action", self._zoom_in, "Ctrl+="),
                ("window.menu_zoom_out_action", self._zoom_out, "Ctrl+-"),
                ("window.menu_zoom_reset_action", self._reset_zoom, "Ctrl+0"),
                None,
                *about,
            ]
        self.exec_menu(
            entries, self.settings_btn.mapToGlobal(self.settings_btn.rect().bottomLeft())
        )

    # =======================================================================
    # Services for the panels and the viewer
    # =======================================================================

    @property
    def has_profile(self) -> bool:
        """
        Tell whether a profile is open.

        Returns
        -------
        bool
            ``False`` on the start page. An open profile is always
            unlocked: locking it closes it.
        """
        return self.manager is not None

    @property
    def profile(self) -> PasswordManager:
        """
        Return the open profile.

        Returns
        -------
        PasswordManager
            :attr:`manager`, for code that only runs with a profile open.

        Raises
        ------
        RuntimeError
            On the start page, where no profile is open.
        """
        if self.manager is None:
            raise RuntimeError("No profile is open.")
        return self.manager

    @property
    def viewer_uuid(self) -> str | None:
        """
        Return the UUID of the item open in the viewer.

        Returns
        -------
        str or None
            The UUID, or ``None`` if the viewer is closed.
        """
        return self._viewer_uuid

    def is_editing(self, uuid: str) -> bool:
        """
        Tell whether an item is open in the viewer in EDIT mode.

        Parameters
        ----------
        uuid : str
            UUID of the item.

        Returns
        -------
        bool
            ``True`` if its edits are pending in the viewer: the item
            must then not be changed from elsewhere, since saving the
            viewer would overwrite those changes with its drafts.
        """
        return self._viewer is not None and self._viewer_uuid == uuid and self._viewer.is_editing

    def ensure_decrypted(self) -> bool:
        """
        Make sure secrets can be decrypted, asking for the secondary password if needed.

        Returns
        -------
        bool
            ``False`` if the user cancelled.

        Notes
        -----
        Called by the viewer before showing, copying or editing a
        secret, and before any other operation needing the data key.
        """
        decrypted = ensure_decrypted(self.profile, self)
        self._update_state_buttons()
        return decrypted

    def get_item(self, uuid: str) -> Item | None:
        """
        Return an item, showing an error if it can't be found.

        Parameters
        ----------
        uuid : str
            UUID of the item.

        Returns
        -------
        Item or None
            The item, or ``None`` after an error message.
        """
        try:
            return self.profile.get_item(uuid)
        except PasswordManagerError as exc:
            show_error(self, "window.could_not_open_item", error=str(exc))
            return None

    def find_vault(self, uuid: str) -> Vault | None:
        """
        Return a vault, if it still exists.

        Parameters
        ----------
        uuid : str
            UUID of the vault.

        Returns
        -------
        Vault or None
            The vault, or ``None`` (silently) if it no longer exists.
        """
        try:
            return self.profile.get_vault(uuid)
        except VaultNotFoundError:
            return None

    def item_display_name(self, uuid: str) -> str:
        """
        Return an item's name for a message.

        Parameters
        ----------
        uuid : str
            UUID of the item.

        Returns
        -------
        str
            The item's name, a placeholder if unnamed, or its UUID if
            it can't be found.
        """
        try:
            return item_display_name(self.profile.get_item(uuid))
        except PasswordManagerError:
            return uuid

    # =======================================================================
    # Translation
    # =======================================================================

    @pyqtSlot()
    def _retranslate_ui(self) -> None:
        """
        Refresh every translated text of the window.

        Connected to :attr:`Translator.language_changed`; the open
        viewer and the start page listen to it on their own.
        """
        tr = translator.translate
        self._update_title()
        self.theme_btn.setToolTip(tr("window.toolbar_theme_tooltip"))
        self.language_combo.setToolTip(tr("window.toolbar_language_tooltip"))
        self.save_btn.setText(tr("common.save"))
        self.lock_btn.setText(f"🔒 {tr('window.toolbar_lock_button')}")
        self.lock_btn.setToolTip(tr("window.toolbar_lock_tooltip"))
        self.settings_btn.setText(f"⚙ {tr('window.toolbar_settings_button')}")
        self.settings_btn.setToolTip(tr("window.toolbar_settings_tooltip"))
        self._update_save_button()
        self._update_state_buttons()
        self._update_toolbar_sizes()
        self.vault_panel.retranslate()
        self.item_panel.retranslate()

    def _update_title(self) -> None:
        """Show the open profile's label in the title bar, or the application name."""
        if not self.has_profile:
            self.setWindowTitle(APP_TITLE)
            return
        name = self.profile.label or translator.translate("common.anonymous_profile")
        self.setWindowTitle(translator.translate("window.title", name=name))

    # =======================================================================
    # Saving
    # =======================================================================

    def save(self) -> None:
        """
        Save the manager to :attr:`file_path` in the background.

        Notes
        -----
        The content is serialized right away, in this thread (fast,
        see :meth:`PasswordManager.to_bytes`); only the file write runs
        in a :class:`SaveWorker`. The window is marked as saved at once;
        :meth:`_on_save_failed` marks it modified again if the write
        fails. A write still running is waited for first, so two
        writes never overlap.
        """
        data = self.profile.to_bytes()
        assert self.file_path is not None  # set with the profile
        self._wait_for_save()
        self._save_thread = SaveWorker(self.file_path, data, self)
        self._save_thread.save_failed.connect(self._on_save_failed)
        self._save_thread.start()
        self._mark_clean()

    def _save_blocking(self) -> bool:
        """
        Save the manager to :attr:`file_path` and wait for the result.

        Returns
        -------
        bool
            ``True`` if the save succeeded; otherwise an error is shown
            and ``False`` is returned.

        Notes
        -----
        Used right before closing, when the file must be written before
        :meth:`PasswordManager.close` erases the keys.
        """
        self._wait_for_save()
        try:
            assert self.file_path is not None  # set with the profile
            self.profile.save(self.file_path)
        except Exception as exc:
            self._on_save_failed(f"{type(exc).__name__}: {exc}")
            return False
        self._mark_clean()
        return True

    def _wait_for_save(self) -> None:
        """Block until the background write, if any, is done."""
        if self._save_thread is not None and self._save_thread.isRunning():
            self._save_thread.wait()

    def _on_save_failed(self, message: str) -> None:
        """
        Report a failed save and mark the window as modified again.

        Parameters
        ----------
        message : str
            Readable description of the error.
        """
        self.mark_dirty()
        show_error(self, "window.save_error_message", error=message)

    def _commit_viewer(self) -> None:
        """Apply the open viewer's unsaved edits to its item, if in EDIT mode."""
        if self._viewer is not None and self._viewer.is_editing:
            self._viewer.save()

    def _on_save_requested(self) -> None:
        """Save button and Ctrl+S: apply the viewer's edits, then save."""
        if not self.has_profile:
            return
        self._commit_viewer()
        self.save()

    def _on_search_requested(self) -> None:
        """Ctrl+F: go to the search bar of the items."""
        if self.has_profile:
            self.item_panel.focus_search()

    def _on_new_item_requested(self) -> None:
        """Ctrl+N: add an item to the shown vault, opened in EDIT mode."""
        if self.has_profile:
            self.item_panel.add_item()

    def _on_edit_requested(self) -> None:
        """Ctrl+E: switch the open item to EDIT mode."""
        if self.has_profile and self._viewer is not None:
            self._viewer.enter_edit_mode()

    @property
    def is_dirty(self) -> bool:
        """Tell whether the open profile has unsaved changes."""
        return self._dirty

    def save_now(self) -> bool:
        """
        Save the open profile right away, without touching the viewer.

        Returns
        -------
        bool
            ``True`` if saved (or nothing to save).

        Notes
        -----
        Used after an unexpected error (see :mod:`crash`): the viewer's
        draft is left alone, since the error may come from it.
        """
        return not self.has_profile or self._save_blocking()

    def quit_now(self) -> None:
        """Close the window without asking anything (unsaved changes are lost)."""
        self._auto_closing = True
        self.close()

    def _save_and_exit(self) -> None:
        """Ctrl+K: apply the viewer's edits, save, then close without prompting."""
        if not self.has_profile:
            self.close()
            return
        self._commit_viewer()
        if self._save_blocking():
            self._auto_closing = True
            self.close()

    def mark_dirty(self) -> None:
        """Record unsaved changes."""
        self._dirty = True
        self._update_save_button()

    def _mark_clean(self) -> None:
        """Record that everything is saved."""
        self._dirty = False
        self._update_save_button()

    def _update_save_button(self) -> None:
        """
        Restyle the Save button through its ``dirty`` property (see the
        ``QPushButton#saveButton[dirty="true"]`` rule of `theme.py`) and
        update its tooltip.
        """
        self.save_btn.setProperty("dirty", "true" if self._dirty else "false")
        refresh_style(self.save_btn)
        self.save_btn.setToolTip(
            translator.translate(
                "window.toolbar_save_tooltip_dirty"
                if self._dirty
                else "window.toolbar_save_tooltip_clean"
            )
        )

    # =======================================================================
    # Decrypt, encrypt, lock
    # =======================================================================

    def _update_state_buttons(self) -> None:
        """Show the profile state on the Decrypt/Encrypt toggle, and show only what applies."""
        tr = translator.translate
        decrypted = self.has_profile and self.profile.is_decrypted
        if decrypted:
            self.crypt_btn.setText(f"🔓 {tr('window.toolbar_encrypt_button')}")
            self.crypt_btn.setToolTip(tr("window.toolbar_encrypt_tooltip"))
        else:
            self.crypt_btn.setText(f"🔐 {tr('window.toolbar_decrypt_button')}")
            self.crypt_btn.setToolTip(tr("window.toolbar_decrypt_tooltip"))
        # Colored by state (see the `QPushButton#cryptButton[state=...]`
        # rules of `theme.py`), like the prompt of the command line.
        self.crypt_btn.setProperty("state", "decrypted" if decrypted else "encrypted")
        refresh_style(self.crypt_btn)
        # Without an open profile, these buttons are neither shown nor
        # clickable; Settings stays, reduced to Updates and Help.
        for button in (self.save_btn, self.crypt_btn, self.lock_btn):
            button.setEnabled(self.has_profile)
        for action in self._session_actions:
            action.setVisible(self.has_profile)

    def _toggle_decrypted(self) -> None:
        """Decrypt (ask for the secondary password) or encrypt (forget the data key)."""
        if not self.has_profile:
            return
        if not self.profile.is_decrypted:
            self.ensure_decrypted()
            return
        self.encrypt()

    def encrypt(self) -> None:
        """
        Forget the data key: secrets can no longer be shown until decrypted again.

        Notes
        -----
        An item being edited is closed first (asking about unsaved
        edits), since saving secret edits needs the data key. Clear
        fields stay visible; a secret still in the clipboard is erased.
        """
        if self._viewer is not None and self._viewer.is_editing and not self.close_viewer():
            return
        self.profile.encrypt()
        clear_secret()
        if self._viewer is not None:
            self._viewer.refresh()
        self._update_state_buttons()

    def lock(self) -> None:
        """
        Lock the profile: save, close it, and go back to the start page.

        Notes
        -----
        Edits of the open item are asked about (cancelling keeps the
        profile open). See :meth:`_lock`.
        """
        if not self.has_profile or not self.close_viewer():
            return
        self._lock()

    def _lock(self) -> bool:
        """
        Save, close the profile and show the start page, without asking anything.

        Returns
        -------
        bool
            ``False`` if the save failed: an error is shown and the
            profile stays open, rather than losing the changes.

        Notes
        -----
        Closing erases both keys (:meth:`PasswordManager.close`) and
        drops every reference to vaults and items (lists emptied, viewer
        closed); a secret still in the clipboard is erased too. Opening
        the profile again reads its file anew from the start page.
        """
        self.close_viewer(ask=False)
        if self._dirty and not self._save_blocking():
            return False
        self._wait_for_save()
        clear_secret()
        self.vault_panel.clear()
        self.item_panel.clear()
        self._inactivity_timer.stop()
        self.profile.close()
        self.manager = None
        self.file_path = None
        self._mark_clean()
        self._show_start_page()
        return True

    def _show_start_page(self) -> None:
        """Show the start page, in place of the three columns."""
        self._stack.setCurrentIndex(_START_PAGE)
        self._update_state_buttons()
        self._update_title()
        self.start_page.focus_first_field()

    @pyqtSlot(object, object)
    def open_session(self, manager: PasswordManager, file_path: Path) -> None:
        """
        Show an unlocked profile: the one just unlocked or created on the start page.

        Parameters
        ----------
        manager : PasswordManager
            The unlocked manager.
        file_path : Path
            Its file.

        Notes
        -----
        The profile's theme and language are applied.
        """
        self.manager = manager
        self.file_path = file_path
        self._mark_clean()

        theme = manager.get_theme()
        if theme and theme != self._theme:
            self._set_theme(theme)
        language = manager.get_language()
        if language and language != translator.language:
            self._set_language(language)

        self._stack.setCurrentIndex(_CONTENT_PAGE)
        self.vault_panel.refresh()
        self._update_state_buttons()
        self._update_title()
        self._reset_inactivity_timer()

    # =======================================================================
    # Theme and language
    # =======================================================================

    def _set_theme(self, theme: str) -> None:
        """
        Apply a theme to the whole application and remember it.

        Parameters
        ----------
        theme : str
            :data:`theme.LIGHT` or :data:`theme.DARK`. Stored in the
            manager's preferences, and on this computer for the start
            page, shown before any profile is unlocked.
        """
        self._theme = theme
        save_theme(theme)
        if self.has_profile:
            self.profile.set_theme(theme)
        apply_theme(QApplication.instance(), theme, self._text_scale)
        self._update_theme_button()

    def _toggle_theme(self) -> None:
        """Switch between the light and dark themes."""
        self._set_theme(LIGHT if self._theme == DARK else DARK)
        if self.has_profile:
            self.mark_dirty()

    def _update_theme_button(self) -> None:
        """Show the icon of the current theme, or an emoji if the icon is missing."""
        icon = _gui_icon("moon.png" if self._theme == DARK else "sun.png")
        if icon is not None:
            self.theme_btn.setIcon(icon)
            self.theme_btn.setText("")
        else:
            self.theme_btn.setIcon(QIcon())
            self.theme_btn.setText("🌙" if self._theme == DARK else "☀️")

    def _update_toolbar_sizes(self) -> None:
        """
        Give every control of the toolbar the same height, and the
        session buttons the same width.

        Notes
        -----
        Emojis in some labels make their buttons a little taller than
        the others: everything follows the tallest. The width of the
        Decrypt/Encrypt toggle takes both of its labels into account,
        so the toolbar doesn't move when it switches. Called again
        after a zoom or a language change.
        """
        buttons = (self.save_btn, self.crypt_btn, self.lock_btn, self.settings_btn)
        crypt_text = self.crypt_btn.text()
        widths, heights = [], [self.language_combo.sizeHint().height()]
        tr = translator.translate
        for text in (f"🔓 {tr('window.toolbar_encrypt_button')}",
                     f"🔐 {tr('window.toolbar_decrypt_button')}"):
            self.crypt_btn.setText(text)
            widths.append(self.crypt_btn.sizeHint().width())
        self.crypt_btn.setText(crypt_text)
        for button in buttons:
            widths.append(button.sizeHint().width())
            heights.append(button.sizeHint().height())
        height, width = max(heights), max(widths)
        for button in buttons:
            button.setFixedSize(width, height)
        self.language_combo.setFixedHeight(height)
        icon_size = max(1, height - _THEME_BTN_ICON_PADDING_PX)
        self.theme_btn.setFixedSize(height, height)
        self.theme_btn.setIconSize(QSize(icon_size, icon_size))

    def _set_language(self, language: str) -> None:
        """
        Switch the display language of the whole application.

        Parameters
        ----------
        language : str
            Language code, stored in the manager's preferences. Every
            widget listening to :attr:`Translator.language_changed`
            retranslates itself.
        """
        if self.has_profile:
            self.profile.set_language(language)
        self.language_combo.set_language(language)
        translator.set_language(language)

    def _on_language_changed(self, index: int) -> None:
        """
        Apply the language picked in the toolbar.

        Parameters
        ----------
        index : int
            Index of the picked language in :attr:`language_combo`.
        """
        language = self.language_combo.itemData(index)
        if language is None or language == translator.language:
            return
        self._set_language(language)
        if self.has_profile:
            self.mark_dirty()

    # =======================================================================
    # Settings dialogs
    # =======================================================================

    def _open_metadata_dialog(self) -> None:
        """Edit the username and the label (the file name never changes: it is the UUID)."""
        dialog = MetadataDialog(self.profile, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        dialog.apply_to(self.profile)
        self._update_title()
        self.mark_dirty()

    def _open_account_settings(self) -> None:
        """Edit the inactivity delay, applied right away (theme and language are in the toolbar)."""
        dialog = AccountSettingsDialog(self.profile, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        dialog.apply_to(self.profile)
        self._reset_inactivity_timer()
        self.mark_dirty()

    def _open_change_password(self) -> None:
        """
        Change the primary or the secondary password, then save at once.

        Notes
        -----
        The current password is always asked, so that an unattended
        unlocked session can't be used to change it. Changing the
        secondary password re-encrypts every secret, so it needs the
        data key: if the profile isn't decrypted yet, the current
        secondary password decrypts it first. The profile is saved
        right after: until then, the file on disk still opens with the
        old password.
        """
        dialog = ChangePasswordDialog(parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        data = dialog.get_data()
        current, new = data["current"], data["new"]
        tr = translator.translate

        secondary = data["target"] == "secondary"

        def change() -> None:
            # The secondary change needs the data key: the current
            # secondary password just typed provides it (a copy, erased
            # by decrypt), so it isn't asked twice.
            try:
                if secondary:
                    if not self.profile.is_decrypted:
                        self.profile.decrypt(bytearray(current))
                    self.profile.change_secondary_password(current, new)
                else:
                    self.profile.change_primary_password(current, new)
            finally:
                current[:] = bytes(len(current))
                new[:] = bytes(len(new))

        try:
            run_blocking(self, tr("credentials.changing"), change)
        except WrongPasswordError:
            warn(self, "credentials.wrong_current_message", "credentials.wrong_current_title")
            return
        except (PasswordManagerError, ValueError) as exc:
            show_error(self, "credentials.change_error", error=str(exc))
            return

        self._update_state_buttons()
        self._commit_viewer()
        self.save()
        inform(self, "credentials.changed_title", "credentials.changed_message")

    def _open_export_items(self) -> None:
        """
        Export a selection of items to a new, standalone profile file.

        Notes
        -----
        The current profile is left untouched. Needs the data key, to
        re-encrypt the exported secrets with the new file's own key.
        """
        if not self.ensure_decrypted():
            return
        dialog = ExportItemsDialog(self.profile, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()
        tr = translator.translate
        try:
            run_blocking(
                self,
                tr("export.exporting"),
                lambda: self.profile.export_items(
                    data["path"],
                    data["item_uuids"],
                    data["primary"],
                    data["secondary"],
                    vault_name=data["vault_name"],
                ),
            )
        except OSError as exc:
            show_error(self, "export.error_message", error=str(exc))
            return
        except PasswordManagerError as exc:
            show_error(self, error=str(exc))
            return
        inform(self, "export.success_title", "export.success_message", path=data["path"])

    def _open_import_items(self) -> None:
        """
        Import the items of another profile file into a vault of this one.

        Notes
        -----
        Needs the data key, to re-encrypt the imported secrets with
        this profile's key.
        """
        if not self.close_viewer() or not self.ensure_decrypted():
            return
        dialog = ImportItemsDialog(self.profile, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()
        tr = translator.translate
        try:
            imported = run_blocking(
                self,
                tr("import.importing"),
                lambda: self.profile.import_items(
                    data["path"],
                    data["primary"],
                    data["secondary"],
                    vault_uuid=data["vault_uuid"],
                    vault_name=tr("import.new_vault_name"),
                ),
            )
        except WrongPasswordError:
            warn(self, "import.wrong_password_message", "import.wrong_password_title")
            return
        except OSError as exc:
            show_error(self, "import.read_error", error=str(exc))
            return
        except PasswordManagerError as exc:
            show_error(self, error=str(exc))
            return

        self.mark_dirty()
        self.vault_panel.refresh()
        if imported:
            self.vault_panel.select_vault(self.profile.vault_of(imported[0].uuid).uuid)
        inform(self, "import.success_title", "import.success_message", count=str(len(imported)))

    def _show_updates(self) -> None:
        """Show the current version and a link to the releases page."""
        show_rich_text(
            self,
            "window.updates_title",
            translator.translate("window.updates_text", version=__version__, url=RELEASES_URL),
        )

    def _open_help(self) -> None:
        """Show the help dialog."""
        HelpDialog(parent=self).exec_()

    # =======================================================================
    # Zoom
    # =======================================================================

    @property
    def _text_scale(self) -> float:
        """
        Return the current zoom as a multiplier of the base font size.

        Returns
        -------
        float
            ``1.0`` at the default zoom.
        """
        if not self._base_font_pt:
            return 1.0
        return (self._base_font_pt + self._zoom_delta_pt) / self._base_font_pt

    def _zoom_in(self) -> None:
        """Enlarge the interface by one step."""
        self._apply_zoom(self._zoom_delta_pt + _ZOOM_STEP_PT)

    def _zoom_out(self) -> None:
        """Shrink the interface by one step."""
        self._apply_zoom(self._zoom_delta_pt - _ZOOM_STEP_PT)

    def _reset_zoom(self) -> None:
        """Restore the default zoom."""
        self._apply_zoom(0)

    def _apply_zoom(self, delta_pt: int) -> None:
        """
        Apply a zoom level to the whole interface.

        Parameters
        ----------
        delta_pt : int
            Offset (pt) from the base font size, clamped to
            ``[_ZOOM_MIN_DELTA_PT, _ZOOM_MAX_DELTA_PT]``.

        Notes
        -----
        Changing the application font rescales most texts; the theme
        is re-applied with the new scale for the few QSS rules with a
        fixed ``font-size``. Both lists are rebuilt so their row fonts
        and icons follow.
        """
        self._zoom_delta_pt = max(_ZOOM_MIN_DELTA_PT, min(_ZOOM_MAX_DELTA_PT, delta_pt))

        app = QApplication.instance()
        font = app.font()
        font.setPointSize(max(1, self._base_font_pt + self._zoom_delta_pt))
        app.setFont(font)
        apply_theme(app, self._theme, self._text_scale)

        self._update_toolbar_sizes()
        if self.has_profile:
            self.vault_panel.refresh()

    # =======================================================================
    # Inactivity
    # =======================================================================

    def _reset_inactivity_timer(self) -> None:
        """Restart the inactivity timer with the manager's current delay, if unlocked."""
        if self.has_profile:
            self._inactivity_timer.start(self.profile.get_lock_timer_s() * 1000)

    def eventFilter(self, obj, event) -> bool:
        """
        Restart the inactivity timer on any user activity in the
        application, dialogs included.

        Parameters
        ----------
        obj : QObject
            Object receiving the event.
        event : QEvent
            The event.

        Returns
        -------
        bool
            Always ``False``: the event keeps propagating.
        """
        if event.type() in _ACTIVITY_EVENT_TYPES:
            self._reset_inactivity_timer()
        return False

    def _on_inactivity_timeout(self) -> None:
        """
        Lock the profile after inactivity, keeping the viewer's edits.

        Notes
        -----
        Postponed while a slow operation runs (see :func:`tasks.is_busy`),
        which uses the manager. A dialog left open is cancelled first,
        and the lock happens a moment later, once it has returned.
        Unlike the Lock button, nothing is asked: the viewer's edits
        are applied, then saved with everything else by :meth:`_lock`.
        """
        if not self.has_profile:
            return
        if is_busy():
            self._reset_inactivity_timer()
            return
        modal = QApplication.activeModalWidget()
        if modal is not None:
            # Close the dialog left open, then retry once its own event
            # loop has returned: its caller must not find the profile
            # locked under its feet.
            if isinstance(modal, QDialog):
                modal.reject()
            self._inactivity_timer.start(_MODAL_RETRY_MS)
            return
        self._commit_viewer()
        if not self._lock():
            self._reset_inactivity_timer()

    # =======================================================================
    # Item viewer
    # =======================================================================

    def open_viewer(self, uuid: str, edit: bool = False) -> None:
        """
        Show an item in the embedded viewer.

        Parameters
        ----------
        uuid : str
            UUID of the item.
        edit : bool, optional
            Whether to start in EDIT mode. Default is ``False``.
        """
        if self._viewer is not None and self._viewer_uuid == uuid:
            if edit and not self._viewer.is_editing:
                self._viewer.enter_edit_mode()
            return

        item = self.get_item(uuid)
        if item is None or not self.close_viewer():
            return

        viewer = ItemViewer(
            self.profile, item, ensure_decrypted=self.ensure_decrypted, parent=self.viewer_panel
        )
        viewer.item_changed.connect(self._on_viewer_item_changed)
        viewer.close_requested.connect(self.close_viewer)
        self._viewer_layout.addWidget(viewer)
        self._viewer = viewer
        self._viewer_uuid = uuid
        self.viewer_panel.setVisible(True)

        if edit:
            viewer.enter_edit_mode()

    def refresh_viewer(self, uuid: str) -> None:
        """
        Redraw the viewer if it shows an item changed from elsewhere.

        Parameters
        ----------
        uuid : str
            UUID of the changed item.
        """
        if self._viewer is not None and self._viewer_uuid == uuid:
            self._viewer.refresh()

    def close_viewer(self, ask: bool = True) -> bool:
        """
        Close the embedded viewer, if open.

        Parameters
        ----------
        ask : bool, optional
            Whether to ask about unsaved edits first. Default is
            ``True``; ``False`` discards them.

        Returns
        -------
        bool
            ``False`` if the user cancelled, ``True`` otherwise.
        """
        viewer = self._viewer
        if viewer is None:
            return True
        if ask and not viewer.confirm_close():
            return False

        self._viewer = None
        self._viewer_uuid = None
        self._viewer_layout.removeWidget(viewer)
        viewer.release()
        viewer.deleteLater()
        self.viewer_panel.setVisible(False)
        return True

    def _on_viewer_item_changed(self) -> None:
        """
        Mark the window as modified after the viewer changed its item.

        Notes
        -----
        The list is reloaded on the next event loop turn: the change
        may come from a selection handler of that very list (saving
        before switching item), which must not see it rebuilt.
        """
        self.mark_dirty()
        QTimer.singleShot(0, self._reload_items)

    def _reload_items(self) -> None:
        """Reload the item list, unless the window is closed or the profile locked."""
        if not self._closed and self.has_profile:
            self.item_panel.refresh()

    # =======================================================================
    # Closing
    # =======================================================================

    def closeEvent(self, event) -> None:
        """
        Ask about the viewer's edits and unsaved changes, then erase
        both keys and close.

        Parameters
        ----------
        event : QCloseEvent
            The close event, ignored if the user cancels or the save
            fails.

        Notes
        -----
        Nothing is asked when closing after Ctrl+K, which already
        saved, nor from the start page, where no profile is open.
        """
        if not self._auto_closing:
            if self.has_profile:
                if not self.close_viewer():
                    event.ignore()
                    return
                if self._dirty:
                    reply = ask_unsaved(
                        self, "window.unsaved_changes_title", "window.unsaved_changes_close_prompt"
                    )
                    if reply == CANCEL or (reply == SAVE and not self._save_blocking()):
                        event.ignore()
                        return

        # A background write must finish before the keys go.
        self._wait_for_save()
        QApplication.instance().removeEventFilter(self)
        self._inactivity_timer.stop()
        self._closed = True
        clear_secret()
        self.start_page.clear_passwords()
        self.close_viewer(ask=False)
        if self.manager is not None:
            self.profile.close()
        event.accept()
