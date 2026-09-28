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

import os
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from PyQt5.QtCore import QEvent, QPoint, QSize, Qt, QThread, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont, QFontMetrics, QIcon, QKeySequence
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QShortcut,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..__version__ import __version__
from ..core.credentials import Credentials
from ..core.exceptions import (
    PasswordManagerError,
    VaultAlreadyExistsError,
    VaultNotFoundError,
)
from ..core.profiles import PROFILES_DIR, profile_path
from .common import (
    TOOLBAR_LEFT_SPACING_PX,
    _DEFAULT_CLOSE_TIMER_S,
    _ITEM_ICON_MIN_SIZE_PX,
    _THEME_BTN_ICON_PADDING_PX,
    _VAULT_ICON_MIN_SIZE_PX,
    _VAULT_NAME_FONT_DELTA_PT,
    _ZOOM_MAX_DELTA_PT,
    _ZOOM_MIN_DELTA_PT,
    _ZOOM_STEP_PT,
    _gui_icon,
    _item_icon_or_default,
)
from .dialogs import (
    AccountSettingsDialog,
    ChangeCredentialsDialog,
    ExportItemsDialog,
    HelpDialog,
    ImportItemsDialog,
    ItemIconDialog,
    MetadataDialog,
    VaultIconDialog,
    vault_icon_pixmap,
)
from .item_viewer import ItemViewer
from .lists import ItemListWidget, SortKey, VaultListWidget, item_sort_key
from .theme import apply_theme, load_theme, save_theme
from .translate import ENGLISH, translator
from .widgets import LanguageComboBox, refresh_style

if TYPE_CHECKING:
    from ..core.item import Item
    from ..core.manager import PasswordManager


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
_SORT_BUTTON_WIDTH_PX = 32
_SORT_ICON_SIZE_PX = 16

# (sort key, translation key of its name), in display order.
_SORT_CHOICES = (
    (SortKey.ALPHABETIC, "window.sort_alphabetic"),
    (SortKey.ALPHANUMERIC, "window.sort_alphanumeric"),
    (SortKey.DATE, "window.sort_date"),
)

# A menu entry: (translation key, slot, shortcut shown or None); None
# stands for a separator.
_MenuEntry = Optional[tuple[str, Callable[[], None], Optional[str]]]


# ---------------------------------------------------------------------------
# Background save
# ---------------------------------------------------------------------------


class _SaveWorker(QThread):
    """
    Thread saving the manager to disk, so encryption and file I/O never
    block the UI.

    Edits made from the UI while it runs are safe:
    :class:`PasswordManager` guards its state with an internal lock.

    Parameters
    ----------
    manager : PasswordManager
        Manager to save.
    path : Path
        Destination file.
    parent : QObject, optional
        Parent object.

    Attributes
    ----------
    save_failed : pyqtSignal(str)
        Emitted with a readable message if the save failed.
    """

    save_failed = pyqtSignal(str)

    def __init__(self, manager: PasswordManager, path: Path, parent=None):
        super().__init__(parent)
        self.manager = manager
        self.path = path

    def run(self) -> None:
        """Save the manager, reporting any error through :attr:`save_failed`."""
        try:
            self.manager.save_changes(self.path)
        except Exception as exc:
            self.save_failed.emit(f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------


class PasswordManagerWindow(QMainWindow):
    """
    Main window of the password manager.

    The toolbar holds the theme toggle, the language switcher, the Save
    button (highlighted while there are unsaved changes) and a Settings
    menu (metadata, credentials, preferences, export/import, zoom,
    updates, help). Below, three columns show the vaults, the items of
    the selected vault (searchable, sortable, movable to another vault
    by drag and drop) and the embedded :class:`ItemViewer` of the open
    item.

    Parameters
    ----------
    manager : PasswordManager
        Manager shown by the window, already unlocked or freshly
        created.
    file_path : Path
        File the manager was loaded from or will be saved to.

    Notes
    -----
    Changes are only written to disk when Save is pressed (or Ctrl+S),
    when the window is closed after confirmation, or when the
    inactivity timer fires; every change otherwise only marks the
    window as modified. Closing the window always clears the
    credentials through :meth:`PasswordManager.close`.
    """

    def __init__(self, manager: PasswordManager, file_path: Path):
        super().__init__()
        self.manager = manager
        self.file_path = file_path

        self._viewer: ItemViewer | None = None
        self._viewer_uuid: str | None = None

        # Set while a list is rebuilt or re-selected by code, so the
        # selection handlers don't mistake it for a user action.
        self._syncing_selection = False

        self._vault_name = ""
        self._vault_items: list[Item] = []
        self._sort_key = SortKey.ALPHABETIC
        self._sort_descending = False

        self._save_thread: _SaveWorker | None = None
        self._dirty = False
        self._auto_closing = False
        self._closed = False

        self._theme = manager.get_theme() or load_theme()
        translator.set_language(manager.get_language() or ENGLISH)

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
        self._update_theme_button_size()
        self._update_list_icon_sizes()
        self._refresh_vaults()

        self._inactivity_timer = QTimer(self)
        self._inactivity_timer.setSingleShot(True)
        self._inactivity_timer.timeout.connect(self._on_inactivity_timeout)
        QApplication.instance().installEventFilter(self)
        self._reset_inactivity_timer()

    # =======================================================================
    # UI construction
    # =======================================================================

    def _build_toolbar(self) -> None:
        """Build the toolbar: theme toggle, language switcher, Save and Settings."""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        left_spacer = QWidget()
        left_spacer.setFixedWidth(TOOLBAR_LEFT_SPACING_PX)
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
        toolbar.addWidget(self.save_btn)

        self.settings_btn = QPushButton()
        self.settings_btn.clicked.connect(self._open_settings_menu)
        toolbar.addWidget(self.settings_btn)

    def _build_ui(self) -> None:
        """Build the three columns: vaults, items and the item viewer panel."""
        central = QWidget()
        main_layout = QHBoxLayout(central)

        # Vaults
        left_widget = QWidget()
        left_widget.setMaximumWidth(_VAULT_LIST_WIDTH_PX)
        left_layout = QVBoxLayout(left_widget)

        self.vaults_title_label = QLabel()
        self.vaults_title_label.setObjectName("sectionTitle")
        left_layout.addWidget(self.vaults_title_label)

        self.vault_list = VaultListWidget()
        self.vault_list.setMaximumWidth(_VAULT_LIST_WIDTH_PX)
        self.vault_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.vault_list.currentItemChanged.connect(self._on_vault_selected)
        self.vault_list.item_dropped.connect(self._on_item_dropped)
        self.vault_list.customContextMenuRequested.connect(self._vault_context_menu)
        left_layout.addWidget(self.vault_list)

        self.add_vault_button = QPushButton()
        self.add_vault_button.setMaximumWidth(_VAULT_LIST_WIDTH_PX)
        self.add_vault_button.clicked.connect(self._add_vault)
        left_layout.addWidget(self.add_vault_button)

        # Items
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        self.info_label = QLabel()
        self.info_label.setWordWrap(True)
        right_layout.addWidget(self.info_label)

        tools_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._refresh_item_list)
        tools_layout.addWidget(self.search_edit, stretch=1)

        self.sort_combo = QComboBox()
        for sort_key, _label_key in _SORT_CHOICES:
            self.sort_combo.addItem("", sort_key)
        self.sort_combo.setCurrentIndex(self.sort_combo.findData(self._sort_key))
        self.sort_combo.currentIndexChanged.connect(self._on_sort_key_changed)
        tools_layout.addWidget(self.sort_combo)

        self.sort_direction_button = QPushButton()
        self.sort_direction_button.setFixedWidth(_SORT_BUTTON_WIDTH_PX)
        self.sort_direction_button.setIconSize(QSize(_SORT_ICON_SIZE_PX, _SORT_ICON_SIZE_PX))
        self.sort_direction_button.clicked.connect(self._toggle_sort_direction)
        self._update_sort_direction_button()
        tools_layout.addWidget(self.sort_direction_button)
        right_layout.addLayout(tools_layout)

        self.item_list = ItemListWidget()
        self.item_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.item_list.itemActivated.connect(self._on_item_activated)
        self.item_list.currentItemChanged.connect(self._on_item_selection_changed)
        self.item_list.customContextMenuRequested.connect(self._item_context_menu)
        right_layout.addWidget(self.item_list)

        self.add_item_button = QPushButton()
        self.add_item_button.clicked.connect(self._add_item)
        right_layout.addWidget(self.add_item_button)

        # Item viewer, hidden until an item is opened
        self.viewer_panel = QWidget()
        self._viewer_layout = QVBoxLayout(self.viewer_panel)
        self._viewer_layout.setContentsMargins(0, 0, 0, 0)
        self._viewer_layout.setSpacing(0)
        self.viewer_panel.setVisible(False)

        main_layout.addWidget(left_widget, 1)
        main_layout.addWidget(right_widget, 2)
        main_layout.addWidget(self.viewer_panel, 3)
        self.setCentralWidget(central)

    def _build_shortcuts(self) -> None:
        """
        Bind the keyboard shortcuts: zoom, save, save and exit, and
        "select all" in the item list.

        Notes
        -----
        Both ``Ctrl+=`` and ``Ctrl++`` zoom in, since platforms report
        the "+"/"=" key differently. ``Ctrl+A`` is scoped to the item
        list, so it never steals "select all" from a text field.
        """
        shortcuts = (
            ("Ctrl+=", self._zoom_in),
            ("Ctrl++", self._zoom_in),
            ("Ctrl+-", self._zoom_out),
            ("Ctrl+0", self._reset_zoom),
            ("Ctrl+S", self._on_save_requested),
            ("Ctrl+K", self._save_and_exit),
        )
        for sequence, slot in shortcuts:
            QShortcut(QKeySequence(sequence), self).activated.connect(slot)

        select_all = QShortcut(QKeySequence("Ctrl+A"), self.item_list)
        select_all.setContext(Qt.WidgetWithChildrenShortcut)
        select_all.activated.connect(self.item_list.selectAll)

    def _exec_menu(self, entries: list[_MenuEntry], pos: QPoint) -> None:
        """
        Show a popup menu and run the slot of the chosen entry.

        Parameters
        ----------
        entries : list
            ``(translation key, slot, shortcut or None)`` per entry,
            ``None`` for a separator. The shortcut is only displayed;
            it is bound in :meth:`_build_shortcuts`.
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
            if shortcut:
                action.setShortcut(QKeySequence(shortcut))
            slots.append((action, slot))

        chosen = menu.exec_(pos)
        for action, slot in slots:
            if chosen is action:
                slot()
                return

    def _open_settings_menu(self) -> None:
        """Show the Settings menu below its button."""
        entries: list[_MenuEntry] = [
            ("window.menu_metadata_action", self._open_metadata_dialog, None),
            ("window.menu_credentials_action", self._open_change_credentials, None),
            ("window.menu_preferences_action", self._open_account_settings, None),
            None,
            ("window.menu_export_action", self._open_export_items, None),
            ("window.menu_import_action", self._open_import_items, None),
            None,
            ("window.menu_zoom_in_action", self._zoom_in, "Ctrl+="),
            ("window.menu_zoom_out_action", self._zoom_out, "Ctrl+-"),
            ("window.menu_zoom_reset_action", self._reset_zoom, "Ctrl+0"),
            None,
            ("window.menu_updates_action", self._show_updates, None),
            ("window.menu_help_action", self._open_help, None),
        ]
        self._exec_menu(
            entries, self.settings_btn.mapToGlobal(self.settings_btn.rect().bottomLeft())
        )

    # =======================================================================
    # Translation
    # =======================================================================

    @pyqtSlot()
    def _retranslate_ui(self) -> None:
        """
        Refresh every translated text of the window.

        Connected to :attr:`Translator.language_changed`; the open
        viewer listens to it on its own.
        """
        tr = translator.translate

        self.setWindowTitle(tr("window.title", filename=self.file_path.name))

        self.theme_btn.setToolTip(tr("window.toolbar_theme_tooltip"))
        self.language_combo.setToolTip(tr("window.toolbar_language_tooltip"))
        self.save_btn.setText(tr("common.save"))
        self.settings_btn.setText(f"⚙ {tr('window.toolbar_settings_button')}")
        self.settings_btn.setToolTip(tr("window.toolbar_settings_tooltip"))
        self._update_save_button()

        self.vaults_title_label.setText(tr("window.vaults_title"))
        self.add_vault_button.setText(tr("window.add_vault_button"))
        self.add_item_button.setText(tr("window.add_item_button"))
        self.search_edit.setPlaceholderText(tr("window.search_placeholder"))
        self.sort_direction_button.setToolTip(tr("window.reverse_sort_tooltip"))
        for index, (_sort_key, label_key) in enumerate(_SORT_CHOICES):
            self.sort_combo.setItemText(index, tr(label_key))

        self._refresh_item_list()

    # =======================================================================
    # Saving
    # =======================================================================

    def save(self) -> None:
        """
        Save the manager to :attr:`file_path` in the background.

        The window is marked as saved right away; :meth:`_on_save_failed`
        marks it modified again if the save fails. A save still running
        is waited for first, so two saves never write the file at once.
        """
        self._wait_for_save()
        self._save_thread = _SaveWorker(self.manager, self.file_path, self)
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
        Used before the credentials are cleared (closing, inactivity),
        when the file must be written before :meth:`PasswordManager.close`.
        """
        self._wait_for_save()
        try:
            self.manager.save_changes(self.file_path)
        except Exception as exc:
            self._on_save_failed(f"{type(exc).__name__}: {exc}")
            return False
        self._mark_clean()
        return True

    def _wait_for_save(self) -> None:
        """Block until the background save, if any, is done."""
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
        self._mark_dirty()
        QMessageBox.warning(
            self,
            translator.translate("window.save_error_title"),
            translator.translate("window.save_error_message", error=message),
        )

    def _commit_viewer(self) -> None:
        """Apply the open viewer's unsaved edits to its item, if in EDIT mode."""
        if self._viewer is not None and self._viewer.is_editing:
            self._viewer.save()

    def _on_save_requested(self) -> None:
        """Save button and Ctrl+S: apply the viewer's edits, then save."""
        self._commit_viewer()
        self.save()

    def _save_and_exit(self) -> None:
        """Ctrl+K: apply the viewer's edits, save, then close without prompting."""
        self._commit_viewer()
        if self._save_blocking():
            self._auto_closing = True
            self.close()

    def _mark_dirty(self) -> None:
        """Record unsaved changes."""
        self._dirty = True
        self._update_save_button()
        self._reset_inactivity_timer()

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
    # Theme and language
    # =======================================================================

    def _set_theme(self, theme: str) -> None:
        """
        Apply a theme to the whole application and remember it.

        Parameters
        ----------
        theme : str
            ``"light"`` or ``"dark"``. Stored in the manager's metadata
            and as the fallback of the unlock wizard, which runs before
            any manager is decrypted.
        """
        self._theme = theme
        save_theme(theme)
        self.manager.set_theme(theme)
        apply_theme(QApplication.instance(), theme, self._text_scale)
        self._update_theme_button()

    def _toggle_theme(self) -> None:
        """Switch between the light and dark themes."""
        self._set_theme("light" if self._theme == "dark" else "dark")
        self._mark_dirty()

    def _update_theme_button(self) -> None:
        """Show the icon of the current theme, or an emoji if the icon is missing."""
        icon = _gui_icon("moon.png" if self._theme == "dark" else "sun.png")
        if icon is not None:
            self.theme_btn.setIcon(icon)
            self.theme_btn.setText("")
        else:
            self.theme_btn.setIcon(QIcon())
            self.theme_btn.setText("🌙" if self._theme == "dark" else "☀️")

    def _update_theme_button_size(self) -> None:
        """
        Make the icon-only theme button as high as the Save button.

        Notes
        -----
        The theme button has no text to grow with the zoomed font, so
        it follows the Save button's size hint, which does.
        """
        height = self.save_btn.sizeHint().height()
        icon_size = max(1, height - _THEME_BTN_ICON_PADDING_PX)
        self.theme_btn.setFixedSize(height, height)
        self.theme_btn.setIconSize(QSize(icon_size, icon_size))

    def _set_language(self, language: str) -> None:
        """
        Switch the display language of the whole application.

        Parameters
        ----------
        language : str
            Language code, stored in the manager's metadata. Every
            widget listening to :attr:`Translator.language_changed`
            retranslates itself.
        """
        self.manager.set_language(language)
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
        self._mark_dirty()

    # =======================================================================
    # Settings dialogs
    # =======================================================================

    def _open_metadata_dialog(self) -> None:
        """Edit the account metadata; a new username also renames the profile file."""
        dialog = MetadataDialog(self.manager, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        new_username = dialog.get_username()
        if new_username and new_username != self.manager.get_username():
            if not self._move_profile_file(new_username):
                return

        dialog.apply_to(self.manager)
        self._mark_dirty()

    def _move_profile_file(self, username: str) -> bool:
        """
        Rename the profile file after a username change.

        Parameters
        ----------
        username : str
            The new username.

        Returns
        -------
        bool
            ``False`` if the username is taken by another profile or
            the file couldn't be renamed (an error is shown), ``True``
            otherwise.

        Notes
        -----
        A profile's file is named after its username in
        :data:`PROFILES_DIR`, so usernames must be unique. A file
        opened from elsewhere keeps its path. If nothing was saved
        under the old name yet, the next save simply writes the new
        file.
        """
        new_path = profile_path(username)
        if new_path == self.file_path:
            return True
        if new_path.exists():
            QMessageBox.warning(
                self,
                translator.translate("common.error_title"),
                translator.translate("metadata.username_already_taken", username=username),
            )
            return False
        if self.file_path.parent != PROFILES_DIR:
            return True

        self._wait_for_save()
        try:
            new_path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(self.file_path, new_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            QMessageBox.critical(
                self,
                translator.translate("common.error_title"),
                translator.translate("metadata.profile_rename_error", error=str(exc)),
            )
            return False

        self.file_path = new_path
        self.setWindowTitle(translator.translate("window.title", filename=new_path.name))
        return True

    def _open_account_settings(self) -> None:
        """Edit the theme, language and inactivity delay, applied right away."""
        dialog = AccountSettingsDialog(self.manager, self._theme, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        theme, language, _close_timer_s = dialog.apply_to(self.manager)
        if theme != self._theme:
            self._set_theme(theme)
        if language != translator.language:
            self._set_language(language)
        self._mark_dirty()

    def _open_change_credentials(self) -> None:
        """
        Change the primary or the secondary password.

        Notes
        -----
        The side left unchanged is carried over by re-supplying its
        current password to fresh :class:`Credentials`.
        """
        dialog = ChangeCredentialsDialog(parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()
        current = self.manager.get_credentials()
        new_credentials = Credentials()
        try:
            if data["target"] == "primary":
                new_credentials.set_primary_password(data["password"])
                new_credentials.set_secondary_password(current.get_secondary_password())
            else:
                new_credentials.set_primary_password(current.get_primary_password())
                new_credentials.set_secondary_password(data["password"])
            self.manager.change_credentials(new_credentials)
        except Exception as exc:
            QMessageBox.critical(
                self,
                translator.translate("common.error_title"),
                translator.translate("credentials.change_error", error=str(exc)),
            )
            return

        self._mark_dirty()
        QMessageBox.information(
            self,
            translator.translate("credentials.changed_title"),
            translator.translate("credentials.changed_message"),
        )

    def _open_export_items(self) -> None:
        """
        Export a selection of items to a new, standalone vault file.

        Notes
        -----
        The current manager is left untouched: the export goes through
        a throwaway manager built by :meth:`PasswordManager._export_items`.
        """
        dialog = ExportItemsDialog(self.manager, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()
        try:
            self.manager._export_items(data["path"], data["items"], data["credentials"])
        except OSError as exc:
            self._show_error(translator.translate("export.error_message", error=str(exc)))
            return
        except PasswordManagerError as exc:
            self._show_error(str(exc))
            return

        QMessageBox.information(
            self,
            translator.translate("export.success_title"),
            translator.translate("export.success_message", path=data["path"]),
        )

    def _open_import_items(self) -> None:
        """Import the items of a standalone vault file into a vault of this manager."""
        dialog = ImportItemsDialog(self.manager, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()
        try:
            imported = self.manager._import_items(
                data["path"], vault=data["vault"], import_credentials=data["credentials"]
            )
        except OSError as exc:
            self._show_error(translator.translate("import.read_error", error=str(exc)))
            return
        except PasswordManagerError as exc:
            self._show_error(str(exc))
            return

        self._refresh_vaults()
        self._select_vault(data["vault"])
        self._mark_dirty()
        QMessageBox.information(
            self,
            translator.translate("import.success_title"),
            translator.translate(
                "import.success_message", count=str(len(imported)), vault=data["vault"]
            ),
        )

    def _show_updates(self) -> None:
        """Show the current version and a link to the releases page."""
        box = QMessageBox(self)
        box.setWindowTitle(translator.translate("window.updates_title"))
        box.setTextFormat(Qt.RichText)
        box.setText(
            translator.translate("window.updates_text", version=__version__, url=RELEASES_URL)
        )
        box.exec_()

    def _open_help(self) -> None:
        """Show the help dialog."""
        HelpDialog(parent=self).exec_()

    def _show_error(self, message: str) -> None:
        """
        Show an error message box.

        Parameters
        ----------
        message : str
            Message to show.
        """
        QMessageBox.critical(self, translator.translate("common.error_title"), message)

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

        self._update_theme_button_size()
        self._update_list_icon_sizes()
        self._refresh_vaults()

    # =======================================================================
    # Inactivity
    # =======================================================================

    def _reset_inactivity_timer(self) -> None:
        """Restart the inactivity timer with the manager's current delay."""
        close_timer_s = self.manager.get_close_timer_s() or _DEFAULT_CLOSE_TIMER_S
        self._inactivity_timer.start(close_timer_s * 1000)

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
        Apply the viewer's edits, save and close after inactivity.

        If the save fails, the window stays open and the timer
        restarts, rather than losing the changes with the credentials.
        """
        self._commit_viewer()
        if not self._save_blocking():
            self._reset_inactivity_timer()
            return
        self._auto_closing = True
        self.close()

    # =======================================================================
    # List rows
    # =======================================================================

    def _row_font(self, list_widget: QListWidget, bold: bool = False) -> QFont:
        """
        Return the row font of a list.

        Parameters
        ----------
        list_widget : QListWidget
            List whose zoom-following font is the base.
        bold : bool, optional
            Whether the font is bold (vault names). Default is ``False``.

        Returns
        -------
        QFont
            The list's font enlarged by :data:`_VAULT_NAME_FONT_DELTA_PT`,
            shared by both lists so their rows have the same height.
        """
        font = QFont(list_widget.font())
        font.setPointSize(font.pointSize() + _VAULT_NAME_FONT_DELTA_PT)
        font.setBold(bold)
        return font

    def _update_list_icon_sizes(self) -> None:
        """Size both lists' icons to their row font at the current zoom."""
        for list_widget, bold, min_size in (
            (self.vault_list, True, _VAULT_ICON_MIN_SIZE_PX),
            (self.item_list, False, _ITEM_ICON_MIN_SIZE_PX),
        ):
            size = max(min_size, QFontMetrics(self._row_font(list_widget, bold)).height())
            list_widget.setIconSize(QSize(size, size))

    # =======================================================================
    # Vaults
    # =======================================================================

    def _refresh_vaults(self) -> None:
        """
        Rebuild the vault list, alphabetically, keeping the selected
        vault if it still exists, then reload its items.
        """
        vault_font = self._row_font(self.vault_list, bold=True)
        vaults = sorted(self.manager.get_vaults(), key=lambda vault: vault.name.casefold())

        self._syncing_selection = True
        try:
            self.vault_list.clear()
            for vault in vaults:
                row = QListWidgetItem(vault.name)
                row.setFont(vault_font)
                pixmap = vault_icon_pixmap(vault.get_icon(), vault.get_icon_color())
                if pixmap is not None:
                    row.setIcon(QIcon(pixmap))
                self.vault_list.addItem(row)
            if self.vault_list.count():
                self.vault_list.setCurrentRow(max(0, self.vault_list.row_of(self._vault_name)))
        finally:
            self._syncing_selection = False

        current = self.vault_list.currentItem()
        self._show_vault(current.text() if current is not None else "")

    def _select_vault(self, name: str) -> None:
        """
        Select a vault in the list, as if clicked.

        Parameters
        ----------
        name : str
            Name of the vault; nothing happens if it isn't listed.
        """
        row = self.vault_list.row_of(name)
        if row >= 0:
            self.vault_list.setCurrentRow(row)

    def _on_vault_selected(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        """
        Show the items of the vault selected by the user.

        Parameters
        ----------
        current : QListWidgetItem or None
            Newly selected row.
        previous : QListWidgetItem or None
            Previously selected row, unused.

        Notes
        -----
        Switching vault closes the viewer, asking about unsaved edits;
        if the user cancels, the previous vault is selected again.
        """
        if self._syncing_selection:
            return
        name = current.text() if current is not None else ""
        if name != self._vault_name and not self._close_viewer():
            QTimer.singleShot(0, self._restore_vault_selection)
            return
        self._show_vault(name)

    def _restore_vault_selection(self) -> None:
        """Select the displayed vault again, without reacting to it."""
        self._syncing_selection = True
        try:
            self.vault_list.setCurrentRow(self.vault_list.row_of(self._vault_name))
        finally:
            self._syncing_selection = False

    def _show_vault(self, name: str) -> None:
        """
        Load and show the items of a vault.

        Parameters
        ----------
        name : str
            Name of the vault, ``""`` for none. Showing another vault
            closes the viewer without asking; callers ask beforehand.
        """
        if name != self._vault_name:
            self._close_viewer(ask=False)
        try:
            vault = self.manager.get_vault(name) if name else None
        except VaultNotFoundError:
            vault = None

        self._vault_name = name if vault is not None else ""
        self._vault_items = list(vault.get_items()) if vault is not None else []
        self.item_list.current_vault_name = self._vault_name
        self._refresh_item_list()

    def _reload_vault(self) -> None:
        """Reload the items of the displayed vault after a change."""
        if not self._closed:
            self._show_vault(self._vault_name)

    def _add_vault(self) -> None:
        """Ask for a name and create an empty vault."""
        name, accepted = QInputDialog.getText(
            self,
            translator.translate("window.new_vault_title"),
            translator.translate("window.new_vault_prompt"),
        )
        name = name.strip()
        if not accepted or not name:
            return

        try:
            self.manager.add_empty_vault(name)
        except VaultAlreadyExistsError:
            self._warn_vault_exists(name)
            return

        self._refresh_vaults()
        self._mark_dirty()

    def _warn_vault_exists(self, name: str) -> None:
        """
        Warn that a vault name is already taken.

        Parameters
        ----------
        name : str
            The taken name.
        """
        QMessageBox.warning(
            self,
            translator.translate("window.vault_already_exists_title"),
            translator.translate("window.vault_already_exists_message", name=name),
        )

    def _vault_context_menu(self, pos: QPoint) -> None:
        """
        Show the context menu of a vault row: rename, icon, delete.

        Parameters
        ----------
        pos : QPoint
            Position of the click in :attr:`vault_list`.
        """
        row = self.vault_list.itemAt(pos)
        if row is None:
            return
        name = row.text()
        self._exec_menu(
            [
                ("window.rename_vault_action", lambda: self._rename_vault(name), None),
                ("window.vault_icon_action", lambda: self._change_vault_icon(name), None),
                ("window.delete_vault_action", lambda: self._delete_vault(name), None),
            ],
            self.vault_list.mapToGlobal(pos),
        )

    def _rename_vault(self, old_name: str) -> None:
        """
        Ask for a new name and rename a vault.

        Parameters
        ----------
        old_name : str
            Current name of the vault.
        """
        new_name, accepted = QInputDialog.getText(
            self,
            translator.translate("window.rename_vault_title"),
            translator.translate("window.rename_vault_prompt", name=old_name),
            text=old_name,
        )
        new_name = new_name.strip()
        if not accepted or not new_name or new_name == old_name:
            return

        try:
            self.manager.rename_vault(old_name, new_name)
        except VaultAlreadyExistsError:
            self._warn_vault_exists(new_name)
            return
        except PasswordManagerError as exc:
            self._show_error(str(exc))
            return

        # Keep the renamed vault selected, and its open item with it.
        if self._vault_name == old_name:
            self._vault_name = new_name
        self._refresh_vaults()
        self._mark_dirty()

    def _change_vault_icon(self, name: str) -> None:
        """
        Pick a vault's icon and color through :class:`VaultIconDialog`.

        Parameters
        ----------
        name : str
            Name of the vault.
        """
        try:
            vault = self.manager.get_vault(name)
        except VaultNotFoundError:
            return

        dialog = VaultIconDialog(vault.get_icon(), vault.get_icon_color(), parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()
        vault.set_icon(data["icon"])
        vault.set_icon_color(data["color"])
        self._refresh_vaults()
        self._mark_dirty()

    def _delete_vault(self, name: str) -> None:
        """
        Delete a vault and its items after confirmation.

        Parameters
        ----------
        name : str
            Name of the vault.

        Notes
        -----
        The confirmation mentions the number of items, so the vault is
        then removed with ``force=True``, items included.
        """
        try:
            item_count = len(self.manager.get_vault(name).get_items())
        except VaultNotFoundError:
            item_count = 0

        if item_count:
            prompt = translator.translate(
                "window.delete_vault_prompt_with_items", vault=name, count=str(item_count)
            )
        else:
            prompt = translator.translate("window.delete_vault_prompt", vault=name)
        if not self._confirm("window.delete_vault_title", prompt):
            return

        if self._vault_name == name:
            self._close_viewer(ask=False)
        try:
            self.manager.remove_vault(name, force=True)
        except PasswordManagerError as exc:
            self._show_error(str(exc))
            return

        self._refresh_vaults()
        self._mark_dirty()

    def _confirm(self, title_key: str, prompt: str) -> bool:
        """
        Ask a yes/no question.

        Parameters
        ----------
        title_key : str
            Translation key of the title.
        prompt : str
            Question, already translated.

        Returns
        -------
        bool
            ``True`` if the user answered yes.
        """
        reply = QMessageBox.question(
            self, translator.translate(title_key), prompt, QMessageBox.Yes | QMessageBox.No
        )
        return reply == QMessageBox.Yes

    # =======================================================================
    # Item list
    # =======================================================================

    def _on_sort_key_changed(self) -> None:
        """Sort the items by the criterion picked in :attr:`sort_combo`."""
        self._sort_key = self.sort_combo.currentData()
        self._refresh_item_list()

    def _toggle_sort_direction(self) -> None:
        """Reverse the sort order."""
        self._sort_descending = not self._sort_descending
        self._update_sort_direction_button()
        self._refresh_item_list()

    def _update_sort_direction_button(self) -> None:
        """Show the icon of the sort order, or an arrow if the icon is missing."""
        icon = _gui_icon("sort_desc.svg" if self._sort_descending else "sort_asc.svg")
        if icon is not None:
            self.sort_direction_button.setIcon(icon)
            self.sort_direction_button.setText("")
        else:
            self.sort_direction_button.setIcon(QIcon())
            self.sort_direction_button.setText("▼" if self._sort_descending else "▲")

    def _refresh_item_list(self) -> None:
        """
        Rebuild the item list from the displayed vault, applying the
        search text and the sort order.

        Notes
        -----
        The row of the open item (or else the current row) is selected
        again after the rebuild, without triggering the selection
        handler.
        """
        if not self._vault_name:
            self._syncing_selection = True
            try:
                self.item_list.clear()
            finally:
                self._syncing_selection = False
            self.info_label.setText(
                translator.translate("window.no_vault") if self.vault_list.count() == 0 else ""
            )
            return

        query = self.search_edit.text().strip().casefold()
        shown = [
            item for item in self._vault_items if query in (item.get("item_name") or "").casefold()
        ]
        shown.sort(key=item_sort_key(self._sort_key), reverse=self._sort_descending)

        current = self.item_list.currentItem()
        keep_uuid = self._viewer_uuid or (current.data(Qt.UserRole) if current else None)
        item_font = self._row_font(self.item_list)

        self._syncing_selection = True
        try:
            self.item_list.clear()
            for item in shown:
                row = QListWidgetItem(
                    item.get("item_name") or translator.translate("common.unnamed_item")
                )
                row.setData(Qt.UserRole, item.uuid)
                row.setFont(item_font)
                icon = _item_icon_or_default(item.get("icon"))
                if icon is not None:
                    row.setIcon(icon)
                self.item_list.addItem(row)
            if keep_uuid is not None:
                row_index = self.item_list.row_of(keep_uuid)
                if row_index >= 0:
                    self.item_list.setCurrentRow(row_index)
        finally:
            self._syncing_selection = False

        self.info_label.setText(
            translator.translate(
                "window.vault_info",
                vault=self._vault_name,
                shown=str(len(shown)),
                total=str(len(self._vault_items)),
            )
        )

    def _select_item(self, uuid: str) -> None:
        """
        Select an item's row without reacting to it.

        Parameters
        ----------
        uuid : str
            UUID of the item; nothing happens if it isn't listed.
        """
        self._syncing_selection = True
        try:
            row = self.item_list.row_of(uuid)
            if row >= 0:
                self.item_list.setCurrentRow(row)
        finally:
            self._syncing_selection = False

    def _on_item_selection_changed(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        """
        Close the viewer when another row is selected.

        Parameters
        ----------
        current : QListWidgetItem or None
            Newly selected row.
        previous : QListWidgetItem or None
            Previously selected row, unused.

        Notes
        -----
        Reacting to any selection change (click, arrows, Tab) keeps the
        highlighted row and the open item in sync; opening takes a
        double click or Enter. Unsaved edits are asked about first; if
        the user cancels, the open item's row is selected again.
        """
        if self._syncing_selection or self._viewer_uuid is None:
            return
        uuid = current.data(Qt.UserRole) if current is not None else None
        if uuid != self._viewer_uuid and not self._close_viewer():
            QTimer.singleShot(0, lambda: self._select_item(self._viewer_uuid or ""))

    def _on_item_activated(self, row: QListWidgetItem) -> None:
        """
        Open the item of a row double-clicked or validated with Enter.

        Parameters
        ----------
        row : QListWidgetItem
            The activated row.
        """
        self._open_viewer(row.data(Qt.UserRole))

    def _item_context_menu(self, pos: QPoint) -> None:
        """
        Show the context menu of an item row: open, rename, icon,
        duplicate, delete.

        Parameters
        ----------
        pos : QPoint
            Position of the click in :attr:`item_list`.
        """
        row = self.item_list.itemAt(pos)
        if row is None:
            return
        uuid = row.data(Qt.UserRole)
        self._exec_menu(
            [
                ("window.open_action", lambda: self._open_viewer(uuid), None),
                ("window.rename_item_action", lambda: self._rename_item(uuid), None),
                ("window.item_icon_action", lambda: self._change_item_icon(uuid), None),
                ("window.duplicate_action", lambda: self._duplicate_item(uuid), None),
                ("window.delete_action", lambda: self._delete_item(uuid), None),
            ],
            self.item_list.mapToGlobal(pos),
        )

    # =======================================================================
    # Items
    # =======================================================================

    def _get_item(self, uuid: str) -> Item | None:
        """
        Return an item, showing an error if it can't be read.

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
            return self.manager.get_item(uuid)
        except Exception as exc:
            self._show_error(translator.translate("window.could_not_open_item", error=str(exc)))
            return None

    def _item_name(self, uuid: str) -> str:
        """
        Return an item's name for a message.

        Parameters
        ----------
        uuid : str
            UUID of the item.

        Returns
        -------
        str
            The item's name, or its UUID if unnamed or unreadable.
        """
        try:
            return self.manager.get_item(uuid).get("item_name") or uuid
        except Exception:
            return uuid

    def _add_item(self) -> None:
        """Create an empty item in the displayed vault and open it in EDIT mode."""
        if not self._vault_name:
            QMessageBox.warning(
                self,
                translator.translate("window.no_vault_title"),
                translator.translate("window.no_vault_message"),
            )
            return
        if not self._close_viewer():
            return

        try:
            item = self.manager.add_empty_item(self._vault_name)
        except PasswordManagerError as exc:
            self._show_error(str(exc))
            return

        # The new item is unnamed: clear the search so it is listed.
        self.search_edit.clear()
        self._reload_vault()
        self._select_item(item.uuid)
        self._open_viewer(item.uuid, edit=True)
        self._mark_dirty()

    def _rename_item(self, uuid: str) -> None:
        """
        Ask for a new name and rename an item.

        Parameters
        ----------
        uuid : str
            UUID of the item.
        """
        item = self._get_item(uuid)
        if item is None:
            return

        old_name = item.get("item_name") or ""
        new_name, accepted = QInputDialog.getText(
            self,
            translator.translate("window.rename_item_title"),
            translator.translate(
                "window.rename_item_prompt",
                name=old_name or translator.translate("common.unnamed_item"),
            ),
            text=old_name,
        )
        new_name = new_name.strip()
        if not accepted or new_name == old_name:
            return

        item.set("item_name", new_name or None)
        self._on_item_modified(uuid)

    def _change_item_icon(self, uuid: str) -> None:
        """
        Pick an item's icon through :class:`ItemIconDialog`.

        Parameters
        ----------
        uuid : str
            UUID of the item.
        """
        item = self._get_item(uuid)
        if item is None:
            return

        dialog = ItemIconDialog(item.get("icon") or "", parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        item.set("icon", dialog.get_path() or None)
        self._on_item_modified(uuid)

    def _on_item_modified(self, uuid: str) -> None:
        """
        Refresh the viewer (if it shows the item) and the list after an
        item was changed from the list.

        Parameters
        ----------
        uuid : str
            UUID of the changed item.
        """
        if self._viewer is not None and self._viewer_uuid == uuid:
            self._viewer.refresh()
        self._reload_vault()
        self._mark_dirty()

    def _duplicate_item(self, uuid: str) -> None:
        """
        Duplicate an item, with a new UUID, in the displayed vault.

        Parameters
        ----------
        uuid : str
            UUID of the item.
        """
        try:
            self.manager.duplicate_item(uuid, self._vault_name)
        except PasswordManagerError as exc:
            self._show_error(str(exc))
            return
        self._reload_vault()
        self._mark_dirty()

    def _delete_item(self, uuid: str) -> None:
        """
        Delete an item after confirmation.

        Parameters
        ----------
        uuid : str
            UUID of the item.
        """
        prompt = translator.translate(
            "window.delete_item_prompt", item=self._item_name(uuid), vault=self._vault_name
        )
        if not self._confirm("window.delete_item_title", prompt):
            return

        if self._viewer_uuid == uuid:
            self._close_viewer(ask=False)
        try:
            self.manager.delete_item(self._vault_name, uuid)
        except PasswordManagerError as exc:
            self._show_error(str(exc))
            return

        self._reload_vault()
        self._mark_dirty()

    def _on_item_dropped(
        self,
        item_uuids: list[str],
        source_vault: str,
        target_vault: str,
    ) -> None:
        """
        Move items dropped onto another vault, after confirmation.

        Parameters
        ----------
        item_uuids : list of str
            UUIDs of the dropped items.
        source_vault : str
            Vault the items come from.
        target_vault : str
            Vault the items are dropped onto.
        """
        names = [self._item_name(uuid) for uuid in item_uuids]
        if len(names) == 1:
            prompt = translator.translate(
                "window.move_item_prompt", item=names[0], source=source_vault, target=target_vault
            )
        else:
            prompt = translator.translate(
                "window.move_items_prompt",
                count=str(len(names)),
                items=", ".join(names),
                source=source_vault,
                target=target_vault,
            )
        if not self._confirm("window.move_item_title", prompt):
            return
        if self._viewer_uuid in item_uuids and not self._close_viewer():
            return

        try:
            for uuid in item_uuids:
                self.manager.move_item(uuid, source_vault, target_vault)
        except PasswordManagerError as exc:
            self._show_error(str(exc))
        finally:
            self._reload_vault()
            self._mark_dirty()

    # =======================================================================
    # Item viewer
    # =======================================================================

    def _open_viewer(self, uuid: str, edit: bool = False) -> None:
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

        item = self._get_item(uuid)
        if item is None or not self._close_viewer():
            return

        viewer = ItemViewer(self.manager, item, parent=self.viewer_panel)
        viewer.item_changed.connect(self._on_viewer_item_changed)
        viewer.close_requested.connect(self._close_viewer)
        self._viewer_layout.addWidget(viewer)
        self._viewer = viewer
        self._viewer_uuid = uuid
        self.viewer_panel.setVisible(True)

        if edit:
            viewer.enter_edit_mode()

    def _close_viewer(self, ask: bool = True) -> bool:
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
        self._mark_dirty()
        QTimer.singleShot(0, self._reload_vault)

    # =======================================================================
    # Closing
    # =======================================================================

    def closeEvent(self, event) -> None:
        """
        Ask about the viewer's edits and unsaved changes, then clear
        the credentials and close.

        Parameters
        ----------
        event : QCloseEvent
            The close event, ignored if the user cancels or the save
            fails.

        Notes
        -----
        Nothing is asked when closing after Ctrl+K or the inactivity
        timeout, which already saved.
        """
        if not self._auto_closing:
            if not self._close_viewer():
                event.ignore()
                return
            if self._dirty:
                reply = QMessageBox.question(
                    self,
                    translator.translate("window.unsaved_changes_title"),
                    translator.translate("window.unsaved_changes_close_prompt"),
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                )
                if reply == QMessageBox.Cancel or (
                    reply == QMessageBox.Yes and not self._save_blocking()
                ):
                    event.ignore()
                    return

        # A background save must finish before the credentials go.
        self._wait_for_save()
        QApplication.instance().removeEventFilter(self)
        self._inactivity_timer.stop()
        self._closed = True
        self.manager.close()
        event.accept()