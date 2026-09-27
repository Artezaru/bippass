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

from PyQt5.QtCore import Qt, QTimer, QEvent, QSize
from PyQt5.QtGui import QFont, QFontMetrics, QIcon, QKeySequence
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
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

from ...core.manager import PasswordManager
from ...core.credentials import Credentials
from ...core.profiles import PROFILES_DIR, profile_path
from ...core.exceptions import (
    VaultNotFoundError,
    VaultAlreadyExistsError,
    ItemAlreadyExistsError,
    PasswordManagerError,
)

from ..item_viewer import ItemViewer, _icon_pixmap_or_default
from ..help_gui import HelpDialog
from ..theme import apply_theme, load_theme, save_theme
from ..translate import translator, ENGLISH, FRENCH, SPANISH

from .common import (
    _gui_icon,
    _t,
    _DEFAULT_CLOSE_TIMER_S,
    _ITEM_ICON_MIN_SIZE_PX,
    _THEME_BTN_ICON_PADDING_PX,
    _VAULT_ICON_MIN_SIZE_PX,
    _VAULT_NAME_FONT_DELTA_PT,
    _ZOOM_MAX_DELTA_PT,
    _ZOOM_MIN_DELTA_PT,
    _ZOOM_STEP_PT,
    TOOLBAR_LEFT_SPACING_PX,
)
from .widgets import (
    ItemListWidget,
    SortKey,
    VaultListWidget,
    _natural_sort_key,
    _SaveWorker,
)
from .dialogs import AccountSettingsDialog, ChangeCredentialsDialog, MetadataDialog
from .export_import import ExportItemsDialog, ImportItemsDialog
from .vault_icon_dialog import VaultIconDialog
from .vault_icons import vault_icon_pixmap


#: Event types counted as "user activity" for the inactivity timer,
#: watched application-wide via an event filter (see
#: `PasswordManagerWindow.eventFilter`).
_ACTIVITY_EVENT_TYPES = (
    QEvent.MouseButtonPress,
    QEvent.MouseMove,
    QEvent.KeyPress,
    QEvent.Wheel,
)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class PasswordManagerWindow(QMainWindow):
    """
    Main window of the password manager.

    A top toolbar holds the theme toggle, the language switcher, the
    Save button (colored differently depending on whether there are
    unsaved changes), and a single Settings button unfolding a menu
    with Metadata, Credentials, Preferences (theme/language/inactivity
    delay, all stored in the manager's metadata), interface zoom
    controls, and Help. There is no separate Close button: the window's
    own close box triggers :meth:`closeEvent`, which prompts to save
    unsaved changes and then always clears the encryption credentials
    via :meth:`PasswordManager.close`.

    Below that, the vault list is shown on the left and, for the
    vault currently selected, a searchable and sortable list of its
    items on the right. Items can be opened for viewing/editing,
    created, deleted (with confirmation), and moved between vaults by
    drag and drop.

    Parameters
    ----------
    manager : PasswordManager
        Manager backing this window; already unlocked (or freshly
        created via :meth:`PasswordManager.new`).
    file_path : Path
        Path of the vault file the manager was loaded from or created
        at, used for the window title and for saving.

    Notes
    -----
    Unlike an earlier version of this window, item/vault mutations
    (create, edit, delete, move) no longer trigger an automatic
    background save: each one only marks the window "dirty" (see
    :meth:`_mark_dirty`), and nothing is written to disk until the
    Save button is pressed, the window is closed, or the inactivity
    timer fires. This avoids the latency a save-on-every-change
    policy used to add to every single edit.
    """

    def __init__(
        self,
        manager: PasswordManager,
        file_path: Path,
    ):
        super().__init__()

        self.manager = manager
        self.file_path = file_path

        # Item currently shown in the embedded viewer panel (at most
        # one at a time, see `_open_item_viewer`/`_close_item_viewer`).
        self._current_viewer: ItemViewer | None = None
        self._current_viewer_uuid: str | None = None

        # Unfiltered, unsorted items of the currently selected vault;
        # `_apply_filter_and_sort` derives the displayed rows from this.
        self._current_vault_items: list = []
        self._current_vault_name: str = ""
        self._sort_key: SortKey = SortKey.ALPHABETIC
        self._sort_descending: bool = False

        # Background save thread, kept as an attribute so it isn't
        # garbage-collected while running; see `save`.
        self._save_thread: _SaveWorker | None = None

        # Whether there are changes not yet written to disk; see
        # `_mark_dirty`/`_mark_clean`/`_update_save_button`.
        self._dirty: bool = False

        # Set right before closing as a consequence of the inactivity
        # timer or a successful "unsaved changes" prompt, so
        # `closeEvent` knows not to prompt again.
        self._auto_closing: bool = False

        # Current app theme ("light"/"dark") and display language are
        # both sourced from the manager's own metadata, so they follow
        # this account rather than a shared, file-wide setting.
        self._theme: str = manager.get_theme() or load_theme()
        translator.set_language(manager.get_language() or ENGLISH)

        # Interface zoom: a point-size delta applied on top of the
        # application's own base font size; see `_apply_zoom`.
        app = QApplication.instance()
        self._base_font_pt: int = app.font().pointSize() if app is not None else 10
        self._zoom_delta_pt: int = 0

        self.setWindowTitle(_t("window_title", filename=file_path.name))

        self.resize(1300, 700)

        self._build_toolbar()
        self._build_ui()
        self._build_shortcuts()
        self._refresh_vaults()

        app = QApplication.instance()
        if app is not None:
            apply_theme(app, self._theme)

        self._update_save_button()

        # Inactivity auto-save/auto-close timer.
        self._inactivity_timer = QTimer(self)
        self._inactivity_timer.setSingleShot(True)
        self._inactivity_timer.timeout.connect(self._on_inactivity_timeout)
        if app is not None:
            app.installEventFilter(self)
        self._reset_inactivity_timer()

    # =============================================================
    # UI construction
    # =============================================================

    def _build_toolbar(self) -> None:
        """
        Build the (deliberately minimal) top toolbar: the theme
        toggle, the language switcher, the Save button, and a single
        Settings button unfolding a menu with Metadata, Credentials,
        Preferences, zoom controls and Help (see
        :meth:`_open_settings_menu`).
        """
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        self._toolbar = toolbar

        # Left-edge spacer, as a real widget rather than
        # `toolbar.setContentsMargins(...)`: `theme.py` gives QToolBar
        # a QSS rule, and once a widget has an active stylesheet, Qt's
        # CSS engine takes over its box model and silently ignores
        # `setContentsMargins()` (padding defaults to 0 unless set in
        # QSS) -- a plain spacer widget isn't subject to that.
        # Change TOOLBAR_LEFT_SPACING_PX (in `common.py`) to adjust
        # the width.
        left_spacer = QWidget()
        left_spacer.setFixedWidth(TOOLBAR_LEFT_SPACING_PX)
        toolbar.addWidget(left_spacer)

        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("smallButton")
        self.theme_btn.clicked.connect(self._toggle_theme)
        self._update_theme_button()
        toolbar.addWidget(self.theme_btn)

        self.language_combo = QComboBox()
        self.language_combo.addItem(_t("language_en"), ENGLISH)
        self.language_combo.addItem(_t("language_fr"), FRENCH)
        self.language_combo.addItem(_t("language_es"), SPANISH)
        self.language_combo.setCurrentIndex(
            self.language_combo.findData(translator.language)
        )
        self.language_combo.currentIndexChanged.connect(self._on_language_changed)
        toolbar.addWidget(self.language_combo)

        toolbar.addSeparator()

        self.save_btn = QPushButton()
        self.save_btn.setObjectName("saveButton")
        self.save_btn.clicked.connect(self.save)
        toolbar.addWidget(self.save_btn)

        self.settings_btn = QPushButton()
        # No "smallButton" objectName here: that rule (padding: 2px)
        # is meant for the icon-only theme toggle, and gave this
        # (text-carrying) button a different, smaller height than
        # `save_btn` -- both now share the default QPushButton
        # padding, so their heights match.
        self.settings_btn.clicked.connect(self._open_settings_menu)
        toolbar.addWidget(self.settings_btn)

        self._retranslate_toolbar()
        # Needs `save_btn` to already exist (matches its height) --
        # done last, once the whole toolbar is built.
        self._update_theme_button_size()

    def _open_settings_menu(self) -> None:
        """
        Build and show the Settings menu below the toolbar's Settings
        button: Metadata, Credentials, Preferences, Export, Import and
        Help dialogs, plus the zoom controls.
        """
        menu = QMenu(self)

        metadata_action = menu.addAction(_t("menu_metadata_action"))
        credentials_action = menu.addAction(_t("menu_credentials_action"))
        preferences_action = menu.addAction(_t("menu_preferences_action"))

        menu.addSeparator()
        export_action = menu.addAction(_t("menu_export_action"))
        import_action = menu.addAction(_t("menu_import_action"))

        menu.addSeparator()
        zoom_in_action = menu.addAction(_t("menu_zoom_in_action"))
        zoom_in_action.setShortcut(QKeySequence("Ctrl+="))
        zoom_out_action = menu.addAction(_t("menu_zoom_out_action"))
        zoom_out_action.setShortcut(QKeySequence("Ctrl+-"))
        zoom_reset_action = menu.addAction(_t("menu_zoom_reset_action"))
        zoom_reset_action.setShortcut(QKeySequence("Ctrl+0"))

        menu.addSeparator()
        help_action = menu.addAction(_t("menu_help_action"))

        chosen = menu.exec_(
            self.settings_btn.mapToGlobal(self.settings_btn.rect().bottomLeft())
        )

        if chosen is metadata_action:
            self._open_metadata_dialog()
        elif chosen is credentials_action:
            self._open_change_credentials()
        elif chosen is preferences_action:
            self._open_account_settings()
        elif chosen is export_action:
            self._open_export_items()
        elif chosen is import_action:
            self._open_import_items()
        elif chosen is zoom_in_action:
            self._zoom_in()
        elif chosen is zoom_out_action:
            self._zoom_out()
        elif chosen is zoom_reset_action:
            self._reset_zoom()
        elif chosen is help_action:
            self._open_help()

    def _build_ui(self) -> None:
        central = QWidget()
        main_layout = QHBoxLayout(central)

        # =========================================================
        # Left column: vaults
        # =========================================================

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        self.vaults_title_label = QLabel()
        self.vaults_title_label.setObjectName("sectionTitle")

        self.vault_list = VaultListWidget()
        self.vault_list.currentItemChanged.connect(
            self._vault_selected
        )
        self.vault_list.item_dropped.connect(self._on_item_dropped)
        self.vault_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.vault_list.customContextMenuRequested.connect(self._vault_context_menu)

        self.add_vault_button = QPushButton()
        self.add_vault_button.clicked.connect(self._add_vault)

        left_layout.addWidget(self.vaults_title_label)
        left_layout.addWidget(self.vault_list)
        left_layout.addWidget(self.add_vault_button)

        # =========================================================
        # Right column: content
        # =========================================================

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        self.info_label = QLabel()
        self.info_label.setWordWrap(True)

        # -- Search + sort toolbar -----------------------------------

        tools_layout = QHBoxLayout()

        self.search_edit = QLineEdit()
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._apply_filter_and_sort)

        self.sort_combo = QComboBox()
        self.sort_combo.currentIndexChanged.connect(self._on_sort_key_changed)

        self.sort_direction_button = QPushButton("▲")
        self.sort_direction_button.setFixedWidth(32)
        self.sort_direction_button.clicked.connect(self._toggle_sort_direction)

        tools_layout.addWidget(self.search_edit, stretch=1)
        tools_layout.addWidget(self.sort_combo)
        tools_layout.addWidget(self.sort_direction_button)

        # -- Item list -------------------------------------------------

        self.item_list = ItemListWidget()
        self.item_list.itemDoubleClicked.connect(self._item_clicked)
        self.item_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.item_list.customContextMenuRequested.connect(self._item_context_menu)
        self._update_item_icon_size()

        self.add_item_button = QPushButton()
        self.add_item_button.clicked.connect(self._add_item)

        right_layout.addWidget(self.info_label)
        right_layout.addLayout(tools_layout)
        right_layout.addWidget(self.item_list)
        right_layout.addWidget(self.add_item_button)

        # =========================================================
        # Third column: embedded item viewer (hidden until an item
        # is opened; see `_open_item_viewer`/`_close_item_viewer`)
        # =========================================================

        self.viewer_panel = QWidget()
        viewer_panel_layout = QVBoxLayout(self.viewer_panel)
        viewer_panel_layout.setContentsMargins(0, 0, 0, 0)
        viewer_panel_layout.setSpacing(0)

        viewer_toolbar = QHBoxLayout()
        viewer_toolbar.setContentsMargins(8, 8, 8, 8)
        viewer_toolbar.addStretch()
        self.close_viewer_button = QPushButton()
        self.close_viewer_button.clicked.connect(self._close_item_viewer)
        viewer_toolbar.addWidget(self.close_viewer_button)
        viewer_panel_layout.addLayout(viewer_toolbar)

        # `_open_item_viewer` inserts the current ItemViewer directly
        # into this layout, at index 0 (below the toolbar above).
        self.viewer_content_layout = QVBoxLayout()
        viewer_panel_layout.addLayout(self.viewer_content_layout, stretch=1)

        self.viewer_panel.setVisible(False)

        main_layout.addWidget(left_widget, 1)
        main_layout.addWidget(right_widget, 2)
        main_layout.addWidget(self.viewer_panel, 3)

        self.setCentralWidget(central)

        self._retranslate_static_texts()
        self._retranslate_sort_combo()

    # =============================================================
    # Translation
    # =============================================================

    def _retranslate_toolbar(self) -> None:
        """Refresh every toolbar button/tooltip's text after a language change."""
        self.theme_btn.setToolTip(_t("toolbar_theme_tooltip"))
        self.language_combo.setToolTip(_t("toolbar_language_tooltip"))

        self.save_btn.setText(_t("toolbar_save_button"))

        self.settings_btn.setText(f"⚙ {_t('toolbar_settings_button')}")
        self.settings_btn.setToolTip(_t("toolbar_settings_tooltip"))

        self._update_save_button()

    def _retranslate_static_texts(self) -> None:
        """Refresh every static (non-toolbar) label/button after a language change."""
        self.setWindowTitle(_t("window_title", filename=self.file_path.name))
        self.vaults_title_label.setText(_t("vaults_title"))
        self.add_vault_button.setText(_t("add_vault_button"))
        self.add_item_button.setText(_t("add_item_button"))
        self.search_edit.setPlaceholderText(_t("search_placeholder"))
        self.sort_direction_button.setToolTip(_t("reverse_sort_tooltip"))
        self.close_viewer_button.setText(_t("close_viewer_button"))

        if self._current_vault_name:
            self._apply_filter_and_sort()
        elif self.vault_list.count() == 0:
            self.info_label.setText(_t("no_vault"))

    def _retranslate_sort_combo(self) -> None:
        """Rebuild the sort combo's item texts, keeping the current selection."""
        self.sort_combo.blockSignals(True)
        self.sort_combo.clear()
        self.sort_combo.addItem(_t("sort_alphabetic"), SortKey.ALPHABETIC)
        self.sort_combo.addItem(_t("sort_alphanumeric"), SortKey.ALPHANUMERIC)
        self.sort_combo.addItem(_t("sort_date"), SortKey.DATE)
        self.sort_combo.setCurrentIndex(
            self.sort_combo.findData(self._sort_key)
        )
        self.sort_combo.blockSignals(False)

    def _retranslate_ui(self) -> None:
        """
        Refresh every translated string in this window after a
        language change.

        Notes
        -----
        Also closes the embedded item viewer, if one is open: unlike
        this window, :class:`ItemViewer` has no retranslate hook of
        its own, so it would otherwise keep showing the previous
        language until reopened.
        """
        self._close_item_viewer()
        self._retranslate_toolbar()
        self._retranslate_static_texts()
        self._retranslate_sort_combo()

    # =============================================================
    # Persistence
    # =============================================================

    def save(self) -> None:
        """
        Persist the manager's current state to :attr:`file_path`.

        Runs :meth:`PasswordManager.save_changes` on a background
        thread (so the UI never blocks on encryption/file I/O), and
        optimistically marks the window clean right away; if the save
        turns out to fail, :meth:`_on_save_failed` marks it dirty
        again. If a previous background save is still in flight, this
        call waits for it to finish first rather than starting a
        second thread writing to the same file concurrently.
        """
        if self._save_thread is not None and self._save_thread.isRunning():
            self._save_thread.wait()

        self._save_thread = _SaveWorker(self.manager, self.file_path, self)
        self._save_thread.save_failed.connect(self._on_save_failed)
        self._save_thread.start()
        self._mark_clean()

    def _save_blocking(self) -> bool:
        """
        Synchronously persist the manager's current state.

        Returns
        -------
        bool
            ``True`` if the save succeeded, ``False`` otherwise (an
            error dialog is shown either way it fails).

        Notes
        -----
        Used instead of :meth:`save` wherever the manager's
        credentials are about to be cleared (window close, inactivity
        timeout): those callers need the write to have actually
        completed before :meth:`PasswordManager.close` runs, which a
        background save cannot guarantee.
        """
        if self._save_thread is not None and self._save_thread.isRunning():
            self._save_thread.wait()

        try:
            self.manager.save_changes(self.file_path)
        except Exception as exc:
            self._on_save_failed(f"{type(exc).__name__}: {exc}")
            return False

        self._mark_clean()
        return True

    def _on_save_failed(self, message: str) -> None:
        """Report a save failure to the user and mark the window dirty again."""
        self._mark_dirty()
        QMessageBox.warning(
            self,
            _t("save_error_title"),
            _t("save_error_message", error=message),
        )

    # =============================================================
    # Dirty-state tracking
    # =============================================================

    def _mark_dirty(self) -> None:
        """Record that there are unsaved changes and restyle the Save button."""
        self._dirty = True
        self._update_save_button()
        self._reset_inactivity_timer()

    def _mark_clean(self) -> None:
        """Record that everything is currently saved and restyle the Save button."""
        self._dirty = False
        self._update_save_button()

    def _update_save_button(self) -> None:
        """
        Apply the "dirty"/"clean" dynamic property to the Save button
        and re-polish it, so the QSS rules in `theme.py`
        (``QPushButton#saveButton[dirty="true"]``) pick up the change,
        and refresh its tooltip to match.
        """
        self.save_btn.setProperty("dirty", "true" if self._dirty else "false")
        self.save_btn.style().unpolish(self.save_btn)
        self.save_btn.style().polish(self.save_btn)
        self.save_btn.setToolTip(
            _t("toolbar_save_tooltip_dirty" if self._dirty else "toolbar_save_tooltip_clean")
        )

    # =============================================================
    # Theme
    # =============================================================

    def _toggle_theme(self) -> None:
        """
        Switch between the light and dark themes, restyling the whole
        application (this window, the item viewer, and any dialog
        shown afterwards), persisting the choice into the manager's
        metadata, and remembering it as the fallback for the unlock
        wizard's own theme (before any manager is decrypted).
        """
        self._theme = "light" if self._theme == "dark" else "dark"
        save_theme(self._theme)

        app = QApplication.instance()
        if app is not None:
            apply_theme(app, self._theme, self._text_scale)

        self._update_theme_button()
        self.manager.set_theme(self._theme)
        self._mark_dirty()

    def _update_theme_button_size(self) -> None:
        """
        Match the theme toggle button's size to `save_btn`'s height,
        so the two sit flush together in the toolbar, and rescale its
        icon to match.

        Notes
        -----
        Unlike text-carrying buttons (Save, Settings, ...), which
        grow on their own because their label follows the application
        font, `theme_btn` is icon-only and has no text to size itself
        by -- its height would otherwise stay put regardless of zoom.
        Rather than recompute it from `_text_scale` independently
        (which could drift from `save_btn`'s actual size), this reads
        `save_btn.sizeHint().height()` directly: `save_btn` already
        grows correctly with the zoomed font, so `theme_btn` simply
        follows it and the two always match, however `save_btn`'s
        size ends up being determined.
        :data:`_THEME_BTN_ICON_PADDING_PX` keeps the icon comfortably
        inside the button rather than filling it edge to edge.
        Called once at construction (:meth:`_build_toolbar`, after
        `save_btn` exists) and again from :meth:`_apply_zoom`.
        """
        height = self.save_btn.sizeHint().height()
        icon_size = max(1, height - _THEME_BTN_ICON_PADDING_PX)
        self.theme_btn.setFixedSize(height, height)
        self.theme_btn.setIconSize(QSize(icon_size, icon_size))

    def _update_theme_button(self) -> None:
        """
        Set the toggle button's icon to reflect the currently active
        theme, using the bundled ``moon.png``/``sun.png`` icons
        (``resources/gui/``) when available, falling back to an
        emoji glyph otherwise.
        """
        icon = _gui_icon("moon.png" if self._theme == "dark" else "sun.png")
        if icon is not None:
            self.theme_btn.setIcon(icon)
            self.theme_btn.setText("")
        else:
            self.theme_btn.setIcon(QIcon())
            self.theme_btn.setText("🌙" if self._theme == "dark" else "☀️")

    # =============================================================
    # Language
    # =============================================================

    def _on_language_changed(self, index: int) -> None:
        """Switch the display language and retranslate the whole window."""
        language = self.language_combo.itemData(index)
        if language is None or language == translator.language:
            return
        translator.set_language(language)
        self.manager.set_language(language)
        self._mark_dirty()
        self._retranslate_ui()

    # =============================================================
    # Metadata / settings / credentials dialogs
    # =============================================================

    def _open_metadata_dialog(self) -> None:
        """
        Open :class:`MetadataDialog` and apply the changes if
        accepted.

        Notes
        -----
        Since a profile's file is now named after its username
        (``~/bippass/<username>.encrypted``, see :mod:`core.profiles`),
        renaming the username here follows the exact same uniqueness
        rule ``credentials_gui._FilePage`` already enforces at
        creation time: refused if another profile already owns that
        username. When accepted and this vault's file currently lives
        in the managed profiles directory, the file is renamed to
        follow (``os.replace``, best-effort -- if the vault hasn't
        been saved to disk yet under its current name, there is
        simply nothing to move, and the next save just writes it
        under the new name directly). A vault opened from outside
        that directory (a custom/imported file) is left where it is.
        """
        dialog = MetadataDialog(self.manager, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        new_username = dialog.username_edit.text().strip() or None
        old_username = self.manager.get_username()

        if new_username and new_username != old_username:
            new_path = profile_path(new_username)
            if new_path.exists() and new_path != self.file_path:
                QMessageBox.warning(
                    self, _t("error_title"),
                    _t("username_already_taken", username=new_username),
                )
                return

            if self.file_path.parent == PROFILES_DIR and new_path != self.file_path:
                try:
                    new_path.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(self.file_path, new_path)
                except FileNotFoundError:
                    # Nothing saved under the old name yet -- fine,
                    # the next save() simply writes to `new_path`.
                    pass
                except OSError as exc:
                    QMessageBox.critical(
                        self, _t("error_title"),
                        _t("profile_rename_error", error=exc),
                    )
                    return
                self.file_path = new_path
                self.setWindowTitle(_t("window_title", filename=self.file_path.name))

        dialog.apply_to(self.manager)
        self._mark_dirty()

    def _open_account_settings(self) -> None:
        """
        Open :class:`AccountSettingsDialog` and, if accepted, apply
        the new theme/language right away and reset the inactivity
        timer to the new delay.
        """
        dialog = AccountSettingsDialog(self.manager, self._theme, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        theme, language, _close_timer_s = dialog.apply_to(self.manager)
        self._mark_dirty()

        if theme != self._theme:
            self._theme = theme
            save_theme(self._theme)
            app = QApplication.instance()
            if app is not None:
                apply_theme(app, self._theme, self._text_scale)
            self._update_theme_button()

        if language != translator.language:
            translator.set_language(language)
            self._retranslate_ui()

        self._reset_inactivity_timer()

    def _open_change_credentials(self) -> None:
        """
        Open :class:`ChangeCredentialsDialog` and, if accepted,
        replace the manager's credentials.

        Notes
        -----
        Only the side chosen in the dialog is actually changed: the
        other side is carried over unchanged by re-supplying its
        current password (still available, per-instance, through
        :meth:`Credentials.get_primary_password`/
        :meth:`Credentials.get_secondary_password`) to the very same
        :meth:`Credentials.set_primary_password`/
        :meth:`Credentials.set_secondary_password` setters. There is
        no PIN to carry over and no iteration count to preserve: both
        are always the fixed
        :attr:`Credentials.PRIMARY_ITERATIONS`/
        :attr:`Credentials.SECONDARY_ITERATIONS`.
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
                self, _t("error_title"), _t("credentials_change_error", error=exc),
            )
            return

        self._mark_dirty()
        QMessageBox.information(
            self, _t("credentials_changed_title"), _t("credentials_changed_message"),
        )

    # =============================================================
    # Export / Import
    # =============================================================

    def _open_export_items(self) -> None:
        """
        Open :class:`ExportItemsDialog` and, if accepted, write the
        selected items to a new, standalone vault file.

        Notes
        -----
        This never touches the current manager's own state (no vault
        or item of *this* manager is modified, and nothing is marked
        dirty): the whole operation happens inside a throwaway
        :class:`PasswordManager` built by
        :meth:`PasswordManager._export_items`, purely for the purpose
        of writing ``path``.
        """
        dialog = ExportItemsDialog(self.manager, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()

        try:
            self.manager._export_items(data["path"], data["items"], data["credentials"])
        except OSError as exc:
            QMessageBox.critical(self, _t("error_title"), _t("export_error_message", error=exc))
            return
        except PasswordManagerError as exc:
            QMessageBox.critical(self, _t("error_title"), str(exc))
            return

        QMessageBox.information(
            self,
            _t("export_success_title"),
            _t("export_success_message", path=data["path"]),
        )

    def _open_import_items(self) -> None:
        """
        Open :class:`ImportItemsDialog` and, if accepted, import the
        file's items into this manager.

        Notes
        -----
        Unlike exporting, this *does* mutate the current manager (the
        target vault is created if needed, and the imported items are
        added to it -- see :meth:`PasswordManager._import_items`), so
        the window is refreshed and marked dirty on success, the same
        as any other item-adding action.
        """
        dialog = ImportItemsDialog(self.manager, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()

        try:
            imported = self.manager._import_items(
                data["path"],
                vault=data["vault"],
                import_credentials=data["credentials"],
            )
        except OSError as exc:
            QMessageBox.critical(self, _t("error_title"), _t("import_read_error", error=exc))
            return
        except PasswordManagerError as exc:
            QMessageBox.critical(self, _t("error_title"), str(exc))
            return

        self._refresh_vaults()
        for row in range(self.vault_list.count()):
            if self.vault_list.item(row).text() == data["vault"]:
                self.vault_list.setCurrentRow(row)
                break

        self._mark_dirty()
        QMessageBox.information(
            self,
            _t("import_success_title"),
            _t("import_success_message", count=len(imported), vault=data["vault"]),
        )

    # =============================================================
    # Help
    # =============================================================

    def _open_help(self) -> None:
        """Open the (non-modal-in-effect, but simply exec'd) Help dialog."""
        HelpDialog(parent=self).exec_()

    # =============================================================
    # Zoom
    # =============================================================

    def _build_shortcuts(self) -> None:
        """
        Wire the interface zoom keyboard shortcuts (also reachable
        from the Settings menu, see :meth:`_open_settings_menu`), plus
        "select all" for the item list.

        Notes
        -----
        Both ``Ctrl+=`` and ``Ctrl++`` are bound to zoom in, since
        "+" normally sits on the same key as "=" (no Shift needed) on
        most keyboard layouts, and different Qt platforms report the
        pressed key combination differently.

        The ``Ctrl+A`` shortcut is scoped to :attr:`item_list` itself
        (``WidgetWithChildrenShortcut``) rather than the whole window,
        so it selects every item in the list only while that list (or
        a child of it) has focus, and never steals "select all" from
        a text field elsewhere in the window (e.g. :attr:`search_edit`).
        """
        for sequence in ("Ctrl+=", "Ctrl++"):
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.activated.connect(self._zoom_in)

        shortcut = QShortcut(QKeySequence("Ctrl+-"), self)
        shortcut.activated.connect(self._zoom_out)

        shortcut = QShortcut(QKeySequence("Ctrl+0"), self)
        shortcut.activated.connect(self._reset_zoom)

        select_all_shortcut = QShortcut(QKeySequence("Ctrl+A"), self.item_list)
        select_all_shortcut.setContext(Qt.WidgetWithChildrenShortcut)
        select_all_shortcut.activated.connect(self.item_list.selectAll)

    @property
    def _text_scale(self) -> float:
        """Current interface zoom, as a multiplier of the base font size."""
        if not self._base_font_pt:
            return 1.0
        return (self._base_font_pt + self._zoom_delta_pt) / self._base_font_pt

    def _zoom_in(self) -> None:
        self._apply_zoom(self._zoom_delta_pt + _ZOOM_STEP_PT)

    def _zoom_out(self) -> None:
        self._apply_zoom(self._zoom_delta_pt - _ZOOM_STEP_PT)

    def _reset_zoom(self) -> None:
        self._apply_zoom(0)

    def _apply_zoom(self, delta_pt: int) -> None:
        """
        Apply a new zoom level by changing the whole application's
        base font point size.

        Parameters
        ----------
        delta_pt : int
            Point-size offset from :attr:`_base_font_pt`, clamped to
            ``[_ZOOM_MIN_DELTA_PT, _ZOOM_MAX_DELTA_PT]``.

        Notes
        -----
        Two things need to change together for *every* piece of text
        in the interface to actually scale, not just most of it:

        - The application's base font, which almost every widget's
          text inherits by default -- changing it alone already
          rescales the vast majority of labels, buttons, fields, etc.
        - The handful of QSS rules in `theme.py` that hardcode a
          ``font-size`` in ``px`` (section titles, the item title
          edit, muted labels): an explicit QSS ``font-size`` overrides
          the inherited widget font outright, so those would otherwise
          stay fixed and ignore the zoom. :func:`_text_scale` is
          reapplied through :func:`apply_theme` right after the font
          change to keep them in step (see `theme.stylesheet`'s
          ``text_scale`` parameter).

        A couple of widgets also used to hardcode their own font via
        ``setFont(QFont(..., <point size>, ...))`` instead of
        following the application font -- e.g. the custom fields
        section title in `item_viewer.py` -- which has been changed to
        derive its size from the current application font instead, so
        it zooms too.

        :meth:`_refresh_vaults` is also called here (which itself
        calls :meth:`_update_vault_icon_size`) so the vault list's
        icon size and bold name font rescale in step with everything
        else, the same way :meth:`_update_item_icon_size` already
        does for the item list's icons.
        """
        self._zoom_delta_pt = max(
            _ZOOM_MIN_DELTA_PT, min(_ZOOM_MAX_DELTA_PT, delta_pt)
        )

        app = QApplication.instance()
        if app is None:
            return

        font = app.font()
        font.setPointSize(max(1, self._base_font_pt + self._zoom_delta_pt))
        app.setFont(font)

        apply_theme(app, self._theme, self._text_scale)
        self._update_theme_button_size()
        self._update_item_icon_size()
        self._refresh_vaults()

    # =============================================================
    # Inactivity timer
    # =============================================================

    def _reset_inactivity_timer(self) -> None:
        """(Re)start the inactivity timer from the manager's current delay."""
        close_timer_s = self.manager.get_close_timer_s() or _DEFAULT_CLOSE_TIMER_S
        self._inactivity_timer.start(close_timer_s * 1000)

    def eventFilter(self, obj, event) -> bool:
        """
        Reset the inactivity timer on any application-wide user
        activity (mouse press/move, key press, wheel).

        Notes
        -----
        Installed on the whole :class:`QApplication` (see
        :meth:`__init__`), not just this window, so interacting with
        a dialog (e.g. :class:`ItemViewer`, :class:`MetadataDialog`)
        counts as activity too. Never consumes the event: always
        returns ``False`` so it keeps propagating normally.
        """
        if event.type() in _ACTIVITY_EVENT_TYPES:
            self._reset_inactivity_timer()
        return False

    def _on_inactivity_timeout(self) -> None:
        """
        Save and close the window after enough inactivity.

        If the save fails, the window is kept open (with an error
        dialog already shown by :meth:`_save_blocking`) and the timer
        is simply restarted, rather than closing anyway and risking
        the unsaved changes being lost along with the credentials.
        """
        if not self._save_blocking():
            self._reset_inactivity_timer()
            return
        self._auto_closing = True
        self.close()

    # =============================================================
    # Vaults
    # =============================================================

    def _update_vault_icon_size(self) -> None:
        """
        Rescale :attr:`vault_list`'s icons to match the size a row
        actually takes at the current zoom level.

        Notes
        -----
        Mirrors :meth:`_update_item_icon_size` exactly, for the same
        reason: ``QListWidget.setIconSize`` is shared by every row, so
        it's derived from ``fontMetrics().height()`` (of the *vault*
        name font -- bold and a bit larger than the base font, see
        :meth:`_refresh_vaults`) rather than hardcoded, so the icon
        keeps a sensible size next to the (larger) vault name and
        follows the interface zoom.
        """
        vault_font = QFont(self.vault_list.font())
        vault_font.setPointSize(vault_font.pointSize() + _VAULT_NAME_FONT_DELTA_PT)
        size = max(
            _VAULT_ICON_MIN_SIZE_PX, QFontMetrics(vault_font).height()
        )
        self.vault_list.setIconSize(QSize(size, size))

    def _refresh_vaults(self) -> None:
        """
        Reload the vault list from the manager, keeping the current
        selection where possible.

        Notes
        -----
        Rendered exactly like :attr:`item_list`'s rows (native
        ``QListWidgetItem`` icon + text, via :attr:`vault_list`'s own
        ``setIconSize``, rather than a custom per-row widget): a
        custom widget with its own margins used to visibly misalign
        the name against the item list right next to it. The name is
        shown bold and a bit larger than the base font
        (:data:`_VAULT_NAME_FONT_DELTA_PT`) via ``QListWidgetItem.setFont``,
        which -- like the item list's icon size -- is recomputed here
        (and by :meth:`_apply_zoom`) from the *current* application
        font, so it keeps following the interface zoom.
        """
        previous_name = self._current_vault_name

        self.vault_list.clear()
        self._update_vault_icon_size()

        vaults = self.manager.get_vaults()

        vault_font = QFont(self.vault_list.font())
        vault_font.setBold(True)
        vault_font.setPointSize(vault_font.pointSize() + _VAULT_NAME_FONT_DELTA_PT)

        for vault in vaults:
            item = QListWidgetItem(vault.name)
            item.setFont(vault_font)

            pixmap = vault_icon_pixmap(vault.get_icon(), vault.get_icon_color())
            if pixmap is not None:
                item.setIcon(QIcon(pixmap))

            self.vault_list.addItem(item)

        if self.vault_list.count() == 0:
            self.info_label.setText(_t("no_vault"))
            return

        for row in range(self.vault_list.count()):
            if self.vault_list.item(row).text() == previous_name:
                self.vault_list.setCurrentRow(row)
                return

        self.vault_list.setCurrentRow(0)

    def _vault_selected(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        """
        Load the items of the newly selected vault and display them.

        Notes
        -----
        Closes the embedded :class:`ItemViewer`, if one is open,
        whenever the *actually selected vault* changes -- comparing
        against :attr:`_current_vault_name` rather than closing
        unconditionally, since this method is also called to simply
        refresh the current vault's item list (after adding, saving,
        deleting, or drag-and-dropping an item), and those callers
        rely on the viewer staying open.
        """
        del previous

        new_vault_name = current.text() if current is not None else ""
        if new_vault_name != self._current_vault_name:
            self._close_item_viewer()

        self._current_vault_items = []
        self._current_vault_name = ""
        self.item_list.current_vault_name = ""

        if current is None:
            self.item_list.clear()
            return

        vault_name = new_vault_name

        try:
            vault = self.manager.get_vault(vault_name)
        except VaultNotFoundError:
            self.item_list.clear()
            return

        self._current_vault_name = vault_name
        self.item_list.current_vault_name = vault_name
        self._current_vault_items = list(vault.get_items())

        self._apply_filter_and_sort()

    def _add_vault(self) -> None:
        """Prompt for a vault name and create it."""
        name, accepted = QInputDialog.getText(
            self,
            _t("new_vault_title"),
            _t("new_vault_prompt"),
        )

        if not accepted:
            return

        name = name.strip()

        if not name:
            return

        try:
            self.manager.add_empty_vault(name)

        except VaultAlreadyExistsError:
            QMessageBox.warning(
                self,
                _t("vault_already_exists_title"),
                _t("vault_already_exists_message", name=name),
            )
            return

        self._refresh_vaults()
        self._mark_dirty()

    def _vault_context_menu(self, pos) -> None:
        """Show the right-click menu ("Rename" / "Icon…" / "Delete") for a vault row."""
        list_item = self.vault_list.itemAt(pos)
        if list_item is None:
            return

        menu = QMenu(self)
        rename_action = menu.addAction(_t("rename_vault_action"))
        icon_action = menu.addAction(_t("vault_icon_action"))
        delete_action = menu.addAction(_t("delete_vault_action"))

        chosen = menu.exec_(self.vault_list.mapToGlobal(pos))
        if chosen is rename_action:
            self._rename_vault(list_item)
        elif chosen is icon_action:
            self._change_vault_icon(list_item)
        elif chosen is delete_action:
            self._delete_vault(list_item)

    def _rename_vault(self, list_item: QListWidgetItem) -> None:
        """
        Prompt for a new name and rename the vault.

        Parameters
        ----------
        list_item : QListWidgetItem
            Row of the vault to rename, as shown in :attr:`vault_list`.
        """
        old_name = list_item.text()

        new_name, accepted = QInputDialog.getText(
            self,
            _t("rename_vault_title"),
            _t("rename_vault_prompt", name=old_name),
            text=old_name,
        )
        if not accepted:
            return

        new_name = new_name.strip()
        if not new_name or new_name == old_name:
            return

        try:
            self.manager.rename_vault(old_name, new_name)
        except VaultAlreadyExistsError:
            QMessageBox.warning(
                self,
                _t("vault_already_exists_title"),
                _t("vault_already_exists_message", name=new_name),
            )
            return
        except PasswordManagerError as exc:
            QMessageBox.critical(self, _t("error_title"), str(exc))
            return

        self._refresh_vaults()
        self._mark_dirty()

    def _change_vault_icon(self, list_item: QListWidgetItem) -> None:
        """
        Open :class:`VaultIconDialog` and, if accepted, apply the
        chosen icon/color to the vault right away.

        Parameters
        ----------
        list_item : QListWidgetItem
            Row of the vault to edit, as shown in :attr:`vault_list`.

        Notes
        -----
        Mirrors :meth:`_edit_icon` in `item_viewer.ItemViewer`: the
        change is applied to the :class:`Vault` immediately (not
        deferred to any Save button of its own), only the window's
        overall dirty flag and the toolbar Save button decide when it
        actually reaches disk.
        """
        vault_name = list_item.text()

        try:
            vault = self.manager.get_vault(vault_name)
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

    def _delete_vault(self, list_item: QListWidgetItem) -> None:
        """
        Delete a vault after explicit user confirmation.

        Parameters
        ----------
        list_item : QListWidgetItem
            Row of the vault to delete, as shown in :attr:`vault_list`.

        Notes
        -----
        The confirmation prompt itself doubles as the "I understand
        this vault is not empty" acknowledgement: once the user
        confirms, this always calls
        :meth:`PasswordManager.remove_vault` with ``force=True``, so a
        vault full of items is deleted right along with them -- there
        is no second, separate warning for that case.
        """
        vault_name = list_item.text()

        try:
            item_count = len(self.manager.get_vault(vault_name).get_items())
        except VaultNotFoundError:
            item_count = 0

        if item_count:
            prompt = _t(
                "delete_vault_prompt_with_items", vault=vault_name, count=item_count
            )
        else:
            prompt = _t("delete_vault_prompt", vault=vault_name)

        reply = QMessageBox.question(
            self,
            _t("delete_vault_title"),
            prompt,
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        if self._current_vault_name == vault_name:
            self._close_item_viewer()

        try:
            self.manager.remove_vault(vault_name, force=True)
        except PasswordManagerError as exc:
            QMessageBox.critical(self, _t("error_title"), str(exc))
            return

        self._refresh_vaults()
        self._mark_dirty()

    # =============================================================
    # Search & sort
    # =============================================================

    def _on_sort_key_changed(self) -> None:
        self._sort_key = self.sort_combo.currentData()
        self._apply_filter_and_sort()

    def _toggle_sort_direction(self) -> None:
        self._sort_descending = not self._sort_descending
        self.sort_direction_button.setText("▼" if self._sort_descending else "▲")
        self._apply_filter_and_sort()

    def _sort_key_func(self):
        """
        Return the ``key=`` callable matching :attr:`_sort_key`.

        Returns
        -------
        callable
            A function mapping an :class:`Item` to a sortable value.
        """
        if self._sort_key is SortKey.DATE:
            return lambda item: item.get("item_date") or ""
        if self._sort_key is SortKey.ALPHANUMERIC:
            return lambda item: _natural_sort_key(item.get("item_name") or "")
        return lambda item: (item.get("item_name") or "").casefold()

    def _update_item_icon_size(self) -> None:
        """
        Rescale :attr:`item_list`'s icons to match the size a row
        actually takes at the current zoom level.

        Notes
        -----
        ``QListWidget.setIconSize`` is a single size shared by every
        row, so there is no true per-``QListWidgetItem`` size to read
        back before the list is populated -- the closest proxy is the
        row height the list's own (zoomed) font would produce, via
        ``fontMetrics().height()``, which grows in step with
        `_apply_zoom` exactly like the item names drawn next to each
        icon. Without this, the icon stays at Qt's default fixed icon
        size regardless of zoom and looks increasingly small next to
        the (now larger) text. Applying a new icon size takes effect
        immediately on already-populated rows, no rebuild needed.
        Called once at construction (:meth:`_build_ui`) and again
        from :meth:`_apply_zoom`.
        """
        size = max(_ITEM_ICON_MIN_SIZE_PX, self.item_list.fontMetrics().height())
        self.item_list.setIconSize(QSize(size, size))

    def _apply_filter_and_sort(self) -> None:
        """
        Rebuild the item list widget from :attr:`_current_vault_items`,
        applying the current search text and sort settings.
        """
        self.item_list.clear()

        query = self.search_edit.text().strip().casefold()
        filtered = [
            item for item in self._current_vault_items
            if query in (item.get("item_name") or "").casefold()
        ]
        filtered.sort(key=self._sort_key_func(), reverse=self._sort_descending)

        for item in filtered:
            list_item = QListWidgetItem(item.get("item_name") or _t("unnamed_item"))
            list_item.setData(Qt.UserRole, item.uuid)

            # Show the item's icon next to its name, falling back to
            # the bundled default icon when the path is missing or
            # unreadable -- reusing the same logic as ItemViewer so
            # the two views never disagree on what icon to show.
            pixmap = _icon_pixmap_or_default(item.get("icon"))
            if pixmap is not None:
                list_item.setIcon(QIcon(pixmap))

            self.item_list.addItem(list_item)

        if self._current_vault_name:
            self.info_label.setText(
                _t(
                    "vault_info",
                    vault=self._current_vault_name,
                    shown=len(filtered),
                    total=len(self._current_vault_items),
                )
            )

    # =============================================================
    # Items
    # =============================================================

    def _add_item(self) -> None:
        """Create a new item in the selected vault and open it in EDIT mode."""
        current = self.vault_list.currentItem()

        if current is None:
            QMessageBox.warning(
                self,
                _t("no_vault_title"),
                _t("no_vault_message"),
            )
            return

        vault_name = current.text()

        try:
            item = self.manager.add_empty_item(vault_name)

        except PasswordManagerError as exc:
            QMessageBox.critical(
                self,
                _t("error_title"),
                str(exc),
            )
            return

        # Clear the search filter so the freshly created (unnamed) item
        # is guaranteed to be visible and selectable in the list.
        self.search_edit.clear()
        self._vault_selected(current, None)

        for row in range(self.item_list.count()):
            list_item = self.item_list.item(row)
            if list_item.data(Qt.UserRole) == item.uuid:
                self.item_list.setCurrentRow(row)
                break

        self._open_item_viewer(item.uuid, start_in_edit_mode=True)
        self._mark_dirty()

    def _item_clicked(self, list_item: QListWidgetItem) -> None:
        """Open the viewer for the clicked item."""
        uuid = list_item.data(Qt.UserRole)
        self._open_item_viewer(uuid)

    def _open_item_viewer(self, uuid: str, start_in_edit_mode: bool = False) -> None:
        """
        Show the :class:`ItemViewer` for the given item in the
        embedded panel on the right of the window.

        Parameters
        ----------
        uuid : str
            UUID of the item to open.
        start_in_edit_mode : bool, optional
            If ``True``, the viewer switches to EDIT mode as soon as
            it is shown (used right after creating a new item).
        """
        if self._current_viewer is not None and self._current_viewer_uuid == uuid:
            # Already the item on display, just adjust its mode.
            if start_in_edit_mode and not self._current_viewer._edit_mode:
                self._current_viewer._enter_edit_mode()
            return

        try:
            item = self.manager.get_item(uuid)
        except Exception as exc:
            QMessageBox.critical(
                self,
                _t("error_title"),
                _t("could_not_open_item", error=exc),
            )
            return

        # Only one item is shown at a time in the panel.
        self._close_item_viewer()

        viewer = ItemViewer(manager=self.manager, item=item, parent=self.viewer_panel)
        # Refresh the item list (name/icon/sort position) once changes
        # are saved from within the viewer; persisting to disk is left
        # to the toolbar Save button (see the class docstring).
        viewer.save_btn.clicked.connect(self._on_item_saved)

        self.viewer_content_layout.addWidget(viewer)
        self._current_viewer = viewer
        self._current_viewer_uuid = uuid
        self.viewer_panel.setVisible(True)

        if start_in_edit_mode:
            viewer._enter_edit_mode()

    def _close_item_viewer(self) -> None:
        """Remove the currently embedded :class:`ItemViewer`, if any, and hide the panel."""
        if self._current_viewer is not None:
            self.viewer_content_layout.removeWidget(self._current_viewer)
            self._current_viewer.deleteLater()
            self._current_viewer = None
            self._current_viewer_uuid = None

        self.viewer_panel.setVisible(False)

    def _on_item_saved(self) -> None:
        """
        Refresh the item list and mark the window dirty after changes
        are saved from within an :class:`ItemViewer`.
        """
        self._vault_selected(self.vault_list.currentItem(), None)
        self._mark_dirty()

    def _item_context_menu(self, pos) -> None:
        """Show the right-click menu ("Open" / "Duplicate" / "Delete") for an item row."""
        list_item = self.item_list.itemAt(pos)
        if list_item is None:
            return

        menu = QMenu(self)
        open_action = menu.addAction(_t("open_action"))
        duplicate_action = menu.addAction(_t("duplicate_action"))
        delete_action = menu.addAction(_t("delete_action"))

        chosen = menu.exec_(self.item_list.mapToGlobal(pos))
        if chosen is open_action:
            self._item_clicked(list_item)
        elif chosen is duplicate_action:
            self._duplicate_item(list_item)
        elif chosen is delete_action:
            self._delete_item(list_item)

    def _duplicate_item(self, list_item: QListWidgetItem) -> None:
        """
        Duplicate an item within its vault.

        Parameters
        ----------
        list_item : QListWidgetItem
            Row of the item to duplicate, as shown in :attr:`item_list`.

        Notes
        -----
        Thin wrapper around :meth:`PasswordManager.duplicate_item`:
        the duplicate always gets a fresh UUID (see that method), so
        it never collides with the item it was copied from, and is
        added to the very same vault the original is in.
        """
        uuid = list_item.data(Qt.UserRole)
        vault_item = self.vault_list.currentItem()
        if vault_item is None:
            return
        vault_name = vault_item.text()

        try:
            self.manager.duplicate_item(uuid, vault_name)
        except PasswordManagerError as exc:
            QMessageBox.critical(self, _t("error_title"), str(exc))
            return

        self._vault_selected(self.vault_list.currentItem(), None)
        self._mark_dirty()

    def _delete_item(self, list_item: QListWidgetItem) -> None:
        """
        Delete an item after explicit user confirmation.

        Parameters
        ----------
        list_item : QListWidgetItem
            Row of the item to delete, as shown in :attr:`item_list`.
        """
        uuid = list_item.data(Qt.UserRole)
        vault_item = self.vault_list.currentItem()
        if vault_item is None:
            return
        vault_name = vault_item.text()

        try:
            item = self.manager.get_item(uuid)
            item_name = item.get("item_name") or uuid
        except Exception:
            item_name = uuid

        reply = QMessageBox.question(
            self,
            _t("delete_item_title"),
            _t("delete_item_prompt", item=item_name, vault=vault_name),
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        if self._current_viewer_uuid == uuid:
            self._close_item_viewer()

        try:
            self.manager.delete_item(vault_name, uuid)
        except PasswordManagerError as exc:
            QMessageBox.critical(self, _t("error_title"), str(exc))
            return

        self._vault_selected(self.vault_list.currentItem(), None)
        self._mark_dirty()

    # =============================================================
    # Drag & drop between vaults
    # =============================================================

    def _on_item_dropped(
        self,
        item_uuids: list[str],
        source_vault: str,
        target_vault: str,
    ) -> None:
        """
        Handle one or more items dropped from :attr:`item_list` onto a
        vault row.

        Parameters
        ----------
        item_uuids : list of str
            UUIDs of the moved items (one, if a single row was
            dragged; several, if a multi-selection was dragged -- see
            :meth:`ItemListWidget.mimeData`).

        source_vault : str
            Name of the vault the items are currently in.

        target_vault : str
            Name of the vault the items are being dropped onto.
        """
        names = []
        for item_uuid in item_uuids:
            try:
                item = self.manager.get_item(item_uuid)
                names.append(item.get("item_name") or item_uuid)
            except Exception:
                names.append(item_uuid)

        if len(item_uuids) == 1:
            prompt = _t(
                "move_item_prompt", item=names[0], source=source_vault, target=target_vault
            )
        else:
            prompt = _t(
                "move_items_prompt",
                count=len(item_uuids),
                items=", ".join(names),
                source=source_vault,
                target=target_vault,
            )

        reply = QMessageBox.question(
            self,
            _t("move_item_title"),
            prompt,
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            for item_uuid in item_uuids:
                self.manager.move_item(item_uuid, source_vault, target_vault)
        except PasswordManagerError as exc:
            QMessageBox.critical(self, _t("error_title"), str(exc))
        finally:
            self._vault_selected(self.vault_list.currentItem(), None)
            self._mark_dirty()

    # =============================================================
    # Closing
    # =============================================================

    def closeEvent(self, event) -> None:
        """
        Prompt to save unsaved changes (unless closing automatically
        after the inactivity timeout, which already saved), then
        always clear the encryption credentials via
        :meth:`PasswordManager.close` before letting the window close.
        """
        if self._dirty and not self._auto_closing:
            reply = QMessageBox.question(
                self,
                _t("unsaved_changes_title"),
                _t("unsaved_changes_close_prompt"),
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
            )
            if reply == QMessageBox.Cancel:
                event.ignore()
                return
            if reply == QMessageBox.Yes:
                if not self._save_blocking():
                    event.ignore()
                    return

        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(self)

        self.manager.close()
        event.accept()
