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
from importlib import resources

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QColor, QIcon, QPainter, QPixmap
from PyQt5.QtWidgets import (
    QButtonGroup,
    QColorDialog,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QHBoxLayout,
    QTextBrowser,
    QComboBox,
    QLineEdit,
    QLabel,
    QPushButton,
    QFormLayout,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from .common import _t
from .translate import translator, ENGLISH, FRENCH, SPANISH


# --------------------------------------------------------------------------
# Vault icons dialog
# --------------------------------------------------------------------------

#: Size (px) of each selectable icon button in the grid, and of the
#: icon drawn inside it.
_ICON_BUTTON_SIZE_PX = 64
_ICON_SIZE_PX = 40

#: Number of icon buttons per row in the selection grid.
_GRID_COLUMNS = 4

#: Fallback tint color when a vault has none configured yet, matching
#: the bundled icons' own native color (plain black shapes).
_DEFAULT_COLOR = "#000000"

#: Explicit selection highlight for each icon button in
#: :class:`VaultIconDialog`'s grid (see the loop building it): a
#: visible border + tinted background while checked, a subtler hover
#: border otherwise -- independent of how subtle the platform style's
#: own "checked" look would otherwise be.
_ICON_BUTTON_STYLE = """
    QPushButton {
        border: 2px solid transparent;
        border-radius: 6px;
    }
    QPushButton:checked {
        border: 2px solid #3478f6;
        background-color: rgba(52, 120, 246, 40);
    }
    QPushButton:hover:!checked {
        border: 2px solid #888888;
    }
"""

def vault_icons_directory() -> str:
    """
    Path to the package's bundled ``resources/vault_icons`` directory.

    Returns
    -------
    str
        The directory path, or ``""`` if the package's resources
        cannot be located.
    """
    try:
        ref = resources.files("bippass").joinpath("resources/vault_icons")
        with resources.as_file(ref) as path:
            return str(path)
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return ""


def list_vault_icon_names() -> list[str]:
    """
    List the bare filenames of every bundled vault icon.

    Returns
    -------
    list of str
        Every ``*.png`` file directly inside ``resources/vault_icons``
        (bare filenames, e.g. ``"github.png"``, never a path), sorted
        case-insensitively. Empty if the directory is missing or
        unreadable.
    """
    directory = vault_icons_directory()
    if not directory or not os.path.isdir(directory):
        return []
    try:
        names = [
            name
            for name in os.listdir(directory)
            if name.lower().endswith(".png")
            and os.path.isfile(os.path.join(directory, name))
        ]
    except OSError:
        return []
    return sorted(names, key=str.casefold)


def resolve_vault_icon_path(name: str) -> str:
    """
    Resolve a bare vault icon filename against the bundled
    ``resources/vault_icons`` directory.

    A path that already has a directory component is returned
    unchanged (mirrors `item_viewer._resolve_icon_path`).

    Parameters
    ----------
    name : str
        Stored vault icon filename (never a full path -- see
        `vault_icon_pixmap`).

    Returns
    -------
    str
        The resolved path, or ``name`` unchanged if it isn't a bare
        filename or the package's resources can't be located.
    """
    head, tail = os.path.split(name)
    if head:
        return name
    try:
        ref = resources.files("bippass").joinpath("resources/vault_icons", tail)
        with resources.as_file(ref) as resolved:
            return str(resolved)
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return name


def load_vault_icon_pixmap(name: str | None) -> QPixmap | None:
    """
    Load the raw (untinted) pixmap for a vault icon filename.

    Parameters
    ----------
    name : str or None
        Bare icon filename, e.g. ``"github.png"``.

    Returns
    -------
    QPixmap or None
        ``None`` if ``name`` is empty, or does not resolve to an
        existing, readable image -- e.g. the icon was removed from
        the bundled resources after a vault was given that name.
        Unlike an item's icon, there is deliberately no bundled
        fallback here: a vault with no icon (or an icon that no
        longer exists) is a normal, common state, not an error.
    """
    if not name:
        return None
    path = resolve_vault_icon_path(name)
    try:
        if not os.path.isfile(path):
            return None
        pixmap = QPixmap(path)
    except OSError:
        return None
    return None if pixmap.isNull() else pixmap


def tint_pixmap(pixmap: QPixmap, color: QColor) -> QPixmap:
    """
    Return a copy of ``pixmap`` with every non-transparent pixel
    recoloured to ``color``, preserving the original alpha shape.

    Parameters
    ----------
    pixmap : QPixmap
        Source icon. The bundled vault icons are plain black shapes
        on a transparent background, but this recolors any icon the
        same way regardless of its original color(s).
    color : QColor
        Color to paint the icon's shape with.

    Returns
    -------
    QPixmap
        A new, tinted pixmap the same size as ``pixmap``.
    """
    tinted = QPixmap(pixmap.size())
    tinted.fill(Qt.transparent)
    painter = QPainter(tinted)
    painter.drawPixmap(0, 0, pixmap)
    # Only pixels already opaque (the icon's shape) get painted here:
    # SourceIn keeps the destination's existing alpha and replaces its
    # color, so the transparent background stays transparent.
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(tinted.rect(), QColor(color))
    painter.end()
    return tinted


def vault_icon_pixmap(name: str | None, color: str | None = None) -> QPixmap | None:
    """
    Load, and optionally tint, the pixmap for a vault's configured
    icon.

    Parameters
    ----------
    name : str or None
        Vault icon filename (``Vault.get_icon()``).
    color : str or None
        Vault icon color (``Vault.get_icon_color()``, e.g.
        ``"#3478f6"``). Left untinted (native icon colors) if empty
        or not a color Qt can parse.

    Returns
    -------
    QPixmap or None
        ``None`` if ``name`` is empty or unresolvable -- callers
        should show no icon at all in that case, never a placeholder.
    """
    pixmap = load_vault_icon_pixmap(name)
    if pixmap is None:
        return None
    if not color:
        return pixmap
    qcolor = QColor(color)
    if not qcolor.isValid():
        return pixmap
    return tint_pixmap(pixmap, qcolor)


class VaultIconDialog(QDialog):
    """
    Dialog to pick a vault's icon and its color.

    Every ``*.png`` bundled in ``resources/vault_icons`` is shown as a
    selectable button, alongside one extra "None" button (no icon at
    all). Choosing a color (via :class:`QColorDialog`) re-tints every
    icon button live, so the preview always matches what would
    actually be saved.

    Parameters
    ----------
    current_icon : str or None
        The vault's current icon filename (``Vault.get_icon()``), or
        ``None`` -- used to pre-select a button.
    current_color : str or None
        The vault's current icon color (``Vault.get_icon_color()``),
        or ``None`` -- defaults to black if not set.
    parent : QWidget, optional
    """

    def __init__(
        self,
        current_icon: str | None,
        current_color: str | None,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle(_t("vault_icon_dialog_title"))
        self.resize(420, 460)

        initial_color = QColor(current_color) if current_color else QColor(_DEFAULT_COLOR)
        if not initial_color.isValid():
            initial_color = QColor(_DEFAULT_COLOR)
        self._color = initial_color
        self._selected_icon: str | None = current_icon
        self._buttons: dict[str | None, QPushButton] = {}

        layout = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setSpacing(8)
        scroll.setWidget(grid_widget)
        layout.addWidget(scroll, stretch=1)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        names: list[str | None] = [None, *list_vault_icon_names()]
        for index, name in enumerate(names):
            btn = QPushButton()
            btn.setCheckable(True)
            btn.setFixedSize(_ICON_BUTTON_SIZE_PX, _ICON_BUTTON_SIZE_PX)
            btn.setIconSize(QSize(_ICON_SIZE_PX, _ICON_SIZE_PX))
            # A checkable QPushButton's default "checked" look is too
            # subtle to read as a selection on some platform styles,
            # so the highlight is spelled out explicitly here rather
            # than left to the style; applies to every button,
            # including the (icon-less, text-less) "None" one.
            btn.setStyleSheet(_ICON_BUTTON_STYLE)
            if name is None:
                # No text either -- "vault_icon_none_label" ("None"/
                # "Aucune"/"Ninguno") doesn't fit this button's fixed
                # size and got clipped against the edges. The tooltip
                # still carries the label for anyone hovering.
                btn.setToolTip(_t("vault_icon_none_label"))
            else:
                pixmap = load_vault_icon_pixmap(name)
                if pixmap is not None:
                    btn.setIcon(QIcon(tint_pixmap(pixmap, self._color)))
                btn.setToolTip(name)
            btn.setChecked(name == current_icon)
            btn.clicked.connect(lambda _checked, n=name: self._select_icon(n))
            self._group.addButton(btn)
            self._buttons[name] = btn
            grid.addWidget(btn, index // _GRID_COLUMNS, index % _GRID_COLUMNS)

        color_row = QHBoxLayout()
        self.color_preview = QLabel()
        self.color_preview.setFixedSize(28, 28)
        self._update_color_preview()
        color_row.addWidget(self.color_preview)

        self.color_button = QPushButton(_t("vault_icon_color_button"))
        self.color_button.clicked.connect(self._choose_color)
        color_row.addWidget(self.color_button)
        color_row.addStretch()
        layout.addLayout(color_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_t("ok_button"))
        buttons.button(QDialogButtonBox.Cancel).setText(_t("cancel_button"))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _select_icon(self, name: str | None) -> None:
        self._selected_icon = name

    def _update_color_preview(self) -> None:
        self.color_preview.setStyleSheet(
            f"background-color: {self._color.name()};"
            "border: 1px solid #888888; border-radius: 4px;"
        )

    def _choose_color(self) -> None:
        color = QColorDialog.getColor(
            self._color, self, _t("vault_icon_color_button")
        )
        if not color.isValid():
            return
        self._color = color
        self._update_color_preview()
        self._retint_buttons()

    def _retint_buttons(self) -> None:
        for name, btn in self._buttons.items():
            if name is None:
                continue
            pixmap = load_vault_icon_pixmap(name)
            if pixmap is not None:
                btn.setIcon(QIcon(tint_pixmap(pixmap, self._color)))

    def get_data(self) -> dict:
        """
        Return the chosen icon filename and color.

        Returns
        -------
        dict
            ``{"icon": str or None, "color": str or None}`` -- the
            bare icon filename (never a path, see
            `vault_icons.load_vault_icon_pixmap`) and the tint color
            as a ``"#rrggbb"`` string. Both are ``None`` when "None"
            is selected: a color is meaningless without an icon to
            apply it to.
        """
        if self._selected_icon is None:
            return {"icon": None, "color": None}
        return {"icon": self._selected_icon, "color": self._color.name()}


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


# ---------------------------------------------------------------------------
# Help dialog
# ---------------------------------------------------------------------------

class HelpDialog(QDialog):
    """
    Read-only dialog showing how to use bippass and its keyboard
    shortcuts, in the current display language.

    Parameters
    ----------
    parent : QWidget, optional
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_t("help_dialog_title"))
        self.resize(560, 620)

        layout = QVBoxLayout(self)

        self.content = QTextBrowser()
        self.content.setOpenExternalLinks(True)
        self.content.setHtml(_t("help_content"))
        layout.addWidget(self.content)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(_t("close_button"))
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)