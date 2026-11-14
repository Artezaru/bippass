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

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QColor, QIcon, QPixmap
from PyQt5.QtWidgets import (
    QButtonGroup,
    QColorDialog,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..common import (
    _VAULT_ICONS_DIR,
    _bundled_icon_name,
    _file_to_base64,
    _vault_icon_names,
    _vault_icon_path,
    tint_pixmap,
    vault_icon_pixmap,
)
from ..theme import DARK, LIGHT, load_theme
from ..translate import translator
from ..widgets import ColorSwatch, ok_cancel_buttons, small_button


_ICON_SIZE_PX = 40
_PREVIEW_SIZE_PX = 64
_GRID_COLUMNS = 5

# Key of the button showing a stored icon that isn't a bundled one.
_CURRENT = "\x00current"

# Color of the shapes drawn on the buttons, by theme: the text color,
# so that they read well whatever the color being chosen. Also the
# color proposed when the vault has none yet.
_SHAPE_COLORS = {LIGHT: "#000000", DARK: "#FFFFFF"}


# ---------------------------------------------------------------------------
# Pixmap helpers
# ---------------------------------------------------------------------------

def load_vault_icon_pixmap(name: str | None) -> QPixmap | None:
    """
    Load the raw (untinted) pixmap of a bundled vault icon.

    Parameters
    ----------
    name : str or None
        Bare icon filename, e.g. ``"github.png"``.

    Returns
    -------
    QPixmap or None
        ``None`` if ``name`` is empty or doesn't resolve to a readable
        image in ``resources/vault_icons``.

    Notes
    -----
    Unlike item icons, there is deliberately no fallback: a vault
    without an icon (or whose icon was removed from the bundled
    resources) is a normal state, not an error.
    """
    path = _vault_icon_path(name) if name else None
    if path is None:
        return None
    pixmap = QPixmap(path)
    return None if pixmap.isNull() else pixmap


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------

class VaultIconDialog(QDialog):
    """
    Dialog to pick a vault's icon and its color.

    Every bundled ``resources/vault_icons/*.png`` is shown as a
    selectable square button (just an outline, ``iconChoiceButton`` in
    ``theme.py``, which also sets its size), next to a "None" button
    (no icon), in a grid scrolling vertically. The shapes are
    drawn in the text color of the theme, black or white, whatever the
    chosen color: a preview next to the color shows the result, the
    picked shape in the picked color, on the background of the vault
    list.

    Parameters
    ----------
    current_icon : str or None
        The vault's current icon, a Base64 image (``Vault.get_icon()``).
        The matching bundled icon is pre-selected; an icon that matches
        none (e.g. from another version) gets its own button, so it
        can be kept.
    current_color : str or None
        The vault's current color (``Vault.get_color()``); the theme's
        text color (see :data:`_SHAPE_COLORS`) if not set or invalid.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(
        self,
        current_icon: str | None,
        current_color: str | None,
        parent=None,
    ):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("vault_icon.dialog_title"))
        self.resize(420, 520)

        shape_color = QColor(_SHAPE_COLORS.get(load_theme(), "#000000"))
        color = QColor(current_color) if current_color else QColor()
        self._color = color if color.isValid() else shape_color
        self._current_icon = current_icon

        self._pixmaps: dict[str, QPixmap] = {}
        for name in _vault_icon_names():
            pixmap = load_vault_icon_pixmap(name)
            if pixmap is not None:
                self._pixmaps[name] = pixmap

        layout = QVBoxLayout(self)

        # Every bundled icon gets a button, in a grid of fixed columns
        # that scrolls vertically: adding icons to `resources/vault_icons`
        # needs no change here.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setSpacing(8)
        grid.setAlignment(Qt.AlignTop | Qt.AlignHCenter)
        scroll.setWidget(grid_widget)
        layout.addWidget(scroll, stretch=1)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        current_key = self._find_current_key(current_icon)
        current_pixmap = vault_icon_pixmap(current_icon) if current_key == _CURRENT else None
        if current_pixmap is not None:
            self._pixmaps[_CURRENT] = current_pixmap
        self._selected_icon: str | None = current_key

        names: list[str | None] = [None, *self._pixmaps]
        for index, icon_name in enumerate(names):
            btn = QPushButton()
            btn.setObjectName("iconChoiceButton")
            btn.setCheckable(True)
            btn.setIconSize(QSize(_ICON_SIZE_PX, _ICON_SIZE_PX))
            if icon_name is None:
                btn.setText("∅")
                btn.setToolTip(tr("vault_icon.none_label"))
            else:
                btn.setIcon(QIcon(tint_pixmap(self._pixmaps[icon_name], shape_color)))
                btn.setToolTip(tr("vault_icon.current_label") if icon_name == _CURRENT else icon_name)
            btn.setChecked(icon_name == current_key)
            btn.clicked.connect(lambda _checked, n=icon_name: self._select_icon(n))
            self._group.addButton(btn)
            grid.addWidget(btn, index // _GRID_COLUMNS, index % _GRID_COLUMNS)

        bottom = QHBoxLayout()
        self.color_swatch = ColorSwatch(self._color.name())
        bottom.addWidget(self.color_swatch)
        self.color_button = small_button(tr("vault_icon.color_button"))
        self.color_button.clicked.connect(self._choose_color)
        bottom.addWidget(self.color_button)
        bottom.addStretch()
        bottom.addWidget(QLabel(tr("vault_icon.preview_label")))
        self.preview = QLabel()
        self.preview.setObjectName("iconPreview")
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setFixedSize(_PREVIEW_SIZE_PX + 16, _PREVIEW_SIZE_PX + 16)
        bottom.addWidget(self.preview)
        layout.addLayout(bottom)

        layout.addWidget(ok_cancel_buttons(self))
        self._update_preview()

    def _find_current_key(self, current_icon: str | None) -> str | None:
        """
        Find which button stands for the vault's current icon.

        Parameters
        ----------
        current_icon : str or None
            The stored Base64 icon.

        Returns
        -------
        str or None
            ``None`` for no icon, the filename of the bundled icon it
            was made from, or :data:`_CURRENT` if it matches none (or
            the bundled icons are missing).

        Notes
        -----
        See :func:`common._bundled_icon_name`.
        """
        if not current_icon:
            return None
        name = _bundled_icon_name(_VAULT_ICONS_DIR, current_icon)
        if name is not None and name in self._pixmaps:
            return name
        return _CURRENT if vault_icon_pixmap(current_icon) is not None else None

    def _select_icon(self, name: str | None) -> None:
        """
        Record the clicked icon as the current selection.

        Parameters
        ----------
        name : str or None
            Bare icon filename, or ``None`` for "no icon".
        """
        self._selected_icon = name
        self._update_preview()

    def _choose_color(self) -> None:
        """Ask for a new color, then refresh the swatch and the preview."""
        color = QColorDialog.getColor(
            self._color, self, translator.translate("vault_icon.color_button")
        )
        if not color.isValid():
            return
        self._color = color
        self.color_swatch.set_color(color.name())
        self._update_preview()

    def _update_preview(self) -> None:
        """Show the selected shape in the selected color, or "∅" for no icon."""
        pixmap = self._pixmaps.get(self._selected_icon) if self._selected_icon else None
        if pixmap is None:
            self.preview.clear()
            self.preview.setText("∅")
            return
        tinted = tint_pixmap(pixmap, self._color)
        self.preview.setPixmap(
            tinted.scaled(_PREVIEW_SIZE_PX, _PREVIEW_SIZE_PX, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        )

    def get_data(self) -> dict:
        """
        Return the chosen icon and color.

        Returns
        -------
        dict
            ``{"icon": str or None, "color": str or None}``: the icon
            as a Base64 image (untinted) and the color as
            ``"#rrggbb"``. Both are ``None`` when "None" is selected,
            since a color is meaningless without an icon.
        """
        name = self._selected_icon
        if name is None:
            return {"icon": None, "color": None}
        if name == _CURRENT:
            icon = self._current_icon
        else:
            path = _vault_icon_path(name)
            icon = _file_to_base64(path) if path is not None else None
        if icon is None:
            return {"icon": None, "color": None}
        return {"icon": icon, "color": self._color.name()}