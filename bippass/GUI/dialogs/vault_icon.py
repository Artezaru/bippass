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
from PyQt5.QtGui import QColor, QIcon, QPainter, QPixmap
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

from ..common import _vault_icon_names, _vault_icon_path
from ..translate import translator
from ..widgets import ok_cancel_buttons


_ICON_BUTTON_SIZE_PX = 64
_ICON_SIZE_PX = 40
_GRID_COLUMNS = 4

# Native color of the bundled icons (plain black shapes).
_DEFAULT_COLOR = "#000000"

# Explicit selection highlight: the platform's own "checked" look is too
# subtle on some styles to read as a selection.
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


def tint_pixmap(pixmap: QPixmap, color: QColor) -> QPixmap:
    """
    Recolor every non-transparent pixel of a pixmap.

    Parameters
    ----------
    pixmap : QPixmap
        Source icon, whatever its original color(s).
    color : QColor
        Color to paint the icon's shape with.

    Returns
    -------
    QPixmap
        A new pixmap the same size as ``pixmap``, with the same alpha
        shape, filled with ``color``.
    """
    tinted = QPixmap(pixmap.size())
    tinted.fill(Qt.transparent)
    painter = QPainter(tinted)
    painter.drawPixmap(0, 0, pixmap)
    # SourceIn keeps the destination's alpha and replaces its color,
    # so the transparent background stays transparent.
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(tinted.rect(), QColor(color))
    painter.end()
    return tinted


def vault_icon_pixmap(name: str | None, color: str | None = None) -> QPixmap | None:
    """
    Load, and optionally tint, the pixmap of a vault's icon.

    Parameters
    ----------
    name : str or None
        Vault icon filename (``Vault.get_icon()``).
    color : str or None, optional
        Vault icon color (``Vault.get_icon_color()``, e.g.
        ``"#3478f6"``). The icon is left untinted if empty or not a
        color Qt can parse.

    Returns
    -------
    QPixmap or None
        ``None`` if ``name`` is empty or unresolvable; callers should
        then show no icon at all, never a placeholder.
    """
    pixmap = load_vault_icon_pixmap(name)
    if pixmap is None or not color:
        return pixmap
    qcolor = QColor(color)
    if not qcolor.isValid():
        return pixmap
    return tint_pixmap(pixmap, qcolor)


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------

class VaultIconDialog(QDialog):
    """
    Dialog to pick a vault's icon and its color.

    Every bundled ``resources/vault_icons/*.png`` is shown as a
    selectable button, next to a "None" button (no icon). Choosing a
    color re-tints every button live, so the preview always matches
    what would be saved.

    Parameters
    ----------
    current_icon : str or None
        The vault's current icon filename (``Vault.get_icon()``), used
        to pre-select a button.
    current_color : str or None
        The vault's current icon color (``Vault.get_icon_color()``);
        black if not set or invalid.
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
        self.setWindowTitle(translator.translate("vault_icon.dialog_title"))
        self.resize(420, 460)

        color = QColor(current_color or _DEFAULT_COLOR)
        self._color = color if color.isValid() else QColor(_DEFAULT_COLOR)
        self._selected_icon: str | None = current_icon

        # Loaded once; a color change only re-tints them.
        self._pixmaps: dict[str, QPixmap] = {}
        for name in _vault_icon_names():
            pixmap = load_vault_icon_pixmap(name)
            if pixmap is not None:
                self._pixmaps[name] = pixmap
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

        names: list[str | None] = [None, *self._pixmaps]
        for index, name in enumerate(names):
            btn = QPushButton()
            btn.setCheckable(True)
            btn.setFixedSize(_ICON_BUTTON_SIZE_PX, _ICON_BUTTON_SIZE_PX)
            btn.setIconSize(QSize(_ICON_SIZE_PX, _ICON_SIZE_PX))
            btn.setStyleSheet(_ICON_BUTTON_STYLE)
            # The "None" label gets clipped at this fixed size, so it
            # only lives in the tooltip.
            btn.setToolTip(
                translator.translate("vault_icon.none_label") if name is None else name
            )
            btn.setChecked(name == current_icon)
            btn.clicked.connect(lambda _checked, n=name: self._select_icon(n))
            self._group.addButton(btn)
            self._buttons[name] = btn
            grid.addWidget(btn, index // _GRID_COLUMNS, index % _GRID_COLUMNS)
        self._retint_buttons()

        color_row = QHBoxLayout()
        self.color_preview = QLabel()
        self.color_preview.setFixedSize(28, 28)
        self._update_color_preview()
        color_row.addWidget(self.color_preview)

        self.color_button = QPushButton(translator.translate("vault_icon.color_button"))
        self.color_button.clicked.connect(self._choose_color)
        color_row.addWidget(self.color_button)
        color_row.addStretch()
        layout.addLayout(color_row)

        layout.addWidget(ok_cancel_buttons(self))

    def _select_icon(self, name: str | None) -> None:
        """
        Record the clicked icon as the current selection.

        Parameters
        ----------
        name : str or None
            Bare icon filename, or ``None`` for "no icon".
        """
        self._selected_icon = name

    def _update_color_preview(self) -> None:
        """Paint the color swatch with the current color."""
        self.color_preview.setStyleSheet(
            f"background-color: {self._color.name()};"
            "border: 1px solid #888888; border-radius: 4px;"
        )

    def _choose_color(self) -> None:
        """Ask for a new color, then refresh the swatch and the icons."""
        color = QColorDialog.getColor(
            self._color, self, translator.translate("vault_icon.color_button")
        )
        if not color.isValid():
            return
        self._color = color
        self._update_color_preview()
        self._retint_buttons()

    def _retint_buttons(self) -> None:
        """Redraw every icon button with the current color."""
        for name, pixmap in self._pixmaps.items():
            self._buttons[name].setIcon(QIcon(tint_pixmap(pixmap, self._color)))

    def get_data(self) -> dict:
        """
        Return the chosen icon filename and color.

        Returns
        -------
        dict
            ``{"icon": str or None, "color": str or None}``: the bare
            icon filename and the color as ``"#rrggbb"``. Both are
            ``None`` when "None" is selected, since a color is
            meaningless without an icon.
        """
        if self._selected_icon is None:
            return {"icon": None, "color": None}
        return {"icon": self._selected_icon, "color": self._color.name()}