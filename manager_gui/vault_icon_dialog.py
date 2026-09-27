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

from PyQt5.QtCore import QSize
from PyQt5.QtGui import QColor, QIcon
from PyQt5.QtWidgets import (
    QButtonGroup,
    QColorDialog,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from .common import _t
from .vault_icons import list_vault_icon_names, load_vault_icon_pixmap, tint_pixmap

#: Size (px) of each selectable icon button in the grid, and of the
#: icon drawn inside it.
_ICON_BUTTON_SIZE_PX = 64
_ICON_SIZE_PX = 40

#: Number of icon buttons per row in the selection grid.
_GRID_COLUMNS = 4

#: Fallback tint color when a vault has none configured yet, matching
#: the bundled icons' own native color (plain black shapes).
_DEFAULT_COLOR = "#000000"


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
            if name is None:
                btn.setText(_t("vault_icon_none_label"))
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
