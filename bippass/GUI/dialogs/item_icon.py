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

from PyQt5.QtCore import QDir, QSize, QSortFilterProxyModel, Qt
from PyQt5.QtGui import QColor, QIcon, QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (
    QColorDialog,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from ..common import (
    _ITEM_ICONS_DIR,
    _bundled_icon_name,
    _file_to_base64,
    _icon_from_base64,
    _item_icon,
    _item_icon_names,
    _item_icon_or_default,
    _item_icon_path,
    _with_background,
)
from ..translate import translator
from ..widgets import ColorSwatch, mark_danger, ok_cancel_buttons, small_button, warn


_COMBO_ICON_SIZE_PX = 32
_COMBO_MAX_VISIBLE_ITEMS = 12
_PREVIEW_SIZE_PX = 64
# Side (px) of the final preview (logo and background).
_FINAL_PREVIEW_SIZE_PX = 48




def _separator() -> QFrame:
    """Return a horizontal line separating two sections of the dialog."""
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setFrameShadow(QFrame.Sunken)
    return line


def _shorten_if_bundled(filename: str) -> str:
    """
    Reduce the path of a bundled item icon to its bare filename.

    A bundled icon picked through the file browser is then stored the
    same way as one picked from the drop-down, rather than as an
    absolute path tied to this machine's install location.

    Parameters
    ----------
    filename : str
        Absolute path returned by the file picker.

    Returns
    -------
    str
        The bare filename if ``filename`` is one of the bundled
        ``resources/item_icons`` files, ``filename`` unchanged
        otherwise.
    """
    name = os.path.basename(filename)
    bundled = _item_icon_path(name)
    if bundled is None:
        return filename
    try:
        return name if os.path.samefile(bundled, filename) else filename
    except OSError:
        return filename


def _icon_for_value(value: str) -> QIcon | None:
    """
    Load the icon a value of the path field designates.

    Parameters
    ----------
    value : str
        A bare bundled filename, or a path to an image file.

    Returns
    -------
    QIcon or None
        The icon, or ``None`` if ``value`` doesn't resolve to a
        readable image.
    """
    if not os.path.dirname(value):
        return _item_icon(value)
    icon = QIcon(value) if os.path.isfile(value) else QIcon()
    return None if icon.isNull() else icon


class ItemIconDialog(QDialog):
    """
    Dialog to pick an item's icon.

    Unlike :class:`VaultIconDialog`, icons keep their own colors since
    they are logos. The dialog has three sections, separated by lines:

    - **the logo**: a search bar filtering the icons by filename
      (typing selects the first match, so "git" + Enter picks
      ``github.png``), a drop-down of every bundled
      ``resources/item_icons/*.png`` with its icon and filename, a
      large preview of the logo as is, and the picked icon (bundled
      filename or file path), with a "Browse..." button to pick any
      image on disk, starting in the user's home folder, and a red
      "Remove" button;
    - **the background color**, painted behind the logo's transparent
      pixels to improve its contrast (or none), next to a preview of
      the final icon -- logo and background -- as the lists show it;
    - Cancel (red) and Apply.

    Parameters
    ----------
    current_icon : str or None
        The item's current icon, a Base64 image (``Item.get_icon()``).
        The matching bundled icon is pre-selected; an icon matching
        none (e.g. a file picked earlier) is kept as long as nothing
        else is picked.
    current_color : str or None, optional
        The item's current background color (``Item.get_color()``);
        ``None`` (the default) for none.
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    :attr:`path_edit` is the single source of truth: the drop-down,
    the search bar and "Browse..." all write into it, and the previews
    and drop-down follow its content. The picked image is only encoded
    by :meth:`get_icon`, scaled down (see
    :func:`common._image_to_base64`): the profile stores the image
    itself, never a path.
    """

    def __init__(self, current_icon: str | None, current_color: str | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("icon_dialog.title"))
        self.setModal(True)
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(translator.translate("icon_dialog.search_placeholder"))
        self.search_edit.setClearButtonEnabled(True)
        layout.addWidget(self.search_edit)

        model = QStandardItemModel(self)
        for name in _item_icon_names():
            entry = QStandardItem(name)
            icon = _item_icon(name)
            if icon is not None:
                entry.setIcon(icon)
            entry.setData(name, Qt.UserRole)
            entry.setToolTip(name)
            model.appendRow(entry)

        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)

        self.icon_combo = QComboBox()
        self.icon_combo.setModel(self._proxy)
        self.icon_combo.setIconSize(QSize(_COMBO_ICON_SIZE_PX, _COMBO_ICON_SIZE_PX))
        self.icon_combo.setMaxVisibleItems(_COMBO_MAX_VISIBLE_ITEMS)
        layout.addWidget(self.icon_combo)

        self.preview = QLabel()
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMinimumHeight(_PREVIEW_SIZE_PX + 16)
        layout.addWidget(self.preview)

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(translator.translate("icon_dialog.path_placeholder"))
        row.addWidget(self.path_edit)

        # Small buttons are never the default one: Enter in the search
        # bar stays bound to Apply.
        browse_btn = small_button(translator.translate("common.browse"))
        browse_btn.clicked.connect(self._browse)
        row.addWidget(browse_btn)
        remove_btn = mark_danger(small_button(translator.translate("icon_dialog.remove_button")))
        remove_btn.clicked.connect(self._remove)
        row.addWidget(remove_btn)
        layout.addLayout(row)

        layout.addWidget(_separator())

        color = QColor(current_color) if current_color else QColor()
        self._color: str | None = color.name() if color.isValid() else None
        color_row = QHBoxLayout()
        color_row.addWidget(QLabel(translator.translate("icon_dialog.background_label")))
        self.color_swatch = ColorSwatch(self._color)
        color_row.addWidget(self.color_swatch)
        color_btn = small_button(translator.translate("icon_dialog.background_button"))
        color_btn.clicked.connect(self._choose_color)
        color_row.addWidget(color_btn)
        no_color_btn = small_button(translator.translate("icon_dialog.no_background_button"))
        no_color_btn.clicked.connect(lambda: self._set_color(None))
        color_row.addWidget(no_color_btn)
        color_row.addStretch()
        color_row.addWidget(QLabel(translator.translate("icon_dialog.preview_label")))
        # The icon as the lists will show it: logo over its background,
        # on the background of the lists (`QLabel#iconPreview`).
        self.final_preview = QLabel()
        self.final_preview.setObjectName("iconPreview")
        self.final_preview.setAlignment(Qt.AlignCenter)
        self.final_preview.setFixedSize(_FINAL_PREVIEW_SIZE_PX + 16, _FINAL_PREVIEW_SIZE_PX + 16)
        color_row.addWidget(self.final_preview)
        layout.addLayout(color_row)

        layout.addWidget(_separator())
        layout.addWidget(ok_cancel_buttons(self, self._on_accept, ok_key="common.apply"))

        self.search_edit.textChanged.connect(self._on_search_changed)
        # `activated` fires on user picks only, not on the programmatic
        # `setCurrentIndex` calls of `_sync_from_path`.
        self.icon_combo.activated.connect(self._on_combo_activated)
        self.path_edit.textChanged.connect(self._sync_from_path)

        # A stored icon that no bundled icon matches is kept until the
        # path field is changed.
        self._current_icon = current_icon
        self._keep_current = False
        # The logo shown by both previews (see `_sync_from_path`).
        self._logo: QIcon | None = None
        bundled = _bundled_icon_name(_ITEM_ICONS_DIR, current_icon)
        if bundled is not None:
            self.path_edit.setText(bundled)
        elif _icon_from_base64(current_icon) is not None:
            self._keep_current = True
        self._sync_from_path(self.path_edit.text())
        self.search_edit.setFocus()

    def _remove(self) -> None:
        """Pick "no icon" (the item then shows the default icon)."""
        self._keep_current = False
        self.path_edit.clear()
        self._sync_from_path("")

    def _on_search_changed(self, text: str) -> None:
        """
        Filter the drop-down and select its first match.

        Parameters
        ----------
        text : str
            Current content of the search bar.
        """
        self._proxy.setFilterFixedString(text.strip())
        if text.strip() and self._proxy.rowCount() > 0:
            self.path_edit.setText(self._proxy.index(0, 0).data(Qt.UserRole))
        else:
            # The filter may have hidden or restored the current entry.
            self._sync_from_path(self.path_edit.text())

    def _on_combo_activated(self, index: int) -> None:
        """
        Use the icon picked in the drop-down.

        Parameters
        ----------
        index : int
            Row of the picked entry in the (filtered) drop-down.
        """
        name = self.icon_combo.itemData(index, Qt.UserRole)
        if name:
            self.path_edit.setText(name)

    def _sync_from_path(self, text: str) -> None:
        """
        Update the drop-down selection and the previews from a value.

        Parameters
        ----------
        text : str
            Current content of :attr:`path_edit`. The drop-down shows
            no selection for a custom path, an empty value or an entry
            hidden by the search filter.
        """
        value = text.strip()
        if value:
            self._keep_current = False
        self.icon_combo.setCurrentIndex(
            self.icon_combo.findData(value, Qt.UserRole) if value else -1
        )
        if value:
            self._logo = _icon_for_value(value)
        elif self._keep_current:
            self._logo = _icon_from_base64(self._current_icon)
        else:
            self._logo = _item_icon_or_default(None)
        self._update_previews()

    def _update_previews(self) -> None:
        """Show the logo as is (top), and the final icon, logo and background (middle)."""
        if self._logo is None:
            self.preview.setText(translator.translate("icon_dialog.not_found"))
            self.final_preview.setText("∅")
            return
        self.preview.setPixmap(self._logo.pixmap(_PREVIEW_SIZE_PX, _PREVIEW_SIZE_PX))
        final = _with_background(self._logo, self._color)
        self.final_preview.setPixmap(final.pixmap(_FINAL_PREVIEW_SIZE_PX, _FINAL_PREVIEW_SIZE_PX))

    def _set_color(self, color: str | None) -> None:
        """
        Use a background color, and refresh the swatch and the previews.

        Parameters
        ----------
        color : str or None
            ``"#rrggbb"``, or ``None`` for no background.
        """
        self._color = color
        self.color_swatch.set_color(color)
        self._update_previews()

    def _choose_color(self) -> None:
        """Ask for a background color, starting from the current one (white if none)."""
        color = QColorDialog.getColor(
            QColor(self._color or "#ffffff"),
            self,
            translator.translate("icon_dialog.background_button"),
        )
        if color.isValid():
            self._set_color(color.name())

    def _browse(self) -> None:
        """Pick an image file on disk, starting in the user's home folder."""
        filename, _filter = QFileDialog.getOpenFileName(
            self,
            translator.translate("icon_dialog.select_title"),
            QDir.homePath(),
            f"{translator.translate('common.image_files_filter')};;"
            f"{translator.translate('common.all_files_filter')}",
        )
        if filename:
            self.path_edit.setText(_shorten_if_bundled(filename))

    def _encode(self) -> str | None:
        """
        Encode the picked image.

        Returns
        -------
        str or None
            The Base64 icon, or ``None`` for no icon or an unreadable
            image.
        """
        if self._keep_current:
            return self._current_icon
        value = self.path_edit.text().strip()
        if not value:
            return None
        path = _item_icon_path(value) if not os.path.dirname(value) else value
        return _file_to_base64(path) if path is not None else None

    def _on_accept(self) -> None:
        """Accept unless the path field designates no readable image."""
        value = self.path_edit.text().strip()
        if value and not self._keep_current and self._encode() is None:
            warn(self, "icon_dialog.not_found")
            return
        self.accept()

    def get_icon(self) -> str | None:
        """
        Return the chosen icon, encoded for storage.

        Returns
        -------
        str or None
            The image as Base64 PNG, scaled down, or ``None`` for no
            icon.
        """
        return self._encode()

    def get_color(self) -> str | None:
        """
        Return the chosen background color.

        Returns
        -------
        str or None
            ``"#rrggbb"``, or ``None`` for no background (transparent
            pixels stay transparent).
        """
        return self._color


def ask_item_icon(
    icon: str | None, color: str | None, parent=None
) -> tuple[str | None, str | None] | None:
    """
    Let the user pick an item's icon and background color.

    Parameters
    ----------
    icon : str or None
        The item's current icon (``Item.get_icon()``).

    color : str or None
        Its current background color (``Item.get_color()``).

    parent : QWidget, optional
        Parent of the dialog.

    Returns
    -------
    tuple of (str or None, str or None) or None
        The new ``(icon, color)``, or ``None`` if the dialog was
        cancelled or nothing changed.
    """
    dialog = ItemIconDialog(icon, color, parent)
    if dialog.exec_() != QDialog.Accepted:
        return None
    choice = (dialog.get_icon(), dialog.get_color())
    return None if choice == (icon, color) else choice
