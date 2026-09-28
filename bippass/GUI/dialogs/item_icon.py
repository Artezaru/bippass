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
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from ..common import (
    _item_icon,
    _item_icon_names,
    _item_icon_or_default,
    _item_icon_path,
    _load_item_icon,
)
from ..translate import translator
from ..widgets import ok_cancel_buttons


_COMBO_ICON_SIZE_PX = 32
_COMBO_MAX_VISIBLE_ITEMS = 12
_PREVIEW_SIZE_PX = 64




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


class ItemIconDialog(QDialog):
    """
    Dialog to pick an item's icon.

    Unlike :class:`VaultIconDialog`, icons keep their own colors since
    they are logos. From top to bottom, the dialog shows:

    - a search bar filtering the icons by filename; typing selects the
      first match, so "git" + Enter picks ``github.png``;
    - a drop-down of every bundled ``resources/item_icons/*.png``,
      with its icon and filename;
    - a large preview of the icon that would be saved;
    - the stored value, with a "Browse..." button to pick any image on
      disk, starting in the user's home folder.

    Parameters
    ----------
    current_path : str
        The item's current icon value: a bare bundled filename, an
        absolute path, or ``""``.
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    :attr:`path_edit` is the single source of truth: the drop-down,
    the search bar and "Browse..." all write into it, and the preview
    and drop-down follow its content.
    """

    def __init__(self, current_path: str, parent=None):
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

        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        layout.addWidget(separator)

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(translator.translate("icon_dialog.path_placeholder"))
        row.addWidget(self.path_edit)

        browse_btn = QPushButton(translator.translate("common.browse"))
        browse_btn.setObjectName("smallButton")
        # Keeps Enter in the search bar bound to OK.
        browse_btn.setAutoDefault(False)
        browse_btn.clicked.connect(self._browse)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        layout.addWidget(ok_cancel_buttons(self))

        self.search_edit.textChanged.connect(self._on_search_changed)
        # `activated` fires on user picks only, not on the programmatic
        # `setCurrentIndex` calls of `_sync_from_path`.
        self.icon_combo.activated.connect(self._on_combo_activated)
        self.path_edit.textChanged.connect(self._sync_from_path)

        self.path_edit.setText(current_path or "")
        self._sync_from_path(self.path_edit.text())
        self.search_edit.setFocus()

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
        Update the drop-down selection and the preview from a value.

        Parameters
        ----------
        text : str
            Current content of :attr:`path_edit`. The drop-down shows
            no selection for a custom path, an empty value or an entry
            hidden by the search filter.
        """
        value = text.strip()
        self.icon_combo.setCurrentIndex(
            self.icon_combo.findData(value, Qt.UserRole) if value else -1
        )
        icon = _load_item_icon(value) if value else _item_icon_or_default(value)
        if icon is None:
            self.preview.setText(translator.translate("icon_dialog.not_found"))
        else:
            self.preview.setPixmap(icon.pixmap(_PREVIEW_SIZE_PX, _PREVIEW_SIZE_PX))

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

    def get_path(self) -> str:
        """
        Return the chosen icon value.

        Returns
        -------
        str
            A bare filename for a bundled icon, an absolute path for a
            user-picked file, or ``""`` for no icon.
        """
        return self.path_edit.text().strip()