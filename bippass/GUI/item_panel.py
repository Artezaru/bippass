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

import html
from typing import TYPE_CHECKING, cast

from PyQt5.QtCore import QPoint, QSize, Qt, QTimer, pyqtSlot
from PyQt5.QtGui import QIcon, QKeySequence
from PyQt5.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidgetItem,
    QPushButton,
    QShortcut,
    QVBoxLayout,
    QWidget,
)

from ..core.common import SortKey
from ..core.exceptions import PasswordManagerError
from .common import _gui_icon, _item_icon_or_default, item_display_name, vault_display_name
from .dialogs import ask_item_icon
from .lists import ItemListWidget, fit_icon_size, row_font
from .translate import translator
from .widgets import ask_text, confirm, show_error, small_button

if TYPE_CHECKING:
    from ..core.vault import Vault
    from .window import PasswordManagerWindow


# (sort key, translation key of its name), in display order.
_SORT_CHOICES = (
    ("name", "window.sort_name"),
    ("creation_date", "window.sort_created"),
    ("modification_date", "window.sort_modified"),
)

_SORT_ICON_SIZE_PX = 16


class ItemPanel(QWidget):
    """
    Middle column of the main window: the items of the shown vault.

    Items are listed sorted by the criterion of the sort box (name,
    creation date or date of last change), in the direction of the
    arrow button next to it, and filtered by the search field (item
    names only). Sorting only changes the display: items have no
    stored order.

    Selecting a row only highlights it; double click or Enter opens the
    item in the viewer. Rows can be dragged onto another vault.

    Parameters
    ----------
    host : PasswordManagerWindow
        Window owning the manager and the item viewer.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, host: PasswordManagerWindow, parent=None):
        super().__init__(parent)
        self._host = host
        self._vault_uuid = ""
        self._sort_key: SortKey = "name"
        self._sort_descending = False

        layout = QVBoxLayout(self)
        self.info_label = QLabel()
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        tools = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self.refresh)
        tools.addWidget(self.search_edit, stretch=1)

        self.sort_combo = QComboBox()
        for key, _label_key in _SORT_CHOICES:
            self.sort_combo.addItem("", key)
        self.sort_combo.setCurrentIndex(self.sort_combo.findData(self._sort_key))
        self.sort_combo.currentIndexChanged.connect(self._on_sort_key_changed)
        tools.addWidget(self.sort_combo)

        self.sort_direction_button = small_button(square=True)
        self.sort_direction_button.setIconSize(QSize(_SORT_ICON_SIZE_PX, _SORT_ICON_SIZE_PX))
        self.sort_direction_button.clicked.connect(self._toggle_sort_direction)
        self._update_sort_direction_button()
        tools.addWidget(self.sort_direction_button)
        layout.addLayout(tools)

        self.item_list = ItemListWidget()
        self.item_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.item_list.itemActivated.connect(lambda row: self._host.open_viewer(row.data(Qt.UserRole)))
        self.item_list.currentItemChanged.connect(self._on_selection_changed)
        self.item_list.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.item_list)

        self.add_button = QPushButton()
        self.add_button.clicked.connect(self.add_item)
        layout.addWidget(self.add_button)

        select_all = QShortcut(QKeySequence("Ctrl+A"), self.item_list)
        select_all.setContext(Qt.WidgetWithChildrenShortcut)
        select_all.activated.connect(self.item_list.selectAll)

        self.retranslate()

    # -- state --------------------------------------------------------------

    def _vault(self) -> Vault | None:
        """
        Return the shown vault.

        Returns
        -------
        Vault or None
            The vault, or ``None`` if none is shown or it no longer exists.
        """
        return self._host.find_vault(self._vault_uuid) if self._vault_uuid else None

    @pyqtSlot()
    def retranslate(self) -> None:
        """Refresh every text of the panel."""
        tr = translator.translate
        self.search_edit.setPlaceholderText(tr("window.search_placeholder"))
        self.sort_combo.setToolTip(tr("window.sort_tooltip"))
        for index, (_key, label_key) in enumerate(_SORT_CHOICES):
            self.sort_combo.setItemText(index, tr(label_key))
        self.sort_direction_button.setToolTip(tr("window.reverse_sort_tooltip"))
        self.add_button.setText(tr("window.add_item_button"))
        self.refresh()

    # -- sorting ------------------------------------------------------------

    def _on_sort_key_changed(self) -> None:
        """Sort the list by the criterion picked in :attr:`sort_combo`."""
        self._sort_key = cast(SortKey, self.sort_combo.currentData())
        self.refresh()

    def _toggle_sort_direction(self) -> None:
        """Reverse the sort direction."""
        self._sort_descending = not self._sort_descending
        self._update_sort_direction_button()
        self.refresh()

    def _update_sort_direction_button(self) -> None:
        """Show the icon of the sort direction, or an arrow if the icon is missing."""
        icon = _gui_icon("sort_desc.svg" if self._sort_descending else "sort_asc.svg")
        if icon is not None:
            self.sort_direction_button.setIcon(icon)
            self.sort_direction_button.setText("")
        else:
            self.sort_direction_button.setIcon(QIcon())
            self.sort_direction_button.setText("▼" if self._sort_descending else "▲")

    # -- list ---------------------------------------------------------------

    def show_vault(self, uuid: str) -> None:
        """
        Show the items of a vault.

        Parameters
        ----------
        uuid : str
            UUID of the vault, ``""`` for none. Showing another vault
            closes the viewer without asking: callers ask beforehand.
        """
        if uuid != self._vault_uuid:
            self._host.close_viewer(ask=False)
        self._vault_uuid = uuid
        self.item_list.current_vault_uuid = uuid
        self.refresh()

    def clear(self) -> None:
        """Empty the list, e.g. when the profile is locked (the vault shown is kept)."""
        with self.item_list.quiet():
            self.item_list.clear()
        self.info_label.setText("")

    @pyqtSlot()
    def refresh(self) -> None:
        """
        Rebuild the list from the shown vault, sorted as chosen, keeping
        only the items whose name matches the search field.

        Notes
        -----
        The row of the open item (or else the current row) is selected
        again after the rebuild, without triggering the selection
        handler.
        """
        if not self._host.has_profile:
            return
        vault = self._vault()
        self.add_button.setEnabled(vault is not None)
        if vault is None:
            self.clear()
            no_vault = not self._host.profile.vault_uuids()
            self.info_label.setText(translator.translate("window.no_vault") if no_vault else "")
            return

        shown = vault.search(
            self.search_edit.text(), self._sort_key, reverse=self._sort_descending
        )
        current = self.item_list.currentItem()
        keep_uuid = self._host.viewer_uuid or (current.data(Qt.UserRole) if current else None)
        fit_icon_size(self.item_list, False)
        font = row_font(self.item_list)

        with self.item_list.quiet():
            self.item_list.clear()
            for item in shown:
                row = QListWidgetItem(item_display_name(item))
                row.setData(Qt.UserRole, item.uuid)
                row.setFont(font)
                icon = _item_icon_or_default(item.get_icon(), item.get_color())
                if icon is not None:
                    row.setIcon(icon)
                self.item_list.addItem(row)
            if keep_uuid is not None:
                index = self.item_list.row_of(keep_uuid)
                if index >= 0:
                    self.item_list.setCurrentRow(index)

        self.info_label.setText(
            translator.translate(
                "window.vault_info",
                # Rich text: a name must not be read as markup.
                vault=html.escape(vault_display_name(vault)),
                shown=str(len(shown)),
                total=str(len(vault)),
            )
        )

    def select_item(self, uuid: str) -> None:
        """
        Select an item's row without reacting to it.

        Parameters
        ----------
        uuid : str
            UUID of the item; nothing happens if it isn't listed.
        """
        with self.item_list.quiet():
            index = self.item_list.row_of(uuid)
            if index >= 0:
                self.item_list.setCurrentRow(index)

    def _on_selection_changed(self, current: QListWidgetItem | None, _previous) -> None:
        """
        Close the viewer when another row is selected.

        Parameters
        ----------
        current : QListWidgetItem or None
            Newly selected row.
        _previous : QListWidgetItem or None
            Previously selected row, unused.

        Notes
        -----
        Keeps the highlighted row and the open item in sync. Unsaved
        edits are asked about first; if the user cancels, the open
        item's row is selected again.
        """
        viewer_uuid = self._host.viewer_uuid
        if self.item_list.syncing or viewer_uuid is None:
            return
        uuid = current.data(Qt.UserRole) if current is not None else None
        if uuid != viewer_uuid and not self._host.close_viewer():
            QTimer.singleShot(0, lambda: self.select_item(viewer_uuid))

    # -- actions ------------------------------------------------------------

    def _context_menu(self, pos: QPoint) -> None:
        """
        Show the context menu of an item row.

        Parameters
        ----------
        pos : QPoint
            Position of the click in :attr:`item_list`.
        """
        row = self.item_list.itemAt(pos)
        if row is None:
            return
        uuid = row.data(Qt.UserRole)
        # While the item is edited in the viewer, its name, icon and
        # content are drafts there: renaming, changing the icon or
        # duplicating it from the list would be overwritten or miss
        # them, so these entries are greyed out until it is saved or
        # cancelled.
        editing = self._host.is_editing(uuid)

        def unless_editing(slot):
            return None if editing else slot

        self._host.exec_menu(
            [
                ("window.open_action", lambda: self._host.open_viewer(uuid), None),
                ("window.rename_item_action", unless_editing(lambda: self._rename_item(uuid)), None),
                ("window.item_icon_action", unless_editing(lambda: self._change_item_icon(uuid)), None),
                ("window.duplicate_action", unless_editing(lambda: self._duplicate_item(uuid)), None),
                None,
                ("window.delete_action", lambda: self._delete_item(uuid), None),
            ],
            self.item_list.mapToGlobal(pos),
        )

    def _changed(self, uuid: str | None = None) -> None:
        """
        Record a change made from the list, and show it.

        Parameters
        ----------
        uuid : str, optional
            UUID of the changed item, refreshed in the viewer if open.
        """
        if uuid is not None:
            self._host.refresh_viewer(uuid)
        self._host.mark_dirty()
        self.refresh()

    def add_item(self) -> None:
        """Create an empty item in the shown vault and open it in EDIT mode (also Ctrl+N)."""
        if self._vault() is None or not self._host.close_viewer():
            return
        item = self._host.profile.add_empty_item(self._vault_uuid)
        # The new item is unnamed: clear the search so it is listed.
        self.search_edit.clear()
        self._changed()
        self.select_item(item.uuid)
        self._host.open_viewer(item.uuid, edit=True)

    def focus_search(self) -> None:
        """Put the cursor in the search bar, its text selected (Ctrl+F)."""
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def _rename_item(self, uuid: str) -> None:
        """
        Ask for a new name and rename an item.

        Parameters
        ----------
        uuid : str
            UUID of the item. A blank name removes it.
        """
        item = self._host.get_item(uuid)
        if item is None:
            return
        old_name = item.get_name() or ""
        new_name = ask_text(
            self,
            "window.rename_item_title",
            translator.translate("window.rename_item_prompt", name=item_display_name(item)),
            old_name,
        )
        if new_name is None or new_name == old_name:
            return
        item.set_name(new_name or None)
        self._changed(uuid)

    def _change_item_icon(self, uuid: str) -> None:
        """
        Pick an item's icon and its background color through :class:`ItemIconDialog`.

        Parameters
        ----------
        uuid : str
            UUID of the item.
        """
        item = self._host.get_item(uuid)
        if item is None:
            return
        choice = ask_item_icon(item.get_icon(), item.get_color(), self)
        if choice is None:
            return
        icon, color = choice
        item.set_icon(icon)
        item.set_color(color)
        self._changed(uuid)

    def _duplicate_item(self, uuid: str) -> None:
        """
        Duplicate an item, in the same vault.

        Parameters
        ----------
        uuid : str
            UUID of the item.

        Notes
        -----
        Needs the data key: the secrets of the copy are re-encrypted
        for its new UUID, so the secondary password may be asked.
        """
        if not self._host.ensure_decrypted():
            return
        try:
            duplicate = self._host.profile.duplicate_item(uuid)
        except PasswordManagerError as exc:
            show_error(self, error=str(exc))
            return
        self._changed()
        self.select_item(duplicate.uuid)

    def _delete_item(self, uuid: str) -> None:
        """
        Delete an item after confirmation.

        Parameters
        ----------
        uuid : str
            UUID of the item.
        """
        vault = self._vault()
        prompt = translator.translate(
            "window.delete_item_prompt",
            item=self._host.item_display_name(uuid),
            vault=vault_display_name(vault) if vault is not None else "",
        )
        if not confirm(self, "window.delete_item_title", prompt):
            return
        if self._host.viewer_uuid == uuid:
            self._host.close_viewer(ask=False)
        try:
            self._host.profile.remove_item(uuid)
        except PasswordManagerError as exc:
            show_error(self, error=str(exc))
            return
        self._changed()

