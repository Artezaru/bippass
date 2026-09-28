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

import re
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable

from PyQt5.QtCore import QMimeData, Qt, pyqtSignal
from PyQt5.QtWidgets import QAbstractItemView, QListWidget, QListWidgetItem

if TYPE_CHECKING:
    from ..core.item import Item


# ---------------------------------------------------------------------------
# Drag & drop
# ---------------------------------------------------------------------------

ITEM_MIME_TYPE = "application/x-passwordmanager-item"

# Payload: "<source vault><_VAULT_SEP><uuid><_UUID_SEP><uuid>...", using
# ASCII unit/record separators, which can't appear in names or UUIDs.
_VAULT_SEP = "\x1f"
_UUID_SEP = "\x1e"


def _encode_payload(source_vault: str, item_uuids: list[str]) -> bytes:
    """
    Encode a drag payload.

    Parameters
    ----------
    source_vault : str
        Name of the vault the items are dragged from.
    item_uuids : list of str
        UUIDs of the dragged items.

    Returns
    -------
    bytes
        The UTF-8 encoded payload.
    """
    return f"{source_vault}{_VAULT_SEP}{_UUID_SEP.join(item_uuids)}".encode("utf-8")


def _decode_payload(data: bytes) -> tuple[str, list[str]]:
    """
    Decode a drag payload built by :func:`_encode_payload`.

    Parameters
    ----------
    data : bytes
        The UTF-8 encoded payload.

    Returns
    -------
    tuple of (str, list of str)
        ``(source_vault, item_uuids)``.
    """
    source_vault, uuids = data.decode("utf-8").split(_VAULT_SEP, 1)
    return source_vault, uuids.split(_UUID_SEP)


class ItemListWidget(QListWidget):
    """
    List of the items of the selected vault.

    Supports multi-selection (Ctrl+click, Shift+click, Ctrl+A) and
    dragging the selected rows onto a :class:`VaultListWidget` to move
    the items into another vault. Each row stores its item's UUID
    under ``Qt.UserRole``.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    current_vault_name : str
        Name of the vault whose items are shown, set by the owning
        window and embedded in the drag payload.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_vault_name = ""
        self.setDragEnabled(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def mimeTypes(self) -> list[str]:
        """
        Return the MIME types produced by a drag.

        Returns
        -------
        list of str
            ``[ITEM_MIME_TYPE]``.
        """
        return [ITEM_MIME_TYPE]

    def mimeData(self, items: list[QListWidgetItem]) -> QMimeData:
        """
        Build the drag payload of the dragged rows.

        Parameters
        ----------
        items : list of QListWidgetItem
            Every selected row.

        Returns
        -------
        QMimeData
            The source vault and the items' UUIDs, under
            :data:`ITEM_MIME_TYPE`.
        """
        mime = QMimeData()
        if items:
            uuids = [str(item.data(Qt.UserRole)) for item in items]
            mime.setData(ITEM_MIME_TYPE, _encode_payload(self.current_vault_name, uuids))
        return mime

    def row_of(self, uuid: str) -> int:
        """
        Return the row of an item.

        Parameters
        ----------
        uuid : str
            UUID of the item.

        Returns
        -------
        int
            The row, or ``-1`` if the item isn't listed.
        """
        for row in range(self.count()):
            if self.item(row).data(Qt.UserRole) == uuid:
                return row
        return -1


class VaultListWidget(QListWidget):
    """
    List of the vaults, accepting items dropped from an
    :class:`ItemListWidget` to move them into another vault.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    item_dropped : pyqtSignal(object, str, str)
        Emitted with ``(item_uuids, source_vault, target_vault)`` when
        items are dropped onto another vault's row; ``item_uuids`` is a
        ``list[str]``.
    """

    item_dropped = pyqtSignal(object, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)

    def row_of(self, name: str) -> int:
        """
        Return the row of a vault.

        Parameters
        ----------
        name : str
            Name of the vault.

        Returns
        -------
        int
            The row, or ``-1`` if the vault isn't listed.
        """
        for row in range(self.count()):
            if self.item(row).text() == name:
                return row
        return -1

    def _accept_items(self, event) -> None:
        """
        Accept a drag carrying items, ignore any other.

        Parameters
        ----------
        event : QDragEnterEvent or QDragMoveEvent
            The drag event.
        """
        if event.mimeData().hasFormat(ITEM_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragEnterEvent(self, event) -> None:
        """
        Accept a drag entering the list if it carries items.

        Parameters
        ----------
        event : QDragEnterEvent
            The drag event.
        """
        self._accept_items(event)

    def dragMoveEvent(self, event) -> None:
        """
        Accept a drag moving over the list if it carries items.

        Parameters
        ----------
        event : QDragMoveEvent
            The drag event.
        """
        self._accept_items(event)

    def dropEvent(self, event) -> None:
        """
        Emit :attr:`item_dropped` for items dropped onto another vault.

        Parameters
        ----------
        event : QDropEvent
            The drop event, ignored if not dropped onto a vault row
            other than the source vault.
        """
        mime = event.mimeData()
        target_row = self.itemAt(event.pos())
        if not mime.hasFormat(ITEM_MIME_TYPE) or target_row is None:
            event.ignore()
            return

        source_vault, item_uuids = _decode_payload(bytes(mime.data(ITEM_MIME_TYPE)))
        target_vault = target_row.text()
        if target_vault == source_vault:
            event.ignore()
            return

        self.item_dropped.emit(item_uuids, source_vault, target_vault)
        event.acceptProposedAction()


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

class SortKey(Enum):
    """Criterion ordering the item list."""

    ALPHABETIC = auto()
    ALPHANUMERIC = auto()
    DATE = auto()


def natural_sort_key(text: str) -> list:
    """
    Build a "natural" sort key, comparing embedded numbers by value.

    Parameters
    ----------
    text : str
        Text to build a key for.

    Returns
    -------
    list
        Alternating case-folded text chunks and integers, so that
        ``"item2"`` sorts before ``"item10"``.
    """
    return [
        int(chunk) if chunk.isdigit() else chunk.casefold()
        for chunk in re.split(r"(\d+)", text)
    ]


def item_sort_key(sort_key: SortKey) -> Callable[[Item], Any]:
    """
    Return the ``key=`` function ordering items by a criterion.

    Parameters
    ----------
    sort_key : SortKey
        The criterion.

    Returns
    -------
    callable
        Function mapping an :class:`Item` to a sortable value.
    """
    if sort_key is SortKey.DATE:
        return lambda item: item.get("item_date") or ""
    if sort_key is SortKey.ALPHANUMERIC:
        return lambda item: natural_sort_key(item.get("item_name") or "")
    return lambda item: (item.get("item_name") or "").casefold()