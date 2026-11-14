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

from contextlib import contextmanager
from typing import Iterator

from PyQt5.QtCore import QMimeData, QSize, Qt, pyqtSignal
from PyQt5.QtGui import QFont, QFontMetrics
from PyQt5.QtWidgets import QAbstractItemView, QListWidget, QListWidgetItem

# Extra size (pt) of the rows of both lists, relative to the base font.
_ROW_FONT_DELTA_PT = 2

# Smallest icon side (px) of both lists.
ICON_MIN_SIZE_PX = 20


# ---------------------------------------------------------------------------
# Row style
# ---------------------------------------------------------------------------

def row_font(list_widget: QListWidget, bold: bool = False) -> QFont:
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
        The list's font enlarged by :data:`_ROW_FONT_DELTA_PT`,
        shared by both lists so their rows have the same height.
    """
    font = QFont(list_widget.font())
    font.setPointSize(font.pointSize() + _ROW_FONT_DELTA_PT)
    font.setBold(bold)
    return font


def fit_icon_size(list_widget: QListWidget, bold: bool, min_size: int = ICON_MIN_SIZE_PX) -> None:
    """
    Size a list's icons to its row font at the current zoom.

    Parameters
    ----------
    list_widget : QListWidget
        The list.
    bold : bool
        Whether its rows are bold, see :func:`row_font`.
    min_size : int, optional
        Smallest icon side (px). Default is :data:`ICON_MIN_SIZE_PX`.
    """
    size = max(min_size, QFontMetrics(row_font(list_widget, bold)).height())
    list_widget.setIconSize(QSize(size, size))


# ---------------------------------------------------------------------------
# Drag & drop
# ---------------------------------------------------------------------------

ITEM_MIME_TYPE = "application/x-passwordmanager-item"

# Payload: "<source vault uuid><_VAULT_SEP><uuid><_UUID_SEP><uuid>...",
# using ASCII unit/record separators, which can't appear in UUIDs.
_VAULT_SEP = "\x1f"
_UUID_SEP = "\x1e"


def _encode_payload(source_vault: str, item_uuids: list[str]) -> bytes:
    """
    Encode a drag payload.

    Parameters
    ----------
    source_vault : str
        UUID of the vault the items are dragged from.
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
        ``(source_vault_uuid, item_uuids)``.
    """
    source_vault, uuids = data.decode("utf-8").split(_VAULT_SEP, 1)
    return source_vault, uuids.split(_UUID_SEP)


class _UuidListWidget(QListWidget):
    """
    List whose rows store a UUID under ``Qt.UserRole``.

    Attributes
    ----------
    syncing : bool
        ``True`` while the list is rebuilt or re-selected by code (see
        :meth:`quiet`): selection handlers must then ignore it.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.syncing = False

    @contextmanager
    def quiet(self) -> Iterator[None]:
        """Set :attr:`syncing` for the duration of a ``with`` block."""
        self.syncing = True
        try:
            yield
        finally:
            self.syncing = False

    def row_of(self, uuid: str) -> int:
        """
        Return the row of a UUID.

        Parameters
        ----------
        uuid : str
            UUID stored in a row.

        Returns
        -------
        int
            The row, or ``-1`` if it isn't listed.
        """
        for row in range(self.count()):
            if self.item(row).data(Qt.UserRole) == uuid:
                return row
        return -1


class ItemListWidget(_UuidListWidget):
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
    current_vault_uuid : str
        UUID of the vault whose items are shown, set by the owning
        panel and embedded in the drag payload.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_vault_uuid = ""
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
            mime.setData(ITEM_MIME_TYPE, _encode_payload(self.current_vault_uuid, uuids))
        return mime



class VaultListWidget(_UuidListWidget):
    """
    List of the vaults, accepting items dropped from an
    :class:`ItemListWidget` to move them into another vault. Each row
    stores its vault's UUID under ``Qt.UserRole``.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    item_dropped : pyqtSignal(object, str, str)
        Emitted with ``(item_uuids, source_vault_uuid,
        target_vault_uuid)`` when items are dropped onto another
        vault's row; ``item_uuids`` is a ``list[str]``.
    """

    item_dropped = pyqtSignal(object, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)


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
        target_vault = target_row.data(Qt.UserRole)
        if target_vault == source_vault:
            event.ignore()
            return

        self.item_dropped.emit(item_uuids, source_vault, target_vault)
        event.acceptProposedAction()
