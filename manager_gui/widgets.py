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
from pathlib import Path

from PyQt5.QtCore import Qt, QMimeData, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QListWidget,
    QListWidgetItem,
)

from ...core.manager import PasswordManager


# ---------------------------------------------------------------------------
# Drag & drop support
# ---------------------------------------------------------------------------

#: Custom MIME type used to drag one or more items from the item list
#: onto a vault, carrying the source vault name and the dragged items'
#: UUIDs.
ITEM_MIME_TYPE = "application/x-passwordmanager-item"

#: Separator between the individual item UUIDs packed into a single
#: drag payload (see `ItemListWidget.mimeData`); chosen (an ASCII
#: "record separator") so it can never collide with a UUID's own
#: characters.
_ITEM_MIME_UUID_SEP = "\x1e"


class ItemListWidget(QListWidget):
    """
    List widget displaying the items of the currently selected vault.

    Supports multi-selection (Ctrl+click, Shift+click, Ctrl+A --
    see `window.PasswordManagerWindow._build_shortcuts`) and dragging
    the selected row(s) out to :class:`VaultListWidget` in order to
    move the corresponding item(s) into a different vault.

    Attributes
    ----------
    current_vault_name : str
        Name of the vault whose items are currently displayed. Set by
        the owning window whenever the vault selection changes, and
        embedded in the drag payload so the drop target knows where
        the item(s) are coming from.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_vault_name: str = ""
        self.setDragEnabled(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def mimeTypes(self) -> list[str]:
        return [ITEM_MIME_TYPE]

    def mimeData(self, items: list[QListWidgetItem]) -> QMimeData:
        """
        Build the drag payload for the given selected row(s).

        Parameters
        ----------
        items : list of QListWidgetItem
            Items being dragged -- every currently selected row, not
            just one, thanks to :attr:`ExtendedSelection`.

        Returns
        -------
        QMimeData
            MIME data carrying
            ``"<source_vault>\\x1f<uuid1>\\x1e<uuid2>\\x1e..."``
            under :data:`ITEM_MIME_TYPE`.
        """
        mime = QMimeData()
        if items:
            uuids = _ITEM_MIME_UUID_SEP.join(
                str(item.data(Qt.UserRole)) for item in items
            )
            payload = f"{self.current_vault_name}\x1f{uuids}"
            mime.setData(ITEM_MIME_TYPE, payload.encode("utf-8"))
        return mime


class VaultListWidget(QListWidget):
    """
    List widget displaying vault names, accepting item drops from
    :class:`ItemListWidget` to move one or more items into a different
    vault.
    """

    #: Emitted when one or more items are dropped onto a vault row,
    #: with ``(item_uuids, source_vault_name, target_vault_name)``.
    #: ``item_uuids`` is a plain ``list[str]`` -- passed as ``object``
    #: since :class:`pyqtSignal` has no dedicated Python-list type.
    item_dropped = pyqtSignal(object, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasFormat(ITEM_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        if event.mimeData().hasFormat(ITEM_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        mime = event.mimeData()
        if not mime.hasFormat(ITEM_MIME_TYPE):
            event.ignore()
            return

        payload = bytes(mime.data(ITEM_MIME_TYPE)).decode("utf-8")
        source_vault, uuids_part = payload.split("\x1f", 1)
        item_uuids = uuids_part.split(_ITEM_MIME_UUID_SEP)

        target_row = self.itemAt(event.pos())
        if target_row is None:
            event.ignore()
            return

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
    """Criterion used to order the item list."""

    DATE = auto()
    ALPHABETIC = auto()
    ALPHANUMERIC = auto()


def _natural_sort_key(text: str) -> list:
    """
    Build a "natural sort" key so that embedded numbers are compared
    by value rather than lexicographically (e.g. ``"item2"`` sorts
    before ``"item10"``).

    Parameters
    ----------
    text : str
        Text to build a sort key for.

    Returns
    -------
    list
        Alternating case-folded text chunks and integers, suitable as
        a ``key=`` argument for :func:`sorted`/``list.sort``.
    """
    return [
        int(chunk) if chunk.isdigit() else chunk.casefold()
        for chunk in re.split(r"(\d+)", text)
    ]


# ---------------------------------------------------------------------------
# Background save
# ---------------------------------------------------------------------------

class _SaveWorker(QThread):
    """
    Background thread persisting the manager's current state to disk.

    Runs :meth:`PasswordManager.save_changes` off the UI thread, so
    encryption and file I/O never block the UI. Safe to run
    concurrently with further edits made from the UI thread while it
    is saving: :class:`PasswordManager` guards its own state with an
    internal lock.

    Parameters
    ----------
    manager : PasswordManager
        Manager whose current state should be saved.
    path : Path
        Destination file path.
    """

    #: Emitted with a human-readable message if the save failed.
    save_failed = pyqtSignal(str)

    def __init__(self, manager: PasswordManager, path: Path, parent=None):
        super().__init__(parent)
        self.manager = manager
        self.path = path

    def run(self) -> None:
        try:
            self.manager.save_changes(self.path)
        except Exception as exc:
            self.save_failed.emit(f"{type(exc).__name__}: {exc}")
