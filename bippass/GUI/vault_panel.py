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

from typing import TYPE_CHECKING

from PyQt5.QtCore import QPoint, Qt, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QDialog,
    QLabel,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core.exceptions import PasswordManagerError
from .common import vault_display_name, vault_icon_pixmap
from .dialogs import VaultIconDialog
from .lists import VaultListWidget, fit_icon_size, row_font
from .translate import translator
from .widgets import ask_text, confirm, show_error

if TYPE_CHECKING:
    from .window import PasswordManagerWindow


class VaultPanel(QWidget):
    """
    Left column of the main window: the vaults, by name.

    Vaults are always listed in alphabetical order (see
    :meth:`PasswordManager.get_vaults`). Rows store the vault UUIDs:
    several vaults may share a name. The context menu renames, changes
    the icon and deletes a vault; items dragged from the item list onto
    a vault are moved into it.

    Parameters
    ----------
    host : PasswordManagerWindow
        Window owning the manager and the item viewer.
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    vault_changed : pyqtSignal(str)
        Emitted with the UUID of the vault to show (``""`` for none),
        after a user selection or a rebuild of the list.
    items_moved : pyqtSignal()
        Emitted after items were dropped into another vault.
    """

    vault_changed = pyqtSignal(str)
    items_moved = pyqtSignal()

    def __init__(self, host: PasswordManagerWindow, parent=None):
        super().__init__(parent)
        self._host = host
        self._current_uuid = ""

        layout = QVBoxLayout(self)
        self.title_label = QLabel()
        self.title_label.setObjectName("sectionTitle")
        layout.addWidget(self.title_label)

        self.vault_list = VaultListWidget()
        self.vault_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.vault_list.currentItemChanged.connect(self._on_selected)
        self.vault_list.item_dropped.connect(self._on_items_dropped)
        self.vault_list.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.vault_list)

        self.add_button = QPushButton()
        self.add_button.clicked.connect(self._add_vault)
        layout.addWidget(self.add_button)

        self.retranslate()

    @pyqtSlot()
    def retranslate(self) -> None:
        """Refresh every text of the panel."""
        tr = translator.translate
        self.title_label.setText(tr("window.vaults_title"))
        self.add_button.setText(tr("window.add_vault_button"))
        self.vault_list.setToolTip(tr("window.vault_list_tooltip"))
        # Unnamed vaults show a translated placeholder.
        if self.vault_list.count() and self._host.has_profile:
            self.refresh()

    # -- list ---------------------------------------------------------------

    def refresh(self) -> None:
        """
        Rebuild the list in alphabetical order, keeping the shown vault
        selected if it still exists (else the first one), then emit
        :attr:`vault_changed`.
        """
        fit_icon_size(self.vault_list, True)
        font = row_font(self.vault_list, bold=True)
        with self.vault_list.quiet():
            self.vault_list.clear()
            for vault in self._host.profile.get_vaults():
                row = QListWidgetItem(vault_display_name(vault))
                row.setData(Qt.UserRole, vault.uuid)
                row.setFont(font)
                pixmap = vault_icon_pixmap(vault.get_icon(), vault.get_color())
                if pixmap is not None:
                    row.setIcon(QIcon(pixmap))
                self.vault_list.addItem(row)
            if self.vault_list.count():
                self.vault_list.setCurrentRow(max(0, self.vault_list.row_of(self._current_uuid)))

        current = self.vault_list.currentItem()
        self._current_uuid = current.data(Qt.UserRole) if current is not None else ""
        self.vault_changed.emit(self._current_uuid)

    def clear(self) -> None:
        """Empty the list, e.g. when the profile is locked (the selection is kept)."""
        with self.vault_list.quiet():
            self.vault_list.clear()

    def select_vault(self, uuid: str) -> None:
        """
        Show a vault, as if clicked (the viewer is closed without asking).

        Parameters
        ----------
        uuid : str
            UUID of the vault; nothing happens if it isn't listed.
        """
        row = self.vault_list.row_of(uuid)
        if row < 0:
            return
        self._host.close_viewer(ask=False)
        with self.vault_list.quiet():
            self.vault_list.setCurrentRow(row)
        self._current_uuid = uuid
        self.vault_changed.emit(uuid)

    def _on_selected(self, current: QListWidgetItem | None, _previous) -> None:
        """
        Show the vault selected by the user.

        Parameters
        ----------
        current : QListWidgetItem or None
            Newly selected row.
        _previous : QListWidgetItem or None
            Previously selected row, unused.

        Notes
        -----
        Switching vault closes the viewer, asking about unsaved edits;
        if the user cancels, the previous vault is selected again.
        """
        if self.vault_list.syncing:
            return
        uuid = current.data(Qt.UserRole) if current is not None else ""
        if uuid == self._current_uuid:
            return
        if not self._host.close_viewer():
            QTimer.singleShot(0, self._restore_selection)
            return
        self._current_uuid = uuid
        self.vault_changed.emit(uuid)

    def _restore_selection(self) -> None:
        """Select the shown vault again, without reacting to it."""
        with self.vault_list.quiet():
            self.vault_list.setCurrentRow(self.vault_list.row_of(self._current_uuid))

    # -- actions ------------------------------------------------------------

    def _context_menu(self, pos: QPoint) -> None:
        """
        Show the context menu of a vault row.

        Parameters
        ----------
        pos : QPoint
            Position of the click in :attr:`vault_list`.
        """
        row = self.vault_list.itemAt(pos)
        if row is None:
            return
        uuid = row.data(Qt.UserRole)
        self._host.exec_menu(
            [
                ("window.rename_vault_action", lambda: self._rename_vault(uuid), None),
                ("window.vault_icon_action", lambda: self._change_vault_icon(uuid), None),
                None,
                ("window.delete_vault_action", lambda: self._delete_vault(uuid), None),
            ],
            self.vault_list.mapToGlobal(pos),
        )

    def _ask_name(self, title_key: str, prompt: str, text: str = "") -> str | None:
        """
        Ask for a vault name.

        Parameters
        ----------
        title_key : str
            Translation key of the dialog title.
        prompt : str
            Question, already translated.
        text : str, optional
            Pre-filled name.

        Returns
        -------
        str or None
            The stripped name (``""`` for no name: the vault is then
            shown with a placeholder), or ``None`` if cancelled.
        """
        return ask_text(self, title_key, prompt, text)

    def _add_vault(self) -> None:
        """Ask for a name, create an empty vault and show it."""
        name = self._ask_name("window.new_vault_title", translator.translate("window.new_vault_prompt"))
        if name is None or not self._host.close_viewer():
            return
        vault = self._host.profile.add_empty_vault(name or None)
        self._host.mark_dirty()
        self._current_uuid = vault.uuid
        self.refresh()

    def _rename_vault(self, uuid: str) -> None:
        """
        Ask for a new name and rename a vault.

        Parameters
        ----------
        uuid : str
            UUID of the vault.
        """
        vault = self._host.find_vault(uuid)
        if vault is None:
            return
        old_name = vault.get_name() or ""
        name = self._ask_name(
            "window.rename_vault_title",
            translator.translate("window.rename_vault_prompt", name=vault_display_name(vault)),
            old_name,
        )
        if name is None or name == old_name:
            return
        vault.set_name(name or None)
        self._host.mark_dirty()
        self.refresh()

    def _change_vault_icon(self, uuid: str) -> None:
        """
        Pick a vault's icon and color through :class:`VaultIconDialog`.

        Parameters
        ----------
        uuid : str
            UUID of the vault.
        """
        vault = self._host.find_vault(uuid)
        if vault is None:
            return
        dialog = VaultIconDialog(vault.get_icon(), vault.get_color(), parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        data = dialog.get_data()
        vault.set_icon(data["icon"])
        vault.set_color(data["color"])
        self._host.mark_dirty()
        self.refresh()

    def _delete_vault(self, uuid: str) -> None:
        """
        Delete a vault and its items after confirmation.

        Parameters
        ----------
        uuid : str
            UUID of the vault.

        Notes
        -----
        The confirmation mentions the number of items, so the vault is
        then removed with ``force=True``, items included.
        """
        vault = self._host.find_vault(uuid)
        if vault is None:
            return
        tr = translator.translate
        name = vault_display_name(vault)
        if len(vault):
            prompt = tr("window.delete_vault_prompt_with_items", vault=name, count=str(len(vault)))
        else:
            prompt = tr("window.delete_vault_prompt", vault=name)
        if not confirm(self, "window.delete_vault_title", prompt):
            return

        viewer_uuid = self._host.viewer_uuid
        if viewer_uuid is not None and viewer_uuid in vault:
            self._host.close_viewer(ask=False)
        try:
            self._host.profile.remove_vault(uuid, force=True)
        except PasswordManagerError as exc:
            show_error(self, error=str(exc))
            return
        self._host.mark_dirty()
        self.refresh()

    def _on_items_dropped(self, item_uuids: list[str], source_uuid: str, target_uuid: str) -> None:
        """
        Move items dropped onto another vault, after confirmation.

        Parameters
        ----------
        item_uuids : list of str
            UUIDs of the dropped items.
        source_uuid : str
            UUID of the vault the items come from.
        target_uuid : str
            UUID of the vault the items are dropped onto.
        """
        source, target = self._host.find_vault(source_uuid), self._host.find_vault(target_uuid)
        if source is None or target is None:
            return
        tr = translator.translate
        names = [self._host.item_display_name(uuid) for uuid in item_uuids]
        if len(names) == 1:
            prompt = tr(
                "window.move_item_prompt",
                item=names[0],
                source=vault_display_name(source),
                target=vault_display_name(target),
            )
        else:
            prompt = tr(
                "window.move_items_prompt",
                count=str(len(names)),
                items=", ".join(names),
                source=vault_display_name(source),
                target=vault_display_name(target),
            )
        if not confirm(self, "window.move_item_title", prompt):
            return
        if self._host.viewer_uuid in item_uuids and not self._host.close_viewer():
            return

        try:
            for uuid in item_uuids:
                self._host.profile.move_item(uuid, target_uuid)
        except PasswordManagerError as exc:
            show_error(self, error=str(exc))
        finally:
            self._host.mark_dirty()
            self.items_moved.emit()
