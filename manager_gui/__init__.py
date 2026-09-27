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

# `manager_gui` used to be a single module (`manager_gui.py`); it has
# been split into this package for readability, but every name that
# used to be importable as `from .manager_gui import X` still is,
# via this re-export -- nothing outside this package needs to change.

from .widgets import (
    ITEM_MIME_TYPE,
    ItemListWidget,
    SortKey,
    VaultListWidget,
)
from .dialogs import AccountSettingsDialog, ChangeCredentialsDialog, MetadataDialog
from .vault_icon_dialog import VaultIconDialog
from .export_import import ExportItemsDialog, ImportItemsDialog
from .window import PasswordManagerWindow

__all__ = [
    "ITEM_MIME_TYPE",
    "ItemListWidget",
    "SortKey",
    "VaultListWidget",
    "AccountSettingsDialog",
    "ChangeCredentialsDialog",
    "MetadataDialog",
    "VaultIconDialog",
    "ExportItemsDialog",
    "ImportItemsDialog",
    "PasswordManagerWindow",
]
