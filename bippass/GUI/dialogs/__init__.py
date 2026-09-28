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

Dialogs of the bippass GUI
==========================

Every dialog is a :class:`QDialog` opened with ``exec_()``. When it
returns ``QDialog.Accepted``, the caller reads the result through the
dialog's ``get_data``, ``get_path``, ``get_password`` or ``apply_to``
method.

Account
-------
- :class:`AccountSettingsDialog` -- theme, language and inactivity
  auto-close delay.
- :class:`MetadataDialog` -- account metadata (username).
- :class:`ChangeCredentialsDialog` -- primary or secondary password.

Items and vaults
----------------
- :class:`ItemIconDialog` -- item icon, bundled logo or image file.
- :class:`CustomFieldDialog` -- new custom field on an item.
- :class:`VaultIconDialog` -- vault icon and its color.
- :class:`ExportItemsDialog` -- export items to a standalone vault file.
- :class:`ImportItemsDialog` -- import items from a standalone vault file.

Tools
-----
- :class:`GeneratorDialog` -- random or memorable password generator.
- :class:`HelpDialog` -- usage and keyboard shortcuts.

Vault icon helpers
------------------
- :func:`load_vault_icon_pixmap` -- raw pixmap of a bundled vault icon.
- :func:`tint_pixmap` -- recolor a pixmap, keeping its alpha shape.
- :func:`vault_icon_pixmap` -- vault icon pixmap, tinted with its color.
"""

from .credentials import ChangeCredentialsDialog
from .custom_field import CustomFieldDialog
from .generator import GeneratorDialog
from .help import HelpDialog
from .item_icon import ItemIconDialog
from .metadata import MetadataDialog
from .settings import AccountSettingsDialog
from .transfer import ExportItemsDialog, ImportItemsDialog
from .vault_icon import (
    VaultIconDialog,
    load_vault_icon_pixmap,
    tint_pixmap,
    vault_icon_pixmap,
)

__all__ = [
    # Account
    "AccountSettingsDialog",
    "MetadataDialog",
    "ChangeCredentialsDialog",
    # Items and vaults
    "ItemIconDialog",
    "CustomFieldDialog",
    "VaultIconDialog",
    "ExportItemsDialog",
    "ImportItemsDialog",
    # Tools
    "GeneratorDialog",
    "HelpDialog",
    # Vault icon helpers
    "load_vault_icon_pixmap",
    "tint_pixmap",
    "vault_icon_pixmap",
]