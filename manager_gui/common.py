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

from importlib import resources

from PyQt5.QtGui import QIcon

from ..translate import translator, manager_gui_translation

#: Shared shorthand for ``translator.translate(key, manager_gui_translation,
#: **kwargs)``, used by every module of this package so they all read
#: from the same translation table.
def _t(key: str, **kwargs: str) -> str:
    return translator.translate(key, manager_gui_translation, **kwargs)


def _gui_icon(filename: str) -> QIcon | None:
    """
    Load one of the package's bundled toolbar icons
    (``bippass/resources/gui/<filename>``), e.g. ``"sun.png"``.

    Uses ``importlib.resources`` for the same reason as the item
    icons in `item_viewer.py`: it goes through the import system's
    own loader rather than manual path arithmetic, so it works
    whether the package is a plain directory or zipped.

    Returns
    -------
    QIcon or None
        The loaded icon, or ``None`` if the package's resources are
        missing, the file doesn't exist, or it isn't a readable
        image -- callers should fall back to a text/emoji label in
        that case.
    """
    try:
        ref = resources.files("bippass").joinpath("resources/gui", filename)
        with resources.as_file(ref) as path:
            if not path.is_file():
                return None
            icon = QIcon(str(path))
            return icon if not icon.isNull() else None
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return None


#: Zoom bounds and step, expressed as a delta (in points) applied to
#: the application's base font size; see `window._apply_zoom`.
_ZOOM_STEP_PT = 1
_ZOOM_MIN_DELTA_PT = -4
_ZOOM_MAX_DELTA_PT = 16

#: Width (px) of the spacer placed before the theme toggle button, at
#: the toolbar's left edge; see `window._build_toolbar`.
TOOLBAR_LEFT_SPACING_PX = 16

#: Padding (px) subtracted from `save_btn`'s height to get the theme
#: toggle button's icon size; see `window._update_theme_button_size`.
_THEME_BTN_ICON_PADDING_PX = 10

#: Minimum row height (px) reserved for an item's icon in `item_list`,
#: below the font-metrics-derived size; see `window._update_item_icon_size`.
_ITEM_ICON_MIN_SIZE_PX = 16

#: Minimum size (px) reserved for a vault's icon in `vault_list`,
#: below the font-metrics-derived size; see
#: `window._update_vault_icon_size`.
_VAULT_ICON_MIN_SIZE_PX = 20

#: How many points larger than the application's base font a vault
#: name is shown at in `vault_list` (also always bold); see
#: `window._refresh_vaults`.
_VAULT_NAME_FONT_DELTA_PT = 2

#: Fallback inactivity delay (seconds) if the manager's metadata
#: somehow doesn't carry a usable one (should not normally happen,
#: see `PasswordManager._DEFAULT_METADATA`).
_DEFAULT_CLOSE_TIMER_S = 300
