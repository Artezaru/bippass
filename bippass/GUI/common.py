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

import functools
import os
from importlib import resources

from PyQt5.QtGui import QIcon


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Zoom step and bounds, as a delta (pt) on the application's base font size.
_ZOOM_STEP_PT = 1
_ZOOM_MIN_DELTA_PT = -4
_ZOOM_MAX_DELTA_PT = 16

# Spacer width (px) before the theme toggle button, at the toolbar's left edge.
TOOLBAR_LEFT_SPACING_PX = 16

# Padding (px) subtracted from `save_btn`'s height to size the theme icon.
_THEME_BTN_ICON_PADDING_PX = 10

# Minimum icon size (px) in `item_list` and `vault_list`.
_ITEM_ICON_MIN_SIZE_PX = 20
_VAULT_ICON_MIN_SIZE_PX = 20

# Extra size (pt) of vault names in `vault_list`, relative to the base font.
_VAULT_NAME_FONT_DELTA_PT = 2

# Inactivity delay (s) used if the manager's metadata carries none.
_DEFAULT_CLOSE_TIMER_S = 300


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

_GUI_ICONS_DIR = "resources/gui_icons"
_VAULT_ICONS_DIR = "resources/vault_icons"
_ITEM_ICONS_DIR = "resources/item_icons"

# Bundled item icon shown when an item has no (readable) icon.
_DEFAULT_ITEM_ICON = "_default.png"


@functools.lru_cache(maxsize=None)
def _resource_path(subdir: str, filename: str) -> str | None:
    """
    Return the absolute path of a bundled resource file.

    Parameters
    ----------
    subdir : str
        Folder inside the package, e.g. ``"resources/gui_icons"``.
    filename : str
        File name inside that folder, e.g. ``"sun.png"``.

    Returns
    -------
    str or None
        Path of ``bippass/<subdir>/<filename>``, or ``None`` if the
        package's resources are missing or the file doesn't exist.

    Notes
    -----
    Goes through ``importlib.resources`` rather than path arithmetic
    from ``__file__``, so it doesn't depend on how the package is laid
    out on disk. For a zipped package, ``resources.as_file`` extracts
    to a temporary file removed on exit of the ``with`` block, so the
    path is only guaranteed for a regular (directory) install -- the
    usual case for pip and PyInstaller.

    Results are cached for the lifetime of the process, since bundled
    resources don't change at runtime.
    """
    if not filename:
        return None
    try:
        ref = resources.files("bippass").joinpath(subdir, filename)
        with resources.as_file(ref) as path:
            return str(path) if path.is_file() else None
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return None


@functools.lru_cache(maxsize=None)
def _resource_icon(subdir: str, filename: str) -> QIcon | None:
    """
    Load a bundled resource file as a :class:`QIcon`.

    Parameters
    ----------
    subdir : str
        Folder inside the package, e.g. ``"resources/gui_icons"``.
    filename : str
        File name inside that folder, e.g. ``"sun.png"``.

    Returns
    -------
    QIcon or None
        The loaded icon, or ``None`` if the file is missing or isn't
        a readable image.

    Notes
    -----
    Results are cached for the lifetime of the process. Sharing one
    :class:`QIcon` between callers is safe since Qt icons are
    implicitly shared (copy-on-write). The cache is filled lazily, so
    the ``QIcon`` is always built after the ``QApplication`` exists.
    """
    path = _resource_path(subdir, filename)
    if path is None:
        return None
    icon = QIcon(path)
    return icon if not icon.isNull() else None


@functools.lru_cache(maxsize=None)
def _list_resource_names(subdir: str, suffix: str = ".png") -> tuple[str, ...]:
    """
    List the bare filenames of the bundled resource files in a folder.

    Parameters
    ----------
    subdir : str
        Folder inside the package, e.g. ``"resources/item_icons"``.
    suffix : str, optional
        Only files ending with this suffix (case-insensitive) are
        listed. Default is ``".png"``.

    Returns
    -------
    tuple of str
        Bare filenames (e.g. ``"github.png"``), sorted
        case-insensitively. Empty if the folder is missing or
        unreadable.

    Notes
    -----
    Uses the ``importlib.resources`` ``Traversable`` API, so nothing
    is extracted, even for a zipped package. Cached like
    :func:`_resource_path`.
    """
    try:
        folder = resources.files("bippass").joinpath(subdir)
        names = [
            entry.name
            for entry in folder.iterdir()
            if entry.is_file() and entry.name.lower().endswith(suffix.lower())
        ]
    except (ModuleNotFoundError, OSError):
        return ()
    return tuple(sorted(names, key=str.casefold))


def _vault_icon_names() -> tuple[str, ...]:
    """
    List the bundled vault icons.

    Returns
    -------
    tuple of str
        Bare filenames of every ``resources/vault_icons/*.png``, sorted.
    """
    return _list_resource_names(_VAULT_ICONS_DIR)


def _item_icon_names() -> tuple[str, ...]:
    """
    List the bundled item icons.

    Returns
    -------
    tuple of str
        Bare filenames of every ``resources/item_icons/*.png``, sorted.
    """
    return _list_resource_names(_ITEM_ICONS_DIR)


def _gui_icon_path(filename: str) -> str | None:
    """
    Return the absolute path of a bundled toolbar icon.

    Useful where Qt needs a path rather than a :class:`QIcon`, e.g. a
    QSS ``url(...)`` -- pass it through ``Path(...).as_posix()`` there,
    since QSS requires forward slashes even on Windows.

    Parameters
    ----------
    filename : str
        File name in ``resources/gui_icons``, e.g. ``"sun.png"``.

    Returns
    -------
    str or None
        The path, or ``None`` if the file can't be found.
    """
    return _resource_path(_GUI_ICONS_DIR, filename)


def _gui_icon(filename: str) -> QIcon | None:
    """
    Load a bundled toolbar icon.

    Parameters
    ----------
    filename : str
        File name in ``resources/gui_icons``, e.g. ``"sun.png"``.

    Returns
    -------
    QIcon or None
        The loaded icon, or ``None`` if it is missing or unreadable.
    """
    return _resource_icon(_GUI_ICONS_DIR, filename)


def _vault_icon_path(filename: str) -> str | None:
    """
    Return the absolute path of a bundled vault icon.

    Parameters
    ----------
    filename : str
        File name in ``resources/vault_icons``.

    Returns
    -------
    str or None
        The path, or ``None`` if the file can't be found.
    """
    return _resource_path(_VAULT_ICONS_DIR, filename)


def _vault_icon(filename: str) -> QIcon | None:
    """
    Load a bundled vault icon.

    Parameters
    ----------
    filename : str
        File name in ``resources/vault_icons``.

    Returns
    -------
    QIcon or None
        The loaded icon, or ``None`` if it is missing or unreadable.
    """
    return _resource_icon(_VAULT_ICONS_DIR, filename)


def _item_icon_path(filename: str) -> str | None:
    """
    Return the absolute path of a bundled item icon.

    Parameters
    ----------
    filename : str
        File name in ``resources/item_icons``, e.g. ``"github.png"``.

    Returns
    -------
    str or None
        The path, or ``None`` if the file can't be found.
    """
    return _resource_path(_ITEM_ICONS_DIR, filename)


def _item_icon(filename: str) -> QIcon | None:
    """
    Load a bundled item icon.

    Parameters
    ----------
    filename : str
        File name in ``resources/item_icons``, e.g. ``"github.png"``.

    Returns
    -------
    QIcon or None
        The loaded icon, or ``None`` if it is missing or unreadable.
    """
    return _resource_icon(_ITEM_ICONS_DIR, filename)


def _load_item_icon(value: str | None) -> QIcon | None:
    """
    Load an item's icon from its stored value.

    Parameters
    ----------
    value : str or None
        A bare filename referring to a bundled item icon
        (``"github.png"``), or a path to an image file on disk.

    Returns
    -------
    QIcon or None
        The icon, or ``None`` if ``value`` is empty or doesn't resolve
        to a readable image. There is no fallback here, see
        :func:`_item_icon_or_default`.

    Notes
    -----
    Bundled icons are cached (see :func:`_resource_icon`); files on
    disk are re-read on every call, since the user may replace them.
    """
    if not value:
        return None
    if not os.path.dirname(value):
        return _item_icon(value)
    try:
        if not os.path.isfile(value):
            return None
    except OSError:
        # e.g. a network share failing mid-lookup: treated as unreadable.
        return None
    icon = QIcon(value)
    return None if icon.isNull() else icon


def _item_icon_or_default(value: str | None) -> QIcon | None:
    """
    Load an item's icon, falling back to the bundled default icon.

    Parameters
    ----------
    value : str or None
        Stored icon value, see :func:`_load_item_icon`.

    Returns
    -------
    QIcon or None
        The item's icon, the bundled ``_default.png`` if the value is
        empty or unreadable, or ``None`` if even the default is
        missing.
    """
    icon = _load_item_icon(value)
    return icon if icon is not None else _item_icon(_DEFAULT_ITEM_ICON)