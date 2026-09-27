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
from importlib import resources

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPainter, QPixmap


def vault_icons_directory() -> str:
    """
    Path to the package's bundled ``resources/vault_icons`` directory.

    Returns
    -------
    str
        The directory path, or ``""`` if the package's resources
        cannot be located.
    """
    try:
        ref = resources.files("bippass").joinpath("resources/vault_icons")
        with resources.as_file(ref) as path:
            return str(path)
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return ""


def list_vault_icon_names() -> list[str]:
    """
    List the bare filenames of every bundled vault icon.

    Returns
    -------
    list of str
        Every ``*.png`` file directly inside ``resources/vault_icons``
        (bare filenames, e.g. ``"github.png"``, never a path), sorted
        case-insensitively. Empty if the directory is missing or
        unreadable.
    """
    directory = vault_icons_directory()
    if not directory or not os.path.isdir(directory):
        return []
    try:
        names = [
            name
            for name in os.listdir(directory)
            if name.lower().endswith(".png")
            and os.path.isfile(os.path.join(directory, name))
        ]
    except OSError:
        return []
    return sorted(names, key=str.casefold)


def resolve_vault_icon_path(name: str) -> str:
    """
    Resolve a bare vault icon filename against the bundled
    ``resources/vault_icons`` directory.

    A path that already has a directory component is returned
    unchanged (mirrors `item_viewer._resolve_icon_path`).

    Parameters
    ----------
    name : str
        Stored vault icon filename (never a full path -- see
        `vault_icon_pixmap`).

    Returns
    -------
    str
        The resolved path, or ``name`` unchanged if it isn't a bare
        filename or the package's resources can't be located.
    """
    head, tail = os.path.split(name)
    if head:
        return name
    try:
        ref = resources.files("bippass").joinpath("resources/vault_icons", tail)
        with resources.as_file(ref) as resolved:
            return str(resolved)
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return name


def load_vault_icon_pixmap(name: str | None) -> QPixmap | None:
    """
    Load the raw (untinted) pixmap for a vault icon filename.

    Parameters
    ----------
    name : str or None
        Bare icon filename, e.g. ``"github.png"``.

    Returns
    -------
    QPixmap or None
        ``None`` if ``name`` is empty, or does not resolve to an
        existing, readable image -- e.g. the icon was removed from
        the bundled resources after a vault was given that name.
        Unlike an item's icon, there is deliberately no bundled
        fallback here: a vault with no icon (or an icon that no
        longer exists) is a normal, common state, not an error.
    """
    if not name:
        return None
    path = resolve_vault_icon_path(name)
    try:
        if not os.path.isfile(path):
            return None
        pixmap = QPixmap(path)
    except OSError:
        return None
    return None if pixmap.isNull() else pixmap


def tint_pixmap(pixmap: QPixmap, color: QColor) -> QPixmap:
    """
    Return a copy of ``pixmap`` with every non-transparent pixel
    recoloured to ``color``, preserving the original alpha shape.

    Parameters
    ----------
    pixmap : QPixmap
        Source icon. The bundled vault icons are plain black shapes
        on a transparent background, but this recolors any icon the
        same way regardless of its original color(s).
    color : QColor
        Color to paint the icon's shape with.

    Returns
    -------
    QPixmap
        A new, tinted pixmap the same size as ``pixmap``.
    """
    tinted = QPixmap(pixmap.size())
    tinted.fill(Qt.transparent)
    painter = QPainter(tinted)
    painter.drawPixmap(0, 0, pixmap)
    # Only pixels already opaque (the icon's shape) get painted here:
    # SourceIn keeps the destination's existing alpha and replaces its
    # color, so the transparent background stays transparent.
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(tinted.rect(), QColor(color))
    painter.end()
    return tinted


def vault_icon_pixmap(name: str | None, color: str | None = None) -> QPixmap | None:
    """
    Load, and optionally tint, the pixmap for a vault's configured
    icon.

    Parameters
    ----------
    name : str or None
        Vault icon filename (``Vault.get_icon()``).
    color : str or None
        Vault icon color (``Vault.get_icon_color()``, e.g.
        ``"#3478f6"``). Left untinted (native icon colors) if empty
        or not a color Qt can parse.

    Returns
    -------
    QPixmap or None
        ``None`` if ``name`` is empty or unresolvable -- callers
        should show no icon at all in that case, never a placeholder.
    """
    pixmap = load_vault_icon_pixmap(name)
    if pixmap is None:
        return None
    if not color:
        return pixmap
    qcolor = QColor(color)
    if not qcolor.isValid():
        return pixmap
    return tint_pixmap(pixmap, qcolor)
