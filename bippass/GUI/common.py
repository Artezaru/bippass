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

import base64
import binascii
import functools
from importlib import resources

from PyQt5.QtCore import QBuffer, QByteArray, QIODevice, QSize, Qt
from PyQt5.QtGui import QColor, QIcon, QImage, QPainter, QPixmap

from .translate import translator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Side (px) of the square images stored as item and vault icons.
_STORED_ICON_SIZE_PX = 64


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


# ---------------------------------------------------------------------------
# Stored icons (Base64)
# ---------------------------------------------------------------------------
#
# Item and vault icons are stored in the profile itself, as a Base64
# PNG image (see `Item.set_icon` and `Vault.set_icon`): a profile stays
# complete when moved to another computer, and no path on disk is ever
# stored. Bundled icons and image files are converted when picked.


def _image_to_base64(image: QImage, size: int = _STORED_ICON_SIZE_PX) -> str | None:
    """
    Encode an image as a stored icon.

    Parameters
    ----------
    image : QImage
        Image to encode.
    size : int, optional
        Side (px) of the square the image is scaled into, keeping its
        aspect ratio. Default is :data:`_STORED_ICON_SIZE_PX`.

    Returns
    -------
    str or None
        The scaled image as a Base64 PNG, or ``None`` if ``image`` is
        null or cannot be encoded.

    Notes
    -----
    Scaling keeps the profile small: a 64 px PNG weighs a few KB,
    whatever the size of the picked file.
    """
    if image.isNull():
        return None
    scaled = image.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.WriteOnly)
    ok = scaled.save(buffer, "PNG")
    buffer.close()
    if not ok:
        return None
    return base64.b64encode(bytes(data)).decode("ascii")


def _file_to_base64(path: str, size: int = _STORED_ICON_SIZE_PX) -> str | None:
    """
    Encode an image file as a stored icon.

    Parameters
    ----------
    path : str
        Path of an image file in any format Qt can read.
    size : int, optional
        See :func:`_image_to_base64`.

    Returns
    -------
    str or None
        The Base64 PNG, or ``None`` if the file is missing or isn't a
        readable image.
    """
    return _image_to_base64(QImage(path), size)


def _bundled_icon_name(subdir: str, icon: str | None) -> str | None:
    """
    Find the bundled icon a stored icon was made from.

    Parameters
    ----------
    subdir : str
        Folder of the bundled icons, :data:`_ITEM_ICONS_DIR` or
        :data:`_VAULT_ICONS_DIR`.

    icon : str or None
        Stored Base64 icon.

    Returns
    -------
    str or None
        The bundled filename, or ``None`` if none matches.

    Notes
    -----
    A bundled icon is encoded the same way every time it is picked
    (see :func:`_file_to_base64`), so comparing encodings finds it.
    The encodings of a folder are computed once per run.
    """
    if not icon:
        return None
    return _bundled_encodings(subdir).get(icon)


@functools.lru_cache(maxsize=None)
def _bundled_encodings(subdir: str) -> dict[str, str]:
    """
    Encode every bundled icon of a folder as a stored icon.

    Returns
    -------
    dict of str to str
        Base64 encoding -> bundled filename.
    """
    encodings: dict[str, str] = {}
    for name in _list_resource_names(subdir):
        path = _resource_path(subdir, name)
        encoded = _file_to_base64(path) if path is not None else None
        if encoded is not None:
            encodings.setdefault(encoded, name)
    return encodings


@functools.lru_cache(maxsize=512)
def _pixmap_from_base64(value: str) -> QPixmap | None:
    """
    Decode a stored icon.

    Parameters
    ----------
    value : str
        Base64-encoded image.

    Returns
    -------
    QPixmap or None
        The image, or ``None`` if ``value`` isn't valid Base64 or
        doesn't hold a readable image.

    Notes
    -----
    Cached by value: lists are rebuilt often (search, zoom...), and
    decoding every icon each time would be wasteful. Sharing a
    :class:`QPixmap` is safe since Qt pixmaps are implicitly shared.
    """
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    pixmap = QPixmap()
    if not pixmap.loadFromData(raw):
        return None
    return pixmap


def _icon_from_base64(value: str | None) -> QIcon | None:
    """
    Load a stored icon as a :class:`QIcon`.

    Parameters
    ----------
    value : str or None
        Base64-encoded image, as returned by ``get_icon()``.

    Returns
    -------
    QIcon or None
        The icon, or ``None`` if ``value`` is empty or unreadable.
    """
    if not value:
        return None
    pixmap = _pixmap_from_base64(value)
    return None if pixmap is None else QIcon(pixmap)


def _with_background(icon: QIcon, color: str | None) -> QIcon:
    """
    Paint an icon over a plain background color.

    Parameters
    ----------
    icon : QIcon
        The icon, possibly with transparent pixels.
    color : str or None
        Background color, e.g. ``"#ffffff"`` (``Item.get_color()``).
        ``None``, an empty string or a color Qt can't parse leaves the
        icon unchanged: its transparent pixels stay transparent.

    Returns
    -------
    QIcon
        A square icon of :data:`_STORED_ICON_SIZE_PX`, filled with
        ``color``, with ``icon`` centered on top: its transparent
        pixels now show the color, which improves the contrast of a
        dark logo on a dark theme (or the reverse).
    """
    qcolor = QColor(color) if color else QColor()
    if not qcolor.isValid():
        return icon
    size = _STORED_ICON_SIZE_PX
    source = icon.pixmap(QSize(size, size))
    canvas = QPixmap(size, size)
    canvas.fill(qcolor)
    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.SmoothPixmapTransform)
    painter.drawPixmap((size - source.width()) // 2, (size - source.height()) // 2, source)
    painter.end()
    return QIcon(canvas)


@functools.lru_cache(maxsize=512)
def _item_icon_or_default(value: str | None, background: str | None = None) -> QIcon | None:
    """
    Load an item's icon, falling back to the bundled default icon.

    Parameters
    ----------
    value : str or None
        Stored icon (Base64), as returned by :meth:`Item.get_icon`.
    background : str or None, optional
        Background color of the icon, as returned by
        :meth:`Item.get_color`. ``None`` (the default) keeps the
        transparent pixels transparent; see :func:`_with_background`.

    Returns
    -------
    QIcon or None
        The item's icon, the bundled ``_default.png`` if the value is
        empty or unreadable, or ``None`` if even the default is
        missing; painted over ``background`` if one is given.

    Notes
    -----
    Cached by ``(value, background)``: item lists are rebuilt often
    (search, zoom...). Sharing a :class:`QIcon` is safe since Qt icons
    are implicitly shared.
    """
    icon = _icon_from_base64(value)
    if icon is None:
        icon = _item_icon(_DEFAULT_ITEM_ICON)
    if icon is None:
        return None
    return _with_background(icon, background)


def tint_pixmap(pixmap: QPixmap, color: QColor) -> QPixmap:
    """
    Recolor every non-transparent pixel of a pixmap.

    Parameters
    ----------
    pixmap : QPixmap
        Source icon, whatever its original color(s).

    color : QColor
        Color to paint the icon's shape with.

    Returns
    -------
    QPixmap
        A new pixmap the same size as ``pixmap``, with the same alpha
        shape, filled with ``color``.
    """
    tinted = QPixmap(pixmap.size())
    tinted.fill(Qt.transparent)
    painter = QPainter(tinted)
    painter.drawPixmap(0, 0, pixmap)
    # SourceIn keeps the destination's alpha and replaces its color,
    # so the transparent background stays transparent.
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(tinted.rect(), QColor(color))
    painter.end()
    return tinted


def vault_icon_pixmap(icon: str | None, color: str | None = None) -> QPixmap | None:
    """
    Decode, and optionally tint, the pixmap of a vault's icon.

    Parameters
    ----------
    icon : str or None
        Stored vault icon, a Base64 image (``Vault.get_icon()``).

    color : str or None, optional
        Vault color (``Vault.get_color()``, e.g. ``"#3478f6"``). The
        icon is left untinted if empty or not a color Qt can parse.

    Returns
    -------
    QPixmap or None
        ``None`` if ``icon`` is empty or unreadable; callers should
        then show no icon at all, never a placeholder.
    """
    pixmap = _pixmap_from_base64(icon) if icon else None
    if pixmap is None or not color:
        return pixmap
    qcolor = QColor(color)
    if not qcolor.isValid():
        return pixmap
    return tint_pixmap(pixmap, qcolor)


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

def vault_display_name(vault) -> str:
    """
    Return the name shown for a vault.

    Parameters
    ----------
    vault : Vault
        The vault.

    Returns
    -------
    str
        Its name, or a translated placeholder if it has none.
    """
    return vault.get_name() or translator.translate("common.unnamed_vault")


def item_display_name(item) -> str:
    """
    Return the name shown for an item.

    Parameters
    ----------
    item : Item
        The item.

    Returns
    -------
    str
        Its name, or a translated placeholder if it has none.
    """
    return item.get_name() or translator.translate("common.unnamed_item")
