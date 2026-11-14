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

# BACKWARD COMPATIBILITY -- see `bippass/backward/__init__.py`.
#
# Conversion of a version 2 profile (`*.encrypted`, written by bippass
# before the format version 3) into a new version 3 profile.
#
# Version 2 file
# --------------
# The whole file is one pyaescbc password-mode bundle, encrypted with the
# primary password, holding UTF-8 JSON:
#
#     {
#       "metadata": {"version": 1, "username", "theme", "language", "close_timer_s"},
#       "auth":     Base64 bundle of `_AUTH_MESSAGE`, encrypted with the secondary password,
#       "vaults":   {<vault name>: {"icon": <file in resources/vault_icons> | null,
#                                   "icon_color": "#rrggbb" | null,
#                                   "items": {<uuid>: <item>}}}
#     }
#
#     <item> = {"item_name", "item_date" (ISO), "icon" (bundled file name or path),
#               "logins", "websites", "phones", "emails": [str] | null,
#               "passwords", "totps": [Base64 bundle] | null,
#               "custom": {<name>: [<kind>, <value>]} | null}
#
# where every secret is its own password-mode bundle, encrypted with the
# secondary password, and a custom <kind> is "SCALAR", "SCALAR LIST",
# "ENCRYPTED" or "ENCRYPTED LIST" (a single value, or a list).
#
# Conversion
# ----------
# The new profile keeps the same two passwords, username, preferences,
# vaults (with their icon and color), items (name, date, icon, every
# field) and custom fields (a single value becomes a one-value field). It
# gets a new UUID, and is written to `core.profiles.PROFILES_DIR`, where
# the start page lists it. The version 2 file is only read, never changed.
# Icons, stored as file names in version 2, are stored as images in
# version 3: a file that no longer exists is dropped.
#
# Every secret is decrypted with the secondary password, then encrypted
# again at once with the data key of the new profile (its clear buffer
# is erased by `Item.set`). Each version 2 secret costs one PBKDF2
# derivation (500 000 iterations): converting many secrets takes a while.

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import getpass
import json
import os
import sys
from importlib import resources
from pathlib import Path
from typing import Callable, Sequence

import pyaescbc

from ..core.exceptions import PasswordManagerError
from ..core.item import FieldKind
from ..core.manager import PasswordManager
from ..core.profiles import ensure_profiles_dir, profile_path

#: Extension of version 2 profile files.
V2_EXTENSION = ".encrypted"

# Clear text of the "auth" value: decrypting it with the secondary
# password checks that password.
_AUTH_MESSAGE = b"PasswordManager::secondary-password-check::v1"

# Folders of the icons bundled with bippass, as named by version 2.
_ITEM_ICONS_DIR = "resources/item_icons"
_VAULT_ICONS_DIR = "resources/vault_icons"

# Predefined item fields of version 2, by kind.
_CLEAR_FIELDS = ("logins", "websites", "phones", "emails")
_SECRET_FIELDS = ("passwords", "totps")

# Custom field kinds of version 2: kind -> encrypted?
_CUSTOM_KINDS = {"SCALAR": False, "SCALAR LIST": False, "ENCRYPTED": True, "ENCRYPTED LIST": True}

#: Turns an image file into a stored icon (Base64), or ``None``.
IconEncoder = Callable[[str], "str | None"]


class ConversionError(Exception):
    """Raised when a version 2 profile can't be converted (unreadable, invalid...)."""


class WrongPrimaryPasswordError(ConversionError):
    """Raised when the primary password doesn't open the version 2 profile."""


class WrongSecondaryPasswordError(ConversionError):
    """Raised when the secondary password doesn't match the version 2 profile."""


# ---------------------------------------------------------------------------
# Reading version 2
# ---------------------------------------------------------------------------

def _decrypt_secret(value: str, secondary: bytearray) -> bytearray:
    """
    Decrypt one version 2 secret.

    Parameters
    ----------
    value : str
        Base64 password-mode bundle.

    secondary : bytearray
        Secondary password (not erased: a copy is used).

    Returns
    -------
    bytearray
        The clear value, owned (and to be erased) by the caller.

    Raises
    ------
    WrongSecondaryPasswordError
        If the password doesn't decrypt it.

    ConversionError
        If the value isn't a valid bundle.
    """
    try:
        bundle = bytearray(base64.b64decode(value, validate=True))
        return pyaescbc.decrypt(bundle, bytearray(secondary), delete_keys=True, delete_data=True)
    except pyaescbc.AuthError as exc:
        raise WrongSecondaryPasswordError("Wrong secondary password.") from exc
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ConversionError(f"Invalid encrypted value: {exc}") from exc


def _read_v2(path: Path, primary: bytearray, secondary: bytearray) -> dict:
    """
    Read a version 2 profile and check both passwords.

    Returns
    -------
    dict
        The decrypted JSON content (``metadata``, ``auth``, ``vaults``).

    Raises
    ------
    WrongPrimaryPasswordError, WrongSecondaryPasswordError, ConversionError
    """
    try:
        bundle = bytearray(path.read_bytes())
    except OSError as exc:
        raise ConversionError(f"Cannot read {path}: {exc}") from exc
    try:
        clear = pyaescbc.decrypt(bundle, bytearray(primary), delete_keys=True, delete_data=True)
    except pyaescbc.AuthError as exc:
        raise WrongPrimaryPasswordError("Wrong primary password.") from exc
    except ValueError as exc:
        raise ConversionError(f"Not a version 2 profile: {exc}") from exc
    try:
        content = json.loads(clear.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ConversionError("Not a version 2 profile: invalid content.") from exc
    finally:
        pyaescbc.delete_bytearray(clear)
    if not isinstance(content, dict) or not {"metadata", "auth", "vaults"} <= set(content):
        raise ConversionError("Not a version 2 profile: missing metadata, auth or vaults.")

    check = _decrypt_secret(content["auth"], secondary)
    same = check == _AUTH_MESSAGE
    pyaescbc.delete_bytearray(check)
    if not same:
        raise WrongSecondaryPasswordError("Wrong secondary password.")
    return content


# ---------------------------------------------------------------------------
# Writing version 3
# ---------------------------------------------------------------------------

def _raw_icon(path: str) -> str | None:
    """Default :data:`IconEncoder`: the image file as is, in Base64 (no resizing)."""
    try:
        return base64.b64encode(Path(path).read_bytes()).decode("ascii")
    except OSError:
        return None


def _icon(value: object, bundled_dir: str, encoder: IconEncoder) -> str | None:
    """
    Turn a version 2 icon (bundled file name or path) into a stored icon.

    Returns
    -------
    str or None
        The Base64 image, or ``None`` if there is no icon or its file
        no longer exists.
    """
    if not isinstance(value, str) or not value:
        return None
    if os.path.dirname(value):
        path = Path(value)
    else:
        try:
            path = Path(str(resources.files("bippass").joinpath(bundled_dir, value)))
        except (ModuleNotFoundError, OSError):
            return None
    return encoder(str(path)) if path.is_file() else None


def _date(value: object) -> str | None:
    """Return a version 2 date (naive, local) in the version 3 form (with its time zone)."""
    if not isinstance(value, str):
        return None
    try:
        date = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return date.astimezone().isoformat()


def _strings(values: object) -> list[str]:
    """Return the non-empty strings of a version 2 list (or single value)."""
    if values is None:
        return []
    if not isinstance(values, list):
        values = [values]
    return [v for v in values if isinstance(v, str) and v.strip()]


def _secrets(values: object, secondary: bytearray) -> list[bytearray]:
    """
    Decrypt the secrets of a version 2 list (or single value).

    Notes
    -----
    If one fails, those already decrypted are erased before the error
    propagates.
    """
    clears: list[bytearray] = []
    try:
        for value in _strings(values):
            clears.append(_decrypt_secret(value, secondary))
    except BaseException:
        for clear in clears:
            pyaescbc.delete_bytearray(clear)
        raise
    return clears


def _fill_item(item, data: dict, manager: PasswordManager, secondary: bytearray,
               encoder: IconEncoder) -> None:
    """Copy one version 2 item into a new, empty version 3 item."""
    data_key = manager.data_key
    name = data.get("item_name")
    item.set_name(name if isinstance(name, str) and name.strip() else None)
    item.set_icon(_icon(data.get("icon"), _ITEM_ICONS_DIR, encoder))
    for field in _CLEAR_FIELDS:
        item.set(field, _strings(data.get(field)))
    for field in _SECRET_FIELDS:
        item.set(field, _secrets(data.get(field), secondary), data_key=data_key)

    customs = data.get("custom") or {}
    for custom_name, entry in customs.items():
        if not isinstance(entry, (list, tuple)) or len(entry) != 2 or entry[0] not in _CUSTOM_KINDS:
            raise ConversionError(f"Invalid custom field {custom_name!r}.")
        kind, value = entry
        if _CUSTOM_KINDS[kind]:
            item.add_custom(custom_name, FieldKind.ENCRYPTED, _secrets(value, secondary),
                            data_key=data_key)
        else:
            item.add_custom(custom_name, FieldKind.CLEAR, _strings(value))

    # Version 2 kept one date, of the last change: it becomes both dates.
    # Private attributes, on purpose: the core has no public way to set
    # dates, and this backward code must not add one.
    date = _date(data.get("item_date"))
    if date is not None:
        item._creation_date = item._modification_date = date


def convert(
    path: str | Path,
    primary: bytearray,
    secondary: bytearray,
    *,
    icon_encoder: IconEncoder | None = None,
    destination: Path | None = None,
) -> Path:
    """
    Convert a version 2 profile into a new version 3 profile.

    Parameters
    ----------
    path : str or Path
        The version 2 file (``*.encrypted``). Only read.

    primary, secondary : bytearray
        Its two passwords, kept by the new profile. Not erased: the
        caller owns them.

    icon_encoder : callable, optional
        Turns an image file into a stored icon. The GUI passes its own
        (scaled, like icons picked in the GUI); default: the file as is.

    destination : Path, optional
        File to write. Default: ``<uuid>.bippass`` in
        :data:`core.profiles.PROFILES_DIR`, listed by the start page.

    Returns
    -------
    Path
        The new profile file.

    Raises
    ------
    WrongPrimaryPasswordError, WrongSecondaryPasswordError
        If a password is wrong (nothing is written).

    ConversionError
        If the file can't be read or converted (nothing is written).
    """
    encoder = icon_encoder or _raw_icon
    content = _read_v2(Path(path), primary, secondary)
    metadata = content.get("metadata") or {}
    username = metadata.get("username")
    username = username if isinstance(username, str) and username.strip() else None

    manager = PasswordManager.create(username, bytearray(primary), bytearray(secondary),
                                     label=username)
    try:
        for setter, value in ((manager.set_theme, metadata.get("theme")),
                              (manager.set_language, metadata.get("language")),
                              (manager.set_lock_timer_s, metadata.get("close_timer_s"))):
            if value is not None:
                try:
                    setter(value)
                except (TypeError, ValueError):
                    pass  # an invalid preference keeps its default

        for vault_name, vault_data in (content.get("vaults") or {}).items():
            vault = manager.add_empty_vault(vault_name)
            icon = _icon(vault_data.get("icon"), _VAULT_ICONS_DIR, encoder)
            vault.set_icon(icon)
            if icon is not None and vault_data.get("icon_color"):
                vault.set_color(vault_data["icon_color"])
            for item_data in (vault_data.get("items") or {}).values():
                item = manager.add_empty_item(vault.uuid)
                _fill_item(item, item_data, manager, secondary, encoder)

        if destination is None:
            ensure_profiles_dir()
            destination = profile_path(manager.uuid)
        manager.save(destination)
    except OSError as exc:
        raise ConversionError(f"Cannot write {destination}: {exc}") from exc
    except (PasswordManagerError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ConversionError(f"Invalid version 2 profile: {exc}") from exc
    finally:
        manager.close()
    return destination


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def _gui_icon_encoder() -> IconEncoder | None:
    """Return the GUI's icon encoder (scaled PNG), if PyQt5 is installed."""
    try:
        from ..GUI.common import _file_to_base64
    except ImportError:
        return None
    return _file_to_base64


def main(argv: Sequence[str] | None = None) -> int:
    """
    Convert version 2 profiles from the command line.

    Parameters
    ----------
    argv : Sequence of str, optional
        Command-line arguments: the files to convert.

    Returns
    -------
    int
        ``0`` if every file was converted, ``1`` otherwise.
    """
    parser = argparse.ArgumentParser(
        prog="python -m bippass.backward.v2_to_v3",
        description="Convert version 2 bippass profiles (*.encrypted) into version 3 profiles.",
    )
    parser.add_argument("files", nargs="+", help="version 2 profile files")
    args = parser.parse_args(argv)

    status = 0
    encoder = _gui_icon_encoder()
    for name in args.files:
        print(f"{name}:")
        primary = bytearray(getpass.getpass("  Primary password: "), "utf-8")
        secondary = bytearray(getpass.getpass("  Secondary password: "), "utf-8")
        try:
            new_path = convert(name, primary, secondary, icon_encoder=encoder)
        except ConversionError as exc:
            print(f"  error: {exc}", file=sys.stderr)
            status = 1
        else:
            print(f"  converted: {new_path}")
        finally:
            pyaescbc.delete_bytearray(primary)
            pyaescbc.delete_bytearray(secondary)
    return status


if __name__ == "__main__":
    sys.exit(main())
