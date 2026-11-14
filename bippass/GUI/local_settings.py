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

# Settings of this computer, kept between runs in a single JSON file,
# outside any profile: the theme shown before a profile is opened, and
# the last profile file opened (pre-selected on the start page).
#
# Every access is best effort: a missing, unreadable or read-only file
# only means the setting isn't remembered.

from __future__ import annotations

import json
from pathlib import Path

#: The settings file.
SETTINGS_FILE_PATH = Path.home() / ".bippass" / "settings.json"


def _read_all() -> dict:
    """
    Read every setting.

    Returns
    -------
    dict
        The stored settings, empty if the file is missing, unreadable
        or not a JSON object.
    """
    try:
        settings = json.loads(SETTINGS_FILE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return settings if isinstance(settings, dict) else {}


def read_setting(key: str, default: object = None) -> object:
    """
    Return one setting.

    Parameters
    ----------
    key : str
        Name of the setting, e.g. ``"theme"``.

    default : object, optional
        Returned if the setting isn't stored.

    Returns
    -------
    object
        The stored value (any JSON value), or ``default``.
    """
    return _read_all().get(key, default)


def write_setting(key: str, value: object) -> None:
    """
    Store one setting, keeping the others.

    Parameters
    ----------
    key : str
        Name of the setting.

    value : object
        Any JSON-serializable value.
    """
    settings = _read_all()
    settings[key] = value
    try:
        SETTINGS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE_PATH.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    except OSError:
        pass
