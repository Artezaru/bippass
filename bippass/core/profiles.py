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

Location and listing of the profiles managed by the application.

Every profile is one file, named after the UUID of the profile (see
:attr:`PasswordManager.uuid`), never after its username::

    ~/.bippass/profiles/<profile uuid>.bippass

so that the file name is always valid on every system, can never
collide with another profile's, never changes, and reveals nothing
about its owner. What a profile picker shows is the profile's
*label* (see :attr:`PasswordManager.label`), read from the
unencrypted envelope of each file, without any password.

:data:`PROFILES_DIR` is only a convenient default location: a profile
file can be opened from anywhere with :meth:`PasswordManager.read`.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from .exceptions import CorruptedFileError, UnsupportedVersionError
from .manager import PasswordManager
from .uuids import _check_uuid
from .common import _normalize


#: Directory holding every managed profile file.
PROFILES_DIR: Path = Path.home() / ".bippass" / "profiles"

#: Extension of a profile file (format version 3 and later).
PROFILE_EXTENSION: str = ".bippass"


@dataclass(frozen=True, slots=True)
class ProfileEntry:
    """
    A profile file found on disk, as shown by a profile picker.

    Attributes
    ----------
    path : Path
        Location of the file.

    label : str or None
        Display name read from the file envelope, or ``None`` for an
        anonymous profile.

    modified : datetime.datetime
        Last modification time of the file, timezone-aware. Useful to
        tell anonymous profiles apart.

    supported : bool
        ``False`` if the file was written by a newer version of
        bippass, which this one can't open.
    """

    path: Path
    label: str | None
    modified: datetime.datetime
    supported: bool


def profile_path(profile_uuid: str) -> Path:
    """
    Return the path of the managed file of a profile.

    Parameters
    ----------
    profile_uuid : str
        UUID of the profile (see :attr:`PasswordManager.uuid`).

    Returns
    -------
    Path
        ``~/.bippass/profiles/<profile_uuid>.bippass``. Callers are
        responsible for creating :data:`PROFILES_DIR` if it does not
        exist yet (see :func:`ensure_profiles_dir`).

    Raises
    ------
    UUIDError
        If ``profile_uuid`` is not a UUID in canonical form: this is
        what guarantees that the resulting path stays inside
        :data:`PROFILES_DIR`.

    Examples
    --------
    >>> manager.save(profile_path(manager.uuid))
    """
    return PROFILES_DIR / f"{_check_uuid(profile_uuid)}{PROFILE_EXTENSION}"


def ensure_profiles_dir() -> Path:
    """
    Create :data:`PROFILES_DIR` if needed, readable by the current user only.

    Returns
    -------
    Path
        :data:`PROFILES_DIR`.

    Raises
    ------
    OSError
        If the directory cannot be created.

    Notes
    -----
    On POSIX systems, the directory is created with mode ``0o700``
    (existing directories are left as they are). Profile files are
    encrypted anyway; this only keeps other local users from listing
    or copying them.
    """
    PROFILES_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    return PROFILES_DIR


def _modified(path: Path) -> datetime.datetime:
    """Last modification time of a file, timezone-aware."""
    return datetime.datetime.fromtimestamp(path.stat().st_mtime).astimezone()


def list_existing_profiles() -> list[ProfileEntry]:
    """
    List the profile files in :data:`PROFILES_DIR`, without any password.

    Returns
    -------
    list of ProfileEntry
        One entry per readable profile file (``*.bippass``); a file of
        a newer format version is flagged as not
        :attr:`ProfileEntry.supported`. Files of older formats are
        obsolete, and not listed. Sorted by label,
        case- and accent-insensitively, anonymous profiles last, most
        recently modified first among equal labels. Empty if the
        directory does not exist or cannot be read.

    Notes
    -----
    Only the unencrypted envelope of each file is read (see
    :meth:`PasswordManager.read`). Files that are not bippass files are
    silently skipped: this list only feeds a convenience picker, the
    rest of the application never depends on it.
    """
    entries: list[ProfileEntry] = []
    try:
        paths = sorted(p for p in PROFILES_DIR.iterdir() if p.is_file())
    except OSError:
        return []

    for path in paths:
        try:
            if path.suffix != PROFILE_EXTENSION:
                continue
            try:
                label = PasswordManager.read(path).label
                supported = True
            except UnsupportedVersionError:
                label, supported = None, False
            entries.append(ProfileEntry(path, label, _modified(path), supported))
        except (OSError, CorruptedFileError):
            continue

    entries.sort(key=lambda e: e.modified, reverse=True)
    entries.sort(key=lambda e: (e.label is None, _normalize(e.label or "")))
    return entries
