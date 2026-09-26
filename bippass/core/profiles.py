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

from pathlib import Path

#: Directory holding every managed profile's encrypted vault file.
PROFILES_DIR: Path = Path.home() / ".bippass" / "profiles"


def profile_path(username: str) -> Path:
    """
    Path of the managed profile file for ``username``.

    Parameters
    ----------
    username : str
        Account username (as stored in the vault's own metadata, and
        typed into the "Username" field when creating a profile or
        editing account metadata).

    Returns
    -------
    Path
        ``~/bippass/<username>.encrypted`` -- callers are responsible
        for creating :data:`PROFILES_DIR` if it doesn't exist yet
        (e.g. via ``profile_path(username).parent.mkdir(parents=True,
        exist_ok=True)``).
    """
    return PROFILES_DIR / f"{username}.encrypted"


def list_existing_profiles() -> list[str]:
    """
    List the usernames of every managed profile currently on disk.

    Returns
    -------
    list of str
        Usernames (derived from the ``.encrypted`` filenames directly
        under :data:`PROFILES_DIR`), sorted case-insensitively. Empty
        if the directory doesn't exist yet or can't be read -- this is
        only used to populate a convenience picker, never something
        the rest of the app depends on.
    """
    try:
        return sorted(
            (path.stem for path in PROFILES_DIR.glob("*.encrypted") if path.is_file()),
            key=str.casefold,
        )
    except OSError:
        return []
