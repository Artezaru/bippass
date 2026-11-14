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

Rendering of profiles, vaults and items for the command line.

Every ``print_*`` function writes to an :class:`Output` (see
:mod:`bippass.cli.console`), styled with rich when available. Nothing
here ever decrypts a value: encrypted fields are only shown as a count
of masked values.
"""

from __future__ import annotations

from typing import Sequence, cast

from ..core.item import Item, FieldKind, _FIELDS
from ..core.types import ClearField
from ..core.vault import Vault
from ..core.manager import PasswordManager
from ..core.profiles import ProfileEntry
from .console import Output


#: Placeholder shown instead of an encrypted value.
MASK = "********"

#: Text shown instead of a missing name or label.
UNNAMED = "(unnamed)"

#: Width of the label column of :func:`print_item` and :func:`print_info`.
_LABEL_WIDTH = 10


def short_uuid(uuid: str) -> str:
    """
    Return the first 8 characters of a UUID, enough to type it back.

    Parameters
    ----------
    uuid : str
        UUID in canonical form.

    Returns
    -------
    str
        The first group of the UUID (e.g. ``"6f1c2e4a"``).
    """
    return uuid[:8]


def short_date(date: str) -> str:
    """
    Return an ISO 8601 date without seconds nor timezone, for display.

    Parameters
    ----------
    date : str
        ISO 8601 date and time.

    Returns
    -------
    str
        ``"YYYY-MM-DD HH:MM"``.
    """
    return date[:16].replace("T", " ")


def custom_ref(index: int) -> str:
    """
    Return the command-line reference of a custom field.

    Parameters
    ----------
    index : int
        0-based position of the field in :meth:`Item.custom_ids`.

    Returns
    -------
    str
        ``"c1"`` for the first custom field, ``"c2"`` for the second,
        and so on. Unlike names, references are unique within an item
        and can never collide with a predefined field.
    """
    return f"c{index + 1}"


#: Description of each state of a manager, as shown by :func:`print_info`.
_STATES: dict[str, str] = {
    "decrypted": "decrypted (unlocked, data key available)",
    "unlocked": "unlocked (data key not available)",
    "locked": "locked",
}


def state_of(manager: PasswordManager) -> str:
    """
    Return the state of a manager, as shown by the prompt.

    Returns
    -------
    str
        ``"decrypted"``, ``"unlocked"`` or ``"locked"`` (also a style
        role of :data:`bippass.cli.console.STYLES`).
    """
    if manager.is_decrypted:
        return "decrypted"
    return "unlocked" if manager.is_unlocked else "locked"


def _field(out: Output, label: str, value: str, role: str | None = None, number: int | None = None) -> None:
    """Write one ``label : value`` line, labels aligned, optionally followed by ``[number]``."""
    out.line(out.style(f"{label:<{_LABEL_WIDTH}}: ", "label") + out.style(value, role)
             + (out.style(f"  [{number}]", "muted") if number is not None else ""))


def print_profiles(out: Output, entries: Sequence[ProfileEntry]) -> None:
    """
    Write the profiles found on disk, numbered from 1.

    Parameters
    ----------
    out : Output
        Where to write.

    entries : Sequence of ProfileEntry
        Profiles, as returned by :func:`list_existing_profiles`.
    """
    rows = [
        [
            str(i),
            entry.label or UNNAMED,
            entry.modified.strftime("%Y-%m-%d %H:%M"),
            "" if entry.supported else "newer version",
            entry.path.name,
        ]
        for i, entry in enumerate(entries, start=1)
    ]
    out.table(["#", "label", "modified", "status", "file"], rows,
              ["muted", "title", "muted", "warn", "muted"])


def print_vaults(out: Output, vaults: Sequence[Vault]) -> None:
    """
    Write vaults, numbered from 1.

    Parameters
    ----------
    out : Output
        Where to write.

    vaults : Sequence of Vault
        Vaults to list: name, short UUID, item count, last activity.
    """
    rows = [
        [
            str(i),
            vault.get_name() or UNNAMED,
            short_uuid(vault.uuid),
            str(len(vault)),
            short_date(vault.last_activity_date),
        ]
        for i, vault in enumerate(vaults, start=1)
    ]
    out.table(["#", "name", "uuid", "items", "last activity"], rows,
              ["muted", "title", "muted", None, "muted"])


def print_items(out: Output, items: Sequence[Item]) -> None:
    """
    Write items, numbered from 1.

    Parameters
    ----------
    out : Output
        Where to write.

    items : Sequence of Item
        Items to list: name, short UUID, first login, first website,
        number of passwords and TOTP secrets, last modification.
    """
    headers = ["#", "name", "uuid", "login", "website", "pw", "totp", "modified"]
    roles: list[str | None] = ["muted", "title", "muted", None, None, None, None, "muted"]
    rows = []
    for i, item in enumerate(items, start=1):
        logins, websites = item.get("logins"), item.get("websites")
        row = [
            str(i),
            item.get_name() or UNNAMED,
            short_uuid(item.uuid),
            logins[0] if logins else "",
            websites[0] if websites else "",
            str(item.count("passwords")),
            str(item.count("totps")),
            short_date(item.modification_date),
        ]
        rows.append(row)
    out.table(headers, rows, roles)


def print_item(out: Output, item: Item) -> None:
    """
    Write every field of an item, encrypted values masked.

    Parameters
    ----------
    out : Output
        Where to write.

    item : Item
        Item to show.

    Notes
    -----
    Every value of every field is numbered (``[1]``, ``[2]``...), so
    that it can be given to ``reveal``, ``editfield`` or
    ``removefield``. Encrypted values are replaced by :data:`MASK`.
    Custom fields are listed with their reference (see
    :func:`custom_ref`), and ``(no value)`` when empty. Nothing is
    decrypted.
    """
    _field(out, "name", item.get_name() or UNNAMED, "title")
    _field(out, "uuid", item.uuid, "muted")
    _field(out, "created", short_date(item.creation_date), "muted")
    _field(out, "modified", short_date(item.modification_date), "muted")
    color = item.get_color()
    if color is not None:
        _field(out, "color", color)
    _field(out, "icon", "yes" if item.get_icon() else "no", "muted")

    for field, kind in _FIELDS.items():
        if kind is FieldKind.CLEAR:
            for i, value in enumerate(item.get(cast(ClearField, field))):
                _field(out, field[:-1], value, number=i + 1)
        else:
            for i in range(item.count(field)):
                _field(out, field[:-1], MASK, "muted", number=i + 1)

    custom_ids = item.custom_ids()
    if not custom_ids:
        return
    out.text("custom fields:", "title")
    width = max(len(item.custom_name(c)) for c in custom_ids)
    for index, custom_id in enumerate(custom_ids):
        head = (
            out.style("  ")
            + out.style(f"{custom_ref(index):<4}", "ref")
            + out.style(f"{item.custom_name(custom_id):<{width}} : ", "label")
        )
        if item.custom_kind(custom_id) is FieldKind.CLEAR:
            values = [out.style(str(v)) + out.style(f"  [{i + 1}]", "muted")
                      for i, v in enumerate(item.get_custom(custom_id))]
        else:
            values = [out.style(f"{MASK}  [{i + 1}]", "muted")
                      for i in range(item.custom_count(custom_id))]
        for value in values or [out.style("(no value)", "muted")]:
            out.line(head + value)


def print_info(out: Output, manager: PasswordManager, path: str | None) -> None:
    """
    Write the state and metadata of a manager.

    Parameters
    ----------
    out : Output
        Where to write.

    manager : PasswordManager
        Loaded manager.

    path : str or None
        File the manager was loaded from, if any.

    Notes
    -----
    File, label and lock state; plus username, UUID, dates, vault and
    item counts and preferences once the primary layer is unlocked.
    """
    state = state_of(manager)
    _field(out, "file", path or "(not saved yet)")
    _field(out, "label", manager.label or UNNAMED, "title")
    _field(out, "state", _STATES[state], state)
    if not manager.is_unlocked:
        return
    _field(out, "username", manager.get_username() or "(none)")
    _field(out, "uuid", manager.uuid, "muted")
    _field(out, "created", short_date(manager.creation_date), "muted")
    _field(out, "modified", short_date(manager.modification_date), "muted")
    _field(out, "vaults", str(len(manager.vault_uuids())))
    _field(out, "items", str(len(manager.item_uuids())))
    _field(out, "theme", str(manager.get_theme()))
    _field(out, "language", str(manager.get_language()))
    _field(out, "auto-lock", f"{manager.get_lock_timer_s()} s")
