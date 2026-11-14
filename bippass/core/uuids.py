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

UUID helpers shared by every collection of uniquely identified elements.

Used wherever elements are identified by a UUID rather than by a name
or a position: items within a password manager, custom fields within
an item. In every case, the collection keeps its elements in an
ordered list, and the UUIDs are either stored in those elements or in
a parallel list aligned with them (see :func:`_get_uuid_index`).

Every UUID handled by bippass is a string in canonical form: 36
lowercase hexadecimal characters and hyphens, e.g.
``"6f1c2e4a-9b3d-4c8e-a1f0-2b7d5e9c0a13"`` (see :func:`_is_uuid`).
New UUIDs are random (version 4).

Notes
-----
Named ``uuids`` rather than ``uuid`` so that it never shadows the
standard library :mod:`uuid` module it relies on.
"""

from __future__ import annotations

import uuid as _std_uuid
from typing import Iterable, Sequence, TypeGuard

from .exceptions import PasswordManagerError


class UUIDError(PasswordManagerError):
    """
    Raised when a UUID is invalid, missing, or duplicated.

    Callers that manage a specific kind of element are expected to
    translate it into a more specific error when relevant (e.g.
    :exc:`ItemNotFoundError`).
    """


def _is_uuid(value: object) -> TypeGuard[str]:
    """
    Check whether a value is a UUID in canonical form.

    Parameters
    ----------
    value : object
        Value to check. Any type is accepted.

    Returns
    -------
    bool
        ``True`` if ``value`` is a ``str`` holding a UUID in canonical
        form (36 lowercase hexadecimal characters and hyphens, as
        produced by ``str(uuid.uuid4())``), ``False`` otherwise.

    Notes
    -----
    Never raises. Non-canonical spellings accepted by
    :class:`uuid.UUID` (uppercase, braces, ``urn:uuid:`` prefix, no
    hyphens) are rejected: a UUID is used as part of the context of
    encrypted values, so two spellings of the same UUID must never
    coexist.

    Examples
    --------
    >>> _is_uuid("6f1c2e4a-9b3d-4c8e-a1f0-2b7d5e9c0a13")
    True
    >>> _is_uuid("6F1C2E4A-9B3D-4C8E-A1F0-2B7D5E9C0A13")
    False
    """
    if not isinstance(value, str):
        return False
    try:
        return str(_std_uuid.UUID(value)) == value
    except ValueError:
        return False


def _check_uuid(value: object) -> str:
    """
    Validate a UUID and return it.

    Parameters
    ----------
    value : object
        Value to check.

    Returns
    -------
    str
        ``value`` itself.

    Raises
    ------
    UUIDError
        If ``value`` is not a UUID in canonical form (see
        :func:`_is_uuid`).
    """
    if not _is_uuid(value):
        raise UUIDError(f"Invalid UUID: {value!r}")
    return value


def _generate_uuid(uuids: Iterable[str]) -> str:
    """
    Generate a new random UUID that is not already used.

    Parameters
    ----------
    uuids : Iterable of str
        UUIDs currently in use. Consumed once.

    Returns
    -------
    str
        A new version 4 UUID in canonical form, not in ``uuids``.

    Notes
    -----
    The UUID is not reserved: it only becomes "used" once the caller
    stores it. A collision of two random version 4 UUIDs is
    astronomically unlikely; the check against ``uuids`` only exists so
    that uniqueness is guaranteed rather than merely probable.

    Examples
    --------
    >>> new = _generate_uuid(existing_uuids)
    """
    used = set(uuids)
    while True:
        candidate = str(_std_uuid.uuid4())
        if candidate not in used:
            return candidate


def _get_uuid_index(value: str, uuids: Sequence[str]) -> int:
    """
    Return the position of a UUID in a sequence.

    Parameters
    ----------
    value : str
        UUID to look for.

    uuids : Sequence of str
        UUIDs, typically aligned with a list of elements (the UUID at
        index ``i`` identifies the element at index ``i``).

    Returns
    -------
    int
        Index of ``value`` in ``uuids``, to retrieve the matching
        element from the aligned list.

    Raises
    ------
    UUIDError
        If ``value`` is not a UUID in canonical form, or is not in
        ``uuids``.

    Examples
    --------
    >>> ids = [field.id for field in fields]
    >>> field = fields[_get_uuid_index(field_id, ids)]
    """
    _check_uuid(value)
    try:
        return list(uuids).index(value)
    except ValueError:
        raise UUIDError(f"Unknown UUID: {value}") from None


def _check_unique_uuids(uuids: Iterable[str]) -> None:
    """
    Check that every UUID of a collection is valid and unique.

    Parameters
    ----------
    uuids : Iterable of str
        UUIDs to check, typically read from a file.

    Raises
    ------
    UUIDError
        If a UUID is not in canonical form, or appears more than once.

    Notes
    -----
    Meant to be called once when a collection is loaded (items of a
    vault file, custom fields of an item), so that every later lookup
    can rely on uniqueness.
    """
    seen: set[str] = set()
    for value in uuids:
        _check_uuid(value)
        if value in seen:
            raise UUIDError(f"Duplicated UUID: {value}")
        seen.add(value)
