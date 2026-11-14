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

Helpers shared by every model class (:class:`Item`, :class:`Vault`,
:class:`PasswordManager`) and by :class:`EncryptedValue`.

- **Dates**: :func:`_now` produces every date stored by bippass,
  :func:`_check_date` validates one read from a file, and
  :func:`_parse_date` reads them back for chronological comparison.
- **Base64**: :func:`_b64encode` and :func:`_b64decode`, used at the
  serialization boundary only.
- **Validation**: the ``_check_*`` functions validate user input and
  serialized data. Each one takes a ``where`` label, used only to build
  a readable error message, and returns the validated value so that it
  can be checked and stored in one expression.
- **Sorting and searching**: :func:`_normalize`, :func:`_sort_items`
  and :func:`_search_by_name`, used by :class:`Vault` and
  :class:`PasswordManager` to sort items and vaults, and find items by
  name.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import re
import unicodedata
from typing import Any, Iterable, Literal, Mapping, TypeAlias

from .exceptions import CorruptedBase64Error


# ---------------------------------------------------------------------------
# Dates
# ---------------------------------------------------------------------------


def _now() -> str:
    """
    Return the current local date and time.

    Returns
    -------
    str
        ISO 8601 date and time, timezone-aware (e.g.
        ``"2026-11-12T10:03:00.123456+01:00"``). Every date stored by
        bippass is produced by this function.
    """
    return datetime.datetime.now().astimezone().isoformat()


def _parse_date(value: str) -> datetime.datetime:
    """
    Parse an ISO 8601 date for chronological comparison.

    Notes
    -----
    Dates written without a timezone (should not happen, see
    :func:`_now`) are assumed to be in local time, so
    that they can still be compared with timezone-aware ones.
    """
    date = datetime.datetime.fromisoformat(value)
    if date.tzinfo is None:
        date = date.astimezone()
    return date


def _check_date(where: str, value: Any, default: str) -> str:
    """
    Check a date read from serialized data.

    Parameters
    ----------
    where : str
        Name of the value, for error messages.

    value : Any
        Value read, or ``None`` if the key was missing.

    default : str
        Date to use when ``value`` is ``None`` (typically :func:`_now`).

    Returns
    -------
    str
        ``value`` itself, or ``default``.

    Raises
    ------
    TypeError
        If ``value`` is neither a ``str`` nor ``None``.

    ValueError
        If ``value`` is not an ISO 8601 date: caught when the file is
        read, rather than at the first sort by date.
    """
    if value is None:
        return default
    if not isinstance(value, str):
        raise TypeError(f"{where} must be a string, not {type(value)}")
    try:
        _parse_date(value)
    except ValueError as exc:
        raise ValueError(f"{where} is not an ISO 8601 date: {value!r}") from exc
    return value


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------


def _b64encode(data: bytes | bytearray) -> str:
    """
    Encode binary data as a Base64 ``str``.

    Parameters
    ----------
    data : bytes or bytearray
        Data to encode.

    Returns
    -------
    str
        The ASCII Base64 text.
    """
    return base64.b64encode(data).decode("ascii")


def _b64decode(where: str, value: Any) -> bytearray:
    """
    Decode a Base64 ``str`` into a ``bytearray``.

    Parameters
    ----------
    where : str
        Name of the value, for error messages.

    value : Any
        Value to decode.

    Returns
    -------
    bytearray
        The decoded data.

    Raises
    ------
    TypeError
        If ``value`` is not a ``str``.

    CorruptedBase64Error
        If ``value`` is not valid Base64 (invalid padding or characters
        outside the Base64 alphabet).
    """
    if not isinstance(value, str):
        raise TypeError(f"{where} must be a string, not {type(value)}")
    try:
        return bytearray(base64.b64decode(value, validate=True))
    except binascii.Error as exc:
        raise CorruptedBase64Error(f"{where} is not valid Base64.") from exc



# ---------------------------------------------------------------------------
# Validation of serialized data and user input
# ---------------------------------------------------------------------------


def _check_keys(where: str, data: Any, allowed: tuple[str, ...]) -> Mapping[str, Any]:
    """
    Check that a serialized section is a mapping holding only known keys.

    Parameters
    ----------
    where : str
        Name of the section, for error messages (e.g. ``"item gui"``).

    data : Any
        Section to check.

    allowed : tuple of str
        Keys the section may contain. Every one of them is optional:
        missing keys are the caller's business (see Notes).


    Returns
    -------
    Mapping of str to Any
        ``data`` itself.


    Raises
    ------
    TypeError
        If ``data`` is not a mapping.

    ValueError
        If ``data`` holds a key not in ``allowed``.


    Notes
    -----
    Implements the reading rule shared by every serialized format of
    bippass: an *unknown* key is an error (the data was written by a
    newer version, and reading it anyway would silently drop that key
    when saving back), while a *missing* key is read by the caller as
    its default value (typically with ``data.get(key, default)``), so
    that data written by an older version can still be read.
    """
    if not isinstance(data, Mapping):
        raise TypeError(f"{where} must be a mapping, not {type(data)}")
    unknown = [key for key in data if key not in allowed]
    if unknown:
        raise ValueError(
            f"Unknown key(s) {unknown} in {where}: the data was probably "
            f"written by a newer version of bippass."
        )
    return data


def _check_optional_str(where: str, value: Any) -> str | None:
    """
    Check that a value is a ``str`` or ``None``.

    Parameters
    ----------
    where : str
        Name of the value, for error messages.

    value : Any
        Value to check.

    Returns
    -------
    str or None
        ``value`` itself.

    Raises
    ------
    TypeError
        If ``value`` is neither a ``str`` nor ``None``.
    """
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{where} must be a string or None, not {type(value)}")
    return value


def _check_name(where: str, value: Any) -> str:
    """
    Check that a value is a non-blank ``str``, and strip it.

    Parameters
    ----------
    where : str
        Name of the value, for error messages.

    value : Any
        Value to check.

    Returns
    -------
    str
        ``value`` without leading and trailing whitespace.

    Raises
    ------
    TypeError
        If ``value`` is not a ``str``.

    ValueError
        If ``value`` is empty or only made of whitespace.

    Notes
    -----
    Stripping keeps names that look identical from differing by
    invisible spaces (``"PIN"`` and ``"PIN "``), and keeps every name
    typeable as is on a command line.
    """
    if not isinstance(value, str):
        raise TypeError(f"{where} must be a string, not {type(value)}")
    value = value.strip()
    if not value:
        raise ValueError(f"{where} must not be empty or blank.")
    return value


def _check_optional_name(where: str, value: Any) -> str | None:
    """
    Check an optional name (of an item, a vault, a profile...), and strip it.

    Parameters
    ----------
    where : str
        Name of the value, for error messages.

    value : Any
        Value to check.

    Returns
    -------
    str or None
        ``value`` without leading and trailing whitespace, or ``None``
        if ``value`` is ``None``, empty or only made of whitespace.

    Raises
    ------
    TypeError
        If ``value`` is neither a ``str`` nor ``None``.

    Notes
    -----
    Same stripping as :func:`_check_name`, but a blank name means "no
    name" instead of being refused: names of items, vaults, the
    username and the label are optional.
    """
    value = _check_optional_str(where, value)
    if value is None:
        return None
    return value.strip() or None


def _check_index(where: str, index: Any) -> int:
    """
    Check a position in an ordered collection.

    Parameters
    ----------
    where : str
        Name of the value, for error messages.

    index : Any
        Value to check, used as for :meth:`list.insert`.

    Returns
    -------
    int
        ``index`` itself.

    Raises
    ------
    TypeError
        If ``index`` is not an ``int`` (a ``bool`` is refused).
    """
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError(f"{where} must be an int, not {type(index)}")
    return index


def _check_lock_timer(value: Any) -> int:
    """
    Check an auto-lock delay, in seconds.

    Parameters
    ----------
    value : Any
        Value to check.

    Returns
    -------
    int
        ``value`` itself.

    Raises
    ------
    TypeError
        If ``value`` is not an ``int`` (a ``bool`` is refused).

    ValueError
        If ``value`` is not strictly positive.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"lock_timer_s must be an int, not {type(value)}")
    if value <= 0:
        raise ValueError(f"lock_timer_s must be strictly positive, not {value}")
    return value


def _check_clear_list(where: str, values: Any) -> list[str]:
    """
    Check that a value is a list (or tuple) of ``str``.

    Parameters
    ----------
    where : str
        Name of the value, for error messages.

    values : Any
        Value to check.

    Returns
    -------
    list of str
        A new list holding the same strings: the caller can store it
        without sharing it with whoever passed ``values``.

    Raises
    ------
    TypeError
        If ``values`` is not a list or tuple, or holds a non-``str``.
    """
    if not isinstance(values, (list, tuple)) or not all(isinstance(v, str) for v in values):
        raise TypeError(f"{where} must be a list of strings.")
    return list(values)


def _check_secret_list(where: str, values: Any) -> list[bytearray]:
    """
    Check that a value is a list (or tuple) of ``bytearray``.

    Parameters
    ----------
    where : str
        Name of the value, for error messages.

    values : Any
        Value to check, typically clear secrets about to be encrypted.

    Returns
    -------
    list of bytearray
        A new list holding the very same ``bytearray`` objects (not
        copies), so that they can still be erased after encryption.

    Raises
    ------
    TypeError
        If ``values`` is not a list or tuple, or holds a
        non-``bytearray``.
    """
    if not isinstance(values, (list, tuple)) or not all(isinstance(v, bytearray) for v in values):
        raise TypeError(f"{where} must be a list of bytearray.")
    return list(values)


# ---------------------------------------------------------------------------
# Sorting and finding items by name
# ---------------------------------------------------------------------------

SortKey: TypeAlias = Literal["name", "creation_date", "modification_date"]

_SORT_KEYS: tuple[str, ...] = ("name", "creation_date", "modification_date")


def _check_sort_key(key: Any) -> SortKey:
    """
    Check a sort key.

    Parameters
    ----------
    key : Any
        Value to check.

    Returns
    -------
    SortKey
        ``key`` itself.

    Raises
    ------
    ValueError
        If ``key`` is not one of ``"name"``, ``"creation_date"``,
        ``"modification_date"``.
    """
    if key not in _SORT_KEYS:
        raise ValueError(f"{key!r} is not a known sort key, expected one of {_SORT_KEYS}")
    return key


def _normalize(text: str) -> str:
    """
    Normalize a text for case- and accent-insensitive comparison.

    Parameters
    ----------
    text : str
        Text to normalize.

    Returns
    -------
    str
        ``text`` case-folded, with every accent and other combining mark
        removed.

    Examples
    --------
    >>> _normalize("Été")
    'ete'
    """
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def _natural_key(text: str) -> list[tuple[int, int | str]]:
    """
    Build a "natural" sort key: numbers compared by value, text normalized.

    Parameters
    ----------
    text : str
        Text to build a key for.

    Returns
    -------
    list of tuple
        One ``(0, number)`` or ``(1, text)`` pair per chunk of
        ``text``, normalized with :func:`_normalize`, so that
        ``"item2"`` sorts before ``"item10"``, and ``"Été"`` next to
        ``"ete"``. The tags keep numbers and texts comparable.

    Examples
    --------
    >>> sorted(["item10", "Item2"], key=_natural_key)
    ['Item2', 'item10']
    """
    return [
        (0, int(chunk)) if chunk.isdigit() else (1, chunk)
        for chunk in re.split(r"(\d+)", _normalize(text))
        if chunk
    ]


def _sort_items(items: Iterable[Any], key: SortKey = "name", *, reverse: bool = False) -> list[Any]:
    """
    Return items sorted by name or date.

    Parameters
    ----------
    items : Iterable of Item or Vault
        Items to sort (anything with ``get_name()`` and the date
        attributes: items, or vaults).

    key : {"name", "creation_date", "modification_date"}, optional
        Sort key (default: ``"name"``).

    reverse : bool, optional
        Descending order: Z to A, or most recent first (default:
        ``False``).

    Returns
    -------
    list of Item
        A new list holding the same instances.

    Raises
    ------
    ValueError
        If ``key`` is not a known sort key.

    Notes
    -----
    Names are compared case- and accent-insensitively, and numbers by
    value (``"item2"`` before ``"item10"``); items without a name
    always come last, whatever ``reverse``. Dates are compared
    chronologically (see :func:`_parse_date`). The sort is stable.
    """
    _check_sort_key(key)
    items = list(items)
    if key == "name":
        named = [it for it in items if it.get_name() is not None]
        unnamed = [it for it in items if it.get_name() is None]
        named.sort(key=lambda it: _natural_key(it.get_name()), reverse=reverse)
        return named + unnamed
    return sorted(items, key=lambda it: _parse_date(getattr(it, key)), reverse=reverse)


def _search_by_name(items: Iterable[Any], query: str) -> list[Any]:
    """
    Return the items whose name contains every word of a query.

    Parameters
    ----------
    items : Iterable of Item
        Items to search (anything with ``get_name()``).

    query : str
        Words to look for in the name, case- and accent-insensitively,
        in any order (``"mail example"`` finds ``"Example Mail"``).

    Returns
    -------
    list of Item
        The matching items, in their original order. Every item if
        ``query`` is blank; never an item without a name otherwise.

    Raises
    ------
    TypeError
        If ``query`` is not a ``str``.

    Notes
    -----
    Only the name is searched: no other field, clear or encrypted.
    """
    if not isinstance(query, str):
        raise TypeError(f"query must be a string, not {type(query)}")
    words = [_normalize(w) for w in query.split()]
    items = list(items)
    if not words:
        return items
    matches = []
    for item in items:
        name = item.get_name()
        if name is not None and all(w in _normalize(name) for w in words):
            matches.append(item)
    return matches
