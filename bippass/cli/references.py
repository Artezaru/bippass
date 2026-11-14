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


What the user refers to on the command line: vaults, items, fields, values.

- :func:`resolve` finds a vault or an item from a number, a UUID
  (prefix) or a name;
- :func:`resolve_field` finds a field of an item, predefined (``login``,
  ``password``...) or custom (``c1``, ``c2``... or its name), as a
  :class:`FieldRef` that hides the difference between both;
- :func:`split_number` separates a trailing value number from a field
  name typed without quotes.

Names are compared case- and accent-insensitively, as in the GUI
(``cd securite`` finds ``Sécurité``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, ContextManager, Sequence, TypeVar, cast

from ..core.common import _normalize
from ..core.datakey import DataKey
from ..core.item import Item, FieldKind, _FIELDS
from ..core.types import ItemField, SecretField
from . import formatting as fmt
from .common import CommandError


T = TypeVar("T")

#: Predefined fields: singular name shown by "show" -> stored (plural) name.
PREDEFINED: dict[str, ItemField] = {name[:-1]: name for name in _FIELDS}


def resolve(
    token: str,
    candidates: Sequence[T],
    uuid_of: Callable[[T], str],
    name_of: Callable[[T], str | None],
    what: str,
) -> T:
    """
    Find one element from what the user typed.

    Parameters
    ----------
    token : str
        Typed reference: a number (1-based, in listing order), a UUID or
        a UUID prefix of at least 4 characters, or a name (case- and
        accent-insensitive).

    candidates : Sequence
        Elements to choose from, in listing order.

    uuid_of, name_of : callable
        Accessors to the UUID and the name of an element.

    what : str
        Kind of element, for error messages.

    Raises
    ------
    CommandError
        If no element, or more than one, matches ``token``.
    """
    if token.isdigit():
        index = int(token) - 1
        if 0 <= index < len(candidates):
            return candidates[index]
        raise CommandError(f"No {what} #{token}.")

    lowered, wanted = token.casefold(), _normalize(token)
    by_uuid = [c for c in candidates if len(token) >= 4 and uuid_of(c).startswith(lowered)]
    by_name = [c for c in candidates if _normalize(name_of(c) or "") == wanted]
    matches = by_uuid or by_name
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise CommandError(f"No {what} matches {token!r}.")
    raise CommandError(f"{len(matches)} {what}s match {token!r}: use its number or UUID instead.")


def split_number(tokens: Sequence[str]) -> tuple[str, str | None]:
    """
    Split a trailing value number from the words of a field name.

    Parameters
    ----------
    tokens : Sequence of str
        Words typed after the command (options already removed).

    Returns
    -------
    tuple of (str, str or None)
        The field name (words joined by spaces), and the value number,
        or ``None`` if the last word is not a number.

    Notes
    -----
    A name made of a single number is kept as a name. A quoted name
    ending with a number (``"Code 2"``) arrives as one word, so it is
    not split.

    Examples
    --------
    >>> split_number(["Card", "PIN", "2"])
    ('Card PIN', '2')
    >>> split_number(["Code 2"])
    ('Code 2', None)
    """
    if len(tokens) > 1 and tokens[-1].isdigit():
        return " ".join(tokens[:-1]), tokens[-1]
    return " ".join(tokens), None


def resolve_custom(item: Item, token: str) -> str:
    """
    Find a custom field of an item from what the user typed.

    Parameters
    ----------
    item : Item
        Item holding the field.

    token : str
        A reference shown by ``show`` (``c1``, ``c2``...), or a name
        (case- and accent-insensitive) used by exactly one custom field.

    Returns
    -------
    str
        Id of the custom field.

    Raises
    ------
    CommandError
        If no field matches, or the name is shared by several fields
        (the error lists their references).

    Notes
    -----
    A reference takes precedence over a custom field that would be
    literally named like one.
    """
    custom_ids = item.custom_ids()
    refs = {fmt.custom_ref(i): c for i, c in enumerate(custom_ids)}
    if token.casefold() in refs:
        return refs[token.casefold()]
    wanted = _normalize(token)
    matches = [fmt.custom_ref(i) for i, c in enumerate(custom_ids)
               if _normalize(item.custom_name(c)) == wanted]
    if len(matches) == 1:
        return refs[matches[0]]
    if not matches:
        raise CommandError(f'No field {token!r}: see "show".')
    raise CommandError(f"Several custom fields are named {token!r}: use {' or '.join(matches)}.")


@dataclass(frozen=True)
class FieldRef:
    """
    One field of an item, predefined or custom, behind a single interface.

    Attributes
    ----------
    item : Item
        Item holding the field.

    predefined : str or None
        Stored name of a predefined field (``"logins"``...), or ``None``.

    custom_id : str or None
        Id of a custom field, or ``None``. Exactly one of
        :attr:`predefined` and :attr:`custom_id` is set.
    """

    item: Item
    predefined: ItemField | None = None
    custom_id: str | None = None

    @property
    def _cid(self) -> str:
        """Id of the custom field (only when :attr:`predefined` is ``None``)."""
        assert self.custom_id is not None
        return self.custom_id

    @property
    def label(self) -> str:
        """Name shown to the user: ``"login"``, or the custom field name."""
        if self.predefined is not None:
            return self.predefined[:-1]
        return self.item.custom_name(self._cid)

    @property
    def encrypted(self) -> bool:
        """Whether the values of the field are encrypted."""
        kind = (_FIELDS[self.predefined] if self.predefined is not None
                else self.item.custom_kind(self._cid))
        return kind is FieldKind.ENCRYPTED

    def count(self) -> int:
        """Number of values, without decrypting anything."""
        if self.predefined is not None:
            return self.item.count(self.predefined)
        return self.item.custom_count(self._cid)

    def get(self, data_key: DataKey | None = None) -> list:
        """Return the values: ``str`` if clear, clear ``bytearray`` copies if encrypted."""
        if self.predefined is not None:
            return self.item.get(self.predefined, data_key=data_key)
        return self.item.get_custom(self._cid, data_key=data_key)

    def set(self, values: list, data_key: DataKey | None = None) -> None:
        """Replace the values (clear ``bytearray`` values are erased once encrypted)."""
        if self.predefined is not None:
            self.item.set(self.predefined, values, data_key=data_key)
        else:
            self.item.set_custom(self._cid, values, data_key=data_key)

    def revealed(self, data_key: DataKey) -> ContextManager[list[bytearray]]:
        """Decrypt the values for the duration of a ``with`` block, then erase them."""
        if self.predefined is not None:
            return self.item.revealed(cast(SecretField, self.predefined), data_key)
        return self.item.revealed_custom(self._cid, data_key)

    def index(self, number: str | None) -> int:
        """
        Turn a value number typed by the user into a 0-based index.

        Parameters
        ----------
        number : str or None
            1-based number, as shown by ``show``. May be omitted only if
            the field holds a single value.

        Raises
        ------
        CommandError
            If the field is empty, the number is out of range, or it is
            omitted while the field holds several values.
        """
        count = self.count()
        if count == 0:
            raise CommandError(f"{self.label!r} has no value.")
        if number is None:
            if count == 1:
                return 0
            raise CommandError(f"{self.label!r} has {count} values: give the number "
                               'of the one to use (see "show").')
        if not number.isdigit() or not 1 <= int(number) <= count:
            raise CommandError(f'No {self.label} #{number}: see "show".')
        return int(number) - 1


def resolve_field(item: Item, token: str) -> FieldRef:
    """
    Find a field of an item from what the user typed.

    Parameters
    ----------
    item : Item
        Item holding the field.

    token : str
        A predefined field, singular or plural (``login``, ``logins``,
        ``password``...), or a custom field (see :func:`resolve_custom`).

    Returns
    -------
    FieldRef
        The field.

    Notes
    -----
    Predefined names take precedence: a custom field named
    ``password`` is reached through its reference (``c1``...).
    """
    key = token.casefold()
    if key in PREDEFINED:
        return FieldRef(item, predefined=PREDEFINED[key])
    if key in PREDEFINED.values():
        return FieldRef(item, predefined=cast(ItemField, key))
    return FieldRef(item, custom_id=resolve_custom(item, token))
