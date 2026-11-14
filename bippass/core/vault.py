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

from typing import Callable, Iterator, cast

from .types import VaultData, ClearString
from .exceptions import ItemNotFoundError, ItemAlreadyExistsError
from .datakey import DataKey
from .item import Item
from .common import (
    _now, _check_keys, _check_optional_str, _check_optional_name, _check_date,
    _parse_date, SortKey, _sort_items, _search_by_name,
)
from .uuids import UUIDError, _check_uuid, _check_unique_uuids, _generate_uuid, _get_uuid_index


#: Keys accepted in each section of the serialized data.
_TOP_KEYS = ("metadata", "items", "gui")
_METADATA_KEYS = ("uuid", "name", "creation_date", "modification_date")
_GUI_KEYS = ("icon", "color")


class Vault:
    """
    Represent a password vault: a collection of items.

    A vault groups :class:`Item` instances under a common name, icon
    and color. It is responsible for storing, retrieving, adding,
    removing its items, and exposes the sorting and the searching of
    them.

    Parameters
    ----------
    vault_uuid : str
        Unique identifier of the vault, in canonical form (see
        :func:`_is_uuid`).

    name : str or None, optional
        Name of the vault, stripped; blank means none (default: ``None``).

    Raises
    ------
    UUIDError
        If ``vault_uuid`` is not a UUID in canonical form.

    TypeError
        If ``name`` is neither a ``str`` nor ``None``.

    Notes
    -----
    **Structure.** A vault is made of three parts, mirrored by its
    serialized form (see :meth:`to_dict`)::

        {
            "metadata": {"uuid", "name", "creation_date", "modification_date"},
            "items":    [{item}, {item}, ...],
            "gui":      {"icon", "color"},
        }

    The vault is identified by its UUID, not by its name: several
    vaults may share the same name. The same reading rules as for
    :class:`Item` apply (see :meth:`from_dict`): unknown keys are
    refused, missing keys take their default value.

    **Items.** Items are kept in a list, in the order they were added.
    That order carries no meaning: interfaces show items sorted (see
    :meth:`sorted_items`). Each item is identified by its own UUID, which it
    stores itself (see :attr:`Item.uuid`): the vault keeps no separate
    index, so the two can never drift apart. UUIDs are unique within a
    vault; uniqueness across every vault is the responsibility of the
    :class:`PasswordManager`.

    Items are held by reference: an item obtained with
    :meth:`get_item`, :meth:`get_items` or iteration *is* the item
    stored in the vault, and modifying it modifies the vault's content.
    Never change the UUID of an item while it is in a vault: remove it,
    call :meth:`Item.change_uuid`, then add it back.

    **Dates.** :attr:`creation_date` is set once, when the vault is
    created. :attr:`modification_date` only records changes to the
    vault itself: renaming it, changing its icon or color, adding or
    removing an item. Any change made *inside* an item does not update
    it: items have their own dates. The most recent
    activity in the vault, items included, is available as
    :attr:`last_activity_date`, computed on demand.

    **Queries.** :meth:`sorted_items` and :meth:`search` return new
    lists of the vault's items. :meth:`search` only looks at item names,
    never at their content. No :class:`DataKey` is needed.

    The textual representation of a vault (:func:`repr`, :func:`str`)
    only shows its UUID and item count, so it stays safe to print or
    log.

    This class performs no locking of its own.

    See Also
    --------
    Item
        Represents an individual password entry.

    PasswordManager
        Manages multiple vaults and the global encryption.
    """

    __slots__ = (
        "_uuid", "_name", "_creation_date", "_modification_date",
        "_items", "_icon", "_color",
    )

    def __init__(self, vault_uuid: str, name: str | None = None) -> None:
        """
        Create an empty vault.

        Parameters
        ----------
        vault_uuid : str
            Unique identifier of the new vault.

        name : str or None, optional
            Name of the new vault.

        Raises
        ------
        UUIDError
            If ``vault_uuid`` is not a UUID in canonical form.

        TypeError
            If ``name`` is neither a ``str`` nor ``None``.

        Notes
        -----
        The vault holds no item and no icon or color, and both dates
        are set to now.
        """
        self._uuid: str = _check_uuid(vault_uuid)
        self._name: ClearString | None = _check_optional_name("name", name)
        now = _now()
        self._creation_date: str = now
        self._modification_date: str = now
        self._items: list[Item] = []
        self._icon: ClearString | None = None
        self._color: ClearString | None = None

    # -----------------------
    # Metadata
    # -----------------------

    @property
    def uuid(self) -> str:
        """
        Return the unique identifier of the vault.

        Returns
        -------
        str
            Vault UUID.
        """
        return self._uuid

    @property
    def creation_date(self) -> str:
        """
        Return the creation date of the vault.

        Returns
        -------
        str
            ISO 8601 date and time, with timezone.
        """
        return self._creation_date

    @property
    def modification_date(self) -> str:
        """
        Return the date of the last change to the vault itself.

        Returns
        -------
        str
            ISO 8601 date and time, with timezone. See the class-level
            Notes for which operations update it.
        """
        return self._modification_date

    @property
    def last_activity_date(self) -> str:
        """
        Return the date of the most recent activity in the vault.

        Returns
        -------
        str
            The most recent of :attr:`modification_date` and the
            :attr:`Item.modification_date` of every item.

        Notes
        -----
        Computed on demand, never stored. Dates are compared
        chronologically, not as strings.
        """
        dates = [self._modification_date, *(item.modification_date for item in self._items)]
        return max(dates, key=_parse_date)

    def _touch(self) -> None:
        """Record a change to the vault itself (see the class-level Notes)."""
        self._modification_date = _now()

    def get_name(self) -> ClearString | None:
        """
        Return the vault name.

        Returns
        -------
        ClearString or None
            Vault name, or ``None`` if unset.
        """
        return self._name

    def set_name(self, value: ClearString | None) -> None:
        """
        Rename the vault.

        Parameters
        ----------
        value : ClearString or None
            New name, stripped. ``None``, or a blank name, removes it.
            Not required to be unique.

        Raises
        ------
        TypeError
            If ``value`` is neither a ``str`` nor ``None``.

        Notes
        -----
        Updates :attr:`modification_date`.
        """
        self._name = _check_optional_name("name", value)
        self._touch()

    # -----------------------
    # GUI
    # -----------------------

    def get_icon(self) -> ClearString | None:
        """
        Return the vault icon, used by the graphical interface only.

        Returns
        -------
        ClearString or None
            The icon image, Base64-encoded, or ``None`` if unset.
        """
        return self._icon

    def set_icon(self, value: ClearString | None) -> None:
        """
        Set the vault icon, used by the graphical interface only.

        Parameters
        ----------
        value : ClearString or None
            The icon image, Base64-encoded. ``None`` removes it. Not
            interpreted nor checked by this class.

        Raises
        ------
        TypeError
            If ``value`` is neither a ``str`` nor ``None``.

        Notes
        -----
        Updates :attr:`modification_date`.
        """
        self._icon = _check_optional_str("icon", value)
        self._touch()

    def get_color(self) -> ClearString | None:
        """
        Return the vault color, used by the graphical interface only.

        Returns
        -------
        ClearString or None
            Color, or ``None`` if unset.
        """
        return self._color

    def set_color(self, value: ClearString | None) -> None:
        """
        Set the vault color, used by the graphical interface only.

        Parameters
        ----------
        value : ClearString or None
            New color. ``None`` removes it. Not interpreted nor checked
            by this class.

        Raises
        ------
        TypeError
            If ``value`` is neither a ``str`` nor ``None``.

        Notes
        -----
        Updates :attr:`modification_date`.
        """
        self._color = _check_optional_str("color", value)
        self._touch()

    # -----------------------
    # Item access
    # -----------------------

    def item_uuids(self) -> tuple[str, ...]:
        """
        Return the UUIDs of the items, in the order they were added.

        Returns
        -------
        tuple of str
            UUID of every item of the vault.
        """
        return tuple(item.uuid for item in self._items)

    def index_of(self, item_uuid: str) -> int:
        """
        Return the position of an item in the stored list (internal use).

        Parameters
        ----------
        item_uuid : str
            UUID of the item.

        Returns
        -------
        int
            Index of the item in the list of :meth:`get_items`.

        Raises
        ------
        ItemNotFoundError
            If ``item_uuid`` is not a valid UUID, or no item of the
            vault has it.
        """
        try:
            return _get_uuid_index(item_uuid, self.item_uuids())
        except UUIDError as exc:
            raise ItemNotFoundError(f"Unknown item UUID: {item_uuid}") from exc

    def get_item(self, item_uuid: str) -> Item:
        """
        Return an item by UUID.

        Parameters
        ----------
        item_uuid : str
            UUID of the item to retrieve.

        Returns
        -------
        Item
            The item itself (not a copy): modifying it modifies the
            vault's content.

        Raises
        ------
        ItemNotFoundError
            If ``item_uuid`` is not a valid UUID, or no item of the
            vault has it.
        """
        return self._items[self.index_of(item_uuid)]

    def get_items(self) -> list[Item]:
        """
        Return every item, in the order they were added.

        Returns
        -------
        list of Item
            A new list, holding the vault's own :class:`Item` instances.
        """
        return list(self._items)

    # -----------------------
    # Item management
    # -----------------------

    def add_item(self, item: Item) -> None:
        """
        Add an existing item to the vault.

        Parameters
        ----------
        item : Item
            Item to add, stored by reference (not copied).


        Raises
        ------
        TypeError
            If ``item`` is not an :class:`Item`.

        ItemAlreadyExistsError
            If an item with the same UUID is already in the vault.


        Notes
        -----
        Updates :attr:`modification_date`. Only checks UUID uniqueness
        within this vault (see the class-level Notes).
        """
        if not isinstance(item, Item):
            raise TypeError(f"item must be an Item, not {type(item)}")
        if item.uuid in self.item_uuids():
            raise ItemAlreadyExistsError(f"Item UUID already exists: {item.uuid}")

        self._items.append(item)
        self._touch()

    def add_empty_item(self, item_uuid: str | None = None) -> Item:
        """
        Create an empty item and add it to the vault.

        Parameters
        ----------
        item_uuid : str or None, optional
            UUID of the new item. ``None`` (the default) generates one
            that is unique *within this vault*: the
            :class:`PasswordManager` should pass a globally unique one.


        Returns
        -------
        Item
            The new item.


        Raises
        ------
        UUIDError
            If ``item_uuid`` is not a UUID in canonical form.

        ItemAlreadyExistsError
            If an item with ``item_uuid`` is already in the vault.


        Notes
        -----
        Updates :attr:`modification_date`.
        """
        if item_uuid is None:
            item_uuid = _generate_uuid(self.item_uuids())
        item = Item(item_uuid)
        self.add_item(item)
        return item

    def remove_item(self, item_uuid: str) -> Item:
        """
        Remove an item from the vault.

        Parameters
        ----------
        item_uuid : str
            UUID of the item to remove.

        Returns
        -------
        Item
            The removed item, untouched: it can be added to another
            vault (this is how an item is moved between vaults).

        Raises
        ------
        ItemNotFoundError
            If no item of the vault has this UUID.

        Notes
        -----
        Updates :attr:`modification_date`.
        """
        item = self._items.pop(self.index_of(item_uuid))
        self._touch()
        return item

    # -----------------------
    # Queries
    # -----------------------

    def sorted_items(self, key: SortKey = "name", *, reverse: bool = False) -> list[Item]:
        """
        Return the items sorted by name or date.

        Parameters
        ----------
        key : {"name", "creation_date", "modification_date"}, optional
            Sort key (default: ``"name"``).

        reverse : bool, optional
            Descending order (default: ``False``).

        Returns
        -------
        list of Item
            A new list of the vault's items.

        Raises
        ------
        ValueError
            If ``key`` is not a known sort key.

        Notes
        -----
        Names are compared case- and accent-insensitively, and numbers
        by value (``"item2"`` before ``"item10"``); items without a name
        always come last. Dates are compared chronologically.
        """
        return _sort_items(self._items, key, reverse=reverse)

    def search(self, query: str, key: SortKey = "name", *, reverse: bool = False) -> list[Item]:
        """
        Return the items whose name matches a query, sorted.

        Parameters
        ----------
        query : str
            Words to look for in item names, case- and
            accent-insensitively, in any order.

        key : {"name", "creation_date", "modification_date"}, optional
            Sort key of the result, as for :meth:`sorted_items`
            (default: ``"name"``).

        reverse : bool, optional
            Descending order (default: ``False``).

        Returns
        -------
        list of Item
            The matching items, sorted. Every item if ``query`` is
            blank.

        Raises
        ------
        TypeError
            If ``query`` is not a ``str``.

        ValueError
            If ``key`` is not a known sort key.

        Notes
        -----
        Only item names are searched: never the content of an item
        (logins, websites, custom fields...), clear or encrypted.
        """
        return _sort_items(_search_by_name(self._items, query), key, reverse=reverse)

    # -----------------------
    # Re-encryption
    # -----------------------

    def _prepare_change_data_key(
        self,
        old_key: DataKey,
        new_key: DataKey,
    ) -> Callable[[], None]:
        """
        Re-encrypt every item with a new key, without committing.

        Parameters
        ----------
        old_key : DataKey
            Key every encrypted value is currently sealed with.

        new_key : DataKey
            Key to re-seal them with.

        Returns
        -------
        callable
            A function taking no argument that commits every item at
            once. It cannot fail.

        Raises
        ------
        ValueError
            If either key has been cleared.

        TamperedDataError
            If a value of any item fails to decrypt with ``old_key``.

        Notes
        -----
        Used by :meth:`PasswordManager.change_secondary_password`. The
        :class:`Item` instances are kept: references held elsewhere stay
        valid. No date is updated. Two-phase, like
        :meth:`Item._prepare_change_data_key`: every
        item is prepared first, and nothing is modified until the
        returned function is called. If any item fails, the exception
        propagates and no item of the vault has changed. This lets the
        :class:`PasswordManager` prepare every vault before committing
        any of them.
        """
        commits = [item._prepare_change_data_key(old_key, new_key) for item in self._items]

        def commit() -> None:
            for item_commit in commits:
                item_commit()

        return commit

    # -----------------------
    # Container protocol
    # -----------------------

    def __len__(self) -> int:
        """
        Return the number of items in the vault.

        Returns
        -------
        int
            Number of items.
        """
        return len(self._items)

    def __contains__(self, item_uuid: object) -> bool:
        """
        Check whether an item UUID is in the vault.

        Parameters
        ----------
        item_uuid : object
            UUID to check.

        Returns
        -------
        bool
            ``True`` if an item of the vault has this UUID.
        """
        return item_uuid in self.item_uuids()

    def __iter__(self) -> Iterator[Item]:
        """
        Iterate over the items, in the order of :meth:`get_items`.

        Yields
        ------
        Item
            Each item of the vault.

        Notes
        -----
        Iterates over a snapshot: adding or removing items during the
        iteration is safe, and does not affect it.
        """
        return iter(list(self._items))

    # -----------------------
    # Serialization
    # -----------------------

    def to_dict(self) -> VaultData:
        """
        Serialize the vault.

        Returns
        -------
        VaultData
            A new dictionary, suitable for JSON serialization (see the
            class-level Notes for its structure). Items are serialized
            with :meth:`Item.to_dict`: nothing is decrypted.
        """
        return {
            "metadata": {
                "uuid": self._uuid,
                "name": self._name,
                "creation_date": self._creation_date,
                "modification_date": self._modification_date,
            },
            "items": [item.to_dict() for item in self._items],
            "gui": {
                "icon": self._icon,
                "color": self._color,
            },
        }

    @classmethod
    def from_dict(cls, data: VaultData) -> Vault:
        """
        Create a vault from its serialized representation.

        Parameters
        ----------
        data : VaultData
            Serialized vault, as returned by :meth:`to_dict`. Not
            modified, and not kept by reference.


        Returns
        -------
        Vault
            The deserialized vault.


        Raises
        ------
        TypeError
            If a section or a value does not have the expected type.

        ValueError
            If a section contains an unknown key, ``metadata.uuid`` is
            missing, or a date is not an ISO 8601 date (see also
            :meth:`Item.from_dict`).

        UUIDError
            If the vault UUID or an item UUID is not a UUID in
            canonical form, or two items share a UUID.


        Notes
        -----
        Same reading rules as :meth:`Item.from_dict`: unknown keys are
        refused, missing keys take their default value. Items are read
        with :meth:`Item.from_dict`.

        Does not update :attr:`modification_date`.
        """
        data = cast(VaultData, _check_keys("vault", data, _TOP_KEYS))

        metadata = _check_keys("vault metadata", data.get("metadata", {}), _METADATA_KEYS)
        if "uuid" not in metadata:
            raise ValueError("vault metadata must contain a 'uuid'.")
        vault = cls(metadata["uuid"], metadata.get("name"))
        vault._creation_date = _check_date(
            "creation_date", metadata.get("creation_date"), vault._creation_date)
        vault._modification_date = _check_date(
            "modification_date", metadata.get("modification_date"), vault._modification_date)

        items = data.get("items") or []
        if not isinstance(items, list):
            raise TypeError("vault items must be a list.")
        parsed = [Item.from_dict(entry) for entry in items]
        _check_unique_uuids(item.uuid for item in parsed)
        vault._items = parsed

        gui = _check_keys("vault gui", data.get("gui", {}), _GUI_KEYS)
        vault._icon = _check_optional_str("icon", gui.get("icon"))
        vault._color = _check_optional_str("color", gui.get("color"))

        return vault

    def __repr__(self) -> str:
        """
        Return a debug-friendly representation of the vault.

        Returns
        -------
        str
            A representation built only from the vault's UUID and item
            count, never from its name or any item content, so it stays
            safe to print or log.
        """
        return f"{type(self).__name__}(uuid={self._uuid!r}, items={len(self._items)})"
