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
from typing import Iterator
import copy

from .types import VaultData, ClearString
from .exceptions import ItemNotFoundError, ItemAlreadyExistsError

from .item import Item
from .credentials import Credentials


class Vault:
    """Represent a password vault containing password items.

    A vault groups multiple :class:`Item` instances under a common name,
    icon, and icon color. It is responsible for creating, storing,
    retrieving, and removing its items.

    Parameters
    ----------
    name : str
        Name of the vault.
    data : VaultData
        Serialized vault data used to initialize the vault.

    Notes
    -----
    Items are deserialized from ``data["items"]`` and represented
    internally as :class:`Item` instances.

    The vault keeps its :class:`Item` instances in memory. Changes made
    through an item obtained with :meth:`get_item` therefore directly
    affect the corresponding item contained by the vault.

    See Also
    --------
    Item
        Represents an individual password entry.

    PasswordManager
        Manages multiple vaults and the global vault encryption.
    """

    def __init__(self, name: str, data: VaultData) -> None:
        """Initialize a vault from serialized data.

        Parameters
        ----------
        name : str
            Name of the vault.
        data : VaultData
            Serialized vault data.

        Notes
        -----
        The ``items`` dictionary from ``data`` is converted into
        :class:`Item` instances. The serialized dictionaries themselves
        are kept by the corresponding :class:`Item` objects.
        """
        self._name: str = name
        self._icon: ClearString | None = data["icon"]
        self._icon_color: ClearString | None = data["icon_color"]
        self._items: dict[str, Item] = {
            item_uuid: Item(item_uuid, item_data)
            for item_uuid, item_data in data["items"].items()
        }

    @classmethod
    def create_empty(cls, name: str) -> Vault:
        """Create an empty vault.

        The returned vault contains no items and has no icon or icon
        color configured.

        Parameters
        ----------
        name : str
            Name of the new vault.

        Returns
        -------
        Vault
            Newly created empty vault.
        """
        return cls(
            name,
            {
                "icon": None,
                "icon_color": None,
                "items": {},
            },
        )

    # -----------------------
    # Item management
    # -----------------------

    def add_empty_item(self, item_uuid: str) -> Item:
        """Create and add an empty item to the vault.

        Parameters
        ----------
        item_uuid : str
            Unique identifier of the new item.

        Returns
        -------
        Item
            Newly created empty item.

        Raises
        ------
        ItemAlreadyExistsError
            If an item with the specified UUID already exists.

        Notes
        -----
        The UUID is checked only against the items currently contained
        in this vault. Global UUID uniqueness, if required, must be
        enforced by the :class:`PasswordManager`.
        """
        item = Item.create_empty(item_uuid)
        self.add_item(item)
        return item

    def get_item(self, item_uuid: str) -> Item:
        """Return an item by UUID.

        Parameters
        ----------
        item_uuid : str
            UUID of the item to retrieve.

        Returns
        -------
        Item
            Item associated with the specified UUID.

        Raises
        ------
        ItemNotFoundError
            If no item with the specified UUID exists in the vault.

        Notes
        -----
        The returned object is the actual :class:`Item` instance managed
        by the vault. Modifying it therefore modifies the item stored in
        this vault.
        """
        try:
            return self._items[item_uuid]
        except KeyError as exc:
            raise ItemNotFoundError(
                f"Unknown item UUID: {item_uuid}"
            ) from exc

    def get_items(self) -> list[Item]:
        """Return all items contained in the vault.

        Returns
        -------
        list of Item
            List containing all items currently stored in the vault.

        Notes
        -----
        The returned list is a new list, but its elements are the actual
        :class:`Item` instances managed by the vault.
        """
        return list(self._items.values())

    def add_item(self, item: Item) -> None:
        """Add an existing item to the vault.

        Parameters
        ----------
        item : Item
            Item to add.

        Raises
        ------
        ItemAlreadyExistsError
            If another item with the same UUID already exists.

        Notes
        -----
        The :class:`Item` instance itself is stored by reference. No copy
        of the item is created.

        UUID uniqueness across multiple vaults is not checked here.
        If UUIDs must be globally unique, that constraint should be
        enforced by the :class:`PasswordManager`.
        """
        if item.uuid in self._items:
            raise ItemAlreadyExistsError(
                f"Item UUID already exists: {item.uuid}"
            )
        self._items[item.uuid] = item

    def remove_item(self, item_uuid: str) -> None:
        """Remove an item from the vault.

        Parameters
        ----------
        item_uuid : str
            UUID of the item to remove.

        Raises
        ------
        ItemNotFoundError
            If no item with the specified UUID exists.

        Notes
        -----
        Removing the item from the vault does not modify the
        :class:`Item` instance itself. Any external reference to the
        removed item remains valid.
        """
        try:
            del self._items[item_uuid]
        except KeyError as exc:
            raise ItemNotFoundError(
                f"Unknown item UUID: {item_uuid}"
            ) from exc

    # -----------------------
    # Credentials
    # -----------------------

    def change_credentials(
        self,
        old_credentials: Credentials,
        new_credentials: Credentials,
    ) -> None:
        """
        Re-encrypt every item in the vault with new secondary credentials.
 
        Parameters
        ----------
        old_credentials : Credentials
            Holds the secondary password and iteration count currently
            used to encrypt this vault's items.
 
        new_credentials : Credentials
            Holds the secondary password and iteration count to
            re-encrypt this vault's items with.
 
        Raises
        ------
        SecondaryPasswordError
            If decryption fails for any item because of an
            authentication error (for example a mismatched
            ``old_credentials``).
 
        Notes
        -----
        Atomic: every item is re-encrypted on a throwaway deep copy
        first (:meth:`Item.change_credentials` is itself atomic per
        item, decrypting all of an item's fields before writing any
        of them back, see its docstring). Only once *every* item's
        copy has been successfully re-encrypted does this method
        replace :attr:`_items` with the copies, in one single
        assignment. If any item fails partway through, wrong
        ``old_credentials``, corrupted data, the exception is raised
        before that final swap, so :attr:`_items` (and therefore every
        real :class:`Item` instance already handed out by
        :meth:`get_item`/:meth:`get_items`/iteration) is left exactly
        as it was: no item ends up re-encrypted while others are not.
 
        The trade-off is memory: for the duration of this call, the
        vault holds two full sets of items, the untouched originals
        and their in-progress copies, rather than mutating items in
        place one at a time.
 
        This also means that, unlike before, a successful call
        replaces every :class:`Item` *instance* in the vault, not
        just their data: any reference obtained via
        :meth:`get_item`/:meth:`get_items`/iteration *before* this
        call keeps pointing at the old, now-detached object, still
        under ``old_credentials`` and no longer part of the vault.
        Callers that hold on to an item across a call to this method
        (an open item editor, say) need to re-fetch it from the vault
        afterwards.
        """
        draft_items: dict[str, Item] = {
            item_uuid: copy.deepcopy(item)
            for item_uuid, item in self._items.items()
        }
 
        for item in draft_items.values():
            item.change_credentials(old_credentials, new_credentials)
 
        # Every copy succeeded: commit them all at once. A plain dict
        # assignment is a single, indivisible step, so no external
        # observer can ever see a mix of old and new items here.
        self._items = draft_items

    # -----------------------
    # Container protocol
    # -----------------------

    def __len__(self) -> int:
        """Return the number of items in the vault.

        Returns
        -------
        int
            Number of items currently stored in the vault.
        """
        return len(self._items)

    def __contains__(self, item_uuid: str) -> bool:
        """Check whether an item UUID exists in the vault.

        Parameters
        ----------
        item_uuid : str
            UUID to check.

        Returns
        -------
        bool
            ``True`` if an item with this UUID is stored in the vault.
        """
        return item_uuid in self._items

    def __iter__(self) -> Iterator[Item]:
        """Iterate over the items contained in the vault.

        Yields
        ------
        Item
            Each item currently stored in the vault, in insertion order.
        """
        return iter(self._items.values())

    # -----------------------
    # Metadata
    # -----------------------

    @property
    def name(self) -> str:
        """Return the vault name.

        Returns
        -------
        str
            Current vault name.
        """
        return self._name

    def rename(self, name: str) -> None:
        """Rename the vault.

        Parameters
        ----------
        name : str
            New vault name.

        Raises
        ------
        TypeError
            If ``name`` is not a ``str``.

        Notes
        -----
        The vault name is not required to be unique by this class.
        Uniqueness constraints between vaults are the responsibility
        of the :class:`PasswordManager`.
        """
        if not isinstance(name, str):
            raise TypeError(f"name must be a string, not {type(name)}")
        self._name = name

    def get_icon(self) -> ClearString | None:
        """Return the vault icon.

        Returns
        -------
        ClearString or None
            Vault icon identifier, or ``None`` if no icon is configured.
        """
        return self._icon

    def set_icon(self, value: ClearString | None) -> None:
        """Set the vault icon.

        Parameters
        ----------
        value : ClearString or None
            Icon identifier. ``None`` removes the current icon.

        Raises
        ------
        TypeError
            If ``value`` is neither a ``str`` nor ``None``.
        """
        if value is not None and not isinstance(value, str):
            raise TypeError(f"value must be a string, not {type(value)}")
        self._icon = value

    def get_icon_color(self) -> ClearString | None:
        """Return the vault icon color.

        Returns
        -------
        ClearString or None
            Icon color, or ``None`` if no color is configured.
        """
        return self._icon_color

    def set_icon_color(self, value: ClearString | None) -> None:
        """Set the vault icon color.

        Parameters
        ----------
        value : ClearString or None
            Icon color. ``None`` removes the current color.

        Raises
        ------
        TypeError
            If ``value`` is neither a ``str`` nor ``None``.
        """
        if value is not None and not isinstance(value, str):
            raise TypeError(f"value must be a string, not {type(value)}")
        self._icon_color = value

    # -----------------------
    # Serialization
    # -----------------------

    def __repr__(self) -> str:
        """
        Return a debug-friendly representation of the vault.

        Returns
        -------
        str
            A representation built from the vault's name and item count
            never from any individual item's field values, so it stays
            safe to print or log regardless of what those items contain.
        """
        return f"{type(self).__name__}(name={self._name!r}, items={len(self._items)})"

    def to_dict(self) -> VaultData:
        """Serialize the vault to its dictionary representation.

        Returns
        -------
        VaultData
            Serialized vault containing the vault metadata and all
            serialized items.

        Notes
        -----
        The returned dictionary is newly constructed. However, the
        serialized item dictionaries returned by :meth:`Item.to_dict`
        are the dictionaries managed by their respective items.
        """
        return {
            "icon": self._icon,
            "icon_color": self._icon_color,
            "items": {
                item.uuid: item.to_dict()
                for item in self._items.values()
            },
        }