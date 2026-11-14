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

from contextlib import contextmanager
from dataclasses import dataclass, field as dataclass_field
from enum import Enum
from typing import Any, Callable, Iterator, Literal, cast, overload

import pyaescbc

from .types import (
    ItemData, ItemField, ClearField, SecretField, ItemFieldsData, CustomFieldData, CustomKind, ClearString,
    ClearStringList, ClearSecretBytesList,
)
from .datakey import DataKey
from .encrypted_value import EncryptedValue
from .common import (
    _now, _check_keys, _check_optional_str, _check_optional_name, _check_name,
    _check_date, _check_index, _check_clear_list, _check_secret_list,
)
from .uuids import _check_uuid, _check_unique_uuids, _generate_uuid, _get_uuid_index


class FieldKind(Enum):
    """
    Storage kind of an item field (predefined or custom).

    Every field holds a list of values; the kind only says whether
    those values are stored in clear or encrypted. The value of each
    member is its name in the serialized data (see :data:`CustomKind`).
    """

    CLEAR = "clear"
    ENCRYPTED = "encrypted"


#: Kind of every predefined field, in serialization order.
_FIELDS: dict[ItemField, FieldKind] = {
    "logins":    FieldKind.CLEAR,
    "websites":  FieldKind.CLEAR,
    "emails":    FieldKind.CLEAR,
    "phones":    FieldKind.CLEAR,
    "passwords": FieldKind.ENCRYPTED,
    "totps":     FieldKind.ENCRYPTED,
}

#: Keys accepted in each section of the serialized data.
_TOP_KEYS = ("metadata", "fields", "customs", "gui")
_METADATA_KEYS = ("uuid", "name", "creation_date", "modification_date")
_CUSTOM_KEYS = ("id", "name", "kind", "values")
_GUI_KEYS = ("icon", "color")

#: Domain label prefixed to every context (see :meth:`Item._context`).
#: NEVER change it: existing values could no longer be decrypted.
_CONTEXT_LABEL = "bippass::item::v3"


def _to_kind(kind: FieldKind | CustomKind) -> FieldKind:
    """
    Normalize a kind given as a :class:`FieldKind` or as its serialized name.

    Raises
    ------
    ValueError
        If ``kind`` is not a known kind.
    """
    if isinstance(kind, FieldKind):
        return kind
    try:
        return FieldKind(kind)
    except ValueError:
        raise ValueError(
            f"{kind!r} is not a known field kind, expected one of "
            f"{tuple(k.value for k in FieldKind)}"
        ) from None


@dataclass(slots=True)
class _CustomField:
    """
    A custom field of an item (internal).

    Attributes
    ----------
    id : str
        UUID of the field, unique within its item. Part of the context
        of its encrypted values: it never changes.

    name : str
        Display name, chosen by the user. Not necessarily unique.

    kind : FieldKind
        Whether :attr:`values` are clear or encrypted.

    values : list of str or list of EncryptedValue
        The values of the field.
    """

    id: str
    name: str
    kind: FieldKind
    values: list = dataclass_field(default_factory=list)


class Item:
    """
    Represent a single password vault item.

    An item contains both unencrypted and encrypted information. Its
    name, logins, websites, phone numbers, email addresses and display
    settings are stored in clear (they are only protected by the
    primary password, which encrypts the whole file). Sensitive values
    such as passwords and TOTP secrets are stored as
    :class:`EncryptedValue` instances, sealed with the :class:`DataKey`.

    Parameters
    ----------
    item_uuid : str
        Globally unique identifier of the item, in canonical form (see
        :func:`_is_uuid`).

    Raises
    ------
    UUIDError
        If ``item_uuid`` is not a UUID in canonical form.

    Notes
    -----
    **Structure.** An item is made of four parts, mirrored by its
    serialized form (see :meth:`to_dict`)::

        {
            "metadata": {"uuid", "name", "creation_date", "modification_date"},
            "fields":   {"logins", "websites", "emails", "phones",
                         "passwords", "totps"},
            "customs":  [{"id", "name", "kind", "values"}, ...],
            "gui":      {"icon", "color"},
        }

    - ``metadata`` identifies the item. The UUID is stored here, and
      only here: the item is the single source of truth for its UUID.
    - ``fields`` holds the predefined fields. Every field is a list of
      values; ``passwords`` and ``totps`` are encrypted, the others are
      clear. An unset field is an empty list.
    - ``customs`` holds the user-defined fields, in display order. Each
      one is identified by its own UUID (``id``), so that several
      custom fields may share the same name, and renaming one never
      requires re-encryption. Each one is either ``"clear"`` or
      ``"encrypted"``, and holds a list of values.
    - ``gui`` holds what is only useful to the graphical interface.

    **Format evolution.** Reading is strict about *unknown* keys and
    lenient about *missing* ones (see :meth:`from_dict`): data written
    by an older version (missing keys) can be read by a newer one, but
    data written by a newer version (unknown keys) is refused by an
    older one, instead of being silently truncated when saved back.

    **In memory.** The item owns its state: it is not a view on a
    serialized dictionary. Encrypted values are held as
    :class:`EncryptedValue` instances, so a clear value and an
    encrypted one can never be confused: clear values are ``str``,
    encrypted ones are :class:`EncryptedValue`, and decrypted ones are
    ``bytearray``.

    **Key.** Every operation on an encrypted field takes the
    :class:`DataKey`. The item never stores it, so an item can be
    copied, serialized or logged without ever involving the key.

    **Context.** Each encrypted value is bound to its place by the
    context passed to :meth:`EncryptedValue.seal` (see
    :meth:`_context`)::

        bippass::item::v3|<item uuid>|field|<field name>   (predefined field)
        bippass::item::v3|<item uuid>|custom|<custom id>   (custom field)

    A value moved to another item, or to another field of the same
    item, therefore fails to decrypt. The index of a value within a
    list is deliberately *not* part of the context: values can be
    removed or reordered without re-encryption. Only
    :meth:`change_uuid` and :meth:`change_data_key` re-encrypt values.

    **Dates.** :attr:`creation_date` is set once, when the item is
    created. :attr:`modification_date` is updated by every user-facing
    change (every ``set_*``, :meth:`set`, and every ``*_custom``
    method that changes something), and *only* by those: technical
    operations (:meth:`change_data_key`, :meth:`change_uuid`,
    serialization, import) never touch it.

    **Memory.** Decrypted values are returned as ``bytearray`` objects,
    which the caller is responsible for erasing (e.g. via
    :func:`pyaescbc.delete_bytearray`). Prefer :meth:`revealed` and
    :meth:`revealed_custom`, which erase them automatically. Clear
    ``bytearray`` values given for encrypted fields are erased once
    they have been successfully encrypted.

    The textual representation of an item (:func:`repr`, :func:`str`)
    only shows its UUID, so it stays safe to print or log.

    This class performs no locking of its own.

    See Also
    --------
    Vault
        Container for multiple :class:`Item` instances.

    EncryptedValue
        A single sensitive value of an item.

    DataKey
        The key passed to every encrypted-field operation of this class.
    """

    __slots__ = (
        "_uuid", "_name", "_creation_date", "_modification_date",
        "_fields", "_customs", "_icon", "_color",
    )

    def __init__(self, item_uuid: str) -> None:
        """
        Create an empty item.

        Parameters
        ----------
        item_uuid : str
            Globally unique identifier of the new item.

        Raises
        ------
        UUIDError
            If ``item_uuid`` is not a UUID in canonical form.

        Notes
        -----
        Every field is empty, and both dates are set to now. Global
        UUID uniqueness is the responsibility of the
        :class:`PasswordManager` (see :func:`_generate_uuid`).
        """
        self._uuid: str = _check_uuid(item_uuid)
        self._name: ClearString | None = None
        now = _now()
        self._creation_date: str = now
        self._modification_date: str = now
        self._fields: dict[ItemField, list] = {name: [] for name in _FIELDS}
        self._customs: list[_CustomField] = []
        self._icon: ClearString | None = None
        self._color: ClearString | None = None

    # -----------------------
    # Metadata
    # -----------------------

    @property
    def uuid(self) -> str:
        """
        Return the unique identifier of the item.

        Returns
        -------
        str
            Item UUID. Use :meth:`change_uuid` to change it.
        """
        return self._uuid

    @property
    def creation_date(self) -> str:
        """
        Return the creation date of the item.

        Returns
        -------
        str
            ISO 8601 date and time, with timezone.
        """
        return self._creation_date

    @property
    def modification_date(self) -> str:
        """
        Return the date of the last user modification of the item.

        Returns
        -------
        str
            ISO 8601 date and time, with timezone. See the class-level
            Notes for which operations update it.
        """
        return self._modification_date

    def _touch(self) -> None:
        """Record a user modification (see the class-level Notes on dates)."""
        self._modification_date = _now()

    def get_name(self) -> ClearString | None:
        """
        Return the item name.

        Returns
        -------
        ClearString or None
            Item name, or ``None`` if unset.
        """
        return self._name

    def set_name(self, value: ClearString | None) -> None:
        """
        Set the item name.

        Parameters
        ----------
        value : ClearString or None
            New name, stripped. ``None``, or a blank name, removes it.

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
        Return the item icon, used by the graphical interface only.

        Returns
        -------
        ClearString or None
            The icon image, Base64-encoded, or ``None`` if unset.
        """
        return self._icon

    def set_icon(self, value: ClearString | None) -> None:
        """
        Set the item icon, used by the graphical interface only.

        Parameters
        ----------
        value : ClearString or None
            The icon image, Base64-encoded. ``None`` removes it. Not
            interpreted nor checked by this class: encoding and
            decoding the image is the job of the graphical interface.

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
        Return the item color, used by the graphical interface only.

        Returns
        -------
        ClearString or None
            Color, or ``None`` if unset.
        """
        return self._color

    def set_color(self, value: ClearString | None) -> None:
        """
        Set the item color, used by the graphical interface only.

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
    # Encryption helpers
    # -----------------------

    def _context(
        self,
        scope: Literal["field", "custom"],
        name: str,
        *,
        item_uuid: str | None = None,
    ) -> bytearray:
        """
        Build the context binding an encrypted value to its place.

        Parameters
        ----------
        scope : {"field", "custom"}
            Whether the value belongs to a predefined field or to a
            custom field.

        name : str
            Predefined field name, or custom field id.

        item_uuid : str, optional
            UUID to use instead of :attr:`uuid` (used by
            :meth:`change_uuid` to build the new context).

        Returns
        -------
        bytearray
            ``bippass::item::v3|<item uuid>|<scope>|<name>``, UTF-8
            encoded.

        Notes
        -----
        The scope component keeps a custom field from ever sharing its
        context with a predefined field.
        """
        uuid = self._uuid if item_uuid is None else item_uuid
        return bytearray(f"{_CONTEXT_LABEL}|{uuid}|{scope}|{name}", "utf-8")

    @staticmethod
    def _seal_all(
        values: list[bytearray],
        data_key: DataKey,
        context: bytearray,
    ) -> list[EncryptedValue]:
        """
        Encrypt every clear value of a list.

        Notes
        -----
        Each clear value is erased once it has been encrypted (see
        :meth:`EncryptedValue.seal`). If an error occurs partway, the
        values already encrypted have been erased, the others have not.
        """
        return [EncryptedValue.seal(v, data_key, context) for v in values]

    @staticmethod
    def _reveal_all(
        values: list[EncryptedValue],
        data_key: DataKey,
        context: bytearray,
    ) -> list[bytearray]:
        """
        Decrypt every value of a list.

        Notes
        -----
        All-or-nothing: if any value fails to decrypt, the values
        already decrypted are erased before the exception propagates.
        """
        clears: list[bytearray] = []
        try:
            for v in values:
                clears.append(v.reveal(data_key, context))
        except BaseException:
            for c in clears:
                pyaescbc.delete_bytearray(c)
            raise
        return clears

    @staticmethod
    @contextmanager
    def _erasing(clears: list[bytearray]) -> Iterator[list[bytearray]]:
        """
        Yield decrypted values, and erase them when the ``with`` block exits.

        Notes
        -----
        Shared by :meth:`revealed` and :meth:`revealed_custom`.
        """
        try:
            yield clears
        finally:
            for c in clears:
                pyaescbc.delete_bytearray(c)

    @staticmethod
    def _reseal_all(
        values: list[EncryptedValue],
        old_key: DataKey,
        old_context: bytearray,
        new_key: DataKey,
        new_context: bytearray,
    ) -> list[EncryptedValue]:
        """
        Re-encrypt every value of a list under a new key and/or context.

        Notes
        -----
        Each intermediate clear value is always erased, whether its
        re-encryption succeeds or not.
        """
        resealed = []
        for value in values:
            clear = value.reveal(old_key, old_context)
            try:
                resealed.append(EncryptedValue.seal(clear, new_key, new_context))
            finally:
                pyaescbc.delete_bytearray(clear)
        return resealed

    def _reseal_everything(
        self,
        old_key: DataKey,
        new_key: DataKey,
        new_uuid: str,
    ) -> tuple[dict[ItemField, list], list[_CustomField]]:
        """
        Re-encrypt every encrypted value, without modifying the item.

        Parameters
        ----------
        old_key, new_key : DataKey
            Key the values are currently sealed with, and key to seal
            them with.

        new_uuid : str
            Item UUID to build the new contexts with.

        Returns
        -------
        tuple
            New ``_fields`` and ``_customs``, to be committed by the
            caller in one go.

        Notes
        -----
        Nothing is written to the item here: if any value fails, the
        exception propagates and the item is left exactly as it was.
        """
        fields = {
            name: (
                self._reseal_all(
                    values,
                    old_key, self._context("field", name),
                    new_key, self._context("field", name, item_uuid=new_uuid),
                )
                if _FIELDS[name] is FieldKind.ENCRYPTED else list(values)
            )
            for name, values in self._fields.items()
        }
        customs = [
            _CustomField(
                custom.id, custom.name, custom.kind,
                self._reseal_all(
                    custom.values,
                    old_key, self._context("custom", custom.id),
                    new_key, self._context("custom", custom.id, item_uuid=new_uuid),
                )
                if custom.kind is FieldKind.ENCRYPTED else list(custom.values),
            )
            for custom in self._customs
        ]
        return fields, customs

    # -----------------------
    # Predefined fields
    # -----------------------

    @staticmethod
    def _kind_of(name: str) -> FieldKind:
        """
        Return the kind of a predefined field.

        Raises
        ------
        KeyError
            If ``name`` is not a predefined field.
        """
        try:
            return _FIELDS[cast(ItemField, name)]
        except KeyError:
            raise KeyError(
                f"{name!r} is not a known item field, expected one of {tuple(_FIELDS)}"
            ) from None

    @overload
    def get(self, field: ClearField, *, data_key: DataKey | None = None) -> ClearStringList: ...

    @overload
    def get(self, field: SecretField, *, data_key: DataKey | None = None) -> ClearSecretBytesList: ...

    @overload
    def get(
        self, field: ItemField, *, data_key: DataKey | None = None
    ) -> ClearStringList | ClearSecretBytesList: ...

    def get(
        self,
        field: ItemField,
        *,
        data_key: DataKey | None = None,
    ) -> ClearStringList | ClearSecretBytesList:
        """
        Return the values of a predefined field.

        Parameters
        ----------
        field : ItemField
            Name of the field to retrieve. See the class-level Notes
            for the predefined fields.

        data_key : DataKey, optional
            Key used to decrypt the field. Required only when ``field``
            is an encrypted field (``"passwords"``, ``"totps"``).


        Returns
        -------
        ClearStringList or ClearSecretBytesList
            A new list of ``str`` for a clear field, a new list of
            decrypted ``bytearray`` for an encrypted field. The caller
            is responsible for erasing the decrypted buffers, or should
            use :meth:`revealed` instead.


        Raises
        ------
        KeyError
            If ``field`` is not a predefined field.

        ValueError
            If ``field`` is an encrypted field and ``data_key`` is not
            provided, or ``data_key`` has been cleared.

        TamperedDataError
            If a value fails to decrypt (see :meth:`EncryptedValue.reveal`).


        Notes
        -----
        Returned lists are always new lists: mutating them does not
        affect the item. Decryption is all-or-nothing: if any value
        fails, none is returned and the ones already decrypted are
        erased.
        """
        kind = self._kind_of(field)
        if kind is FieldKind.CLEAR:
            return list(self._fields[field])
        if data_key is None:
            raise ValueError(f"{field!r} is an encrypted field: data_key is required.")
        return self._reveal_all(self._fields[field], data_key, self._context("field", field))

    @contextmanager
    def revealed(
        self,
        field: Literal["passwords", "totps"],
        data_key: DataKey,
    ) -> Iterator[ClearSecretBytesList]:
        """
        Decrypt an encrypted field for the duration of a ``with`` block.

        Parameters
        ----------
        field : {"passwords", "totps"}
            Encrypted predefined field to decrypt.

        data_key : DataKey
            Key used to decrypt the field.


        Yields
        ------
        ClearSecretBytesList
            The decrypted values. Erased when the ``with`` block exits,
            normally or through an exception: do not keep a reference
            to them beyond the block.


        Raises
        ------
        KeyError, ValueError, TamperedDataError
            See :meth:`get`.

        TypeError
            If ``field`` is not an encrypted field.


        Examples
        --------
        >>> with item.revealed("totps", data_key) as secrets:
        ...     code, remaining = generate_totp_code(secrets[0])
        """
        if self._kind_of(field) is not FieldKind.ENCRYPTED:
            raise TypeError(f"{field!r} is not an encrypted field.")
        with self._erasing(cast(list[bytearray], self.get(field, data_key=data_key))) as clears:
            yield clears

    def count(self, field: ItemField) -> int:
        """
        Return the number of values of a predefined field, without decrypting.

        Parameters
        ----------
        field : ItemField
            Name of the field.

        Returns
        -------
        int
            Number of values stored in ``field``.

        Raises
        ------
        KeyError
            If ``field`` is not a predefined field.
        """
        self._kind_of(field)
        return len(self._fields[field])

    def set(
        self,
        field: ItemField,
        values: ClearStringList | ClearSecretBytesList,
        *,
        data_key: DataKey | None = None,
    ) -> None:
        """
        Replace the values of a predefined field.

        Parameters
        ----------
        field : ItemField
            Name of the field to update. See the class-level Notes for
            the predefined fields.

        values : ClearStringList or ClearSecretBytesList
            New values: a list of ``str`` for a clear field, a list of
            clear ``bytearray`` for an encrypted field. An empty list
            clears the field.

        data_key : DataKey, optional
            Key used to encrypt the field. Required only when ``field``
            is an encrypted field.


        Raises
        ------
        KeyError
            If ``field`` is not a predefined field.

        TypeError
            If ``values`` does not match the field's kind.

        ValueError
            If ``field`` is an encrypted field and ``data_key`` is not
            provided, or ``data_key`` has been cleared.


        Notes
        -----
        Updates :attr:`modification_date`.

        For an encrypted field, every clear ``bytearray`` of ``values``
        is erased once it has been encrypted. The field is replaced
        only once *every* value has been encrypted: if an error occurs
        partway, the item is left unchanged (but the values already
        encrypted have been erased).
        """
        kind = self._kind_of(field)
        if kind is FieldKind.CLEAR:
            self._fields[field] = _check_clear_list(field, values)
        else:
            clears = _check_secret_list(field, values)
            if data_key is None:
                raise ValueError(f"{field!r} is an encrypted field: data_key is required.")
            self._fields[field] = self._seal_all(clears, data_key, self._context("field", field))
        self._touch()

    # --------------------
    # Custom fields
    # --------------------

    def _custom(self, custom_id: str) -> _CustomField:
        """
        Return a custom field by id.

        Raises
        ------
        UUIDError
            If ``custom_id`` is not a UUID, or no custom field has it.
        """
        return self._customs[_get_uuid_index(custom_id, [c.id for c in self._customs])]

    def custom_ids(self) -> tuple[str, ...]:
        """
        Return the ids of the custom fields, in display order.

        Returns
        -------
        tuple of str
            Ids of every custom field. Empty tuple if there is none.
        """
        return tuple(c.id for c in self._customs)

    def custom_name(self, custom_id: str) -> str:
        """
        Return the name of a custom field.

        Parameters
        ----------
        custom_id : str
            Id of the custom field.

        Returns
        -------
        str
            Display name of the field.

        Raises
        ------
        UUIDError
            If no custom field has this id.
        """
        return self._custom(custom_id).name

    def custom_kind(self, custom_id: str) -> FieldKind:
        """
        Return the kind of a custom field.

        Parameters
        ----------
        custom_id : str
            Id of the custom field.

        Returns
        -------
        FieldKind
            Whether the field is clear or encrypted.

        Raises
        ------
        UUIDError
            If no custom field has this id.
        """
        return self._custom(custom_id).kind

    def custom_count(self, custom_id: str) -> int:
        """
        Return the number of values of a custom field, without decrypting.

        Parameters
        ----------
        custom_id : str
            Id of the custom field.

        Returns
        -------
        int
            Number of values of the field.

        Raises
        ------
        UUIDError
            If no custom field has this id.
        """
        return len(self._custom(custom_id).values)

    def _seal_custom(
        self,
        custom_id: str,
        kind: FieldKind,
        values: Any,
        data_key: DataKey | None,
        where: str,
    ) -> list:
        """
        Check the values of a custom field and convert them for storage.

        Returns
        -------
        list of str or list of EncryptedValue
            A new list, ready to be stored.
        """
        if kind is FieldKind.CLEAR:
            return _check_clear_list(where, values)
        clears = _check_secret_list(where, values)
        if data_key is None:
            raise ValueError(f"{where} is an encrypted field: data_key is required.")
        return self._seal_all(clears, data_key, self._context("custom", custom_id))

    def add_custom(
        self,
        name: str,
        kind: FieldKind | CustomKind,
        values: ClearStringList | ClearSecretBytesList,
        *,
        data_key: DataKey | None = None,
    ) -> str:
        """
        Add a new custom field at the end of the custom fields.

        Parameters
        ----------
        name : str
            Display name of the field. Must not be empty; may be shared
            with other custom fields.

        kind : FieldKind or CustomKind
            ``FieldKind.CLEAR``/``"clear"`` or
            ``FieldKind.ENCRYPTED``/``"encrypted"``.

        values : ClearStringList or ClearSecretBytesList
            Initial values: a list of ``str`` for a clear field, a list
            of clear ``bytearray`` for an encrypted field. May be empty.

        data_key : DataKey, optional
            Key used to encrypt the values. Required only for an
            encrypted field.


        Returns
        -------
        str
            The id of the new field, generated so that it is unique
            within this item.


        Raises
        ------
        TypeError
            If ``name`` is not a ``str``, or ``values`` does not match
            ``kind``.

        ValueError
            If ``name`` is empty, ``kind`` is unknown, or the field is
            encrypted and ``data_key`` is not provided or has been
            cleared.


        Notes
        -----
        Updates :attr:`modification_date`. Clear ``bytearray`` values
        are erased once encrypted, as in :meth:`set`.
        """
        name = _check_name("name", name)
        field_kind = _to_kind(kind)
        custom_id = _generate_uuid(self.custom_ids())
        stored = self._seal_custom(custom_id, field_kind, values, data_key, f"custom field {name!r}")
        self._customs.append(_CustomField(custom_id, name, field_kind, stored))
        self._touch()
        return custom_id

    def get_custom(
        self,
        custom_id: str,
        *,
        data_key: DataKey | None = None,
    ) -> ClearStringList | ClearSecretBytesList:
        """
        Return the values of a custom field.

        Parameters
        ----------
        custom_id : str
            Id of the custom field.

        data_key : DataKey, optional
            Key used to decrypt the field. Required only for an
            encrypted field.


        Returns
        -------
        ClearStringList or ClearSecretBytesList
            A new list of ``str`` for a clear field, a new list of
            decrypted ``bytearray`` for an encrypted field. The caller
            is responsible for erasing the decrypted buffers, or should
            use :meth:`revealed_custom` instead.


        Raises
        ------
        UUIDError
            If no custom field has this id.

        ValueError
            If the field is encrypted and ``data_key`` is not provided,
            or ``data_key`` has been cleared.

        TamperedDataError
            If a value fails to decrypt.
        """
        custom = self._custom(custom_id)
        if custom.kind is FieldKind.CLEAR:
            return list(custom.values)
        if data_key is None:
            raise ValueError(f"Custom field {custom.name!r} is encrypted: data_key is required.")
        return self._reveal_all(custom.values, data_key, self._context("custom", custom.id))

    @contextmanager
    def revealed_custom(
        self,
        custom_id: str,
        data_key: DataKey,
    ) -> Iterator[ClearSecretBytesList]:
        """
        Decrypt an encrypted custom field for the duration of a ``with`` block.

        Parameters
        ----------
        custom_id : str
            Id of the encrypted custom field.

        data_key : DataKey
            Key used to decrypt the field.


        Yields
        ------
        ClearSecretBytesList
            The decrypted values. Erased when the ``with`` block exits.


        Raises
        ------
        UUIDError, ValueError, TamperedDataError
            See :meth:`get_custom`.

        TypeError
            If the field is not encrypted.
        """
        if self.custom_kind(custom_id) is not FieldKind.ENCRYPTED:
            raise TypeError(f"Custom field {custom_id} is not encrypted.")
        with self._erasing(cast(list[bytearray], self.get_custom(custom_id, data_key=data_key))) as clears:
            yield clears

    def set_custom(
        self,
        custom_id: str,
        values: ClearStringList | ClearSecretBytesList,
        *,
        data_key: DataKey | None = None,
    ) -> None:
        """
        Replace the values of a custom field.

        Parameters
        ----------
        custom_id : str
            Id of the custom field.

        values : ClearStringList or ClearSecretBytesList
            New values, matching the field's kind.

        data_key : DataKey, optional
            Key used to encrypt the values. Required only if the field
            is encrypted.


        Raises
        ------
        UUIDError
            If no custom field has this id.

        TypeError
            If ``values`` does not match the kind.

        ValueError
            If the field is encrypted and ``data_key`` is not provided
            or has been cleared.


        Notes
        -----
        Updates :attr:`modification_date`. The field keeps its id, name,
        kind and position: the kind of a custom field is chosen once
        and for all by :meth:`add_custom`. The values are replaced only
        once every one of them has been converted: if an error occurs,
        the field is left unchanged.
        """
        custom = self._custom(custom_id)
        custom.values = self._seal_custom(
            custom.id, custom.kind, values, data_key, f"custom field {custom.name!r}"
        )
        self._touch()

    def rename_custom(self, custom_id: str, name: str) -> None:
        """
        Rename a custom field.

        Parameters
        ----------
        custom_id : str
            Id of the custom field.

        name : str
            New display name. Must not be empty; may be shared with
            other custom fields.

        Raises
        ------
        UUIDError
            If no custom field has this id.

        TypeError
            If ``name`` is not a ``str``.

        ValueError
            If ``name`` is empty.

        Notes
        -----
        Updates :attr:`modification_date`. No re-encryption is needed:
        the context of encrypted values uses the field id, not its
        name, so no key is required.
        """
        custom = self._custom(custom_id)
        custom.name = _check_name("name", name)
        self._touch()

    def move_custom(self, custom_id: str, index: int) -> None:
        """
        Move a custom field to another position.

        Parameters
        ----------
        custom_id : str
            Id of the custom field.

        index : int
            New position, as for :meth:`list.insert` (``0`` moves it
            first, ``len(item.custom_ids())`` or more moves it last).

        Raises
        ------
        UUIDError
            If no custom field has this id.

        TypeError
            If ``index`` is not an ``int``.

        Notes
        -----
        Updates :attr:`modification_date`. No re-encryption is needed.
        """
        _check_index("index", index)
        custom = self._custom(custom_id)
        self._customs.remove(custom)
        self._customs.insert(index, custom)
        self._touch()

    def remove_custom(self, custom_id: str) -> None:
        """
        Remove a custom field.

        Parameters
        ----------
        custom_id : str
            Id of the custom field to remove.

        Raises
        ------
        UUIDError
            If no custom field has this id.

        Notes
        -----
        Updates :attr:`modification_date`. No decryption is performed:
        no key is needed.
        """
        self._customs.remove(self._custom(custom_id))
        self._touch()

    # ----------------
    # Re-encryption
    # ----------------

    def change_data_key(self, old_key: DataKey, new_key: DataKey) -> None:
        """
        Re-encrypt every encrypted value with a new data key.

        Parameters
        ----------
        old_key : DataKey
            Key every encrypted value is currently sealed with.

        new_key : DataKey
            Key to re-seal them with.


        Raises
        ------
        ValueError
            If either key has been cleared.

        TamperedDataError
            If a value fails to decrypt with ``old_key``.


        Notes
        -----
        Used to move an item to another profile (export and import),
        and, through :meth:`_prepare_change_data_key`, when the
        secondary password is changed, which always draws a new data
        key (see :meth:`PasswordManager.change_secondary_password`).

        Atomic: every value is re-encrypted first, and the item is
        updated in one go only once all of them succeeded. If any value
        fails, the item is left exactly as it was.

        Does not update :attr:`modification_date`.
        """
        self._prepare_change_data_key(old_key, new_key)()

    def _prepare_change_data_key(
        self,
        old_key: DataKey,
        new_key: DataKey,
    ) -> Callable[[], None]:
        """
        Re-encrypt every encrypted value with a new key, without committing.

        Parameters
        ----------
        old_key, new_key : DataKey
            See :meth:`change_data_key`.

        Returns
        -------
        callable
            A function taking no argument that commits the re-encrypted
            values to the item. It cannot fail.

        Raises
        ------
        ValueError, TamperedDataError
            See :meth:`change_data_key`.

        Notes
        -----
        Two-phase version of :meth:`change_data_key`, so that a
        container (:class:`Vault`, :class:`PasswordManager`) can
        prepare *every* item first and commit all of them only once
        all succeeded, while keeping the very same :class:`Item`
        instances (references held elsewhere, e.g. by an open editor,
        stay valid). Nothing is modified until the returned function is
        called.
        """
        fields, customs = self._reseal_everything(old_key, new_key, self._uuid)

        def commit() -> None:
            self._fields, self._customs = fields, customs

        return commit

    def change_uuid(self, new_uuid: str, data_key: DataKey) -> None:
        """
        Give the item a new UUID, re-encrypting its values accordingly.

        Parameters
        ----------
        new_uuid : str
            New UUID of the item.

        data_key : DataKey
            Key every encrypted value is sealed with. The item UUID is
            part of the context of every encrypted value (see the
            class-level Notes), so they are all re-encrypted under the
            new UUID.


        Raises
        ------
        UUIDError
            If ``new_uuid`` is not a UUID in canonical form.

        ValueError
            If ``data_key`` has been cleared.

        TamperedDataError
            If a value fails to decrypt.


        Notes
        -----
        Rarely needed: only when an item imported from another account
        has a UUID that collides with an existing one. Global UUID
        uniqueness is the responsibility of the :class:`PasswordManager`,
        which chooses ``new_uuid`` (see :func:`_generate_uuid`).

        Atomic: the UUID and the values are updated in one go, only
        once every value has been re-encrypted.

        Does not update :attr:`modification_date`.
        """
        new_uuid = _check_uuid(new_uuid)
        if new_uuid == self._uuid:
            return
        fields, customs = self._reseal_everything(data_key, data_key, new_uuid)
        self._uuid, self._fields, self._customs = new_uuid, fields, customs

    # -----------------
    # Serialization
    # -----------------

    def to_dict(self) -> ItemData:
        """
        Serialize the item.

        Returns
        -------
        ItemData
            A new dictionary, suitable for JSON serialization (see the
            class-level Notes for its structure). Encrypted values are
            stored Base64-encoded (see :meth:`EncryptedValue.to_json`);
            nothing is decrypted.
        """
        def dump(kind: FieldKind, values: list) -> list[str]:
            if kind is FieldKind.ENCRYPTED:
                return [v.to_json() for v in values]
            return list(values)

        return {
            "metadata": {
                "uuid": self._uuid,
                "name": self._name,
                "creation_date": self._creation_date,
                "modification_date": self._modification_date,
            },
            "fields": cast(ItemFieldsData, {
                name: dump(_FIELDS[name], values)
                for name, values in self._fields.items()
            }),
            "customs": [
                {
                    "id": custom.id,
                    "name": custom.name,
                    "kind": custom.kind.value,
                    "values": dump(custom.kind, custom.values),
                }
                for custom in self._customs
            ],
            "gui": {
                "icon": self._icon,
                "color": self._color,
            },
        }

    @classmethod
    def from_dict(cls, data: ItemData) -> Item:
        """
        Create an item from its serialized representation.

        Parameters
        ----------
        data : ItemData
            Serialized item, as returned by :meth:`to_dict`. Not
            modified, and not kept by reference.


        Returns
        -------
        Item
            The deserialized item. Its encrypted values are not
            authenticated yet: that only happens when they are
            decrypted.


        Raises
        ------
        TypeError
            If a section or a value does not have the expected type.

        ValueError
            If a section contains an unknown key, a required key
            (``metadata.uuid``, or a custom field's ``id``, ``name`` or
            ``kind``) is missing, a kind is unknown, a date is not an
            ISO 8601 date, or an encrypted value is not a key-mode
            bundle (e.g. data from an older format, which must be
            migrated instead).

        UUIDError
            If the item UUID or a custom field id is not a UUID in
            canonical form, or two custom fields share an id.

        CorruptedBase64Error
            If an encrypted value is not valid Base64.


        Notes
        -----
        Reading rules, so that the format can evolve:

        - an **unknown** key, in any section, is an error: the data was
          written by a newer version, and reading it anyway would
          silently drop that key when saving back;
        - a **missing** key is read as its default (``None``, an empty
          list, or now for a date), so that data written by an older
          version, lacking a key added since, can still be read.
          ``None`` is also accepted wherever a list is expected.

        Does not update :attr:`modification_date`.
        """
        def load_secrets(raw: list[str]) -> list[EncryptedValue]:
            return [EncryptedValue.from_json(v) for v in raw]

        data = cast(ItemData, _check_keys("item", data, _TOP_KEYS))

        metadata = _check_keys("item metadata", data.get("metadata", {}), _METADATA_KEYS)
        if "uuid" not in metadata:
            raise ValueError("item metadata must contain a 'uuid'.")
        item = cls(metadata["uuid"])
        item._name = _check_optional_name("name", metadata.get("name"))
        item._creation_date = _check_date(
            "creation_date", metadata.get("creation_date"), item._creation_date)
        item._modification_date = _check_date(
            "modification_date", metadata.get("modification_date"), item._modification_date)

        fields = _check_keys("item fields", data.get("fields", {}), tuple(_FIELDS))
        for name, kind in _FIELDS.items():
            raw = fields.get(name)
            raw = [] if raw is None else _check_clear_list(name, raw)
            if kind is FieldKind.ENCRYPTED:
                item._fields[name] = load_secrets(raw)
            else:
                item._fields[name] = raw

        customs = data.get("customs") or []
        if not isinstance(customs, list):
            raise TypeError("item customs must be a list.")
        parsed: list[_CustomField] = []
        for entry in customs:
            entry = cast(CustomFieldData, _check_keys("custom field", entry, _CUSTOM_KEYS))
            for key in ("id", "name", "kind"):
                if key not in entry:
                    raise ValueError(f"custom field must contain a {key!r}.")
            custom_id = _check_uuid(entry["id"])
            custom_name = _check_name("custom field name", entry["name"])
            kind = _to_kind(entry["kind"])
            raw = entry.get("values")
            raw = [] if raw is None else _check_clear_list(f"custom field {custom_name!r}", raw)
            values: list[EncryptedValue] | list[str]
            if kind is FieldKind.ENCRYPTED:
                values = load_secrets(raw)
            else:
                values = raw
            parsed.append(_CustomField(custom_id, custom_name, kind, values))
        _check_unique_uuids(c.id for c in parsed)
        item._customs = parsed

        gui = _check_keys("item gui", data.get("gui", {}), _GUI_KEYS)
        item._icon = _check_optional_str("icon", gui.get("icon"))
        item._color = _check_optional_str("color", gui.get("color"))

        return item

    def deepcopy(self) -> Item:
        """
        Return a deep copy of this item.

        Returns
        -------
        Item
            A new :class:`Item` with the same UUID, dates and values:
            mutating the copy never affects the original, and vice
            versa.

        Notes
        -----
        No encryption or decryption is performed: encrypted values are
        copied as they are, so the copy still needs the same
        :class:`DataKey` (and the same UUID, see :meth:`change_uuid`)
        to read them.
        """
        return Item.from_dict(self.to_dict())

    def __deepcopy__(self, memo: dict) -> Item:
        """Support :func:`copy.deepcopy` (see :meth:`deepcopy`)."""
        return self.deepcopy()

    def __repr__(self) -> str:
        """
        Return a debug-friendly representation of the item.

        Returns
        -------
        str
            A representation built only from the item's UUID, never
            from any field value, so it stays safe to print or log.
        """
        return f"{type(self).__name__}(uuid={self._uuid!r})"
