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

import base64
import binascii
import datetime

from enum import Enum, auto
from typing import Literal, Sequence, cast, Tuple, TypeAlias
from .types import ItemData, ClearString, CryptedBase64String, ClearSecretBytes, ClearStringList, ClearSecretBytesList, CryptedBase64StringList, ItemKind
from .exceptions import SecondaryPasswordError, CorruptedBase64Error, CorruptedUtf8Error
from .credentials import Credentials

import pyaescbc


ItemField: TypeAlias = Literal[
    "item_name", "icon", "item_date",
    "logins", "websites", "phones", "emails",
    "passwords", "totps",
]

class FieldKind(Enum):
    SCALAR = auto()
    ENCRYPTED = auto()
    SCALAR_LIST = auto()
    ENCRYPTED_LIST = auto()

_FIELDS: dict[str, FieldKind] = {
    "item_name": FieldKind.SCALAR,
    "item_date": FieldKind.SCALAR,
    "icon":      FieldKind.SCALAR,
    "logins":    FieldKind.SCALAR_LIST,
    "websites":  FieldKind.SCALAR_LIST,
    "phones":    FieldKind.SCALAR_LIST,
    "emails":    FieldKind.SCALAR_LIST,
    "passwords": FieldKind.ENCRYPTED_LIST,
    "totps":     FieldKind.ENCRYPTED_LIST,
}

_CUSTOM_KINDS: dict[str, FieldKind] = {
    "SCALAR":         FieldKind.SCALAR,
    "ENCRYPTED":      FieldKind.ENCRYPTED,
    "SCALAR LIST":    FieldKind.SCALAR_LIST,
    "ENCRYPTED LIST": FieldKind.ENCRYPTED_LIST,
}


class Item:
    """
    Represent a single password vault item.

    An item contains both unencrypted and encrypted information. Metadata
    such as the item name, icon, logins, websites, phone numbers, and email
    addresses are stored directly in the item data. Sensitive values such
    as passwords and TOTP secrets are stored as Base64-encoded encrypted
    values.

    The :class:`Item` class is responsible for managing its own data and
    performing encryption or decryption of sensitive fields. The caller
    must provide a :class:`Credentials` instance holding the secondary
    password and iteration count when accessing encrypted values.

    Parameters
    ----------
    item_uuid : str
        Globally unique identifier of the item.

    data : ItemData
        Serialized item data.

    Notes
    -----
    The ``data`` dictionary is kept by reference and modified directly
    when the item is updated. No copy of the dictionary is created.

    Encrypted fields use the following representation::

        bytearray
            ↓ pyaescbc.encrypt()
        bytearray
            ↓ base64.b64encode()
        str

    Decryption performs the inverse operations.

    Every encrypted-field operation takes a :class:`Credentials`
    instance rather than a bare ``password``/``iterations`` pair.
    ``Credentials`` is meant to be a single object shared across every
    item of a :class:`PasswordManager` (typically
    ``manager._credentials``, or whatever a caller like
    :class:`ItemViewer` obtains from it), so its password is *not*
    wiped after each individual encrypt/decrypt call: every
    :func:`pyaescbc.encrypt`/:func:`pyaescbc.decrypt` call below uses
    ``delete_keys=False`` for exactly this reason — only
    :meth:`Credentials.clear` (or overwriting it via
    :meth:`Credentials.set_secondary_password`) is allowed to erase that
    password. What *does* get wiped after each call, via
    ``delete_data=True``, is the transient plaintext/ciphertext buffer
    involved in that one call — never the shared credentials.

    See Also
    --------
    Vault
        Container for multiple :class:`Item` instances.

    PasswordManager
        Top-level manager responsible for vaults and encryption contexts.

    Credentials
        Holds the password and iteration count passed to every
        encrypted-field operation on this class.
    """

    def __init__(self, item_uuid: str, data: ItemData) -> None:
        """
        Initialize an item.

        Parameters
        ----------
        item_uuid : str
            Globally unique identifier of the item.
        
        data : ItemData
            Serialized item data. The dictionary is stored by reference.
        """
        self._uuid: str = item_uuid
        self._data: ItemData = data

    @classmethod
    def create_empty(cls, item_uuid: str) -> Item:
        """
        Create an empty item.

        All optional item fields are initialized to ``None``. The item
        can subsequently be populated using the public setter methods.

        Parameters
        ----------
        item_uuid : str
            Globally unique identifier for the new item.

        Returns
        -------
        Item
            Newly created empty item.

        Notes
        -----
        UUID uniqueness is normally guaranteed by
        :meth:`PasswordManager.create_uuid` or
        :meth:`PasswordManager.add_empty_item`.
        """
        return cls(
            item_uuid,
            {
                "item_name": None,
                "item_date": datetime.datetime.now().isoformat(),
                "icon": None,
                "logins": None,
                "passwords": None,
                "totps": None,
                "websites": None,
                "phones": None,
                "emails": None,
                "custom": None,
            },
        )

    @property
    def uuid(self) -> str:
        """
        Return the unique identifier of the item.

        Returns
        -------
        str
            Item UUID.
        """
        return self._uuid

    def _update(self) -> None:
        """
        Udpate the date of the item.
        """
        self._data['item_date'] = datetime.datetime.now().isoformat()

    # --------------------
    # Encryption
    # --------------------

    def _decrypt(
        self,
        value: CryptedBase64String,
        password: bytearray,
    ) -> bytearray:
        """
        Decrypt a Base64-encoded encrypted value into a clear-text ``bytearray``.

        Parameters
        ----------
        value : CryptedBase64String
            Base64-encoded encrypted data, as stored in the item.

        password : bytearray
            Secondary password used to derive the decryption key, as
            held by a :class:`Credentials` instance. Passed through
            unchanged (never wiped, never copied): see the class-level
            Notes for why.


        Returns
        -------
        bytearray
            Decrypted data, encoded as UTF-8 bytes. The caller is
            responsible for erasing this buffer (e.g. via
            :func:`pyaescbc.delete_bytearray`) once it is no longer
            needed.


        Raises
        ------
        TypeError
            If ``value`` is not a ``str`` or ``password`` is not a
            ``bytearray``.

        CorruptedBase64Error
            If ``value`` is not valid Base64 data (invalid padding
            or characters outside the Base64 alphabet).

        SecondaryPasswordError
            If ``password`` is wrong, causing authentication of the
            encrypted data to fail.


        Notes
        -----
        Errors other than the ones listed above (for example a
        ``ValueError`` or ``TypeError`` raised internally by
        :func:`pyaescbc.decrypt` because of a malformed argument) are
        intentionally left unhandled: they indicate a programming
        error rather than a normal, user-recoverable failure, and
        should not be disguised as :exc:`SecondaryPasswordError`.

        The decoded ciphertext buffer is wiped after use
        (``delete_data=True``); ``password`` is left untouched
        (``delete_keys=False``) since it belongs to a shared
        :class:`Credentials` instance that outlives this single call.
        """
        if not isinstance(value, str):
            raise TypeError(f"Expected value as string, got {type(value)}")
        if not isinstance(password, bytearray):
            raise TypeError(f"Expected password as bytearray, got {type(password)}")

        try:
            encrypted_data: bytearray = bytearray(
                base64.b64decode(value, validate=True)
            )
        except binascii.Error as exc:
            raise CorruptedBase64Error(
                "Corrupted item data: invalid Base64 encoding."
            ) from exc

        try:
            return pyaescbc.decrypt(
                encrypted_data, password,
                delete_keys=False, delete_data=True,
            )
        except pyaescbc.AuthError as exc:
            raise SecondaryPasswordError(
                "Wrong secondary password."
            ) from exc

        
    def _encrypt(
        self,
        value: bytearray,
        password: bytearray,
        iterations: int,
    ) -> CryptedBase64String:
        """
        Encrypt a clear-text ``bytearray`` and encode the result as Base64.

        Parameters
        ----------
        value : bytearray
            Clear-text UTF-8 encoded data to encrypt. This buffer is
            erased (zeroed) before the function returns, regardless
            of success or failure.

        password : bytearray
            Secondary password used to derive the encryption key, as
            held by a :class:`Credentials` instance. Passed through
            unchanged (never wiped, never copied): see the class-level
            Notes for why.

        iterations : int
            Number of iterations used to derive the encryption key.


        Returns
        -------
        CryptedBase64String
            Base64-encoded encrypted data, suitable for storage.


        Raises
        ------
        TypeError
            If ``value`` is not a ``bytearray``, ``password`` is not
            a ``bytearray``, or ``iterations`` is not an ``int``.

        SecondaryPasswordError
            If encryption fails because of an authentication error
            (for example a mismatched key derivation).


        Notes
        -----
        ``value`` is always erased before this function returns, even
        if an exception is raised (``delete_data=True``), so that the
        clear-text secret does not linger in memory beyond the call.
        ``password`` is left untouched (``delete_keys=False``) since
        it belongs to a shared :class:`Credentials` instance that
        outlives this single call.
        """
        if not isinstance(value, bytearray):
            raise TypeError(f"Expected value as bytearray, got {type(value)}")
        if not isinstance(password, bytearray):
            raise TypeError(f"Expected password as bytearray, got {type(password)}")
        if not isinstance(iterations, int):
            raise TypeError(f"Expected iterations as integer, got {type(iterations)}")

        try:
            encrypted_data: bytearray = pyaescbc.encrypt(
                value, password, iterations=iterations,
                delete_keys=False, delete_data=True,
            )
        except pyaescbc.AuthError as exc:
            raise SecondaryPasswordError(
                "Wrong secondary password or iterations."
            ) from exc

        try:
            return base64.b64encode(encrypted_data).decode('utf-8')
        finally:
            pyaescbc.delete_bytearray(encrypted_data)

    # -----------------------
    # Internal getter and setters
    # -----------------------
    def _decrypt_converter(
        self,
        field: str,
        value: ClearString | CryptedBase64String | ClearStringList | CryptedBase64StringList | None,
        kind: FieldKind,
        credentials: Credentials | None,
    ) -> ClearString | ClearSecretBytes | ClearStringList | ClearSecretBytesList | None:
        """
        Convert a stored item value into its clear-text representation.

        The conversion performed by this method depends on the supplied
        :class:`FieldKind`. Plain fields are returned without encryption
        processing, while encrypted fields are decrypted using the
        secondary password and iteration count held by ``credentials``.

        Parameters
        ----------
        field : str
            Name of the field being converted, used only to build
            readable error messages.

        value : ClearString or CryptedBase64String or ClearStringList or
                CryptedBase64StringList or None
            Value as stored internally by the item.

        kind : FieldKind
            Storage kind describing how ``value`` is represented.

            ``FieldKind.SCALAR``
                A single unencrypted string.

            ``FieldKind.ENCRYPTED``
                A single Base64-encoded encrypted value.

            ``FieldKind.SCALAR_LIST``
                A list of unencrypted strings.

            ``FieldKind.ENCRYPTED_LIST``
                A list of Base64-encoded encrypted values.

        credentials : Credentials, optional
            Holds the secondary password and iteration count used to
            decrypt ``ENCRYPTED``/``ENCRYPTED_LIST`` values. Required
            for those two kinds; ignored otherwise.


        Returns
        -------
        ClearString or ClearSecretBytes or ClearStringList or ClearSecretBytesList or None
            The field's value: a plain string for scalar fields, a
            decrypted ``bytearray`` for encrypted fields, a
            list of strings for clear-list fields, a list of
            decrypted ``bytearray`` for encrypted-list fields, or
            ``None`` if the field is not set.


        Raises
        ------
        ValueError
            If an encrypted field is accessed without ``credentials``.

        CorruptedBase64Error
            If an encrypted value contains invalid Base64 data.

        SecondaryPasswordError
            If decryption fails because the secondary credentials are
            incorrect or the encrypted data cannot be authenticated.


        Notes
        -----
        Decrypted values are returned as ``bytearray`` objects so that
        callers can explicitly erase their contents from memory when they
        are no longer required.

        List values are returned as new lists and therefore do not expose
        the item's internal list object.
        """
        if value is None:
            return None

        if kind is FieldKind.SCALAR:
            if not isinstance(value, str):
                raise TypeError(f"value must be a string, not {type(value)}")
            return cast(ClearString, value)

        if kind is FieldKind.ENCRYPTED:
            if not isinstance(value, str):
                raise TypeError(f"value must be a string, not {type(value)}")
            if credentials is None:
                raise ValueError(
                    f"{field!r} is an encrypted field: credentials are required."
                )
            return cast(ClearSecretBytes, self._decrypt(
                value,
                credentials.get_secondary_password(),
            ))

        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise TypeError(f"value must be a list, not {type(value)}")

        if kind is FieldKind.SCALAR_LIST:
            if not all(isinstance(v, str) for v in value):
                raise TypeError("value must contain strings.")
            return cast(ClearStringList, list(value))

        if kind is FieldKind.ENCRYPTED_LIST:
            if not all(isinstance(v, str) for v in value):
                raise TypeError("value must contain base64 strings.")
            if credentials is None:
                raise ValueError(
                    f"{field!r} is an encrypted field: credentials are required."
                )
            password = credentials.get_secondary_password()
            return cast(ClearSecretBytesList, [self._decrypt(v, password) for v in value])

        raise AssertionError(f"unhandled field kind: {kind!r}")  # pragma: no cover

    def _encrypt_converter(
        self,
        field: str,
        value: ClearString | ClearSecretBytes | ClearStringList | ClearSecretBytesList | None,
        kind: FieldKind,
        credentials: Credentials | None,
    ) -> ClearString | CryptedBase64String | ClearStringList | CryptedBase64StringList | None:
        """
        Convert a clear-text item value into its internal representation.

        The conversion performed by this method depends on the supplied
        :class:`FieldKind`. Plain fields remain unencrypted, while sensitive
        fields are encrypted using the secondary password and iteration
        count held by ``credentials``.

        Parameters
        ----------
        field : str
            Name of the field being converted, used only to build
            readable error messages.

        value : ClearString or ClearSecretBytes or ClearStringList or
                ClearSecretBytesList or None
            Clear-text value supplied by the caller.

            ``bytearray`` values are used for encrypted fields so that
            sensitive data can be explicitly erased from memory.

        kind : FieldKind
            Storage kind describing how ``value`` must be stored.

            ``FieldKind.SCALAR``
                Stores a single clear-text string.

            ``FieldKind.ENCRYPTED``
                Encrypts a single ``bytearray`` and stores the result
                as a Base64-encoded string.

            ``FieldKind.SCALAR_LIST``
                Stores a list of clear-text strings.

            ``FieldKind.ENCRYPTED_LIST``
                Encrypts each ``bytearray`` in the list and stores the
                resulting Base64 strings.

        credentials : Credentials, optional
            Holds the secondary password and iteration count used to
            encrypt ``ENCRYPTED``/``ENCRYPTED_LIST`` values. Required
            for those two kinds; ignored otherwise.

        Returns
        -------
        ClearString or CryptedBase64String or ClearStringList or CryptedBase64StringList or None
            Value converted to the representation used internally by
            the item.

        Raises
        ------
        TypeError
            If ``value`` does not match the type required by ``kind``.

        ValueError
            If an encrypted field is provided without ``credentials``.

        SecondaryPasswordError
            If encryption fails because of an authentication error.

        Notes
        -----
        Encrypted values are converted to Base64 strings after encryption,
        making them directly serializable to JSON.

        The ``bytearray`` values supplied for encrypted fields are passed
        to :meth:`_encrypt`, which is responsible for clearing the
        clear-text buffer after encryption.
        """
        if value is None:
            return None

        if kind is FieldKind.SCALAR:
            if not isinstance(value, str):
                raise TypeError(f"value must be a string, not {type(value)}")
            return cast(ClearString, value)

        if kind is FieldKind.ENCRYPTED:
            if not isinstance(value, bytearray):
                raise TypeError(f"value must be a bytearray, not {type(value)}")
            if credentials is None:
                raise ValueError(
                    f"{field!r} is an encrypted field: credentials are required."
                )
            return cast(CryptedBase64String, self._encrypt(
                value,
                credentials.get_secondary_password(),
                credentials.get_secondary_iterations(),
            ))

        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise TypeError(f"value must be a list, not {type(value)}")

        if kind is FieldKind.SCALAR_LIST:
            if not all(isinstance(v, str) for v in value):
                raise TypeError("value must contain strings.")
            return cast(ClearStringList, list(value))

        if kind is FieldKind.ENCRYPTED_LIST:
            if credentials is None:
                raise ValueError(
                    f"{field!r} is an encrypted field: credentials are required."
                )
            if not all(isinstance(v, bytearray) for v in value):
                raise TypeError("value must contain bytearray.")
            password = credentials.get_secondary_password()
            iterations = credentials.get_secondary_iterations()
            return cast(CryptedBase64StringList, [
                self._encrypt(v, password, iterations) for v in value
            ])

        raise AssertionError(f"unhandled field kind: {kind!r}")  # pragma: no cover

    # -----------------------
    # Getters and Setters
    # -----------------------
    def _kind_of(self, field: str) -> FieldKind:
        """Return the storage kind associated with a field name.

        Parameters
        ----------
        field : str
            Name of the item field to look up.

        Returns
        -------
        FieldKind
            Storage kind describing how ``field`` is represented
            (scalar, encrypted, clear list, or encrypted list).

        Raises
        ------
        KeyError
            If ``field`` is not a recognized item field.
        """
        try:
            return _FIELDS[field]
        except KeyError:
            raise KeyError(
                f"{field!r} is not a known item field, expected one of {tuple(_FIELDS)}"
            ) from None

    def get(
        self,
        field: ItemField,
        *,
        credentials: Credentials | None = None,
    ) -> ClearString | ClearSecretBytes | ClearStringList | ClearSecretBytesList | None:
        """Return the value of an item field.

        Parameters
        ----------
        field : ItemField
            Name of the field to retrieve. See :data:`_FIELDS` for the
            set of recognized fields.

        credentials : Credentials, optional
            Holds the secondary password and iteration count used to
            decrypt the field. Required only when ``field`` is an
            encrypted field (e.g. ``"passwords"``, ``"totps"``).


        Returns
        -------
        ClearString or ClearSecretBytes or ClearStringList or ClearSecretBytesList or None
            The field's value: a plain string for scalar fields, a
            decrypted ``bytearray`` for encrypted fields, a
            list of strings for clear-list fields, a list of
            decrypted ``bytearray`` for encrypted fields, or
            ``None`` if the field is not set.


        Raises
        ------
        KeyError
            If ``field`` is not a recognized item field.

        ValueError
            If ``field`` is an encrypted field and ``credentials`` is
            not provided.

        SecondaryPasswordError
            If decryption fails because of a wrong password or
            corrupted data.


        Notes
        -----
        List fields are returned as new lists, never a reference to
        the item's internal storage: mutating the returned list does
        not affect the item.
        """
        kind = self._kind_of(field)
        value = self._data[field]
        try:
            return self._decrypt_converter(field, value, kind, credentials)
        except TypeError as exc:
            raise TypeError(
                f"Error getting field '{field}' with kind '{kind}' - {exc}. Value is '{value}'"
            ) from exc
    
    def set(
        self,
        field: ItemField,
        value: ClearString | ClearSecretBytes | ClearStringList | ClearSecretBytesList | None,
        *,
        credentials: Credentials | None = None,
    ) -> None:
        """Set the value of an item field.

        Parameters
        ----------
        field : ItemField
            Name of the field to update. See :data:`_FIELDS` for the
            set of recognized fields.

        value : ClearString or ClearSecretBytes or ClearStringList or ClearSecretBytesList or None
            New field value. Must be a ``str`` for scalar fields, a
            decrypted ``bytearray`` for encrypted fields, a
            list of ``str`` for clear-list fields, or a list of
            ``bytearray`` for encrypted-list fields. ``None`` removes
            the value.

        credentials : Credentials, optional
            Holds the secondary password and iteration count used to
            encrypt the field. Required only when ``field`` is an
            encrypted field.


        Raises
        ------
        KeyError
            If ``field`` is not a recognized item field.

        TypeError
            If ``value`` does not match the expected type for
            ``field``'s kind.

        ValueError
            If ``field`` is an encrypted field and ``credentials`` is
            not provided.
        """
        kind = self._kind_of(field)
        try:
            self._data[field] = self._encrypt_converter(field, value, kind, credentials)
        except TypeError as exc:
            raise TypeError(
                f"Error setting field '{field}' with kind '{kind}' - {exc}. Given value is '{value}'"
            ) from exc
        self._update()


    # --------------------
    # Custom field
    # --------------------    
    def custom_fields(self) -> Tuple[str, ...]:
        """Return the names of the custom fields.

        Returns
        -------
        tuple of str
            Names of the custom fields currently set on this
            item. Empty tuple if none are set.
        """
        store = self._data["custom"]
        return tuple(store) if store else ()

    def _custom_kind_map(self, kind: str) -> FieldKind:
        """
        Return the storage kind associated with a kind name.

        Parameters
        ----------
        kind : str
            Name of the item kind to look up.

        Returns
        -------
        FieldKind
            Storage kind describing how ``field`` is represented
            (scalar, encrypted, clear list, or encrypted list).

        Raises
        ------
        KeyError
            If ``field`` is not a recognized item field.
        """
        try:
            return _CUSTOM_KINDS[kind]
        except KeyError:
            raise KeyError(
                f"{kind!r} is not a known item kind, expected one of {tuple(_CUSTOM_KINDS)}"
            ) from None

    def get_custom(
        self,
        field: str,
        *,
        credentials: Credentials | None = None,
    ) -> ClearString | ClearSecretBytes | ClearStringList | ClearSecretBytesList | None:
        """Return the value of a custom item field.

        Parameters
        ----------
        field : str
            Name of the field to retrieve.

        credentials : Credentials, optional
            Holds the secondary password and iteration count used to
            decrypt the field. Required only when ``field`` is an
            encrypted field.


        Returns
        -------
        ClearString or ClearSecretBytes or ClearStringList or ClearSecretBytesList or None
            The field's value: a plain string for scalar fields, a
            decrypted ``bytearray`` for encrypted fields, a
            list of strings for clear-list fields, a list of
            decrypted ``bytearray`` for encrypted-list fields, or
            ``None`` if the field is not set.


        Raises
        ------
        KeyError
            If ``field`` is not a recognized item field.

        ValueError
            If ``field`` is an encrypted field and ``credentials`` is
            not provided.

        SecondaryPasswordError
            If decryption fails because of a wrong password or
            corrupted data.


        Notes
        -----
        List fields are returned as new lists, never a reference to
        the item's internal storage: mutating the returned list does
        not affect the item.
        """
        store = self._data["custom"] or {}
        if field not in store:
            raise KeyError(f"{field!r} not in {tuple(store)}")

        kindstr, value = store[field]
        kind = self._custom_kind_map(kindstr)

        try:
            return self._decrypt_converter(field, value, kind, credentials)
        except TypeError as exc:
            raise TypeError(
                f"Error getting custom field '{field}' with kind '{kind}' - {exc}. Value is '{value}'"
            ) from exc


    def set_custom(
        self,
        field: str,
        value: ClearString | ClearSecretBytes | ClearStringList | ClearSecretBytesList | None,
        kindstr: ItemKind | None,
        *,
        credentials: Credentials | None = None,
    ) -> None:
        """
        Set the value of a custom item field.

        Parameters
        ----------
        field : str
            Name of the field to update. 

        value : ClearString or ClearSecretBytes or ClearStringList or ClearSecretBytesList or None
            New field value. Must be a ``str`` for scalar fields, a
            decrypted ``bytearray`` for encrypted fields, a
            list of ``str`` for clear-list fields, or a list of
            ``bytearray`` for encrypted-list fields. ``None`` removes
            the value.

        kindstr : ItemKind or None
            The kind of the setted item. 
            None is accepted only if the field already exist.

        credentials : Credentials, optional
            Holds the secondary password and iteration count used to
            encrypt the field. Required only when ``field`` is an
            encrypted field.


        Raises
        ------
        KeyError
            If ``field`` is not a recognized item field.

        TypeError
            If ``value`` does not match the expected type for
            ``field``'s kind.

        ValueError
            If ``field`` is an encrypted field and ``credentials`` is
            not provided.
        """
        if not isinstance(field, str):
            raise TypeError(f"field must be a string, not {type(field)}")
        
        if kindstr is None:
            if field not in self.custom_fields():
                raise TypeError(f"kindstr must be a string, not {type(kindstr)}")
            kindstr = self._data["custom"][field][0]
            
        kind = self._custom_kind_map(kindstr)

        try:
            value = self._encrypt_converter(field, value, kind, credentials)
        except TypeError as exc:
            raise TypeError(
                f"Error setting custom field '{field}' with kind '{kind}' - {exc}. Given value is '{value}'"
            ) from exc
        
        if not self._data['custom']:
            self._data['custom'] = {}
        
        self._data['custom'][field] = (kindstr, value)
        self._update()

    def remove_custom(
        self,
        field: str,
    ) -> None:
        """
        Remove a custom item field.

        Parameters
        ----------
        field : str
            Name of the custom field to remove.

        Raises
        ------
        TypeError
            If ``field`` is not a string.

        KeyError
            If ``field`` does not exist.

        Notes
        -----
        Removing an encrypted custom field only removes its encrypted
        representation from the item. No decryption is performed.

        If the item no longer contains any custom fields after removal,
        the internal custom-field storage is set to ``None``.

        Examples
        --------
        >>> item.remove_custom("RecoveryCode")
        """
        if not isinstance(field, str):
            raise TypeError(
                f"field must be a string, not {type(field)}"
            )

        store = self._data["custom"]

        if not store or field not in store:
            raise KeyError(
                f"{field!r} is not a custom field."
            )

        del store[field]

        if not store:
            self._data["custom"] = None

        self._update()

    # ----------------
    # Force
    # ----------------
    def _force_encrypt(
        self,
        credentials: Credentials,
    ) -> None:
        """
        Considering each CryptedBase64String of the ItemData as ClearString.
        Use the given credentials to encrypt all the sensitive datas.
        
        .. warning::

            Do not use on encrypted items !

        Parameters
        ----------
        credentials : Credentials
            Holds the secondary password and iteration count used to
            encrypt every sensitive field.


        Raises
        ------
        TypeError
            If a stored value cannot be converted to the ``bytearray``
            expected for its field kind.

        SecondaryPasswordError
            If encryption fails because of an authentication error
            (for example a mismatched key derivation).
        """
        for field, kind in _FIELDS.items():
            value = self._data[field]

            if value is not None:
                if kind is FieldKind.ENCRYPTED:
                    value = bytearray(value, 'utf-8')
                if kind is FieldKind.ENCRYPTED_LIST:
                    value = list(bytearray(v, 'utf-8') for v in value)
            
            self.set(
                field, 
                value,
                credentials=credentials,
            )

        store = self._data['custom'] or {}
        for field, (kindstr, value) in store.items():
            kind = self._custom_kind_map(kindstr)

            if value is not None:
                if kind is FieldKind.ENCRYPTED:
                    value = bytearray(value, 'utf-8')
                if kind is FieldKind.ENCRYPTED_LIST:
                    value = list(bytearray(v, 'utf-8') for v in value)
            
            self.set_custom(
                field, 
                value,
                kindstr,
                credentials=credentials,
            )

    def _force_decrypt(
        self,
        credentials: Credentials,
    ) -> None:
        """
        Decrypt each CryptedBase64String of the ItemData to ClearString.
        Use the given credentials to decrypt all the sensitive datas.
        
        .. warning::

            Thiw will remove the encryption of the full item !

        Parameters
        ----------
        credentials : Credentials
            Holds the secondary password and iteration count used to
            decrypt every sensitive field.


        Raises
        ------
        TypeError
            If a decrypted value cannot be converted back to ``str``.

        SecondaryPasswordError
            If decryption fails because of an authentication error
            (for example a mismatched key derivation).
        """
        for field, kind in _FIELDS.items():
            value = self.get(
                field, 
                credentials=credentials,
            )

            if value is not None:
                if kind is FieldKind.ENCRYPTED:
                    value = value.decode('utf-8')
                if kind is FieldKind.ENCRYPTED_LIST:
                    value = list(v.decode('utf-8') for v in value)
            
            self._data[field] = value

        store = self._data['custom'] or {}
        for field, (kindstr, value) in store.items():
            kind = self._custom_kind_map(kindstr)
            value = self.get_custom(
                field, 
                credentials=credentials,
            )

            if value is not None:
                if kind is FieldKind.ENCRYPTED:
                    value = value.decode('utf-8')
                if kind is FieldKind.ENCRYPTED_LIST:
                    value = list(v.decode('utf-8') for v in value)
            
            store[field] = (kindstr, value)

    def change_credentials(
        self,
        old_credentials: Credentials,
        new_credentials: Credentials,
    ) -> None:
        """
        Re-encrypt all sensitive data with new secondary credentials.
        
        This method allows changing the secondary password and/or
        iteration count by re-encrypting all item data, decrypting
        every field with ``old_credentials`` and re-encrypting it with
        ``new_credentials``.
        
        .. warning::

            All data will be encrypted with the new credentials!
            ``old_credentials`` will no longer work for this item
            after this operation.

        Parameters
        ----------
        old_credentials : Credentials
            Holds the secondary password and iteration count
            currently used to encrypt this item's data.

        new_credentials : Credentials
            Holds the secondary password and iteration count to
            re-encrypt this item's data with.

        Raises
        ------
        SecondaryPasswordError
            If decryption fails because of an authentication error
            (for example a mismatched old key derivation).

        Notes
        -----
        Atomic with respect to ``old_credentials`` failures: every
        field — standard and custom — is decrypted with
        ``old_credentials`` first, all of them, before anything is
        written back. If any field fails to decrypt (wrong
        ``old_credentials``, corrupted data), this method raises
        during that first pass, before touching ``self._data`` at
        all, so the item is left exactly as it was.

        Only once every field has been successfully decrypted does
        the second pass run: re-encrypting and writing each field
        with ``new_credentials``. That pass does not decrypt
        anything, so it should not normally fail the way the first
        pass can — but it is not itself guarded. If it did fail
        partway through (a programming error, not a wrong password),
        the item could be left with some fields already under
        ``new_credentials`` and others still under
        ``old_credentials``. See :meth:`Vault.change_credentials`
        for the same decrypt-everything-first, then
        commit-everything pattern applied across a whole vault.

        Renamed from the original ``change_credantials`` (a typo) to
        ``change_credentials`` while this method was already being
        updated to take :class:`Credentials` instances instead of
        separate password/iteration arguments — update any caller
        accordingly.
        """
        # Phase 1 -- decrypt everything with `old_credentials` first,
        # writing nothing back yet. A failure here (wrong password,
        # corrupted data) raises before any mutation happens.
        standard_values = {
            field: self.get(field, credentials=old_credentials)
            for field in _FIELDS
        }

        custom_store = self._data['custom'] or {}
        custom_values = {
            field: (kindstr, self.get_custom(field, credentials=old_credentials))
            for field, (kindstr, _stored) in custom_store.items()
        }

        # Phase 2 -- everything above decrypted successfully, so it is
        # now safe to re-encrypt and commit every field with
        # `new_credentials`.
        for field, value in standard_values.items():
            self.set(field, value, credentials=new_credentials)

        for field, (kindstr, value) in custom_values.items():
            self.set_custom(field, value, kindstr, credentials=new_credentials)

        self._update()
            
    # -----------------
    # Export
    # -----------------
    def to_dict(self) -> ItemData:
        """
        Return the serialized item data.

        Returns
        -------
        ItemData
            Internal item representation suitable for JSON serialization.

        Notes
        -----
        The returned dictionary is the actual internal dictionary and is
        therefore not a copy. Modifying it directly modifies the item.
        """
        return self._data