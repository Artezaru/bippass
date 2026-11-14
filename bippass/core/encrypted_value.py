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

from dataclasses import dataclass

import pyaescbc

from .common import _b64decode, _b64encode
from .exceptions import TamperedDataError
from .datakey import DataKey


#: Magic of a pyaescbc key-mode bundle (``pyaescbc.encrypt_with_key``).
#: Duplicated here because pyaescbc only exposes it from an internal module.
_PACK_MAGIC = b"PACK"


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class EncryptedValue:
    """
    Represent a single sensitive value, encrypted with the data key.

    An :class:`EncryptedValue` holds nothing but a pyaescbc key-mode
    bundle (``PACK``): the ciphertext of one secret (a password, a TOTP
    secret, an encrypted custom field, ...). It never holds the clear
    value, nor the key used to encrypt it. The key, and the context the
    value is bound to, are supplied by the caller on every operation.

    Instances are immutable: "changing" a secret means sealing a new
    :class:`EncryptedValue` and replacing the old one, never mutating it
    in place.

    Parameters
    ----------
    bundle : bytearray
        Key-mode encrypted bundle, as produced by
        :func:`pyaescbc.encrypt_with_key`. Stored by reference.

    Notes
    -----
    Encrypted values use the following representation::

        bytearray (clear)
            ↓ pyaescbc.encrypt_with_key(data_key.key, authdata=context)
        bytearray (bundle, kept in memory)
            ↓ base64.b64encode()
        str (stored in the JSON, see :meth:`to_json`)

    Decryption performs the inverse operations.

    The bundle is kept in memory as a raw ``bytearray``: Base64 only
    exists at the serialization boundary (:meth:`to_json`/
    :meth:`from_json`). The bundle is not secret: it is never wiped by
    this class, and :meth:`reveal` never modifies it
    (``delete_data=False``).

    The dataclass is frozen, so :attr:`bundle` cannot be reassigned,
    but the ``bytearray`` itself remains mutable: it must be treated as
    read-only. Instances compare and hash by identity (``eq=False``):
    two seals of the same clear value never produce the same bundle
    anyway (random IV), so comparing bundles would be meaningless.

    **Key.** Every operation takes a :class:`DataKey`, never a raw
    ``bytearray`` nor a password: this makes it impossible to encrypt a
    value with a password used as a key, without any brute-force
    protection. Key-mode bundles involve no key derivation, so sealing
    or revealing a value only takes microseconds. The key is never
    wiped by this class (``delete_keys=False``): it is shared by every
    value of a password manager, and only :meth:`DataKey.clear` is
    allowed to erase it.

    **Context.** Every operation also takes a ``context``, passed to
    pyaescbc as ``authdata``: it is authenticated by the HMAC but neither
    encrypted nor stored in the bundle. It binds the value to its place
    in the password manager (typically the item UUID and the field
    name), so that a ciphertext copied from one item or field to
    another fails to decrypt instead of being silently accepted. The
    exact same context must be given to :meth:`reveal` as to
    :meth:`seal`. It is a ``bytearray``, as pyaescbc expects, and is
    never modified nor wiped: it is not secret. Building it is the job
    of :class:`Item`, not of the caller.

    The textual representation of an instance (:func:`repr`,
    :func:`str`) never shows the bundle, so it stays safe to print or
    log.

    See Also
    --------
    DataKey
        The key passed to every operation of this class.

    Item
        Holds the :class:`EncryptedValue` instances of an entry and
        builds their context.
    """

    bundle: bytearray

    def __post_init__(self) -> None:
        """
        Validate the bundle.

        Raises
        ------
        TypeError
            If ``bundle`` is not a ``bytearray``.

        ValueError
            If ``bundle`` is not a pyaescbc key-mode (``PACK``) bundle.

        Notes
        -----
        Only the magic is checked here, so that a password-mode
        (``PACB``) bundle from a version 1 file, which must go through
        the migration code instead, is rejected early with a clear
        message. The full structure of the bundle and its integrity are
        only checked when it is decrypted (:meth:`reveal`).
        """
        if not isinstance(self.bundle, bytearray):
            raise TypeError(f"bundle must be bytearray, not {type(self.bundle)}")
        if self.bundle[: len(_PACK_MAGIC)] != _PACK_MAGIC:
            raise ValueError(
                "bundle is not a pyaescbc key-mode (PACK) bundle."
            )

    # --------------------
    # Encryption
    # --------------------

    @classmethod
    def seal(
        cls,
        clear: bytearray,
        data_key: DataKey,
        context: bytearray,
    ) -> EncryptedValue:
        """
        Encrypt a clear-text value into a new :class:`EncryptedValue`.

        Parameters
        ----------
        clear : bytearray
            Clear-text UTF-8 encoded data to encrypt. It may be empty.
            Erased (zeroed) once it has been successfully encrypted, see
            Notes.

        data_key : DataKey
            Data key to encrypt with. Passed through unchanged (never
            wiped, never copied): see the class-level Notes.

        context : bytearray
            Context the value is bound to (see the class-level Notes).
            The same value must be given to :meth:`reveal`. Never
            modified (pyaescbc does not modify ``authdata``).


        Returns
        -------
        EncryptedValue
            The encrypted value.


        Raises
        ------
        TypeError
            If ``clear`` or ``context`` is not a ``bytearray``, or
            ``data_key`` is not a :class:`DataKey`.

        ValueError
            If ``data_key`` has been cleared.


        Notes
        -----
        ``clear`` is erased only if the encryption succeeded
        (``delete_data=True``, see :func:`pyaescbc.encrypt_with_key`):
        if an exception is raised, the clear-text value is left
        untouched so that it is not lost, and the caller remains
        responsible for erasing it.

        Examples
        --------
        >>> data_key = DataKey.random()
        >>> value = EncryptedValue.seal(
        ...     bytearray(b"hunter2"), data_key, bytearray(b"item-uuid|passwords")
        ... )
        """
        if not isinstance(clear, bytearray):
            raise TypeError(f"clear must be bytearray, not {type(clear)}")
        if not isinstance(data_key, DataKey):
            raise TypeError(f"data_key must be DataKey, not {type(data_key)}")
        if not isinstance(context, bytearray):
            raise TypeError(f"context must be bytearray, not {type(context)}")

        bundle: bytearray = pyaescbc.encrypt_with_key(
            clear, data_key.key,
            authdata=context,
            delete_keys=False, delete_data=True,
        )
        return cls(bundle)

    def reveal(
        self,
        data_key: DataKey,
        context: bytearray,
    ) -> bytearray:
        """
        Decrypt the value into a clear-text ``bytearray``.

        Parameters
        ----------
        data_key : DataKey
            Data key the value was sealed with. Passed through
            unchanged (never wiped, never copied): see the class-level
            Notes.

        context : bytearray
            Context the value was sealed with (see :meth:`seal`).


        Returns
        -------
        bytearray
            Decrypted data, encoded as UTF-8 bytes. The caller is
            responsible for erasing this buffer (e.g. via
            :func:`pyaescbc.delete_bytearray`) once it is no longer
            needed: :meth:`Item.revealed` does so.


        Raises
        ------
        TypeError
            If ``context`` is not a ``bytearray``, or ``data_key`` is
            not a :class:`DataKey`.

        ValueError
            If ``data_key`` has been cleared, or the bundle is malformed.

        TamperedDataError
            If authentication of the bundle fails: wrong ``data_key``, wrong
            ``context`` (the value was moved to another item or field),
            or the bundle has been modified.


        Notes
        -----
        A wrong secondary password is not reported here: it is
        detected once, when the data key itself is unwrapped
        (:meth:`DataKey.unwrap`). Since the
        data key has already been checked by then, an authentication
        failure here means the data itself is wrong, hence
        :exc:`TamperedDataError` rather than :exc:`SecondaryPasswordError`.

        The bundle is decrypted only after its HMAC has been verified
        (see :func:`pyaescbc.decrypt_with_key`). It is passed by
        reference and never wiped (``delete_data=False``): the value
        stays usable after being revealed.
        """
        if not isinstance(data_key, DataKey):
            raise TypeError(f"data_key must be DataKey, not {type(data_key)}")
        if not isinstance(context, bytearray):
            raise TypeError(f"context must be bytearray, not {type(context)}")

        try:
            return pyaescbc.decrypt_with_key(
                self.bundle, data_key.key,
                authdata=context,
                delete_keys=False, delete_data=False,
            )
        except pyaescbc.AuthError as exc:
            raise TamperedDataError(
                "Encrypted value failed authentication: wrong key or "
                "context, or the data has been tampered with."
            ) from exc

    # -----------------
    # Serialization
    # -----------------

    def to_json(self) -> str:
        """
        Return the serialized representation of the value.

        Returns
        -------
        str
            The bundle, Base64-encoded, suitable for JSON serialization.
        """
        return _b64encode(self.bundle)

    @classmethod
    def from_json(cls, value: str) -> EncryptedValue:
        """
        Create an :class:`EncryptedValue` from its serialized representation.

        Parameters
        ----------
        value : str
            Base64-encoded bundle, as returned by :meth:`to_json`.


        Returns
        -------
        EncryptedValue
            The deserialized value. Its bundle is not authenticated
            yet: that only happens when it is decrypted (:meth:`reveal`).


        Raises
        ------
        TypeError
            If ``value`` is not a ``str``.

        CorruptedBase64Error
            If ``value`` is not valid Base64 data (invalid padding or
            characters outside the Base64 alphabet).

        ValueError
            If the decoded data is not a pyaescbc key-mode (``PACK``)
            bundle (see :meth:`__post_init__`).
        """
        return cls(_b64decode("encrypted value", value))

    def __repr__(self) -> str:
        """
        Return a debug-friendly representation of the value.

        Returns
        -------
        str
            Always ``"EncryptedValue(<redacted>)"``: neither the bundle
            nor its length is shown, so it stays safe to print or log.
        """
        return f"{type(self).__name__}(<redacted>)"
