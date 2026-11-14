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

from typing import Literal, NoReturn, TypeAlias, SupportsIndex

import pyaescbc

from .exceptions import WrongPasswordError


KeyPurpose: TypeAlias = Literal["file", "data"]

#: Additional authenticated data bound to a wrapped key, per purpose.
#: Each purpose has its own label, so that a wrapped key can never be
#: accepted for the other purpose (e.g. if both passwords are equal),
#: nor any other password-mode bundle encrypted with the same password.
#: NEVER change them: existing wrapped keys could no longer be unwrapped.
_WRAP_AUTHDATA: dict[str, bytes] = {
    "file": b"bippass::file-key::v3",
    "data": b"bippass::data-key::v3",
}


def _wrap_authdata(purpose: KeyPurpose) -> bytearray:
    """
    Return the authenticated data of a wrapped key.

    Raises
    ------
    ValueError
        If ``purpose`` is not a known purpose.
    """
    try:
        return bytearray(_WRAP_AUTHDATA[purpose])
    except KeyError:
        raise ValueError(
            f"{purpose!r} is not a known key purpose, expected one of {tuple(_WRAP_AUTHDATA)}"
        ) from None


class DataKey:
    """
    Hold a random 32-byte key, stored wrapped by a password.

    A :class:`DataKey` is a 32-byte uniformly random key, as produced by
    :func:`pyaescbc.generate_key`, used with pyaescbc's key mode, which
    involves no key derivation: each operation takes microseconds. A
    password manager holds two of them (see :class:`Credentials`):

    - the **file key** (purpose ``"file"``), wrapped by the primary
      password, encrypts the whole content of the file;
    - the **data key** (purpose ``"data"``), wrapped by the secondary
      password, encrypts every :class:`EncryptedValue` (passwords,
      TOTP secrets, encrypted custom fields).

    A key is never stored in clear: it is stored *wrapped*, i.e.
    encrypted with its password by pyaescbc's password mode (see
    :meth:`wrap`/:meth:`unwrap`). The slow PBKDF2 derivation of each
    password therefore happens once per unlock, not once per value nor
    once per save.

    Parameters
    ----------
    key : bytearray
        32-byte random key. Stored by reference: the :class:`DataKey`
        takes ownership of it and wipes it in :meth:`clear`.

    Raises
    ------
    TypeError
        If ``key`` is not a :class:`bytearray`.

    ValueError
        If ``key`` is not exactly :data:`pyaescbc.KEY_SIZE` (32) bytes
        long.

    Notes
    -----
    The key lifecycle is::

        DataKey.random()                       (new profile, password change)
            ↓ wrap(password, purpose)
        bytearray (wrapped key, PACB bundle, stored in the file)
            ↓ unwrap(password, purpose)        (every unlock)
        DataKey (in memory for the session)
            ↓ clear()                          (lock / close)
        cleared, unusable

    **Why a dedicated type.** Key-mode functions of pyaescbc accept any
    32-byte ``bytearray`` as a key, including a 32-character password,
    which would then be used without any brute-force protection.
    Requiring a :class:`DataKey` wherever a data key is expected (see
    :class:`EncryptedValue`) makes that mistake impossible: a password
    can only enter the picture through :meth:`wrap`/:meth:`unwrap`.

    **Ownership.** The underlying ``bytearray`` is owned by this
    instance: :attr:`key` returns it by reference, so that it can be
    handed to pyaescbc without copying, but callers must never keep it
    beyond the call, nor wipe it themselves. Only :meth:`clear` is
    allowed to erase it.

    **No copies.** Copying (:func:`copy.copy`, :func:`copy.deepcopy`)
    and pickling are refused with a :class:`TypeError`: an untracked
    copy of the key would never be cleared. This also guarantees that
    no key is ever reachable from the state copied by
    :meth:`Item.deepcopy`.

    **After clear().** Every method that needs the key raises
    :class:`ValueError` once :meth:`clear` has been called, rather than
    silently encrypting with a zeroed key.

    The textual representation of an instance (:func:`repr`,
    :func:`str`) never shows the key, so it stays safe to print or log.

    Instances compare and hash by identity.

    This class performs no locking of its own (see the notes on threads
    of :class:`PasswordManager`).

    See Also
    --------
    EncryptedValue
        A single sensitive value, sealed and revealed with a
        :class:`DataKey`.

    Credentials
        Holds the :class:`DataKey` of a password manager for the
        duration of a session.
    """

    __slots__ = ("_key",)

    def __init__(self, key: bytearray) -> None:
        """
        Wrap an existing 32-byte random key.

        Parameters
        ----------
        key : bytearray
            32-byte random key, stored by reference (see the
            class-level Notes on ownership).

        Raises
        ------
        TypeError
            If ``key`` is not a :class:`bytearray`.

        ValueError
            If ``key`` is not exactly :data:`pyaescbc.KEY_SIZE` bytes
            long.

        Notes
        -----
        Prefer :meth:`random` to create a new key and :meth:`unwrap` to
        restore a stored one: this constructor does not, and cannot,
        check that ``key`` is actually random. Never pass a password.
        """
        if not isinstance(key, bytearray):
            raise TypeError(f"key must be bytearray, not {type(key)}")
        if len(key) != pyaescbc.KEY_SIZE:
            raise ValueError(
                f"key must be {pyaescbc.KEY_SIZE} bytes long."
            )
        self._key: bytearray | None = key

    @classmethod
    def random(cls) -> DataKey:
        """
        Create a new random data key.

        Returns
        -------
        DataKey
            A new key, drawn by :func:`pyaescbc.generate_key` from a
            cryptographically secure source of randomness.

        Notes
        -----
        Used when a profile is created, and whenever a password is
        changed (see :meth:`PasswordManager.change_primary_password`
        and :meth:`PasswordManager.change_secondary_password`).

        Examples
        --------
        >>> data_key = DataKey.random()
        """
        return cls(pyaescbc.generate_key())

    # ----------------
    # Access
    # ----------------

    @property
    def key(self) -> bytearray:
        """
        Return the raw key, to be passed to pyaescbc.

        Returns
        -------
        bytearray
            The 32-byte key, by reference (not a copy). Do not keep it,
            modify it or wipe it: see the class-level Notes on
            ownership.

        Raises
        ------
        ValueError
            If :meth:`clear` has been called.
        """
        if self._key is None:
            raise ValueError("The data key has been cleared.")
        return self._key

    @property
    def is_cleared(self) -> bool:
        """
        Whether :meth:`clear` has been called.

        Returns
        -------
        bool
            ``True`` if the key has been erased and can no longer be
            used.
        """
        return self._key is None

    # ----------------
    # Wrapping
    # ----------------

    def wrap(
        self,
        password: bytearray,
        iterations: int,
        *,
        purpose: KeyPurpose,
        delete_password: bool = True,
    ) -> bytearray:
        """
        Encrypt the key with a password, for storage.

        Parameters
        ----------
        password : bytearray
            Password used to derive the wrapping key.

        iterations : int
            Number of PBKDF2 iterations used to derive the wrapping key
            (see :class:`Credentials`). Stored in the wrapped key: it is
            not needed by :meth:`unwrap`.

        purpose : {"file", "data"}
            What the key is used for (keyword-only). Bound to the
            wrapped key as authenticated data: :meth:`unwrap` must be
            given the same purpose.

        delete_password : bool, optional
            Wipe ``password`` at the end of the call, even if an error
            occurs (default: ``True``). Once the key is wrapped, the
            password is no longer needed in memory.


        Returns
        -------
        bytearray
            The wrapped key: a pyaescbc password-mode (``PACB``) bundle,
            authenticated with the label of ``purpose``. Not secret.


        Raises
        ------
        TypeError
            If ``password`` is not a :class:`bytearray` or
            ``iterations`` is not an ``int``.

        ValueError
            If :meth:`clear` has been called, ``purpose`` is unknown,
            ``password`` is empty, or ``iterations`` is out of
            pyaescbc's allowed range.


        Notes
        -----
        The key itself is passed to :func:`pyaescbc.encrypt` with
        ``delete_data=False``: it stays usable after being wrapped.

        Slow by design (one full PBKDF2 derivation).

        Examples
        --------
        >>> wrapped = data_key.wrap(bytearray(b"secondary"), 5_000_000, purpose="data")
        """
        authdata = _wrap_authdata(purpose)
        return pyaescbc.encrypt(
            self.key, password,
            authdata=authdata,
            iterations=iterations,
            delete_keys=delete_password, delete_data=False,
        )

    @classmethod
    def unwrap(
        cls,
        wrapped: bytearray,
        password: bytearray,
        *,
        purpose: KeyPurpose,
        delete_password: bool = True,
    ) -> DataKey:
        """
        Decrypt a wrapped key with a password.

        Parameters
        ----------
        wrapped : bytearray
            Wrapped key, as returned by :meth:`wrap`. Never modified.

        password : bytearray
            Password the key was wrapped with.

        purpose : {"file", "data"}
            Purpose the key was wrapped for (keyword-only, see
            :meth:`wrap`).

        delete_password : bool, optional
            Wipe ``password`` at the end of the call, even if an error
            occurs (default: ``True``). Set it to ``False`` only if the
            caller still needs the password afterwards, and erases it
            itself.


        Returns
        -------
        DataKey
            The unwrapped key.


        Raises
        ------
        TypeError
            If ``wrapped`` or ``password`` is not a :class:`bytearray`.

        ValueError
            If ``purpose`` is unknown, ``password`` is empty,
            ``wrapped`` is malformed, or its content is not a 32-byte
            key.

        WrongPasswordError
            If ``password`` is wrong, ``wrapped`` was wrapped for
            another purpose, or it has been tampered with
            (authentication of the wrapped key fails). Callers
            translate it into :exc:`PrimaryPasswordError` or
            :exc:`SecondaryPasswordError`.


        Notes
        -----
        This is where a password is verified: a successful unwrap
        proves the password is right, so no separate ``auth`` value is
        needed.

        Slow by design (one full PBKDF2 derivation).

        Examples
        --------
        >>> data_key = DataKey.unwrap(wrapped, bytearray(b"secondary"), purpose="data")
        """
        authdata = _wrap_authdata(purpose)
        try:
            clear: bytearray = pyaescbc.decrypt(
                wrapped, password,
                authdata=authdata,
                delete_keys=delete_password, delete_data=False,
            )
        except pyaescbc.AuthError as exc:
            raise WrongPasswordError(
                "Wrong password, or the wrapped key has been tampered with."
            ) from exc

        if len(clear) != pyaescbc.KEY_SIZE:
            pyaescbc.delete_bytearray(clear)
            raise ValueError("The wrapped data does not contain a valid data key.")

        return cls(clear)

    # ----------------
    # Cleanup
    # ----------------

    def clear(self) -> None:
        """
        Erase the key from memory.

        Notes
        -----
        Irreversible. :attr:`key`, :meth:`wrap`, and every
        :class:`EncryptedValue` operation given this instance raise
        :class:`ValueError` after this call: the underlying bytearray
        is zeroed in place and then dropped. Calling it more than once
        is harmless.

        Wiping is best-effort: Python and the underlying libraries may
        keep immutable copies of the key (see pyaescbc's notes).
        """
        if self._key is not None:
            pyaescbc.delete_bytearray(self._key)
            self._key = None

    # ----------------
    # Copy protection
    # ----------------

    def __copy__(self) -> NoReturn:
        """Refuse shallow copies (see the class-level Notes)."""
        raise TypeError(f"{type(self).__name__} must not be copied.")

    def __deepcopy__(self, memo: dict) -> NoReturn:
        """Refuse deep copies (see the class-level Notes)."""
        raise TypeError(f"{type(self).__name__} must not be copied.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        """Refuse pickling (see the class-level Notes)."""
        raise TypeError(f"{type(self).__name__} must not be pickled.")

    # ----------------
    # Debug representation
    # ----------------

    def __repr__(self) -> str:
        """
        Return a debug-friendly representation of the key.

        Returns
        -------
        str
            ``"DataKey(<redacted>)"``, or ``"DataKey(<cleared>)"`` once
            :meth:`clear` has been called: the key is never shown, so
            it stays safe to print or log.
        """
        state = "cleared" if self._key is None else "redacted"
        return f"{type(self).__name__}(<{state}>)"
