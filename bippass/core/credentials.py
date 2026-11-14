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

from typing import NoReturn, SupportsIndex

from .datakey import DataKey


class Credentials:
    """
    Hold the two keys of an unlocked password manager.

    A :class:`PasswordManager` is protected by two independent
    passwords, each of which wraps a random :class:`DataKey`:

    - the **primary** password wraps the **file key**, which encrypts
      the whole content of the file (vaults, items, metadata);
    - the **secondary** password wraps the **data key**, which encrypts
      every sensitive value (passwords, TOTP secrets, encrypted custom
      fields) inside that content.

    This class holds the two *keys*, never the passwords: a password is
    only needed for the time it takes to unwrap (or wrap) its key, and
    is erased right after (see :meth:`DataKey.unwrap`).

    Notes
    -----
    **Layers.** Each key is set independently, as each layer is
    unlocked (see :meth:`PasswordManager.unlock` and
    :meth:`PasswordManager.decrypt`). Reading a key whose layer
    is still locked raises :class:`RuntimeError`.

    **Iterations.** Both passwords use the same, fixed number of PBKDF2
    iterations (:attr:`PRIMARY_ITERATIONS`, :attr:`SECONDARY_ITERATIONS`).
    Since a password is only derived when its layer is unlocked or its
    password changed, never per value nor per save, a high count costs
    the user a few seconds per session at most, while multiplying the
    cost of every guess for an attacker.

    **Ownership.** The keys are owned by this instance: setting a new
    key clears the previous one (unless it is the same object), and
    :meth:`clear` clears both. Copying and pickling are refused, for
    the same reason as for :class:`DataKey`.

    This class performs no locking of its own.

    See Also
    --------
    DataKey
        The keys held by this class.

    PasswordManager
        Owns one :class:`Credentials` instance for its whole session.
    """

    __slots__ = ("_file_key", "_data_key")

    #: PBKDF2 iterations used to wrap the file key with the primary password.
    PRIMARY_ITERATIONS: int = 5_000_000

    #: PBKDF2 iterations used to wrap the data key with the secondary password.
    SECONDARY_ITERATIONS: int = 5_000_000

    def __init__(self) -> None:
        """
        Create an empty credentials holder: both layers are locked.
        """
        self._file_key: DataKey | None = None
        self._data_key: DataKey | None = None

    # ----------------
    # File key (primary layer)
    # ----------------

    @property
    def file_key(self) -> DataKey:
        """
        Return the file key.

        Returns
        -------
        DataKey
            The key encrypting the file content, by reference.

        Raises
        ------
        RuntimeError
            If the primary layer is locked (no file key set, or
            :meth:`clear` has been called).
        """
        if self._file_key is None:
            raise RuntimeError("The primary layer is locked: no file key.")
        return self._file_key

    @property
    def has_file_key(self) -> bool:
        """Whether the primary layer is unlocked."""
        return self._file_key is not None

    def set_file_key(self, key: DataKey) -> None:
        """
        Set the file key.

        Parameters
        ----------
        key : DataKey
            New file key, stored by reference: this instance takes
            ownership of it.

        Raises
        ------
        TypeError
            If ``key`` is not a :class:`DataKey`.

        Notes
        -----
        The previous file key, if any (and if it is not ``key``
        itself), is cleared.
        """
        if not isinstance(key, DataKey):
            raise TypeError(f"key must be DataKey, not {type(key)}")
        if self._file_key is not None and self._file_key is not key:
            self._file_key.clear()
        self._file_key = key

    # ----------------
    # Data key (secondary layer)
    # ----------------

    @property
    def data_key(self) -> DataKey:
        """
        Return the data key.

        Returns
        -------
        DataKey
            The key encrypting every sensitive value, by reference.
            This is the object to pass to every encrypted-field
            operation of :class:`Item`.

        Raises
        ------
        RuntimeError
            If the secondary layer is locked (no data key set, or
            :meth:`clear` has been called).
        """
        if self._data_key is None:
            raise RuntimeError("The secondary layer is locked: no data key.")
        return self._data_key

    @property
    def has_data_key(self) -> bool:
        """Whether the secondary layer is unlocked."""
        return self._data_key is not None

    def set_data_key(self, key: DataKey) -> None:
        """
        Set the data key.

        Parameters
        ----------
        key : DataKey
            New data key, stored by reference: this instance takes
            ownership of it.

        Raises
        ------
        TypeError
            If ``key`` is not a :class:`DataKey`.

        Notes
        -----
        The previous data key, if any (and if it is not ``key``
        itself), is cleared.
        """
        if not isinstance(key, DataKey):
            raise TypeError(f"key must be DataKey, not {type(key)}")
        if self._data_key is not None and self._data_key is not key:
            self._data_key.clear()
        self._data_key = key

    # ----------------
    # Cleanup
    # ----------------

    def clear_data_key(self) -> None:
        """
        Erase the data key only: lock the secondary layer again.

        Notes
        -----
        The file key is kept. Calling it when the secondary layer is
        already locked is harmless.
        """
        if self._data_key is not None:
            self._data_key.clear()
        self._data_key = None

    def clear(self) -> None:
        """
        Erase both keys from memory.

        Notes
        -----
        Irreversible: both layers are locked again, and every key
        property raises :class:`RuntimeError` afterwards. Calling it
        more than once is harmless.
        """
        for key in (self._file_key, self._data_key):
            if key is not None:
                key.clear()
        self._file_key = None
        self._data_key = None

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

    def __repr__(self) -> str:
        """
        Return a debug-friendly representation.

        Returns
        -------
        str
            Only which layers are unlocked, never any key.
        """
        return (
            f"{type(self).__name__}(primary={'unlocked' if self.has_file_key else 'locked'}, "
            f"secondary={'unlocked' if self.has_data_key else 'locked'})"
        )
