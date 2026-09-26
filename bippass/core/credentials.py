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

import pyaescbc


class Credentials:
    """
    Hold the primary and secondary encryption credentials.

    A :class:`PasswordManager` needs two independent passwords: the
    *primary* password, used to encrypt and decrypt the whole manager
    bundle, and the *secondary* password, used to encrypt and decrypt
    individual sensitive item fields (passwords, TOTP secrets,
    encrypted custom fields). This class stores both, alongside the
    fixed iteration count that goes with each (see
    :attr:`PRIMARY_ITERATIONS`/:attr:`SECONDARY_ITERATIONS`).

    Notes
    -----
    There is no PIN anymore, and no per-password iteration count
    derived from one: every primary password is encrypted with
    :attr:`PRIMARY_ITERATIONS` iterations, and every secondary
    password with :attr:`SECONDARY_ITERATIONS`, full stop. This
    reflects pyaescbc's own current API, which dropped PIN-derived
    iteration counts in favor of the caller simply choosing a fixed
    one.

    Passwords are stored by reference, never copied: the caller
    retains control over the lifetime of the underlying bytearrays.

    This class performs no locking of its own. Callers that need
    thread-safety (such as :class:`PasswordManager`) are responsible
    for synchronizing access to a shared instance.

    See Also
    --------
    PasswordManager
        Uses one :class:`Credentials` instance to hold both its
        primary and secondary passwords.
    """

    #: Fixed iteration count for the primary password.
    PRIMARY_ITERATIONS = 5_000_000

    #: Fixed iteration count for the secondary password.
    SECONDARY_ITERATIONS = 500_000

    def __init__(self) -> None:
        """
        Create an empty credentials holder.

        Neither the primary nor the secondary password is set yet:
        call :meth:`set_primary_password` and
        :meth:`set_secondary_password` before using any of the
        getters.
        """
        self._primary_password: bytearray | None = None
        self._secondary_password: bytearray | None = None

    # ----------------
    # Primary
    # ----------------

    def set_primary_password(self, password: bytearray) -> None:
        """
        Set the primary password.

        Parameters
        ----------
        password : bytearray
            Primary password, stored by reference.

        Raises
        ------
        TypeError
            If ``password`` is not a :class:`bytearray`.

        Notes
        -----
        If a primary password was already set, the previous one is
        wiped from memory before being replaced, so this method also
        doubles as "change the primary password".
        """
        if not isinstance(password, bytearray):
            raise TypeError(f"password must be bytearray, not {type(password)}")

        if self._primary_password is not None:
            pyaescbc.delete_bytearray(self._primary_password)

        self._primary_password = password

    def get_primary_password(self) -> bytearray:
        """
        Return the primary password.

        Returns
        -------
        bytearray
            The primary password, by reference (not a copy).

        Raises
        ------
        ValueError
            If :meth:`set_primary_password` has not been called yet,
            or :meth:`clear` has since been called.
        """
        if self._primary_password is None:
            raise ValueError("Primary credentials have not been set yet.")
        return self._primary_password

    def get_primary_iterations(self) -> int:
        """
        Return the primary iteration count.

        Returns
        -------
        int
            Always :attr:`PRIMARY_ITERATIONS`.
        """
        return self.PRIMARY_ITERATIONS

    # ----------------
    # Secondary
    # ----------------

    def set_secondary_password(self, password: bytearray) -> None:
        """
        Set the secondary password.

        Parameters
        ----------
        password : bytearray
            Secondary password, stored by reference.

        Raises
        ------
        TypeError
            If ``password`` is not a :class:`bytearray`.

        Notes
        -----
        If a secondary password was already set, the previous one is
        wiped from memory before being replaced, so this method also
        doubles as "change the secondary password".
        """
        if not isinstance(password, bytearray):
            raise TypeError(f"password must be bytearray, not {type(password)}")

        if self._secondary_password is not None:
            pyaescbc.delete_bytearray(self._secondary_password)

        self._secondary_password = password

    def get_secondary_password(self) -> bytearray:
        """
        Return the secondary password.

        Returns
        -------
        bytearray
            The secondary password, by reference (not a copy).

        Raises
        ------
        ValueError
            If :meth:`set_secondary_password` has not been called
            yet, or :meth:`clear` has since been called.
        """
        if self._secondary_password is None:
            raise ValueError("Secondary credentials have not been set yet.")
        return self._secondary_password

    def get_secondary_iterations(self) -> int:
        """
        Return the secondary iteration count.

        Returns
        -------
        int
            Always :attr:`SECONDARY_ITERATIONS`.
        """
        return self.SECONDARY_ITERATIONS

    # ----------------
    # Cleanup
    # ----------------

    def clear(self) -> None:
        """
        Erase both the primary and secondary passwords from memory.

        Notes
        -----
        Irreversible. Every getter raises :class:`ValueError` after
        this call: the underlying bytearrays are zeroed in place and
        then dropped.
        """
        if self._primary_password is not None:
            pyaescbc.delete_bytearray(self._primary_password)
        if self._secondary_password is not None:
            pyaescbc.delete_bytearray(self._secondary_password)

        self._primary_password = None
        self._secondary_password = None