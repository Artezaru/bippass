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
import copy
import json
import os
import threading
import uuid
from pathlib import Path
from typing import cast

from .exceptions import (
    VaultNotFoundError,
    VaultAlreadyExistsError,
    ItemAlreadyExistsError,
    PasswordManagerError,
    PrimaryPasswordError,
    SecondaryPasswordError,
    CorruptedBase64Error,
)
from .types import PasswordManagerData, Metadata, ClearString, CryptedBase64String

import pyaescbc

from .vault import Vault
from .item import Item
from .credentials import Credentials


class PasswordManager:
    """Manage encrypted password vaults and their credentials.

    ``PasswordManager`` is the top-level object responsible for managing
    :class:`Vault` instances, maintaining global item UUID uniqueness,
    handling the primary encryption credentials, and validating the
    secondary encryption credentials.

    Construction is deliberately inert: creating a
    :class:`PasswordManager` only stores its raw (still encrypted)
    ``data`` and its :class:`Credentials`, without decrypting anything.
    Actually decrypting the data and building the vaults is
    :meth:`decrypt_data`'s job; verifying the secondary credentials is
    :meth:`check_secondary`'s. See their docstrings, and :meth:`__init__`'s
    Notes, for why they are split out like this.

    Parameters
    ----------
    data : bytearray
        Encrypted password manager bundle produced by :meth:`encrypt`.
        Not touched until :meth:`decrypt_data` is called.

    credentials : Credentials
        Holds both the primary password/iteration pair (used by
        :meth:`decrypt_data`) and the secondary one (used by
        :meth:`check_secondary` and every encrypted item field
        operation thereafter).


    Raises
    ------
    TypeError
        If ``data`` is not a :class:`bytearray` or ``credentials`` is
        not a :class:`Credentials` instance.


    Notes
    -----
    ``credentials`` is stored by reference: the manager does not
    create its own :class:`Credentials` instance, and does not copy
    or wipe its password on a per-call basis (see :class:`Item`'s
    class-level docstring for why that matters). Only
    :meth:`close` (via :meth:`Credentials.clear`) erases it.

    Item UUIDs are not stored separately by the manager: they are
    derived on demand from the vaults' items (see :attr:`uuids`), so
    they can never drift out of sync with the actual items even if a
    :class:`Vault` is modified directly.

    Every method that reads or mutates :attr:`_vaults` (directly or
    through a :class:`Vault`) acquires :attr:`_lock`, a re-entrant
    lock, before doing so. This makes it safe to call, for instance,
    :meth:`save_changes` from a background thread while the UI thread
    concurrently edits an item, adds a vault, or otherwise mutates the
    manager, see :meth:`save_changes` for the intended usage.


    See Also
    --------
    Vault
        Container for password items.

    Item
        Individual password vault item.

    Credentials
        Holds the primary and secondary password/iteration pairs.
    """

    _AUTH_MESSAGE: bytes = (
        b"PasswordManager::secondary-password-check::v1"
    )

    _DEFAULT_METADATA: Metadata = {
        "version": 1,
        "username": None,
        "theme": "dark",
        "language": "en",
        "close_timer_s": 300,
    }

    def __init__(
        self,
        data: bytearray,
        credentials: Credentials,
    ) -> None:
        """Store the manager's raw data and credentials.

        Parameters
        ----------
        data : bytearray
            Encrypted password manager bundle.

        credentials : Credentials
            Holds the primary and secondary password/iteration pairs.

        Raises
        ------
        TypeError
            If ``data`` is not a :class:`bytearray` or ``credentials``
            is not a :class:`Credentials` instance.

        Notes
        -----
        Nothing is decrypted and no vault is built here:
        :attr:`_vaults` starts out as ``None``, and every method that
        needs it raises a clear :class:`RuntimeError` until
        :meth:`decrypt_data` has been called (see
        :meth:`_require_decrypted`).

        Splitting construction (this method), decryption
        (:meth:`decrypt_data`), and secondary-credential verification
        (:meth:`check_secondary`) into three separate steps lets a
        caller, typically a GUI unlock dialog, report each kind of
        failure distinctly and in order: "file unreadable" before
        even reaching here, then "wrong primary password" from
        :meth:`decrypt_data`, then "wrong secondary password" from
        :meth:`check_secondary`, instead of one opaque failure out of
        a single all-in-one constructor.
        """
        if not isinstance(data, bytearray):
            raise TypeError(f"data must be bytearray, not {type(data)}")
        if not isinstance(credentials, Credentials):
            raise TypeError(
                f"credentials must be Credentials, not {type(credentials)}"
            )

        # Re-entrant so that a locked method can freely call another
        # locked method on the same thread
        self._lock: threading.RLock = threading.RLock()

        self._data: bytearray = data
        self._credentials: Credentials = credentials

        self._metadata: Metadata | None = None
        self._auth: CryptedBase64String | None = None
        self._vaults: dict[str, Vault] | None = None

    @classmethod
    def _with_metadata_defaults(cls, metadata: Metadata) -> Metadata:
        """
        Fill in any :class:`Metadata` key missing from ``metadata``
        with its default value from :attr:`_DEFAULT_METADATA`.

        Parameters
        ----------
        metadata : Metadata
            Metadata as decrypted, or as supplied to :meth:`new`,
            possibly missing keys added by a later software version.

        Returns
        -------
        Metadata
            A new dict: every key already present in ``metadata``
            (including an explicit ``None``) is kept as-is; every
            missing key is set to its default.
        """
        return {**cls._DEFAULT_METADATA, **metadata}

    @classmethod
    def new(cls, metadata: Metadata, credentials: Credentials) -> PasswordManager:
        """
        Create a brand-new, empty password manager.

        Unlike the normal constructor, which expects previously
        encrypted ``data`` that :meth:`decrypt_data` will later
        decrypt, this is for starting a manager from scratch, no
        file exists yet.

        Parameters
        ----------
        metadata : Metadata
            Initial manager metadata (e.g. username, format version).
            Any key it omits is filled in with its default (see
            :meth:`_with_metadata_defaults`).

        credentials : Credentials
            Holds the primary and secondary password/iteration pairs
            this manager will encrypt and decrypt with.

        Returns
        -------
        PasswordManager
            A new manager with no vaults, ready to use immediately,
            there is nothing to decrypt or authenticate, so neither
            :meth:`decrypt_data` nor :meth:`check_secondary` needs to
            be called.

        Raises
        ------
        TypeError
            If ``metadata`` is not a ``dict`` or ``credentials`` is
            not a :class:`Credentials` instance.

        Notes
        -----
        Bypasses :meth:`decrypt_data` entirely: :attr:`_vaults` is
        set directly to an empty dict, and :attr:`_data` is left as
        an empty placeholder (it is only ever read by
        :meth:`decrypt_data`, which this manager will never need to
        call).

        :attr:`_auth` is left as ``None``: a valid auth value is
        derived from ``credentials`` the next time this manager is
        serialized (:meth:`to_dict`/:meth:`encrypt`), exactly as for
        :meth:`_from_unencrypted_bundle`. Calling
        :meth:`check_secondary` on a manager created this way would
        raise, since there is nothing yet to check it against, which
        is expected: the caller just handed these credentials over
        directly, there's no stored auth value to be wrong about.

        ``credentials`` need not have its primary/secondary passwords
        set yet at the time this is called: since it is stored by
        reference, a caller may build an empty :class:`Credentials`,
        pass it here, and fill in
        :meth:`Credentials.set_primary_password`/
        :meth:`Credentials.set_secondary_password` afterwards, useful
        for a step-by-step "create a new vault" GUI flow where the
        file (and thus this manager) is chosen before the passwords
        are.
        """
        if not isinstance(metadata, dict):
            raise TypeError(f"metadata must be a dict, not {type(metadata)}")
        if not isinstance(credentials, Credentials):
            raise TypeError(
                f"credentials must be Credentials, not {type(credentials)}"
            )

        instance = cls(bytearray(), credentials)
        instance._metadata = cls._with_metadata_defaults(metadata)
        instance._vaults = {}
        return instance

    def _require_decrypted(self) -> None:
        """
        Raise a clear error if :meth:`decrypt_data` has not run yet.

        Raises
        ------
        RuntimeError
            If :attr:`_vaults` is still ``None``.

        Notes
        -----
        Called at the top of every method that reads or mutates
        :attr:`_vaults` or :attr:`_metadata` directly. Methods that
        only reach those through another guarded method (e.g.
        :meth:`get_item` through :meth:`get_vault`) do not need to
        call this themselves: the guard is hit transitively, with the
        same clear message.
        """
        if self._vaults is None:
            raise RuntimeError(
                "PasswordManager data has not been decrypted yet; "
                "call decrypt_data() first."
            )

    def _load_manager_data(self, manager_data: PasswordManagerData) -> None:
        """
        Populate metadata, the stored auth value, and vaults.

        Parameters
        ----------
        manager_data : PasswordManagerData
            Deserialized password manager data, as produced by
            :meth:`_decrypt` (for :meth:`decrypt_data`) or by
            ``json.loads`` directly on an already-cleartext bundle
            (for :meth:`_from_unencrypted_bundle`).

        Notes
        -----
        Does not itself acquire :attr:`_lock`; every caller is
        responsible for that.
        """
        self._metadata = self._with_metadata_defaults(manager_data["metadata"])
        self._auth = manager_data["auth"]
        self._vaults = {
            name: Vault(name, vault_data)
            for name, vault_data in manager_data["vaults"].items()
        }

    def decrypt_data(self) -> None:
        """
        Decrypt the manager's stored data and build its vaults.

        Uses the primary password and iteration count held by
        :attr:`_credentials` to decrypt :attr:`_data`, then populates
        the manager's metadata and vaults from the result.

        Raises
        ------
        RuntimeError
            If this method has already been called: calling it again
            would silently discard the in-memory vaults (and any
            unsaved change made to them) built by the first call.

        PrimaryPasswordError
            If the primary credentials are invalid.

        ValueError
            If the decrypted data is not a valid password manager
            structure.

        Notes
        -----
        Every method that reads or mutates vaults or metadata (e.g.
        :meth:`get_vault`, :meth:`to_dict`) requires this to have run
        first, see :meth:`_require_decrypted`.

        Does not itself verify the secondary credentials: call
        :meth:`check_secondary` afterwards for that.
        """
        with self._lock:
            if self._vaults is not None:
                raise RuntimeError(
                    "decrypt_data() has already been called; calling "
                    "it again would discard any changes made since."
                )
            manager_data = self._decrypt(self._data)
            self._load_manager_data(manager_data)

    def check_secondary(self) -> None:
        """
        Verify the secondary password and iteration count.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        CorruptedBase64Error
            If the stored authentication value is not valid Base64.

        SecondaryPasswordError
            If the secondary credentials are invalid.

        Notes
        -----
        Deliberately separate from :meth:`decrypt_data`, so a caller
        can choose whether, and when, to validate the secondary
        credentials. :meth:`_from_unencrypted_bundle`, for instance,
        never calls this: the unencrypted bundle it imports is not
        expected to carry a meaningful ``auth`` value yet (a fresh one
        is generated the next time the manager is serialized).
        """
        with self._lock:
            if self._auth is None:
                raise RuntimeError(
                    "decrypt_data() must be called before check_secondary()."
                )
            self._check_secondary_credentials(self._auth)

    @classmethod
    def _from_unencrypted_bundle(
        cls,
        data: bytearray,
        credentials: Credentials,
        unencrypted_secrets: bool = True,
    ) -> PasswordManager:
        """
        Create a password manager from an unencrypted JSON bundle.

        This method is intended for importing password manager data from
        an unencrypted JSON representation. The sensitive fields stored in
        each :class:`Item` are considered to contain cleartext values,
        despite using the ``CryptedBase64String`` representation internally.

        After the manager has been created, all sensitive item fields are
        encrypted using ``credentials``' secondary password and iteration
        count.

        The secondary authentication value stored in the unencrypted bundle
        is not validated, :meth:`check_secondary` is simply never called
        here. A new authentication value is generated automatically when
        the resulting manager is serialized.

        Parameters
        ----------
        data : bytearray
            UTF-8 encoded JSON bundle containing the unencrypted password
            manager data.

        credentials : Credentials
            Holds the primary password/iteration pair used to encrypt the
            resulting bundle (see :meth:`encrypt`) and the secondary one
            used to encrypt every sensitive item field.

        unencrypted_secrets : bool
            If True, sensitive fields stored in
            each :class:`Item` are considered to contain cleartext values
            and will be encrypted by the credentials.

        Returns
        -------
        PasswordManager
            Password manager initialized from the unencrypted bundle, with
            all sensitive item fields encrypted using ``credentials``.

        Raises
        ------
        TypeError
            If ``data`` is not a :class:`bytearray` or ``credentials`` is
            not a :class:`Credentials` instance.

        ValueError
            If ``data`` does not contain valid password manager JSON data.

        Warning
        -------
        This method is intended for importing trusted unencrypted bundles.
        The input contains sensitive information in cleartext and should be
        handled accordingly.

        Notes
        -----
        Unlike :meth:`decrypt_data`, the bundle here is not
        primary-encrypted yet, so it is parsed directly with
        ``json.loads`` rather than through :meth:`_decrypt`.
        """
        instance = cls(data, credentials)

        try:
            manager_data: object = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid unencrypted password manager data.") from exc
        if not isinstance(manager_data, dict):
            raise ValueError(
                "The unencrypted password manager bundle must be a JSON object."
            )

        instance._load_manager_data(cast(PasswordManagerData, manager_data))

        if unencrypted_secrets:
            for vault in instance._vaults.values():
                for item in vault._items.values():
                    item._force_encrypt(instance._credentials)

        return instance

    def _to_unencrypted_bundle(self, unencrypted_secrets: bool = True) -> bytearray:
        """
        Export the password manager as an unencrypted JSON bundle.

        This method decrypts all sensitive fields contained in the manager's
        items and serializes the complete manager as UTF-8 encoded JSON.

        The returned JSON contains the password manager metadata, vaults,
        items, and sensitive values in cleartext. It is therefore intended
        primarily for exporting, backup, migration, or interoperability
        purposes and must be handled as sensitive data.

        Parameters
        ----------
        unencrypted_secrets : bool
            If True, sensitive fields stored in
            each :class:`Item` will be decrypted by the credentials.

        Returns
        -------
        bytearray
            UTF-8 encoded JSON representation of the password manager with
            sensitive item fields stored as cleartext values.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        Warning
        -------
        The returned bundle contains passwords, TOTP secrets, and other
        sensitive information in cleartext. It must not be stored or
        transmitted without appropriate protection.

        Notes
        -----
        The returned bundle is not encrypted with the primary password.

        This method permanently decrypts every item in place (via
        :meth:`Item._force_decrypt`): it mutates the manager's own
        state, it does not operate on a copy. It is guarded by
        :attr:`_lock` for that reason.

        See Also
        --------
        _from_unencrypted_bundle
            Create a password manager from an unencrypted JSON bundle.
        """
        with self._lock:
            self._require_decrypted()

            if unencrypted_secrets:
                for vault in self._vaults.values():
                    for item in vault._items.values():
                        item._force_decrypt(self._credentials)

            dict_repr = self.to_dict()
            dict_repr['auth'] = ""

            return bytearray(json.dumps(dict_repr, ensure_ascii=False, indent=4).encode("utf-8"))

    # ----------------
    # Encryption
    # ----------------

    def _decrypt(self, data: bytearray) -> PasswordManagerData:
        """Decrypt and deserialize the password manager data.

        Parameters
        ----------
        data : bytearray
            Encrypted password manager bundle.

        Returns
        -------
        PasswordManagerData
            Deserialized password manager data.

        Raises
        ------
        PrimaryPasswordError
            If the primary credentials are invalid.

        ValueError
            If the decrypted content is not valid UTF-8, valid JSON,
            or does not contain the required top-level fields.
        """
        try:
            clear_data: bytearray = pyaescbc.decrypt(
                data,
                bytearray(self._credentials.get_primary_password()),
                delete_keys=True,
                delete_data=True,
            )
        except pyaescbc.AuthError as exc:
            raise PrimaryPasswordError(
                "Wrong primary password."
            ) from exc

        try:
            manager_data: object = json.loads(clear_data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Invalid decrypted password manager data."
            ) from exc

        if not isinstance(manager_data, dict):
            raise ValueError(
                "The decrypted password manager must be a JSON object."
            )

        required_fields: tuple[str, ...] = ("metadata", "auth", "vaults")
        missing_fields: list[str] = [
            field for field in required_fields if field not in manager_data
        ]
        if missing_fields:
            raise ValueError(
                f"Missing password manager fields: {missing_fields}"
            )

        return cast(PasswordManagerData, manager_data)

    def _check_secondary_credentials(self, auth: CryptedBase64String) -> None:
        """Validate the secondary password.

        Parameters
        ----------
        auth : CryptedBase64String
            Base64-encoded encrypted authentication value stored in
            the password manager data.

        Raises
        ------
        CorruptedBase64Error
            If ``auth`` is not valid Base64.

        SecondaryPasswordError
            If the secondary password is invalid.
        """
        try:
            encrypted_auth: bytearray = bytearray(
                base64.b64decode(auth, validate=True)
            )
        except binascii.Error as exc:
            raise CorruptedBase64Error(
                "Corrupted password manager data: invalid Base64 encoding."
            ) from exc

        try:
            clear_auth: bytearray = pyaescbc.decrypt(
                encrypted_auth,
                bytearray(self._credentials.get_secondary_password()),
                delete_keys=True,
                delete_data=True,
            )
        except pyaescbc.AuthError as exc:
            raise SecondaryPasswordError(
                "Invalid secondary password."
            ) from exc

        if clear_auth != self._AUTH_MESSAGE:
            raise SecondaryPasswordError("Invalid secondary password.")

    def _create_auth(self) -> CryptedBase64String:
        """Create the secondary credential verification value.

        Returns
        -------
        CryptedBase64String
            Base64-encoded encrypted authentication value.

        Notes
        -----
        Thin wrapper around :meth:`create_auth` using this manager's
        own credentials, so there is only one place (that classmethod)
        that ever turns a secondary password/iteration pair into an
        ``auth`` value.
        """
        return self.create_auth(self._credentials)

    @classmethod
    def create_auth(cls, credentials: Credentials) -> CryptedBase64String:
        """Create a secondary credential verification value.

        Useful when creating a new password manager before it has
        been serialized for the first time.

        Parameters
        ----------
        credentials : Credentials
            Holds the secondary password and iteration count to
            encrypt the authentication value with.

        Returns
        -------
        CryptedBase64String
            Base64-encoded encrypted authentication value.

        Raises
        ------
        TypeError
            If ``credentials`` is not a :class:`Credentials` instance.

        Notes
        -----
        Reads the secondary password straight from ``credentials``
        (:meth:`Credentials.get_secondary_password`), and the
        iteration count is always
        :attr:`Credentials.SECONDARY_ITERATIONS` -- a fixed constant
        now rather than anything derived per-password, so there is no
        way for this value to drift from what
        :meth:`_check_secondary_credentials` later checks against.
        """
        if not isinstance(credentials, Credentials):
            raise TypeError(
                f"credentials must be Credentials, not {type(credentials)}"
            )

        encrypted_auth: bytearray = pyaescbc.encrypt(
            bytearray(cls._AUTH_MESSAGE),
            bytearray(credentials.get_secondary_password()),
            iterations=credentials.get_secondary_iterations(),
            delete_keys=True,
            delete_data=True,
        )
        return base64.b64encode(encrypted_auth).decode("ascii")

    def encrypt(self) -> bytearray:
        """Encrypt the complete password manager.

        Returns
        -------
        bytearray
            Encrypted password manager bundle suitable for storage.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`to_json`/:meth:`to_dict`).

        Notes
        -----
        Guarded by :attr:`_lock` so the serialized snapshot (produced
        by :meth:`to_json`) reflects a single consistent state, even
        if another thread is concurrently mutating a vault or an item.
        """
        with self._lock:
            clear_data: bytearray = bytearray(self.to_json().encode("utf-8"))
            primary_password = bytearray(self._credentials.get_primary_password())
            primary_iterations = self._credentials.get_primary_iterations()
        return pyaescbc.encrypt(
            clear_data,
            primary_password,
            iterations=primary_iterations,
            delete_keys=True,
            delete_data=True,
        )

    def save_changes(self, path: str | Path) -> None:
        """
        Encrypt the current state of the manager and write it to disk.

        Parameters
        ----------
        path : str or Path
            Destination file. Created if it does not exist yet,
            overwritten if it does.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`encrypt`).

        OSError
            If the encrypted bundle cannot be written to ``path``.

        Notes
        -----
        This is the method meant to be called after any change to the
        manager's state, saving an item from :class:`ItemViewer`,
        creating/renaming/removing a vault, adding/deleting/moving an
        item, or shutting the application down, and it is safe to
        call from a background thread: :meth:`encrypt` (which this
        method calls) takes :attr:`_lock` internally to obtain a
        consistent snapshot, so it can run concurrently with, e.g.,
        the UI thread editing another item. Once the snapshot has been
        encrypted, the actual disk write happens outside the lock so
        that slow I/O never blocks other threads from mutating the
        manager in the meantime; the on-disk file will simply reflect
        whichever snapshot was current at the moment :meth:`encrypt`
        was called.

        The write itself is atomic: the encrypted bundle is first
        written to a sibling temporary file, then moved into place
        with :func:`os.replace` (an atomic rename on POSIX and
        Windows). This means a crash, a full disk, or the application
        being killed mid-write can never leave ``path`` truncated or
        otherwise corrupted, either the old file is still there
        untouched, or the new one is there complete.

        This method does not call :meth:`close`: the manager's
        in-memory credentials remain usable after saving, since the
        caller may go on to make further changes and save again.
        """
        path = Path(path)
        encrypted = self.encrypt()

        tmp_path = path.with_name(path.name + ".tmp")
        try:
            tmp_path.write_bytes(bytes(encrypted))
            os.replace(tmp_path, path)
        except OSError:
            tmp_path.unlink(missing_ok=True)
            raise

    def close(self) -> None:
        """
        Erase the manager's primary and secondary passwords from memory.

        Notes
        -----
        Irreversible: after calling this method, any subsequent
        operation that needs to decrypt or encrypt data (including
        :meth:`encrypt` and therefore :meth:`save_changes`) will fail.
        Make sure any pending change has already been saved before
        closing the manager.
        """
        with self._lock:
            self._credentials.clear()

    def get_credentials(self) -> Credentials:
        """
        Return the manager's :class:`Credentials` instance.

        Returns
        -------
        Credentials
            Holds both the primary and secondary password/iteration
            pairs.

        Notes
        -----
        This is the object to pass to :meth:`Item.get`/:meth:`Item.set`
        (and :meth:`Item.get_custom`/:meth:`Item.set_custom`) when
        reading or writing an item's encrypted fields from outside
        this class, for instance from :class:`ItemViewer`. It is the
        very same instance this manager itself encrypts and decrypts
        with, so its password is never copied or wiped on a per-call
        basis (see :class:`Item`'s class-level docstring); only
        :meth:`close` (via :meth:`Credentials.clear`) erases it.
        """
        with self._lock:
            return self._credentials

    def change_credentials(self, new_credentials: Credentials) -> None:
        """
        Replace the manager's credentials, re-encrypting every vault.

        Parameters
        ----------
        new_credentials : Credentials
            Replacement credentials. Its secondary password and
            iteration count are used to re-encrypt every vault's
            items; its primary password/iteration pair simply becomes
            this manager's new primary credentials (see Notes).

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        SecondaryPasswordError
            If decryption fails for any item because of an
            authentication error against the manager's *current*
            secondary credentials. This should not normally happen,
            since those are, by construction, the credentials every
            item was last encrypted with, but see
            :meth:`Vault.change_credentials` and
            :meth:`Item.change_credentials` for exactly what is
            checked.

        Notes
        -----
        Atomic: every vault is re-encrypted on a throwaway deep copy
        first (:meth:`Vault.change_credentials` is itself atomic per
        vault, which in turn relies on :meth:`Item.change_credentials`
        being atomic per item). Only once *every* vault's copy has
        succeeded does this method replace :attr:`_vaults` and
        :attr:`_credentials` together, in one go. If any vault fails
        partway through, the exception is raised before that
        replacement, so both :attr:`_vaults` and :attr:`_credentials`
        are left exactly as they were, no vault ends up re-encrypted
        while others are not, and the manager never ends up holding a
        mix of old and new credentials.

        ``new_credentials`` entirely replaces :attr:`_credentials`,
        including its primary password/iteration pair: this method
        doubles as how to change the *primary* password too, simply
        by giving ``new_credentials`` different primary keys (with
        the same, or also different, secondary keys). Nothing needs
        to happen for the primary password beyond that swap: it only
        ever encrypts the outer bundle as a whole, in :meth:`encrypt`,
        the next time :meth:`save_changes` runs, it plays no part in
        how individual vaults or items are encrypted.

        As with :meth:`Vault.change_credentials`, the trade-off is
        memory: for the duration of this call, the manager holds two
        full sets of vaults (and, transitively, items) at once.

        To change only one of the two (e.g. the primary password
        while leaving the secondary one untouched), build
        ``new_credentials`` with
        :meth:`Credentials.set_primary_password`/
        :meth:`Credentials.set_secondary_password` for the side being
        changed, and, for the side that should stay the same, the
        very same method again, simply fed with this manager's
        current password for that side (:meth:`get_credentials`, then
        :meth:`Credentials.get_primary_password` or
        :meth:`Credentials.get_secondary_password`). There is no PIN
        to carry over and no iteration count to derive or preserve
        anymore: it is always the fixed
        :attr:`Credentials.PRIMARY_ITERATIONS`/
        :attr:`Credentials.SECONDARY_ITERATIONS`.
        """
        with self._lock:
            self._require_decrypted()

            draft_vaults: dict[str, Vault] = {
                name: copy.deepcopy(vault) for name, vault in self._vaults.items()
            }
            for vault in draft_vaults.values():
                vault.change_credentials(self._credentials, new_credentials)

            self._vaults = draft_vaults
            self._credentials = new_credentials

    # ----------------
    # Serialization
    # ----------------

    def to_dict(self) -> PasswordManagerData:
        """Serialize the complete password manager to a dictionary.

        Returns
        -------
        PasswordManagerData
            Complete serialized password manager data.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        Notes
        -----
        The ``auth`` field is regenerated from the current secondary
        credentials. Item UUIDs are not serialized separately: they
        are already present inside each vault's items.
        """
        with self._lock:
            self._require_decrypted()
            return {
                "metadata": self._metadata,
                "auth": self._create_auth(),
                "vaults": {
                    vault.name: vault.to_dict()
                    for vault in self._vaults.values()
                },
            }

    def to_json(self) -> str:
        """Serialize the password manager to JSON.

        Returns
        -------
        str
            JSON representation of the complete password manager.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`to_dict`).
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=4)

    # ----------------
    # UUID management
    # ----------------

    @property
    def uuids(self) -> tuple[str, ...]:
        """Return all item UUIDs currently registered across all vaults.

        Returns
        -------
        tuple of str
            UUIDs of every item contained in any vault managed by
            this object.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        Notes
        -----
        Computed from the vaults' items rather than stored
        separately, so it can never drift out of sync with the
        actual items even if a :class:`Vault` is modified directly.
        """
        with self._lock:
            self._require_decrypted()
            return tuple(
                item.uuid
                for vault in self._vaults.values()
                for item in vault.get_items()
            )

    def create_uuid(self) -> str:
        """Generate a globally unique item UUID.

        Returns
        -------
        str
            Newly generated UUID that does not conflict with any
            UUID currently registered by the manager.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :attr:`uuids`).

        Notes
        -----
        The generated UUID is not added to the manager automatically.
        It is only reserved when the corresponding item is added.
        """
        with self._lock:
            existing = self.uuids
            while True:
                item_uuid = str(uuid.uuid4())
                if item_uuid not in existing:
                    return item_uuid

    # ----------------
    # Vault management
    # ----------------

    def get_vault(self, name: str) -> Vault:
        """Return a vault by name.

        Parameters
        ----------
        name : str
            Name of the vault to retrieve.

        Returns
        -------
        Vault
            Vault associated with ``name``.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        VaultNotFoundError
            If no vault with the specified name exists.
        """
        with self._lock:
            self._require_decrypted()
            try:
                return self._vaults[name]
            except KeyError as exc:
                raise VaultNotFoundError(f"Unknown vault: {name!r}") from exc

    def get_vaults(self) -> list[Vault]:
        """Return all vaults.

        Returns
        -------
        list of Vault
            List containing all vaults currently managed.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.
        """
        with self._lock:
            self._require_decrypted()
            return list(self._vaults.values())

    def add_vault(self, vault: Vault) -> None:
        """Add an existing vault to the manager.

        Parameters
        ----------
        vault : Vault
            Vault to add.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        VaultAlreadyExistsError
            If another vault with the same name already exists.

        Notes
        -----
        The vault is stored by reference and is not copied. UUID
        collisions between the supplied vault's items and UUIDs
        already registered by the manager are not validated here.
        """
        with self._lock:
            self._require_decrypted()
            if vault.name in self._vaults:
                raise VaultAlreadyExistsError(f"Vault already exists: {vault.name!r}")
            self._vaults[vault.name] = vault

    def add_empty_vault(self, name: str) -> Vault:
        """Create and add an empty vault.

        Parameters
        ----------
        name : str
            Name of the new vault.

        Returns
        -------
        Vault
            Newly created empty vault.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`add_vault`).

        VaultAlreadyExistsError
            If a vault with the specified name already exists.
        """
        with self._lock:
            vault = Vault.create_empty(name)
            self.add_vault(vault)
            return vault

    def remove_vault(self, name: str) -> None:
        """Remove a vault.

        Parameters
        ----------
        name : str
            Name of the vault to remove.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        VaultNotFoundError
            If the specified vault does not exist.
        """
        with self._lock:
            self._require_decrypted()
            if name not in self._vaults:
                raise VaultNotFoundError(f"Unknown vault: {name!r}")
            del self._vaults[name]

    def rename_vault(self, old_name: str, new_name: str) -> None:
        """Rename an existing vault.

        Parameters
        ----------
        old_name : str
            Current vault name.

        new_name : str
            New vault name.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        VaultNotFoundError
            If ``old_name`` does not identify an existing vault.

        VaultAlreadyExistsError
            If ``new_name`` is already used by another vault.
        """
        with self._lock:
            self._require_decrypted()
            if old_name not in self._vaults:
                raise VaultNotFoundError(f"Unknown vault: {old_name!r}")
            if new_name in self._vaults:
                raise VaultAlreadyExistsError(f"Vault already exists: {new_name!r}")

            vault = self._vaults.pop(old_name)
            vault.rename(new_name)
            self._vaults[new_name] = vault

    # ----------------
    # Item management
    # ----------------

    def get_item(self, item_uuid: str, vault: str = None) -> Item:
        """Return an item by UUID within a given vault.

        Parameters
        ----------
        item_uuid : str
            UUID of the item to retrieve.

        vault : str
            Name of the vault containing the item.

        Returns
        -------
        Item
            Item associated with ``item_uuid``.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`get_vault`/:attr:`uuids`).

        VaultNotFoundError
            If the specified vault does not exist.

        ItemNotFoundError
            If the specified item does not exist in that vault.
        """
        with self._lock:
            if vault is not None:
                return self.get_vault(vault).get_item(item_uuid)
            else:
                if not item_uuid in self.uuids:
                    raise ValueError("item uuid invalid")

                for vault in self.get_vaults():
                    if item_uuid in vault._items.keys():
                        return vault.get_item(item_uuid)

    def add_empty_item(self, vault: str, item_uuid: str | None = None) -> Item:
        """Create and add an empty item to a vault.

        Parameters
        ----------
        vault : str
            Name of the vault receiving the new item.

        item_uuid : str or None, optional
            UUID to assign to the item. If ``None``, a new globally
            unique UUID is generated.

        Returns
        -------
        Item
            Newly created empty item.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`get_vault`/:attr:`uuids`).

        VaultNotFoundError
            If the target vault does not exist.

        ItemAlreadyExistsError
            If the supplied UUID is already used by another item.
        """
        with self._lock:
            target_vault = self.get_vault(vault)

            if item_uuid is None:
                item_uuid = self.create_uuid()
            elif item_uuid in self.uuids:
                raise ItemAlreadyExistsError(f"Item UUID already exists: {item_uuid}")

            return target_vault.add_empty_item(item_uuid)

    def remove_item(self, item_uuid: str, vault: str) -> None:
        """Remove an item.

        Parameters
        ----------
        item_uuid : str
            UUID of the item to remove.

        vault : str
            Name of the vault containing the item.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`get_vault`).

        VaultNotFoundError
            If the specified vault does not exist.

        ItemNotFoundError
            If the specified item does not exist.
        """
        with self._lock:
            self.get_vault(vault).remove_item(item_uuid)

    def delete_item(self, vault: str, item_uuid: str) -> None:
        """Delete an item from a vault.

        Parameters
        ----------
        vault : str
            Name of the vault containing the item.

        item_uuid : str
            UUID of the item to delete.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`remove_item`).

        VaultNotFoundError
            If the specified vault does not exist.

        ItemNotFoundError
            If the specified item does not exist in that vault.

        Notes
        -----
        This is the same operation as :meth:`remove_item`, exposed
        under the name and argument order (``vault`` first, then
        ``item_uuid``) expected by the GUI layer, which naturally
        knows which vault it is acting on before it knows which item.
        """
        with self._lock:
            self.remove_item(item_uuid, vault)

    def move_item(self, item_uuid: str, source_vault: str, target_vault: str) -> None:
        """Move an item from one vault to another.

        Parameters
        ----------
        item_uuid : str
            UUID of the item to move.

        source_vault : str
            Name of the vault the item currently belongs to.

        target_vault : str
            Name of the vault the item should be moved into.

        Raises
        ------
        ValueError
            If ``source_vault`` and ``target_vault`` are the same.

        RuntimeError
            If :meth:`decrypt_data` has not been called yet (reached
            transitively through :meth:`get_vault`).

        VaultNotFoundError
            If ``source_vault`` or ``target_vault`` does not exist.

        ItemNotFoundError
            If the item does not exist in ``source_vault``.

        ItemAlreadyExistsError
            If an item with the same UUID unexpectedly already exists
            in ``target_vault``. This should not normally happen,
            since item UUIDs are meant to be unique across the whole
            manager (see :attr:`uuids`), but is still checked before
            any data is moved, so a corrupted vault can never silently
            overwrite an existing item.

        Notes
        -----
        The item is relocated by reference: it is not re-encrypted,
        re-serialized, or copied, only removed from one vault's item
        store and inserted into the other's. Because :class:`Vault`
        does not expose a public method for inserting an already
        constructed :class:`Item`, this reaches into the target
        vault's internal ``_items`` mapping directly, the same
        private attribute :meth:`get_item` already relies on above.
        """
        if source_vault == target_vault:
            raise ValueError("source_vault and target_vault must differ.")

        with self._lock:
            source = self.get_vault(source_vault)
            target = self.get_vault(target_vault)

            item = source.get_item(item_uuid)

            if item_uuid in target._items:
                raise ItemAlreadyExistsError(
                    f"Item UUID already exists in {target_vault!r}: {item_uuid}"
                )

            source.remove_item(item_uuid)
            target._items[item_uuid] = item

    # ----------------
    # Metadata
    # ----------------

    def get_username(self) -> ClearString | None:
        """Return the username stored in the manager metadata.

        Returns
        -------
        ClearString or None
            Stored username, or ``None`` if no username is configured.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.
        """
        with self._lock:
            self._require_decrypted()
            return self._metadata["username"]

    def set_username(self, value: ClearString | None) -> None:
        """Set the username stored in the manager metadata.

        Parameters
        ----------
        value : ClearString or None
            New username. ``None`` removes the stored username.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        TypeError
            If ``value`` is neither a ``str`` nor ``None``.
        """
        if value is not None and not isinstance(value, str):
            raise TypeError(f"value must be a string, not {type(value)}")
        with self._lock:
            self._require_decrypted()
            self._metadata["username"] = value

    def get_theme(self) -> ClearString | None:
        """Return the display theme stored in the manager metadata.

        Returns
        -------
        ClearString or None
            ``"light"`` or ``"dark"`` (see :mod:`theme`), or ``None``
            if unset (should not normally happen, see
            :attr:`_DEFAULT_METADATA`).

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.
        """
        with self._lock:
            self._require_decrypted()
            return self._metadata["theme"]

    def set_theme(self, value: ClearString | None) -> None:
        """Set the display theme stored in the manager metadata.

        Parameters
        ----------
        value : ClearString or None
            New theme (``"light"`` or ``"dark"``). ``None`` clears it.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        TypeError
            If ``value`` is neither a ``str`` nor ``None``.
        """
        if value is not None and not isinstance(value, str):
            raise TypeError(f"value must be a string, not {type(value)}")
        with self._lock:
            self._require_decrypted()
            self._metadata["theme"] = value

    def get_language(self) -> ClearString | None:
        """Return the display language stored in the manager metadata.

        Returns
        -------
        ClearString or None
            Language code (e.g. ``"en"``, ``"fr"``, ``"es"``, see
            :mod:`translate`), or ``None`` if unset.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.
        """
        with self._lock:
            self._require_decrypted()
            return self._metadata["language"]

    def set_language(self, value: ClearString | None) -> None:
        """Set the display language stored in the manager metadata.

        Parameters
        ----------
        value : ClearString or None
            New language code. ``None`` clears it.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        TypeError
            If ``value`` is neither a ``str`` nor ``None``.
        """
        if value is not None and not isinstance(value, str):
            raise TypeError(f"value must be a string, not {type(value)}")
        with self._lock:
            self._require_decrypted()
            self._metadata["language"] = value

    def get_close_timer_s(self) -> int:
        """Return the inactivity auto-close delay stored in the metadata.

        Returns
        -------
        int
            Number of seconds of inactivity before the application
            auto-saves and closes.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.
        """
        with self._lock:
            self._require_decrypted()
            return self._metadata["close_timer_s"]

    def set_close_timer_s(self, value: int) -> None:
        """Set the inactivity auto-close delay stored in the metadata.

        Parameters
        ----------
        value : int
            New delay in seconds. Must be strictly positive.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.

        TypeError
            If ``value`` is not an ``int``.

        ValueError
            If ``value`` is not strictly positive.
        """
        if not isinstance(value, int):
            raise TypeError(f"value must be an int, not {type(value)}")
        if value <= 0:
            raise ValueError(f"value must be strictly positive, not {value}")
        with self._lock:
            self._require_decrypted()
            self._metadata["close_timer_s"] = value

    def get_version(self) -> int:
        """
        Return the password manager data format version.

        Returns
        -------
        int
            Current data format version.

        Raises
        ------
        RuntimeError
            If :meth:`decrypt_data` has not been called yet.
        """
        with self._lock:
            self._require_decrypted()
            return self._metadata["version"]

    # ----------------
    # Debug representation
    # ----------------

    def __repr__(self) -> str:
        """
        Return a debug-friendly representation of the manager.

        Returns
        -------
        str
            A representation built only from whether the manager has
            been decrypted yet and, if so, how many vaults it holds,
            never from any vault, item, or credential content, so it
            stays safe to print or log.
        """
        if self._vaults is None:
            return f"{type(self).__name__}(decrypted=False)"
        return f"{type(self).__name__}(decrypted=True, vaults={len(self._vaults)})"