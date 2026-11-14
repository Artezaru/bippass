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

import json
import os
from pathlib import Path
from typing import Any, Iterable, Literal, cast

import pyaescbc

from .types import ClearString, PayloadData, PreferencesData
from .exceptions import (
    CorruptedBase64Error, CorruptedFileError, ItemAlreadyExistsError,
    ItemNotFoundError, PrimaryPasswordError, SecondaryPasswordError,
    TamperedDataError, UnsupportedVersionError, VaultAlreadyExistsError,
    VaultNotFoundError, WrongPasswordError,
)
from .common import (
    _now, _b64decode, _b64encode, _check_date, _check_keys,
    _check_lock_timer, _check_optional_name, _check_optional_str, _sort_items,
)
from .credentials import Credentials
from .datakey import DataKey
from .item import Item
from .vault import Vault
from .uuids import UUIDError, _check_uuid, _check_unique_uuids, _generate_uuid, _get_uuid_index


#: Value of the ``"format"`` key of every bippass file.
FORMAT_NAME = "bippass"

#: File format version written by this software.
FORMAT_VERSION = 3

#: Prefix of the authenticated data of the encrypted payload. Binds the
#: payload to this format version: a payload can never be read as
#: another version. NEVER change it: existing files could no longer be
#: decrypted.
_PAYLOAD_AUTHDATA = b"bippass::payload::v3"

#: Keys accepted in each section of the serialized data.
_ENVELOPE_KEYS = ("format", "version", "label", "primary_key", "payload")
_PAYLOAD_KEYS = ("metadata", "secondary_key", "vaults", "preferences")
_METADATA_KEYS = ("uuid", "username", "creation_date", "modification_date")
_PREFERENCES_KEYS = ("theme", "language", "lock_timer_s")

#: Value of every preference absent from a file.
_DEFAULT_PREFERENCES: PreferencesData = {
    "theme": "dark",
    "language": "en",
    "lock_timer_s": 300,
}


def _payload_authdata(label: str | None) -> bytearray:
    """
    Build the authenticated data of the payload.

    Returns
    -------
    bytearray
        ``bippass::payload::v3|<label as JSON>``: the label is
        authenticated together with the payload, so that changing it in
        the envelope makes the file fail to decrypt. JSON encoding keeps
        ``None`` and ``""`` distinct.
    """
    return bytearray(_PAYLOAD_AUTHDATA + b"|" + json.dumps(label).encode("utf-8"))


class PasswordManager:
    """
    Manage an encrypted password file: its vaults, items and keys.

    ``PasswordManager`` is the top-level object of bippass. It reads and
    writes a profile file, unlocks it with the primary and secondary
    passwords, owns the :class:`Vault` instances, guarantees that item
    UUIDs are unique across every vault, and handles password changes
    and the exchange of items between profiles.

    Instances are not created directly: use :meth:`read` (or
    :meth:`from_bytes`) to open an existing file, or :meth:`create` to
    start a new one.

    Notes
    -----
    **File format (version 3).** A file is a small JSON *envelope*,
    whose only encrypted part is the ``payload``::

        {
            "format":      "bippass",
            "version":     3,
            "label":       "<display name, or null>",
            "primary_key": "<file key, wrapped by the primary password>",
            "payload":     "<content, encrypted with the file key>"
        }

    and the decrypted payload is::

        {
            "metadata":      {"uuid", "username", "creation_date", "modification_date"},
            "secondary_key": "<data key, wrapped by the secondary password>",
            "vaults":        [{vault}, {vault}, ...],
            "preferences":   {"theme", "language", "lock_timer_s"}
        }

    Binary values are Base64-encoded. The format, version and label are
    readable without any password, so that the right reading code can
    be chosen, and a profile picker can show the profile, before
    anything is asked to the user (see :meth:`from_bytes`). The payload
    is authenticated together with its format version and the label.

    **Label.** The label is the only piece of content readable without
    a password: a display name for profile pickers (see
    :mod:`profiles`), chosen by the user, who may leave it ``None`` to
    keep the profile anonymous. It is independent of the username,
    which is only stored inside the encrypted payload.

    **Two keys, two layers** (see :class:`Credentials`):

    - the **primary** password only unwraps the *file key*, which
      decrypts the payload: everything but the sensitive values
      (vault and item names, logins, websites, ...);
    - the **secondary** password only unwraps the *data key*, which
      decrypts the sensitive values (passwords, TOTP secrets, encrypted
      custom fields).

    The slow PBKDF2 derivation of a password (see
    :attr:`Credentials.PRIMARY_ITERATIONS`) therefore only happens when
    unlocking or changing that password. Saving only uses the file key:
    it takes milliseconds, and does not need the data key.

    **Lifecycle.** The same verbs as the interfaces, so that a caller
    can report each kind of failure distinctly and in order::

        manager = PasswordManager.read(path)  # CorruptedFileError, UnsupportedVersionError
        manager.unlock(primary)               # PrimaryPasswordError
        manager.decrypt(secondary)            # SecondaryPasswordError
        ...
        manager.encrypt()                     # forget the data key
        manager.save(path)
        manager.close()                       # erases both keys, irreversibly

    Locking a profile is not a state of the manager: the interfaces
    lock by saving and closing it, and read the file again to reopen it.

    ===========  ===================  ==========================================
    State        Reached by           What is available
    ===========  ===================  ==========================================
    locked       :meth:`read`         the label only
    unlocked     :meth:`unlock`       vaults, items, clear fields, metadata
    decrypted    :meth:`decrypt`      the data key, to decrypt secrets on demand
    closed       :meth:`close`        nothing
    ===========  ===================  ==========================================

    :meth:`unlock` really decrypts something: the file content, which
    then stays in memory. :meth:`decrypt` decrypts no secret: it only
    unwraps the data key, with which each secret can then be decrypted
    when asked for (see :meth:`Item.get` with ``data_key``), and erased
    right after. Symmetrically, :meth:`encrypt` re-encrypts nothing: it
    forgets the data key, since secrets are never held in clear. Methods
    called too early raise :class:`RuntimeError`.

    **Passwords** are given as ``bytearray`` and erased as soon as they
    have been used, whether the operation succeeds or not: the caller
    must not reuse a password ``bytearray`` after passing it.

    **Data key.** Always obtain the data key from :attr:`data_key` right
    before using it, never keep it: :meth:`change_secondary_password`
    replaces it and erases the previous one.

    **Uniqueness.** Item UUIDs are unique across every vault of the
    manager; vault UUIDs are unique among vaults. Several vaults (or
    items) may share the same name.

    **Order.** Neither vaults nor items have an order chosen by the
    user: :meth:`get_vaults` returns the vaults sorted by name, and
    interfaces show the items of a vault sorted too (see
    :meth:`Vault.sorted_items`).

    **Dates.** :attr:`modification_date` records changes to the manager
    itself: changing the username, the label or a password, adding or
    removing a vault. Changing preferences, and any change made inside
    a vault or an item, do not update it.

    **Threads.** This class performs no locking. Every method is meant
    to be called from one thread (typically the GUI thread). To save
    without blocking that thread, split :meth:`save` in two: call
    :meth:`to_bytes` in the GUI thread (fast: it only serializes and
    encrypts with the file key), then hand the returned bytes to
    :meth:`write_file` in a worker thread. :meth:`write_file` touches
    nothing but its arguments, so it is safe to run concurrently with
    any further change to the manager.

    The textual representation of a manager (:func:`repr`, :func:`str`)
    only shows its state and vault count, so it stays safe to print or
    log.

    See Also
    --------
    Credentials
        Holds the file key and the data key of an unlocked manager.

    Vault, Item
        The content of the manager.
    """

    def __init__(self) -> None:
        """
        Create a blank, locked manager (internal).

        Notes
        -----
        Use :meth:`read`, :meth:`from_bytes` or :meth:`create` instead.
        """
        self._credentials: Credentials = Credentials()
        self._wrapped_file_key: bytearray | None = None
        self._encrypted_payload: bytearray | None = None
        self._wrapped_data_key: bytearray | None = None

        self._label: ClearString | None = None
        self._uuid: str | None = None
        self._username: ClearString | None = None
        self._creation_date: str | None = None
        self._modification_date: str | None = None
        self._vaults: list[Vault] | None = None
        self._preferences: PreferencesData = cast(PreferencesData, dict(_DEFAULT_PREFERENCES))
        self._closed: bool = False

    # ----------------
    # Opening and creation
    # ----------------

    @classmethod
    def read(cls, path: str | Path) -> PasswordManager:
        """
        Open a file, without unlocking it.

        Parameters
        ----------
        path : str or Path
            File to read.

        Returns
        -------
        PasswordManager
            A locked manager: call :meth:`unlock` next.

        Raises
        ------
        OSError
            If the file cannot be read.

        CorruptedFileError, UnsupportedVersionError
            See :meth:`from_bytes`.
        """
        return cls.from_bytes(Path(path).read_bytes())

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> PasswordManager:
        """
        Open the content of a file, without unlocking it.

        Parameters
        ----------
        data : bytes or bytearray
            Content of a bippass file. Not modified.


        Returns
        -------
        PasswordManager
            A locked manager: call :meth:`unlock` next.


        Raises
        ------
        TypeError
            If ``data`` is neither ``bytes`` nor ``bytearray``.

        UnsupportedVersionError
            If the file is a valid bippass file of another format
            version (including version 1 files, which were a raw
            password-mode bundle with no envelope).

        CorruptedFileError
            If ``data`` is not a bippass file, or its envelope is
            malformed.


        Notes
        -----
        No password is needed nor asked here: only the unencrypted
        envelope is read, which is enough to tell the format version.
        Older formats are not read.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes or bytearray, not {type(data)}")

        if bytes(data[:4]) == b"PACB":
            raise UnsupportedVersionError(
                "This is a version 1 bippass file: it must be converted first."
            )

        try:
            envelope = json.loads(bytes(data).decode("utf-8"))
            envelope = _check_keys("file envelope", envelope, _ENVELOPE_KEYS)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise CorruptedFileError("Not a valid bippass file.") from exc

        if envelope.get("format") != FORMAT_NAME:
            raise CorruptedFileError("Not a bippass file.")
        version = envelope.get("version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise CorruptedFileError("Invalid format version.")
        if version != FORMAT_VERSION:
            raise UnsupportedVersionError(
                f"Format version {version} is not supported "
                f"(this software reads version {FORMAT_VERSION})."
            )

        try:
            label = _check_optional_name("label", envelope.get("label"))
            wrapped_file_key = _b64decode("primary_key", envelope.get("primary_key"))
            payload = _b64decode("payload", envelope.get("payload"))
        except (TypeError, CorruptedBase64Error) as exc:
            raise CorruptedFileError("Corrupted file envelope.") from exc

        manager = cls()
        manager._label = label
        manager._wrapped_file_key = wrapped_file_key
        manager._encrypted_payload = payload
        return manager

    @classmethod
    def create(
        cls,
        username: ClearString | None,
        primary_password: bytearray,
        secondary_password: bytearray,
        *,
        label: ClearString | None = None,
    ) -> PasswordManager:
        """
        Create a new, empty, fully unlocked manager.

        Parameters
        ----------
        username : ClearString or None
            Username of the new profile, stored encrypted. Stripped;
            blank means none.

        primary_password : bytearray
            Primary password. Erased once used.

        secondary_password : bytearray
            Secondary password. Erased once used.

        label : ClearString or None, optional
            Display name readable without any password (keyword-only,
            see the class-level Notes). Stripped. ``None`` (the default),
            or a blank label, keeps the profile anonymous; a GUI would
            typically propose the username.


        Returns
        -------
        PasswordManager
            A manager with no vault, unlocked and decrypted. Nothing is
            written to disk until :meth:`save` is called.


        Raises
        ------
        TypeError
            If ``username`` or ``label`` is neither a ``str`` nor
            ``None``, or a password is not a ``bytearray``.

        ValueError
            If a password is empty.


        Notes
        -----
        Slow by design: both passwords go through a full PBKDF2
        derivation (see :class:`Credentials`). A fresh random file key
        and data key are generated.
        """
        username = _check_optional_name("username", username)
        label = _check_optional_name("label", label)
        manager = cls()
        manager._label = label
        file_key, data_key = DataKey.random(), DataKey.random()
        try:
            manager._wrapped_file_key = file_key.wrap(
                primary_password, Credentials.PRIMARY_ITERATIONS, purpose="file"
            )
            manager._wrapped_data_key = data_key.wrap(
                secondary_password, Credentials.SECONDARY_ITERATIONS, purpose="data"
            )
        except BaseException:
            file_key.clear()
            data_key.clear()
            for password in (primary_password, secondary_password):
                if isinstance(password, bytearray):
                    pyaescbc.delete_bytearray(password)
            raise

        manager._credentials.set_file_key(file_key)
        manager._credentials.set_data_key(data_key)
        manager._uuid = _generate_uuid(())
        manager._username = username
        now = _now()
        manager._creation_date = now
        manager._modification_date = now
        manager._vaults = []
        return manager

    # ----------------
    # Unlocking
    # ----------------

    def unlock(self, password: bytearray) -> None:
        """
        Unlock the profile: decrypt the file content with the primary password.

        Parameters
        ----------
        password : bytearray
            Primary password. Erased once used, even if wrong.


        Raises
        ------
        RuntimeError
            If the profile is already unlocked, or the manager is closed.

        PrimaryPasswordError
            If ``password`` is wrong.

        TamperedDataError
            If the password is right but the payload fails
            authentication (the file, or its label, has been modified).

        CorruptedFileError
            If the decrypted payload is not valid bippass data.


        Notes
        -----
        On success, vaults, items, clear fields, metadata and
        preferences are in memory, and the encrypted payload is dropped.
        Secrets stay encrypted: see :meth:`decrypt`. Slow by design (one
        full PBKDF2 derivation).
        """
        self._require_open()
        if self._credentials.has_file_key:
            raise RuntimeError("The profile is already unlocked.")

        assert self._wrapped_file_key is not None  # set by read() or create()
        try:
            file_key = DataKey.unwrap(self._wrapped_file_key, password, purpose="file")
        except WrongPasswordError as exc:
            raise PrimaryPasswordError("Wrong primary password.") from exc

        try:
            try:
                clear = pyaescbc.decrypt_with_key(
                    self._encrypted_payload, file_key.key,
                    authdata=_payload_authdata(self._label),
                )
            except pyaescbc.AuthError as exc:
                raise TamperedDataError("The file content has been tampered with.") from exc
            try:
                payload = json.loads(clear.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CorruptedFileError("Invalid file content.") from exc
            finally:
                pyaescbc.delete_bytearray(clear)
            try:
                self._load_payload(payload)
            except (TypeError, ValueError, UUIDError, CorruptedBase64Error) as exc:
                raise CorruptedFileError(f"Invalid file content: {exc}") from exc
        except BaseException:
            file_key.clear()
            raise

        self._credentials.set_file_key(file_key)
        self._encrypted_payload = None

    def decrypt(self, password: bytearray) -> None:
        """
        Unwrap the data key with the secondary password.

        Parameters
        ----------
        password : bytearray
            Secondary password. Erased once used, even if wrong.


        Raises
        ------
        RuntimeError
            If the profile is locked, already decrypted, or closed.

        SecondaryPasswordError
            If ``password`` is wrong.


        Notes
        -----
        Nothing is decrypted by this call: secrets stay encrypted in
        the items. Afterwards, the data key is available as
        :attr:`data_key`, so that each secret can be decrypted on demand
        (e.g. ``item.get("passwords", data_key=manager.data_key)``).
        Slow by design (one full PBKDF2 derivation).
        """
        self._require_unlocked()
        if self._credentials.has_data_key:
            raise RuntimeError("The profile is already decrypted: the data key is available.")
        assert self._wrapped_data_key is not None  # set by unlock() or create()
        try:
            data_key = DataKey.unwrap(self._wrapped_data_key, password, purpose="data")
        except WrongPasswordError as exc:
            raise SecondaryPasswordError("Wrong secondary password.") from exc
        self._credentials.set_data_key(data_key)

    @property
    def is_unlocked(self) -> bool:
        """Whether the profile is unlocked: its content (vaults, items, clear fields) is in memory."""
        return not self._closed and self._credentials.has_file_key

    @property
    def is_decrypted(self) -> bool:
        """Whether the profile is decrypted: the data key is available to decrypt secrets on demand."""
        return not self._closed and self._credentials.has_data_key

    @property
    def data_key(self) -> DataKey:
        """
        Return the data key, to pass to the encrypted-field operations of :class:`Item`.

        Returns
        -------
        DataKey
            The current data key, by reference.

        Raises
        ------
        RuntimeError
            If the data key is not available (see :meth:`decrypt`).

        Notes
        -----
        Obtain it right before each use, never keep it: see the
        class-level Notes.
        """
        return self._require_decrypted()

    def _require_open(self) -> None:
        """Raise :class:`RuntimeError` if the manager has been closed."""
        if self._closed:
            raise RuntimeError("The password manager has been closed.")

    def _require_wrapped_file_key(self) -> bytearray:
        """Return the wrapped file key, or raise :class:`RuntimeError` once closed."""
        self._require_open()
        if self._wrapped_file_key is None:
            raise RuntimeError("The password manager has no file key.")
        return self._wrapped_file_key

    def _require_unlocked(self) -> list[Vault]:
        """
        Return the vaults, raising :class:`RuntimeError` if the profile is locked.
        """
        self._require_open()
        if self._vaults is None or not self._credentials.has_file_key:
            raise RuntimeError("The profile is locked: call unlock() first.")
        return self._vaults

    def _require_decrypted(self) -> DataKey:
        """
        Return the data key, raising :class:`RuntimeError` if it is not available.
        """
        self._require_unlocked()
        if not self._credentials.has_data_key:
            raise RuntimeError("The data key is not available: call decrypt() first.")
        return self._credentials.data_key

    def _touch(self) -> None:
        """Record a change to the manager itself (see the class-level Notes)."""
        self._modification_date = _now()

    # ----------------
    # (De)serialization of the content
    # ----------------

    def _load_payload(self, payload: Any) -> None:
        """
        Load a decrypted payload (see the class-level Notes for its structure).

        Notes
        -----
        Same reading rules as :meth:`Item.from_dict`: unknown keys are
        refused, missing keys take their default value. Every vault UUID
        must be unique, and so must every item UUID across all vaults.
        Nothing is kept unless the whole payload is valid.
        """
        payload = _check_keys("file content", payload, _PAYLOAD_KEYS)
        if "secondary_key" not in payload:
            raise ValueError("file content must contain a 'secondary_key'.")
        wrapped_data_key = _b64decode("secondary_key", payload["secondary_key"])

        metadata = _check_keys("file metadata", payload.get("metadata", {}), _METADATA_KEYS)
        if "uuid" not in metadata:
            raise ValueError("file metadata must contain a 'uuid'.")
        uuid = _check_uuid(metadata["uuid"])
        username = _check_optional_name("username", metadata.get("username"))
        now = _now()
        creation_date = _check_date("creation_date", metadata.get("creation_date"), now)
        modification_date = _check_date("modification_date", metadata.get("modification_date"), now)

        vaults = payload.get("vaults") or []
        if not isinstance(vaults, list):
            raise TypeError("vaults must be a list.")
        parsed = [Vault.from_dict(entry) for entry in vaults]
        _check_unique_uuids(vault.uuid for vault in parsed)
        _check_unique_uuids(item for vault in parsed for item in vault.item_uuids())

        preferences = _check_keys("preferences", payload.get("preferences", {}), _PREFERENCES_KEYS)
        self._preferences = {
            "theme": _check_optional_str(
                "theme", preferences.get("theme", _DEFAULT_PREFERENCES["theme"])),
            "language": _check_optional_str(
                "language", preferences.get("language", _DEFAULT_PREFERENCES["language"])),
            "lock_timer_s": _check_lock_timer(
                preferences.get("lock_timer_s", _DEFAULT_PREFERENCES["lock_timer_s"])),
        }
        self._uuid, self._username = uuid, username
        self._creation_date, self._modification_date = creation_date, modification_date
        self._vaults = parsed
        self._wrapped_data_key = wrapped_data_key

    def _payload(self) -> PayloadData:
        """Serialize the content of the file (nothing is decrypted)."""
        vaults = self._require_unlocked()
        # All set once unlocked (by unlock() or create()).
        assert self._uuid is not None and self._wrapped_data_key is not None
        assert self._creation_date is not None and self._modification_date is not None
        return {
            "metadata": {
                "uuid": self._uuid,
                "username": self._username,
                "creation_date": self._creation_date,
                "modification_date": self._modification_date,
            },
            "secondary_key": _b64encode(self._wrapped_data_key),
            "vaults": [vault.to_dict() for vault in vaults],
            "preferences": cast(PreferencesData, dict(self._preferences)),
        }

    # ----------------
    # Saving and closing
    # ----------------

    def to_bytes(self) -> bytearray:
        """
        Serialize the whole manager into the (encrypted) content of a file.

        Returns
        -------
        bytearray
            The complete file content (envelope included), ready to be
            written with :meth:`write_file`.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        Notes
        -----
        Fast: only the file key is used (no key derivation), and the
        data key is not needed. Counterpart of :meth:`from_bytes`. A new random IV
        is drawn on every call.

        This is the half of :meth:`save` that reads the manager: call
        it from the thread that owns the manager (see the class-level
        Notes on threads).

        The intermediate JSON text of the payload is an immutable
        ``str`` that cannot be erased; it holds no sensitive value in
        clear (those stay encrypted with the data key).
        """
        clear = bytearray(json.dumps(self._payload(), ensure_ascii=False).encode("utf-8"))
        encrypted = pyaescbc.encrypt_with_key(
            clear, self._credentials.file_key.key,
            authdata=_payload_authdata(self._label),
            delete_data=True,
        )
        envelope = {
            "format": FORMAT_NAME,
            "version": FORMAT_VERSION,
            "label": self._label,
            "primary_key": _b64encode(self._require_wrapped_file_key()),
            "payload": _b64encode(encrypted),
        }
        return bytearray(json.dumps(envelope, indent=4).encode("utf-8"))

    @staticmethod
    def write_file(path: str | Path, data: bytes | bytearray) -> None:
        """
        Atomically write the content of a file.

        Parameters
        ----------
        path : str or Path
            Destination file. Its parent directory must exist. Created
            if it does not exist yet, replaced if it does.

        data : bytes or bytearray
            Content to write, typically returned by :meth:`to_bytes`.

        Raises
        ------
        OSError
            If the file cannot be written. ``path`` is then left
            untouched.

        Notes
        -----
        The content is written to a sibling temporary file, flushed to
        disk, then moved into place with :func:`os.replace` (atomic on
        POSIX and Windows): a crash or a full disk can never leave
        ``path`` truncated. Either the old file is still there, or the
        new one is there complete.

        Uses nothing but its arguments: safe to call from a worker
        thread while the manager keeps being used (see the class-level
        Notes on threads).
        """
        path = Path(path)
        tmp_path = path.with_name(path.name + ".tmp")
        try:
            with open(tmp_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        except OSError:
            tmp_path.unlink(missing_ok=True)
            raise

    def save(self, path: str | Path) -> None:
        """
        Encrypt the manager and write it to a file.

        Parameters
        ----------
        path : str or Path
            Destination file.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        OSError
            If the file cannot be written.

        Notes
        -----
        Shorthand for ``write_file(path, to_bytes())``, entirely in the
        calling thread. See the class-level Notes to write from a
        worker thread instead.
        """
        self.write_file(path, self.to_bytes())

    def encrypt(self) -> None:
        """
        Forget the data key: secrets can no longer be decrypted.

        Raises
        ------
        RuntimeError
            If the manager is closed.

        Notes
        -----
        Counterpart of :meth:`decrypt`. Nothing needs re-encrypting:
        secrets are never held in clear, only decrypted on demand, so
        erasing the data key is enough to make them unreadable again
        until :meth:`decrypt` is called. Everything else (vaults,
        items, clear fields) stays available. Harmless if the data key
        is already forgotten.
        """
        self._require_open()
        self._credentials.clear_data_key()

    def close(self) -> None:
        """
        Erase both keys from memory and drop the content.

        Notes
        -----
        Irreversible: every later operation raises
        :class:`RuntimeError`. Unsaved changes are lost: save first.
        Calling it more than once is harmless.
        """
        self._credentials.clear()
        self._vaults = None
        self._encrypted_payload = None
        self._closed = True

    # ----------------
    # Passwords
    # ----------------

    def change_primary_password(
        self,
        current_password: bytearray,
        new_password: bytearray,
    ) -> None:
        """
        Change the primary password.

        Parameters
        ----------
        current_password : bytearray
            Current primary password, required so that an unlocked but
            unattended session cannot be used to change it. Erased once
            used.

        new_password : bytearray
            New primary password. Erased once used.


        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        PrimaryPasswordError
            If ``current_password`` is wrong. Nothing is changed.

        ValueError
            If ``new_password`` is empty. Nothing is changed.


        Notes
        -----
        A new random file key is generated and wrapped with
        ``new_password``: anyone who knows the old password and kept an
        old copy of the file can therefore not use it to read files
        saved from now on. Nothing else is re-encrypted.

        Takes effect on disk at the next :meth:`save`: save right
        after. Updates :attr:`modification_date`. Slow by design (two
        full PBKDF2 derivations).
        """
        self._require_unlocked()
        self._check_current_password(current_password, new_password, "file")

        new_key = DataKey.random()
        try:
            wrapped = new_key.wrap(new_password, Credentials.PRIMARY_ITERATIONS, purpose="file")
        except BaseException:
            new_key.clear()
            raise

        self._wrapped_file_key = wrapped
        self._credentials.set_file_key(new_key)
        self._touch()

    def change_secondary_password(
        self,
        current_password: bytearray,
        new_password: bytearray,
    ) -> None:
        """
        Change the secondary password.

        Parameters
        ----------
        current_password : bytearray
            Current secondary password, required so that an unlocked
            but unattended session cannot be used to change it. Erased
            once used.

        new_password : bytearray
            New secondary password. Erased once used.


        Raises
        ------
        RuntimeError
            If the data key is not available (see :meth:`decrypt`).

        SecondaryPasswordError
            If ``current_password`` is wrong. Nothing is changed.

        ValueError
            If ``new_password`` is empty. Nothing is changed.

        TamperedDataError
            If a sensitive value fails to decrypt. Nothing is changed.


        Notes
        -----
        A new random data key is generated and wrapped with
        ``new_password``, and every sensitive value of every item is
        re-encrypted with it (fast: no key derivation is involved).
        Anyone who knows the old password and kept an old copy of the
        file can therefore not use it to read values saved from now on.

        Atomic: every item is prepared first, and everything is
        committed at once only once all succeeded; the :class:`Item`
        and :class:`Vault` instances are kept. The previous data key is
        erased: references to it held elsewhere become unusable (see
        the class-level Notes on the data key).

        Takes effect on disk at the next :meth:`save`: save right
        after. Updates :attr:`modification_date`, but no vault's or
        item's. Slow by design (two full PBKDF2 derivations).
        """
        old_key = self._require_decrypted()
        self._check_current_password(current_password, new_password, "data")

        new_key = DataKey.random()
        try:
            commits = [vault._prepare_change_data_key(old_key, new_key)
                       for vault in self._require_unlocked()]
            wrapped = new_key.wrap(new_password, Credentials.SECONDARY_ITERATIONS, purpose="data")
        except BaseException:
            new_key.clear()
            raise

        for commit in commits:
            commit()
        self._wrapped_data_key = wrapped
        self._credentials.set_data_key(new_key)
        self._touch()

    def _check_current_password(
        self,
        current_password: bytearray,
        new_password: bytearray,
        purpose: Literal["file", "data"],
    ) -> None:
        """
        Verify a current password before changing it.

        Notes
        -----
        If verification fails, ``new_password`` is erased too, so that
        no password is ever left behind by a failed change.
        """
        wrapped = self._wrapped_file_key if purpose == "file" else self._wrapped_data_key
        assert wrapped is not None  # the manager is unlocked here
        error = PrimaryPasswordError if purpose == "file" else SecondaryPasswordError
        try:
            DataKey.unwrap(wrapped, current_password, purpose=purpose).clear()
        except BaseException as exc:
            if isinstance(new_password, bytearray):
                pyaescbc.delete_bytearray(new_password)
            if isinstance(exc, WrongPasswordError):
                raise error(f"Wrong current {'primary' if purpose == 'file' else 'secondary'} password.") from exc
            raise

    # ----------------
    # Label (readable without password)
    # ----------------

    @property
    def label(self) -> ClearString | None:
        """
        Return the label of the profile.

        Returns
        -------
        ClearString or None
            Display name, or ``None`` for an anonymous profile.
            Available as soon as the file has been read: no password is
            needed.

        Raises
        ------
        RuntimeError
            If the manager is closed.
        """
        self._require_open()
        return self._label

    def set_label(self, value: ClearString | None) -> None:
        """
        Set the label of the profile.

        Parameters
        ----------
        value : ClearString or None
            New display name, stripped. ``None``, or a blank label, makes
            the profile anonymous.

        Raises
        ------
        RuntimeError
            If the profile is locked: the label is authenticated
            with the payload, which must be re-encrypted.

        TypeError
            If ``value`` is neither a ``str`` nor ``None``.

        Notes
        -----
        Takes effect on disk at the next :meth:`save`. Updates
        :attr:`modification_date`.
        """
        self._require_unlocked()
        self._label = _check_optional_name("label", value)
        self._touch()

    # ----------------
    # Metadata
    # ----------------

    @property
    def uuid(self) -> str:
        """
        Return the unique identifier of the profile.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        self._require_unlocked()
        assert self._uuid is not None
        return self._uuid

    @property
    def creation_date(self) -> str:
        """
        Return the creation date of the profile (ISO 8601, with timezone).

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        self._require_unlocked()
        assert self._creation_date is not None
        return self._creation_date

    @property
    def modification_date(self) -> str:
        """
        Return the date of the last change to the manager itself.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        Notes
        -----
        See the class-level Notes for which operations update it.
        """
        self._require_unlocked()
        assert self._modification_date is not None
        return self._modification_date

    def get_username(self) -> ClearString | None:
        """
        Return the username.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        self._require_unlocked()
        return self._username

    def set_username(self, value: ClearString | None) -> None:
        """
        Set the username.

        Parameters
        ----------
        value : ClearString or None
            New username, stripped. ``None``, or a blank username,
            removes it.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        TypeError
            If ``value`` is neither a ``str`` nor ``None``.

        Notes
        -----
        Updates :attr:`modification_date`. The file name does not
        depend on the username (see :func:`profile_path`), and neither
        does the :attr:`label`: change it separately if wanted.
        """
        self._require_unlocked()
        self._username = _check_optional_name("username", value)
        self._touch()

    # ----------------
    # Preferences
    # ----------------

    def get_theme(self) -> ClearString | None:
        """
        Return the display theme (e.g. ``"dark"``, ``"light"``).

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        self._require_unlocked()
        return self._preferences["theme"]

    def set_theme(self, value: ClearString | None) -> None:
        """
        Set the display theme.

        Parameters
        ----------
        value : ClearString or None
            New theme. Not interpreted by this class.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        TypeError
            If ``value`` is neither a ``str`` nor ``None``.
        """
        self._require_unlocked()
        self._preferences["theme"] = _check_optional_str("theme", value)

    def get_language(self) -> ClearString | None:
        """
        Return the display language code (e.g. ``"en"``, ``"fr"``).

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        self._require_unlocked()
        return self._preferences["language"]

    def set_language(self, value: ClearString | None) -> None:
        """
        Set the display language code.

        Parameters
        ----------
        value : ClearString or None
            New language code. Not interpreted by this class.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        TypeError
            If ``value`` is neither a ``str`` nor ``None``.
        """
        self._require_unlocked()
        self._preferences["language"] = _check_optional_str("language", value)

    def get_lock_timer_s(self) -> int:
        """
        Return the inactivity delay, in seconds, before an interface locks
        the profile (saves and closes it).

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        self._require_unlocked()
        return self._preferences["lock_timer_s"]

    def set_lock_timer_s(self, value: int) -> None:
        """
        Set the inactivity delay before an interface locks the profile.

        Parameters
        ----------
        value : int
            New delay in seconds. Must be strictly positive.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        TypeError
            If ``value`` is not an ``int``.

        ValueError
            If ``value`` is not strictly positive.
        """
        self._require_unlocked()
        self._preferences["lock_timer_s"] = _check_lock_timer(value)

    # ----------------
    # Vaults
    # ----------------

    def vault_uuids(self) -> tuple[str, ...]:
        """
        Return the UUIDs of the vaults, in the order of :meth:`get_vaults`.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        return tuple(vault.uuid for vault in self.get_vaults())

    def get_vaults(self) -> list[Vault]:
        """
        Return every vault, sorted by name.

        Returns
        -------
        list of Vault
            A new list, holding the manager's own :class:`Vault`
            instances, in alphabetical order: case- and
            accent-insensitive, numbers by value, unnamed vaults last
            (same rules as :meth:`Vault.sorted_items`).

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        return _sort_items(self._require_unlocked(), "name")

    def get_vault(self, vault_uuid: str) -> Vault:
        """
        Return a vault by UUID.

        Parameters
        ----------
        vault_uuid : str
            UUID of the vault.

        Returns
        -------
        Vault
            The vault itself (not a copy).

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        VaultNotFoundError
            If ``vault_uuid`` is not a valid UUID, or no vault has it.
        """
        vaults = self._require_unlocked()
        try:
            return vaults[_get_uuid_index(vault_uuid, [vault.uuid for vault in vaults])]
        except UUIDError as exc:
            raise VaultNotFoundError(f"Unknown vault UUID: {vault_uuid}") from exc

    def _add_vault(self, vault: Vault) -> None:
        """
        Append an existing vault, with its items (internal).

        Parameters
        ----------
        vault : Vault
            Vault to add, stored by reference.


        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        TypeError
            If ``vault`` is not a :class:`Vault`.

        VaultAlreadyExistsError
            If a vault with the same UUID is already in the manager.

        ItemAlreadyExistsError
            If one of its items has a UUID already used in the manager.


        Notes
        -----
        Updates :attr:`modification_date`. The vault is left untouched:
        UUID collisions must be resolved before.
        """
        vaults = self._require_unlocked()
        if not isinstance(vault, Vault):
            raise TypeError(f"vault must be a Vault, not {type(vault)}")
        if vault.uuid in self.vault_uuids():
            raise VaultAlreadyExistsError(f"Vault UUID already exists: {vault.uuid}")
        collisions = set(vault.item_uuids()) & set(self.item_uuids())
        if collisions:
            raise ItemAlreadyExistsError(f"Item UUID(s) already exist: {sorted(collisions)}")
        vaults.append(vault)
        self._touch()

    def add_empty_vault(self, name: ClearString | None = None) -> Vault:
        """
        Create an empty vault.

        Parameters
        ----------
        name : ClearString or None, optional
            Name of the new vault, stripped. Not required to be unique.

        Returns
        -------
        Vault
            The new vault.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        TypeError
            If ``name`` is neither a ``str`` nor ``None``.

        Notes
        -----
        Updates :attr:`modification_date`.
        """
        self._require_unlocked()
        vault = Vault(_generate_uuid(self.vault_uuids()), name)
        self._add_vault(vault)
        return vault

    def remove_vault(self, vault_uuid: str, *, force: bool = False) -> Vault:
        """
        Remove a vault.

        Parameters
        ----------
        vault_uuid : str
            UUID of the vault to remove.

        force : bool, optional
            If ``False`` (the default), removing a vault that still
            holds items is refused, so that a full vault can never be
            discarded by accident.


        Returns
        -------
        Vault
            The removed vault, with its items.


        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        VaultNotFoundError
            If no vault has this UUID.

        ValueError
            If the vault is not empty and ``force`` is ``False``.


        Notes
        -----
        Updates :attr:`modification_date`.
        """
        vault = self.get_vault(vault_uuid)
        if len(vault) and not force:
            raise ValueError("The vault is not empty: pass force=True to remove it anyway.")
        self._require_unlocked().remove(vault)
        self._touch()
        return vault

    # ----------------
    # Items
    # ----------------

    def item_uuids(self) -> tuple[str, ...]:
        """
        Return the UUIDs of every item of every vault.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        return tuple(uuid for vault in self._require_unlocked() for uuid in vault.item_uuids())

    def all_items(self) -> list[Item]:
        """
        Return every item of every vault, vault by vault.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).
        """
        return [item for vault in self._require_unlocked() for item in vault]

    def find_item(self, item_uuid: str) -> tuple[Vault, Item]:
        """
        Find an item and the vault holding it.

        Parameters
        ----------
        item_uuid : str
            UUID of the item.

        Returns
        -------
        tuple of (Vault, Item)
            The vault holding the item, and the item itself.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        ItemNotFoundError
            If no item of any vault has this UUID.
        """
        for vault in self._require_unlocked():
            if item_uuid in vault:
                return vault, vault.get_item(item_uuid)
        raise ItemNotFoundError(f"Unknown item UUID: {item_uuid}")

    def get_item(self, item_uuid: str) -> Item:
        """
        Return an item by UUID, whatever its vault.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        ItemNotFoundError
            If no item of any vault has this UUID.
        """
        return self.find_item(item_uuid)[1]

    def vault_of(self, item_uuid: str) -> Vault:
        """
        Return the vault holding an item.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        ItemNotFoundError
            If no item of any vault has this UUID.
        """
        return self.find_item(item_uuid)[0]

    def add_empty_item(self, vault_uuid: str) -> Item:
        """
        Create an empty item in a vault.

        Parameters
        ----------
        vault_uuid : str
            UUID of the vault receiving the item.

        Returns
        -------
        Item
            The new item, with a UUID unique across every vault.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        VaultNotFoundError
            If no vault has this UUID.
        """
        vault = self.get_vault(vault_uuid)
        item = Item(_generate_uuid(self.item_uuids()))
        vault.add_item(item)
        return item

    def remove_item(self, item_uuid: str) -> Item:
        """
        Remove an item, whatever its vault.

        Parameters
        ----------
        item_uuid : str
            UUID of the item.

        Returns
        -------
        Item
            The removed item.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        ItemNotFoundError
            If no item of any vault has this UUID.

        Notes
        -----
        Updates the :attr:`Vault.modification_date` of its vault.
        """
        return self.vault_of(item_uuid).remove_item(item_uuid)

    def move_item(self, item_uuid: str, vault_uuid: str) -> None:
        """
        Move an item to another vault.

        Parameters
        ----------
        item_uuid : str
            UUID of the item.

        vault_uuid : str
            UUID of the destination vault. Moving an item to its own
            vault does nothing.

        Raises
        ------
        RuntimeError
            If the profile is locked (see :meth:`unlock`).

        ItemNotFoundError
            If no item of any vault has this UUID.

        VaultNotFoundError
            If no vault has ``vault_uuid``.

        Notes
        -----
        A removal and an addition: both vaults'
        :attr:`Vault.modification_date` are updated. No re-encryption
        is ever needed: the context of encrypted values does not
        include the vault.
        """
        source, item = self.find_item(item_uuid)
        target = self.get_vault(vault_uuid)
        if source is target:
            return
        source.remove_item(item_uuid)
        target.add_item(item)

    def duplicate_item(self, item_uuid: str) -> Item:
        """
        Duplicate an item, in the same vault.

        Parameters
        ----------
        item_uuid : str
            UUID of the item to duplicate.

        Returns
        -------
        Item
            The duplicate: a new UUID, both dates set to now, and an
            independent copy of every value.

        Raises
        ------
        RuntimeError
            If the data key is not available: the duplicate's values are
            re-encrypted under its new UUID.

        ItemNotFoundError
            If no item of any vault has this UUID.
        """
        data_key = self._require_decrypted()
        vault, original = self.find_item(item_uuid)
        data = original.to_dict()
        now = _now()
        data["metadata"]["creation_date"] = now
        data["metadata"]["modification_date"] = now
        duplicate = Item.from_dict(data)
        duplicate.change_uuid(_generate_uuid(self.item_uuids()), data_key)
        vault.add_item(duplicate)
        return duplicate

    # ----------------
    # Item exchange between profiles
    # ----------------

    def export_items(
        self,
        path: str | Path,
        item_uuids: Iterable[str],
        primary_password: bytearray,
        secondary_password: bytearray,
        *,
        vault_name: ClearString | None = "exported items",
    ) -> None:
        """
        Export a selection of items to a new, standalone file.

        Parameters
        ----------
        path : str or Path
            Destination file. Replaced if it exists.

        item_uuids : Iterable of str
            UUIDs of the items to export, from any vault.

        primary_password, secondary_password : bytearray
            Passwords protecting the exported file (to be shared with
            its recipient, not this profile's own). Erased once used.

        vault_name : ClearString or None, optional
            Name of the single vault of the exported file.


        Raises
        ------
        RuntimeError
            If the data key is not available (see :meth:`decrypt`).

        ItemNotFoundError
            If an item cannot be found. Nothing is written.

        OSError
            If the file cannot be written.


        Notes
        -----
        The exported file is an ordinary version 3 file, with its own
        random keys, holding one vault with a copy of every exported
        item (UUIDs and dates kept), re-encrypted with its data key.
        Items of this profile are never modified. Slow by design (two
        full PBKDF2 derivations).
        """
        data_key = self._require_decrypted()
        items = [self.get_item(uuid) for uuid in item_uuids]

        export = PasswordManager.create(None, primary_password, secondary_password)
        try:
            vault = export.add_empty_vault(vault_name)
            for item in items:
                copy = item.deepcopy()
                copy.change_data_key(data_key, export.data_key)
                vault.add_item(copy)
            export.save(path)
        finally:
            export.close()

    def import_items(
        self,
        path: str | Path,
        primary_password: bytearray,
        secondary_password: bytearray,
        *,
        vault_uuid: str | None = None,
        vault_name: ClearString | None = "imported items",
    ) -> list[Item]:
        """
        Import every item of another file (typically from :meth:`export_items`).

        Parameters
        ----------
        path : str or Path
            File to import from: any version 3 file.

        primary_password, secondary_password : bytearray
            Passwords of that file. Erased once used.

        vault_uuid : str or None, optional
            UUID of the vault receiving the items. ``None`` (the
            default) creates a new vault, named ``vault_name``.

        vault_name : ClearString or None, optional
            Name of the vault created when ``vault_uuid`` is ``None``
            (counterpart of the ``vault_name`` of :meth:`export_items`).
            Ignored otherwise.


        Returns
        -------
        list of Item
            The added items, in the order they were read.


        Raises
        ------
        RuntimeError
            If the data key of this manager is not available (see :meth:`decrypt`).

        VaultNotFoundError
            If no vault has ``vault_uuid``.

        OSError
            If the file cannot be read.

        CorruptedFileError, UnsupportedVersionError
            If the file cannot be opened (see :meth:`from_bytes`).

        PrimaryPasswordError, SecondaryPasswordError
            If a password of that file is wrong.


        Notes
        -----
        Each item is copied and re-encrypted with this profile's data
        key. An item whose UUID collides with one of this profile gets
        a fresh UUID (:meth:`Item.change_uuid`); its dates are kept.

        Atomic: every item is prepared first, and nothing is added
        (nor any vault created) unless all of them succeeded.
        """
        data_key = self._require_decrypted()
        target = None if vault_uuid is None else self.get_vault(vault_uuid)

        source = PasswordManager.read(path)
        try:
            source.unlock(primary_password)
            source.decrypt(secondary_password)
            used = set(self.item_uuids())
            prepared: list[Item] = []
            for item in source.all_items():
                copy = item.deepcopy()
                copy.change_data_key(source.data_key, data_key)
                if copy.uuid in used:
                    copy.change_uuid(_generate_uuid(used), data_key)
                used.add(copy.uuid)
                prepared.append(copy)
        finally:
            source.close()

        if target is None:
            target = self.add_empty_vault(vault_name)
        for item in prepared:
            target.add_item(item)
        return prepared

    # ----------------
    # Debug representation
    # ----------------

    def __repr__(self) -> str:
        """
        Return a debug-friendly representation of the manager.

        Returns
        -------
        str
            Only the unlock state and, once unlocked, the vault count:
            never any name, value or key.
        """
        if self._closed:
            return f"{type(self).__name__}(closed)"
        if self._vaults is None:
            return f"{type(self).__name__}(locked)"
        state = "decrypted" if self._credentials.has_data_key else "unlocked"
        return f"{type(self).__name__}({state}, vaults={len(self._vaults)})"
