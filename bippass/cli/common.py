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

Small helpers shared by the shell modules.
"""

from __future__ import annotations

import getpass
from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator

import pyaescbc

if TYPE_CHECKING:
    from pathlib import Path

    from ..core.item import Item
    from ..core.manager import PasswordManager
    from ..core.vault import Vault
    from .clipboard import ClipboardGuard
    from .console import Output


class CommandError(Exception):
    """Raised by a command to report a user error, without a traceback."""


def ask_password(prompt: str) -> bytearray:
    """
    Ask a password without echo.

    Returns
    -------
    bytearray
        The typed password, UTF-8 encoded, to be handed to (and erased
        by) the manager.

    Notes
    -----
    :func:`getpass.getpass` returns an immutable ``str``, which cannot
    be erased: this is a limit of the terminal input, not of bippass.
    """
    return bytearray(getpass.getpass(prompt), "utf-8")


def ask_secret(prompt: str, *, confirm: bool = True) -> bytearray:
    """
    Ask a new secret value without echo, optionally twice.

    Parameters
    ----------
    prompt : str
        Prompt of the first input.

    confirm : bool, optional
        Ask it a second time and check both match (default: ``True``),
        since a typo in a hidden value cannot be seen.

    Returns
    -------
    bytearray
        The value, UTF-8 encoded.

    Raises
    ------
    CommandError
        If the value is empty, or both inputs differ (both are erased).
    """
    value = ask_password(prompt)
    if not value:
        raise CommandError("Empty value: nothing changed.")
    if confirm:
        again = ask_password("Repeat: ")
        same = again == value
        pyaescbc.delete_bytearray(again)
        if not same:
            pyaescbc.delete_bytearray(value)
            raise CommandError("The two values differ: nothing changed.")
    return value


@contextmanager
def erase_on_error(values: list) -> Iterator[list]:
    """
    Erase secret values if the block they are used in fails.

    Parameters
    ----------
    values : list
        Values obtained so far: clear secrets (``bytearray``), or plain
        ``str`` values, which are left alone. The list may still change
        inside the block: whatever ``bytearray`` it holds when an
        exception propagates is erased.

    Yields
    ------
    list
        ``values`` itself.

    Examples
    --------
    >>> with erase_on_error([]) as secrets:
    ...     secrets.append(ask_secret("New secret: "))
    ...     item.set("passwords", secrets, data_key=data_key)
    """
    try:
        yield values
    except BaseException:
        for value in values:
            if isinstance(value, bytearray):
                pyaescbc.delete_bytearray(value)
        raise


class ShellContract:
    """
    What the command mixins (``EditingCommands``, ``ProfileCommands``)
    expect from the shell they are mixed into.

    Empty at run time: the attributes and methods are those of
    :class:`bippass.cli.shell.BippassShell`; they are only declared
    here for type checkers.
    """

    if TYPE_CHECKING:
        out: Output
        manager: PasswordManager | None
        path: Path | None
        vault_uuid: str | None
        item_uuid: str | None
        dirty: bool
        _clipboard: ClipboardGuard

        def _args(self, arg: str) -> list[str]: ...
        def _print(self, text: str = "", role: str | None = None) -> None: ...
        def _ask_line(self, prompt: str) -> str: ...
        def _require_unlocked(self) -> PasswordManager: ...
        def _require_decrypted(self) -> PasswordManager: ...
        def _vault(self) -> Vault | None: ...
        def _item(self) -> Item | None: ...
        def _current_item(self) -> Item: ...
        def _resolve_vault(self, token: str) -> Vault: ...
        def _resolve_item(self, token: str, vault: Vault) -> Item: ...
        def _check_discard(self, args: list[str], command: str) -> list[str]: ...
        def _changed(self) -> None: ...
        def _drop(self) -> None: ...
