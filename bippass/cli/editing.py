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


Editing commands of the shell (see :mod:`bippass.cli.shell`).

Every command acts *where you are*, like ``cd``:

- at the root, ``add``/``remove`` act on vaults;
- in a vault, ``add``/``remove`` act on items, ``rename`` renames the vault;
- in an item, ``rename``, ``move``, ``remove`` and the ``*field`` commands
  act on that item: ``addfield`` creates a custom field, ``addtofield``
  adds values to an existing field (predefined or custom),
  ``editfield`` replaces one value, ``removefield`` removes one.

Every field command reads ``<field> [number]``: the field name (spaces
allowed, no quotes needed), then the value number shown by ``show``.
Clear values come last, after ``--values`` (several, separated by
``;``) or ``--value`` (one, taken as typed).

Changes are only kept in memory until ``save``: the shell marks the
prompt with ``*`` and refuses to close or quit without ``--discard``
while changes are unsaved.

Secret values (passwords, TOTP secrets, encrypted custom fields) are
never typed on the command line: they are asked without echo (or
generated with ``--generate``), like the passwords of the profile.
The help of every command is in :mod:`bippass.cli.help_texts`.
"""

from __future__ import annotations

import re

import pyaescbc

from ..core.item import FieldKind
from ..core.password_generator import generate_random_password
from . import formatting as fmt
from .common import CommandError, ShellContract, ask_secret, erase_on_error
from .references import PREDEFINED, resolve_field, split_number


#: Default length of a generated password (see ``--generate``).
GENERATED_LENGTH = 20

_NO_SECRET_ON_COMMAND_LINE = (
    "Secret values are never typed on the command line: they are asked without "
    "echo (use --count n for several), or generated with --generate [length]."
)
_SECRET_OPTIONS_ONLY = "--count and --generate are for secret fields only."


def _split_option(arg: str, option: str) -> tuple[str, str | None]:
    """
    Split a command line at ``option``, which takes the rest of the line.

    Parameters
    ----------
    arg : str
        Raw arguments of the command.

    option : str
        ``"--values"`` or ``"--value"``.

    Returns
    -------
    tuple of (str, str or None)
        What comes before the option (field name, number and other
        options), and everything after it, as typed (no shell-like
        parsing, so that any character can be stored). ``None`` if the
        option is absent.
    """
    match = re.search(rf"(?:^|\s){re.escape(option)}(?:\s|$)", arg)
    if match is None:
        return arg, None
    return arg[:match.start()], arg[match.end():]


def _split_values(arg: str) -> tuple[str, list[str] | None]:
    r"""
    Split a command line at ``--values``, and its values on ``;``.

    Returns
    -------
    tuple of (str, list of str or None)
        What comes before ``--values``, and the values: stripped, empty
        ones dropped. ``None`` if there is no ``--values``.

    Raises
    ------
    CommandError
        If ``--values`` is followed by no value.

    Notes
    -----
    Write ``\;`` for a ``;`` inside a value.

    Examples
    --------
    >>> _split_values('clear Backup codes --values 1111; 2222 ; 3\\;3')
    ('clear Backup codes', ['1111', '2222', '3;3'])
    """
    head, tail = _split_option(arg, "--values")
    if tail is None:
        return head, None
    values = [v.replace("\\;", ";").strip() for v in re.split(r"(?<!\\);", tail)]
    values = [v for v in values if v]
    if not values:
        raise CommandError("--values needs at least one value (separate them with ';').")
    return head, values


def _secret_options(tokens: list[str]) -> tuple[list[str], int | None, int | None]:
    """
    Extract ``--count <n>`` and ``--generate [length]`` from tokens.

    Returns
    -------
    tuple of (list of str, int or None, int or None)
        The remaining tokens (field name and number), the count and the
        generated length; ``None`` for an option not given.

    Raises
    ------
    CommandError
        If an option value is not a positive integer.
    """
    rest: list[str] = []
    count = generate = None
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "--count":
            if i + 1 >= len(tokens) or not tokens[i + 1].isdigit() or int(tokens[i + 1]) < 1:
                raise CommandError("--count needs a positive number.")
            count, i = int(tokens[i + 1]), i + 2
        elif token == "--generate":
            # A number right after --generate is its length, never a value number.
            if i + 1 < len(tokens) and tokens[i + 1].isdigit():
                if int(tokens[i + 1]) < 1:
                    raise CommandError("--generate needs a positive length.")
                generate, i = int(tokens[i + 1]), i + 2
            else:
                generate, i = GENERATED_LENGTH, i + 1
        else:
            rest.append(token)
            i += 1
    return rest, count, generate


class EditingCommands(ShellContract):
    """
    Mixin adding the editing commands to :class:`BippassShell`.

    Relies on the shell's state helpers (``_require_unlocked``,
    ``_require_decrypted``, ``_vault``, ``_item``, ``_current_item``,
    ``_resolve_vault``, ``_resolve_item``, ``_args``, ``_print``) and
    calls ``_changed`` after every modification.
    """

    # ----------------
    # Vaults and items
    # ----------------

    def do_add(self, arg: str) -> None:
        """``add``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_unlocked()
        name = " ".join(self._args(arg))
        if not name:
            raise CommandError("Usage: add <name>")
        if self.item_uuid is not None:
            raise CommandError('Already in an item: use "addfield" to add a field, '
                               'or "cd .." to add an item.')
        if self.vault_uuid is None:
            vault = manager.add_empty_vault(name)
            self._changed()
            number = manager.vault_uuids().index(vault.uuid) + 1
            self._print(f"Added vault {vault.get_name()!r} (#{number}).", "ok")
            return
        item = manager.add_empty_item(self.vault_uuid)
        item.set_name(name)
        self.item_uuid = item.uuid
        self._changed()
        self._print(f"Added item {item.get_name()!r}: you are now in it.", "ok")

    def do_rename(self, arg: str) -> None:
        """``rename``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_unlocked()
        name = " ".join(self._args(arg))
        if not name:
            raise CommandError("Usage: rename <new name>")
        target = self._item() or self._vault()
        if target is None:
            raise CommandError("Go into a vault or an item first.")
        target.set_name(name)
        self._changed()
        self._print(f"Renamed to {target.get_name()!r}.", "ok")

    def do_move(self, arg: str) -> None:
        """``move``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_unlocked()
        item = self._current_item()
        args = self._args(arg)
        if not args:
            raise CommandError("Usage: move <vault>")
        target = self._resolve_vault(" ".join(args))
        if target.uuid == self.vault_uuid:
            raise CommandError("The item is already in this vault.")
        manager.move_item(item.uuid, target.uuid)
        self.vault_uuid = target.uuid
        self._changed()
        self._print(f"Moved to vault {target.get_name() or fmt.UNNAMED!r}.", "ok")

    def do_remove(self, arg: str) -> None:
        """``remove``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_unlocked()
        args = self._args(arg)
        force = "--force" in args
        name = " ".join(a for a in args if a != "--force")

        if self.item_uuid is not None:
            if name:
                raise CommandError('In an item, "remove" takes no name: it removes this item.')
            item = manager.remove_item(self.item_uuid)
            self.item_uuid = None
            self._changed()
            self._print(f"Removed item {item.get_name() or fmt.UNNAMED!r}.", "ok")
            return
        if not name:
            raise CommandError("Usage: remove <vault | item> [--force]")
        current_vault = self._vault()
        if current_vault is not None:
            item = self._resolve_item(name, current_vault)
            manager.remove_item(item.uuid)
            self._changed()
            self._print(f"Removed item {item.get_name() or fmt.UNNAMED!r}.", "ok")
            return
        vault = self._resolve_vault(name)
        if len(vault) and not force:
            raise CommandError(
                f"Vault {vault.get_name() or fmt.UNNAMED!r} holds {len(vault)} item(s): "
                "add --force to remove it with them."
            )
        manager.remove_vault(vault.uuid, force=True)
        self._changed()
        self._print(f"Removed vault {vault.get_name() or fmt.UNNAMED!r}.", "ok")

    # ----------------
    # Fields
    # ----------------

    def _new_secrets(
        self, count: int | None, generate: int | None, what: str, *, confirm: bool = True,
    ) -> list[bytearray]:
        """
        Get ``count`` (default 1) new secret values: generated with
        ``generate`` characters, or asked without echo (twice if
        ``confirm``).

        Notes
        -----
        If an input fails (empty, or the two inputs differ), the values
        already obtained are erased before the error propagates.
        """
        count = count or 1
        with erase_on_error([]) as values:
            for n in range(count):
                if generate is not None:
                    values.append(bytearray(generate_random_password(generate, use_special=True),
                                            "utf-8"))
                else:
                    label = what if count == 1 else f"{what} {n + 1}/{count}"
                    values.append(ask_secret(f"New {label}: ", confirm=confirm))
        if generate is not None:
            self._print(f"Generated {count} {what}(s) of {generate} characters.", "ok")
        return values

    def do_addfield(self, arg: str) -> None:
        """``addfield``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        item = self._current_item()
        head, values = _split_values(arg)
        tokens = self._args(head)
        if not tokens or tokens[0] not in ("clear", "secret"):
            if tokens and tokens[0].casefold() in (*PREDEFINED, *PREDEFINED.values()):
                raise CommandError(f'{tokens[0]!r} is a predefined field: use '
                                   f'"addtofield {tokens[0]} --values ...".')
            raise CommandError("Usage: addfield <clear | secret> <name> [--values v1; v2...]")
        kind = tokens[0]
        tokens, count, generate = _secret_options(tokens[1:])
        name = " ".join(tokens)
        if not name:
            raise CommandError(f"Usage: addfield {kind} <name> ...")

        if kind == "clear":
            if count is not None or generate is not None:
                raise CommandError(_SECRET_OPTIONS_ONLY)
            custom_id = item.add_custom(name, FieldKind.CLEAR, values or [])
        else:
            if values is not None:
                raise CommandError(_NO_SECRET_ON_COMMAND_LINE)
            data_key = self._require_decrypted().data_key
            with erase_on_error(self._new_secrets(count, generate, "secret")) as secrets:
                custom_id = item.add_custom(name, FieldKind.ENCRYPTED, secrets, data_key=data_key)
        ref = fmt.custom_ref(item.custom_ids().index(custom_id))
        self._changed()
        self._print(f"Custom field {item.custom_name(custom_id)!r} added as {ref}, with "
                    f"{item.custom_count(custom_id)} value(s).", "ok")

    def do_addtofield(self, arg: str) -> None:
        """``addtofield``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        item = self._current_item()
        head, values = _split_values(arg)
        tokens, count, generate = _secret_options(self._args(head))
        if not tokens:
            raise CommandError("Usage: addtofield <field> [--values v1; v2...]")
        field = resolve_field(item, " ".join(tokens))

        if not field.encrypted:
            if count is not None or generate is not None:
                raise CommandError(_SECRET_OPTIONS_ONLY)
            if values is None:
                raise CommandError(f"Usage: addtofield {' '.join(tokens)} --values v1; v2...")
            field.set(field.get() + values)
            added = len(values)
        else:
            if values is not None:
                raise CommandError(_NO_SECRET_ON_COMMAND_LINE)
            data_key = self._require_decrypted().data_key
            with erase_on_error(self._new_secrets(count, generate, field.label,
                                                 confirm=field.predefined != "totps")) as secrets:
                added = len(secrets)
                secrets[:0] = field.get(data_key)        # current values first
                field.set(secrets, data_key)
        self._changed()
        self._print(f"Added {added} value(s) to {field.label!r}.", "ok")

    def do_editfield(self, arg: str) -> None:
        """``editfield``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        item = self._current_item()
        head, value = _split_option(arg, "--value")
        tokens, count, generate = _secret_options(self._args(head))
        name, number = split_number(tokens)
        if not name or count is not None:
            raise CommandError("Usage: editfield <field> [number] [--value <new value> | --generate [length]]")
        field = resolve_field(item, name)
        index = field.index(number)

        if not field.encrypted:
            if generate is not None:
                raise CommandError(_SECRET_OPTIONS_ONLY)
            if value is None or not value.strip():
                raise CommandError(f"Usage: editfield {field.label} [number] --value <new value>")
            values = field.get()
            values[index] = value.strip()
            field.set(values)
        else:
            if value is not None:
                raise CommandError(_NO_SECRET_ON_COMMAND_LINE)
            data_key = self._require_decrypted().data_key
            with erase_on_error(field.get(data_key)) as values:
                new = self._new_secrets(None, generate, field.label,
                                        confirm=field.predefined != "totps")[0]
                pyaescbc.delete_bytearray(values[index])
                values[index] = new
                field.set(values, data_key)
        self._changed()
        self._print(f"{field.label} [{index + 1}] updated.", "ok")

    def do_removefield(self, arg: str) -> None:
        """``removefield``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        item = self._current_item()
        name, number = split_number(self._args(arg))
        if not name:
            raise CommandError("Usage: removefield <field> [number]")
        field = resolve_field(item, name)

        if field.custom_id is not None and number is None:
            label = field.label
            item.remove_custom(field.custom_id)
            self._changed()
            self._print(f"Custom field {label!r} removed.", "ok")
            return
        index = field.index(number)
        data_key = self._require_decrypted().data_key if field.encrypted else None
        with erase_on_error(field.get(data_key)) as values:
            removed = values.pop(index)
            if isinstance(removed, bytearray):
                pyaescbc.delete_bytearray(removed)
            field.set(values, data_key)
        self._changed()
        self._print(f"{field.label} [{index + 1}] removed.", "ok")
