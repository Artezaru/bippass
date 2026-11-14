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


Profile-level commands of the shell (see :mod:`bippass.cli.shell`):
creating a profile, changing its passwords, exporting and importing
items, and generating passwords.

As everywhere in the shell, passwords are asked without echo, never
typed as command arguments; a new password is asked twice.
"""

from __future__ import annotations

from pathlib import Path

import pyaescbc

from ..core.manager import PasswordManager
from ..core.password_generator import generate_random_password
from ..core.profiles import ensure_profiles_dir, profile_path
from . import formatting as fmt
from .common import CommandError, ShellContract, ask_password, ask_secret
from .editing import GENERATED_LENGTH


def _erase(*passwords: bytearray) -> None:
    """Erase password buffers (already erased ones stay zeroed)."""
    for password in passwords:
        pyaescbc.delete_bytearray(password)


class ProfileCommands(ShellContract):
    """
    Mixin adding the profile-level commands to :class:`BippassShell`.

    Relies on the shell's state helpers (``_require_unlocked``,
    ``_require_decrypted``, ``_vault``, ``_item``, ``_check_discard``,
    ``_drop``, ``_args``, ``_print``, ``_ask_line``, ``_clipboard``).
    """

    def do_create(self, arg: str) -> None:
        """``create``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        args = self._check_discard(self._args(arg), "create")
        if len(args) > 1:
            raise CommandError("Usage: create [path] [--discard]")
        username = self._ask_line("Username (optional): ").strip() or None
        answer = self._ask_line(
            f"Label, shown without password [{username or 'none'}] (\"-\" for none): "
        ).strip()
        label = None if answer == "-" else (answer or username)

        primary = ask_secret("Primary password (opens the profile): ")
        try:
            secondary = ask_secret("Secondary password (protects the secrets): ")
        except BaseException:
            _erase(primary)
            raise
        manager = PasswordManager.create(username, primary, secondary, label=label)
        if args:
            path = Path(args[0]).expanduser()
        else:
            ensure_profiles_dir()
            path = profile_path(manager.uuid)
        if path.exists():
            manager.close()
            raise CommandError(f"{path} already exists.")
        try:
            manager.save(path)
        except BaseException:
            manager.close()
            raise
        self._drop()
        self.manager, self.path = manager, path
        self._print(f"Created and saved to {path}: the profile is open and decrypted.", "ok")

    def do_passwd(self, arg: str) -> None:
        """``passwd``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_unlocked()
        args = self._args(arg)
        if args not in (["primary"], ["secondary"]):
            raise CommandError("Usage: passwd <primary | secondary>")
        target = args[0]
        current = ask_password(f"Current {target} password: ")
        try:
            new = ask_secret(f"New {target} password: ")
        except BaseException:
            _erase(current)
            raise
        try:
            if bytes(new) == bytes(current):
                raise CommandError("The new password is the same as the current one.")
            if target == "secondary":
                # Changing it needs the data key: the current password
                # decrypts the profile first, so it isn't asked twice.
                if not manager.is_decrypted:
                    manager.decrypt(bytearray(current))
                manager.change_secondary_password(current, new)
            else:
                manager.change_primary_password(current, new)
        finally:
            _erase(current, new)
        if self.path is None:
            self._changed()
            self._print(f'{target.capitalize()} password changed: use "save <path>" to keep it.', "ok")
            return
        manager.save(self.path)
        self.dirty = False
        self._print(f"{target.capitalize()} password changed, and {self.path} saved.", "ok")

    # ----------------
    # Transfer
    # ----------------

    def do_export(self, arg: str) -> None:
        """``export``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_decrypted()
        args = self._args(arg)
        force = "--force" in args
        args = [a for a in args if a != "--force"]
        if len(args) != 1:
            raise CommandError("Usage: export <path> [--force]")
        path = Path(args[0]).expanduser()
        if path.exists() and not force:
            raise CommandError(f"{path} already exists: add --force to replace it.")

        item, vault = self._item(), self._vault()
        if item is not None:
            uuids, vault_name = [item.uuid], vault.get_name() if vault else None
        elif vault is not None:
            uuids, vault_name = [i.uuid for i in vault], vault.get_name()
        else:
            uuids, vault_name = list(manager.item_uuids()), "exported items"
        if not uuids:
            raise CommandError("Nothing to export here.")

        self._print("The exported file gets its own two passwords.")
        primary = ask_secret("Primary password of the exported file: ")
        try:
            secondary = ask_secret("Secondary password of the exported file: ")
        except BaseException:
            _erase(primary)
            raise
        try:
            manager.export_items(path, uuids, primary, secondary,
                                 vault_name=vault_name or "exported items")
        finally:
            _erase(primary, secondary)
        self._print(f"Exported {len(uuids)} item(s) to {path}.", "ok")

    def do_import(self, arg: str) -> None:
        """``import``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_decrypted()
        args = self._args(arg)
        if len(args) != 1:
            raise CommandError("Usage: import <path>")
        path = Path(args[0]).expanduser()
        if not path.is_file():
            raise CommandError(f"{path} doesn't exist.")
        vault = self._vault()
        primary = ask_password("Primary password of the file: ")
        try:
            secondary = ask_password("Secondary password of the file: ")
        except BaseException:
            _erase(primary)
            raise
        try:
            items = manager.import_items(path, primary, secondary,
                                         vault_uuid=vault.uuid if vault else None)
        finally:
            _erase(primary, secondary)
        self._changed()
        if items:
            target = manager.vault_of(items[0].uuid)
            where = target.get_name() or fmt.UNNAMED
        else:
            where = (vault.get_name() if vault else None) or "-"
        self._print(f"Imported {len(items)} item(s) into vault {where!r}.", "ok")

    # ----------------
    # Generator
    # ----------------

    def do_generate(self, arg: str) -> None:
        """``generate``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        args = self._args(arg)
        show = "--show" in args
        special = "--no-special" not in args
        rest = [a for a in args if a not in ("--show", "--no-special")]
        if len(rest) > 1 or (rest and (not rest[0].isdigit() or int(rest[0]) < 1)):
            raise CommandError("Usage: generate [length] [--no-special] [--show]")
        length = int(rest[0]) if rest else GENERATED_LENGTH
        password = generate_random_password(length, use_special=special)
        if show:
            self.out.line(self.out.style(password, "secret"))
            return
        self._clipboard.copy(password)
        self._print(f"Generated {length} characters, copied to the clipboard (cleared in "
                    f"{self._clipboard.clear_after_s:g} s).", "ok")
