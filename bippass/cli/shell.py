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


Interactive command-line shell to browse a password manager.

The shell works like a tiny file system: the profile is the root, its
vaults are directories, and their items are entries::

    /                     the profile        (ls = vaults)
    /<vault>              a vault            (ls = items)
    /<vault>/<item>       an item            (ls = show)

Typical session::

    bippass> load ~/.bippass/profiles/6f1c2e4a-....bippass
    bippass[Alice|locked]> unlock          # asks the primary password
    bippass[Alice|unlocked]> decrypt       # asks the secondary password
    bippass[Alice|decrypted]> ls
    bippass[Alice|decrypted]> cd Perso
    bippass[Alice|decrypted]:/Perso> cd 2
    bippass[Alice|decrypted]:/Perso/GitHub> reveal password
    bippass[Alice|decrypted]:/Perso/GitHub> close

Passwords are always asked interactively, without echo (see
:func:`bippass.cli.common.ask_password`), never given as command
arguments: they would otherwise end up in the terminal scrollback and
history.

The help of every command lives in :mod:`bippass.cli.help_texts` only:
the ``do_*`` docstrings just point to it.
"""

from __future__ import annotations

import cmd
import shlex
import threading
import traceback
from pathlib import Path
from typing import Sequence

from ..core.exceptions import PasswordManagerError
from ..core.item import Item
from ..core.vault import Vault
from ..core.manager import PasswordManager
from ..core.profiles import PROFILES_DIR, ProfileEntry, list_existing_profiles
from ..core.totp import generate_totp_code
from . import clipboard
from . import formatting as fmt
from . import help_texts
from .common import CommandError, ask_password
from .console import Output
from .editing import EditingCommands
from .profile_commands import ProfileCommands
from .references import FieldRef, resolve, resolve_field, split_number


#: Errors caused by what the user typed or by the files they named:
#: printed as one line. Any other exception is a bug, printed with its
#: traceback (the shell keeps running).
USER_ERRORS: tuple[type[BaseException], ...] = (
    CommandError,
    PasswordManagerError,   # wrong password, corrupted file...
    clipboard.ClipboardError,
    OSError,                # missing file, permissions...
    ValueError,             # invalid value refused by the core (blank name, bad TOTP secret...)
)


class BippassShell(EditingCommands, ProfileCommands, cmd.Cmd):
    """
    Interactive shell browsing one password manager at a time.

    Parameters
    ----------
    stdin, stdout : file-like, optional
        Streams to read commands from and write output to (default: the
        terminal), as for :class:`cmd.Cmd`.

    color : bool or None, optional
        Force colors on or off (see :class:`Output`).

    Notes
    -----
    Editing commands (see :mod:`bippass.cli.editing`) change the
    manager in memory only: nothing is written until ``save``. While
    changes are unsaved, the prompt shows ``*``, and ``load``,
    ``close`` and ``quit`` refuse to discard them unless given
    ``--discard``.

    User errors (see :data:`USER_ERRORS`) are printed as a single line.
    Ctrl-C cancels the current line or input, never leaves the shell.
    The manager is closed (its keys erased) on ``lock``, ``close``,
    ``quit``, end of input (Ctrl-D), or when another profile is loaded.

    Auto-lock: while a profile is unlocked, waiting at the prompt for
    longer than its ``lock_timer_s`` preference locks it, like ``lock``
    (saved if needed, closed, screen cleared). A timer thread does it,
    only between commands: every command runs under a lock the timer
    must get first. If the save fails, the profile stays open.
    """

    intro = None

    def __init__(self, stdin=None, stdout=None, *, color: bool | None = None) -> None:
        super().__init__(stdin=stdin, stdout=stdout)
        if stdin is not None:
            self.use_rawinput = False
        self.out = Output(self.stdout, color)
        self.manager: PasswordManager | None = None
        self.path: Path | None = None
        self.vault_uuid: str | None = None
        self.item_uuid: str | None = None
        self._profiles: list[ProfileEntry] = []
        self.dirty: bool = False
        self._eof_warned: bool = False
        self._greeted: bool = False
        self._clipboard = clipboard.ClipboardGuard()
        # Auto-lock (see the class Notes): armed between commands.
        self._command_lock = threading.Lock()
        self._lock_timer: threading.Timer | None = None

    # ----------------
    # Shell plumbing
    # ----------------

    @property
    def prompt(self) -> str:  # type: ignore[override]
        """Prompt showing the profile label, its state, and the current location."""
        out = self.out
        if self.manager is None:
            return out.prompt(out.style("bippass", "title") + out.style("> "))
        state = fmt.state_of(self.manager)
        label = self.manager.label or fmt.UNNAMED
        markup = (
            out.style("bippass", "title") + out.style("[")
            + out.style(label) + (out.style("*", "warn") if self.dirty else "")
            + out.style("|") + out.style(state, state) + out.style("]")
        )
        if state != "locked":
            markup += out.style(":") + out.style(self._location(), "path")
        return out.prompt(markup + out.style("> "))

    def preloop(self) -> None:
        """Greet the user once, when the interactive loop first starts; arm the auto-lock."""
        self._arm_lock_timer()
        if not self._greeted:
            self._greeted = True
            self.out.line(self.out.style("bippass", "title")
                          + self.out.style(' command line. Type "help" for the list of commands.'))

    def cmdloop(self, intro: str | None = None) -> None:
        """Run the interactive loop; Ctrl-C at the prompt cancels the line."""
        while True:
            try:
                super().cmdloop(intro)
                return
            except KeyboardInterrupt:
                self._print("^C")

    def _print(self, text: str = "", role: str | None = None) -> None:
        """Write a line of plain text (user data included) to the shell output."""
        self.out.text(text, role)

    def precmd(self, line: str) -> str:
        """Stop the auto-lock timer; forget a first Ctrl-D as soon as another command is typed."""
        self._disarm_lock_timer()
        if line != "EOF":
            self._eof_warned = False
        return line

    def postcmd(self, stop: bool, line: str) -> bool:
        """Start the auto-lock timer again, unless the shell stops."""
        if not stop:
            self._arm_lock_timer()
        return stop

    def _arm_lock_timer(self) -> None:
        """Start the auto-lock timer, if a profile is unlocked."""
        self._disarm_lock_timer()
        if self.manager is None or not self.manager.is_unlocked:
            return
        self._lock_timer = threading.Timer(self.manager.get_lock_timer_s(), self._auto_lock)
        self._lock_timer.daemon = True
        self._lock_timer.start()

    def _disarm_lock_timer(self) -> None:
        """Stop the auto-lock timer, if running."""
        if self._lock_timer is not None:
            self._lock_timer.cancel()
            self._lock_timer = None

    def _auto_lock(self) -> None:
        """
        Timer callback: lock the profile after inactivity, like ``lock``.

        Notes
        -----
        Skipped if a command is running (it holds the command lock).
        Unsaved changes are saved first; if that fails (or there is no
        file to save to), the profile stays open and a warning is
        printed.
        """
        if not self._command_lock.acquire(blocking=False):
            return
        try:
            if self.manager is None or not self.manager.is_unlocked:
                return
            if self.dirty:
                if self.path is None:
                    self._print()
                    self._print('Not auto-locked: unsaved changes and no file (use "save <path>").', "warn")
                    return
                try:
                    self.manager.save(self.path)
                except (PasswordManagerError, OSError) as exc:
                    self._print()
                    self._print(f"Not auto-locked: saving failed ({exc}).", "warn")
                    return
            self._drop()
            self._clear_screen('Locked after inactivity. Use "load" to open a profile.')
            self.stdout.write(self.prompt)
            self.stdout.flush()
        finally:
            self._command_lock.release()

    def _ask_line(self, prompt: str) -> str:
        """
        Ask for one line of (non-secret) text.

        Parameters
        ----------
        prompt : str
            Question.

        Returns
        -------
        str
            The answer, without its line ending (empty at end of input).
        """
        if self.use_rawinput:
            return input(prompt)
        self.stdout.write(prompt)
        self.stdout.flush()
        return self.stdin.readline().rstrip("\r\n")

    def onecmd(self, line: str) -> bool:
        """Run one command, turning user errors into a one-line message."""
        try:
            with self._command_lock:
                return super().onecmd(line)
        except KeyboardInterrupt:
            self._print()
            self._print("Cancelled.", "warn")
        except USER_ERRORS as exc:
            self._print(f"error: {exc}", "error")
        except Exception:
            self._print("internal error (please report it):", "error")
            self._print(traceback.format_exc().rstrip(), "muted")
        return False

    def emptyline(self) -> bool:
        """Do nothing on an empty line (instead of repeating the last command)."""
        return False

    def default(self, line: str) -> None:
        """Report an unknown command."""
        raise CommandError(f'Unknown command {line.split()[0]!r}: type "help".')

    @staticmethod
    def _args(arg: str) -> list[str]:
        """Split command arguments, honoring quotes (e.g. ``cd "My vault"``)."""
        try:
            return shlex.split(arg)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

    def _no_args(self, arg: str, command: str) -> None:
        """Fail if a command that takes no argument was given some."""
        if self._args(arg):
            raise CommandError(f"Usage: {command}")

    # ----------------
    # State helpers
    # ----------------

    def _require_loaded(self) -> PasswordManager:
        """Return the manager, or fail if no profile is loaded."""
        if self.manager is None:
            raise CommandError('No profile loaded: use "load" first.')
        return self.manager

    def _require_unlocked(self) -> PasswordManager:
        """Return the manager, or fail if its primary layer is locked."""
        manager = self._require_loaded()
        if not manager.is_unlocked:
            raise CommandError('The profile is locked: use "unlock" first.')
        return manager

    def _require_decrypted(self) -> PasswordManager:
        """Return the manager, or fail if its secondary layer is locked."""
        manager = self._require_unlocked()
        if not manager.is_decrypted:
            raise CommandError('Secrets are encrypted: use "decrypt" first.')
        return manager

    def _vault(self) -> Vault | None:
        """Return the current vault, if any."""
        if self.vault_uuid is None:
            return None
        return self._require_unlocked().get_vault(self.vault_uuid)

    def _item(self) -> Item | None:
        """Return the current item, if any."""
        if self.item_uuid is None:
            return None
        return self._require_unlocked().get_item(self.item_uuid)

    def _current_item(self) -> Item:
        """Return the current item, or fail."""
        self._require_unlocked()
        item = self._item()
        if item is None:
            raise CommandError('Go into an item first ("cd <item>").')
        return item

    def _location(self) -> str:
        """Return the current location, e.g. ``/Perso/GitHub``."""
        vault, item = self._vault(), self._item()
        parts = [p for p in (
            vault and (vault.get_name() or fmt.short_uuid(vault.uuid)),
            item and (item.get_name() or fmt.short_uuid(item.uuid)),
        ) if p]
        return "/" + "/".join(parts)

    def _resolve_vault(self, token: str) -> Vault:
        """Find a vault of the profile from what the user typed."""
        return resolve(token, self._require_unlocked().get_vaults(),
                       lambda v: v.uuid, lambda v: v.get_name(), "vault")

    def _resolve_item(self, token: str, vault: Vault) -> Item:
        """Find an item of a vault from what the user typed."""
        return resolve(token, vault.sorted_items(),
                       lambda i: i.uuid, lambda i: i.get_name(), "item")

    def _changed(self) -> None:
        """Record that the profile has unsaved changes."""
        self.dirty = True

    def _check_discard(self, args: list[str], command: str) -> list[str]:
        """
        Refuse to lose unsaved changes, unless ``--discard`` is in ``args``.

        Returns
        -------
        list of str
            ``args`` without ``--discard``.
        """
        if self.dirty and "--discard" not in args:
            raise CommandError(
                f'Unsaved changes: use "save" first, or "{command} --discard" to lose them.'
            )
        return [a for a in args if a != "--discard"]

    def _drop(self) -> None:
        """Close the current manager, if any, clear the clipboard and reset the location."""
        self._disarm_lock_timer()
        self._clipboard.clear_now()
        if self.manager is not None:
            self.manager.close()
        self.manager, self.path = None, None
        self.vault_uuid = self.item_uuid = None
        self.dirty = False

    def _clear_screen(self, message: str) -> None:
        """Clear the screen, scrollback included, then confirm with ``message``."""
        # So that secrets revealed earlier cannot be scrolled back to.
        self.out.clear_screen()
        self._print(message, "ok")

    # ----------------
    # Profile commands
    # ----------------

    def do_profiles(self, arg: str) -> None:
        """``profiles``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._no_args(arg, "profiles")
        self._profiles = list_existing_profiles()
        if not self._profiles:
            self._print(f"No profile in {PROFILES_DIR}.")
            return
        fmt.print_profiles(self.out, self._profiles)

    def do_load(self, arg: str) -> None:
        """``load``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        args = self._check_discard(self._args(arg), "load <path | number>")
        if len(args) != 1:
            raise CommandError("Usage: load <path | number> [--discard]")
        token = args[0]
        if token.isdigit() and not Path(token).exists():
            if not self._profiles:
                self._profiles = list_existing_profiles()
            index = int(token) - 1
            if not 0 <= index < len(self._profiles):
                raise CommandError(f'No profile #{token}: see "profiles".')
            path = self._profiles[index].path
        else:
            path = Path(token).expanduser()

        manager = PasswordManager.read(path)
        self._drop()
        self.manager, self.path = manager, path
        self._print(f'Loaded {path}. Use "unlock" to open it.', "ok")

    def do_unlock(self, arg: str) -> None:
        """``unlock``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_loaded()
        self._no_args(arg, "unlock")
        if manager.is_unlocked:
            raise CommandError("The profile is already unlocked.")
        manager.unlock(ask_password("Primary password: "))
        self._print(f"Unlocked: {len(manager.vault_uuids())} vault(s), "
                    f"{len(manager.item_uuids())} item(s).", "ok")

    def do_decrypt(self, arg: str) -> None:
        """``decrypt``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_unlocked()
        self._no_args(arg, "decrypt")
        if manager.is_decrypted:
            raise CommandError("The profile is already decrypted.")
        manager.decrypt(ask_password("Secondary password: "))
        self._print("Decrypted: secrets can now be shown.", "ok")

    def do_info(self, arg: str) -> None:
        """``info``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_loaded()
        self._no_args(arg, "info")
        fmt.print_info(self.out, manager, str(self.path) if self.path else None)

    def do_save(self, arg: str) -> None:
        """``save``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_unlocked()
        args = self._args(arg)
        if len(args) > 1:
            raise CommandError("Usage: save [path]")
        path = Path(args[0]).expanduser() if args else self.path
        if path is None:
            raise CommandError('No file to save to: use "save <path>".')
        manager.save(path)
        self.path = path
        self.dirty = False
        self._print(f"Saved to {path}.", "ok")

    def do_encrypt(self, arg: str) -> None:
        """``encrypt``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_decrypted()
        self._no_args(arg, "encrypt")
        manager.encrypt()
        self._clipboard.clear_now()
        self._clear_screen('Encrypted: use "decrypt" to show secrets again.')

    def do_lock(self, arg: str) -> None:
        """``lock``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_loaded()
        self._no_args(arg, "lock")
        saved = None
        if self.dirty:
            if self.path is None:
                raise CommandError('No file to save to: use "save <path>" first.')
            manager.save(self.path)
            saved = self.path
        self._drop()
        done = f"{saved} saved and closed" if saved else "closed (nothing to save)"
        self._clear_screen(f'Locked: {done}. Use "load" to open a profile.')

    def do_close(self, arg: str) -> None:
        """``close``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_loaded()
        if self._check_discard(self._args(arg), "close"):
            raise CommandError("Usage: close [--discard]")
        self._drop()
        self._print("Closed.", "ok")

    # ----------------
    # Navigation
    # ----------------

    def do_pwd(self, arg: str) -> None:
        """``pwd``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_unlocked()
        self._no_args(arg, "pwd")
        self._print(self._location())

    def do_cd(self, arg: str) -> None:
        """``cd``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_unlocked()
        args = self._args(arg)
        if not args:
            raise CommandError("Usage: cd <vault | item | .. | />")
        target = " ".join(args)  # unquoted names with spaces
        if target == "/":
            self.vault_uuid = self.item_uuid = None
        elif target == "..":
            if self.item_uuid is not None:
                self.item_uuid = None
            else:
                self.vault_uuid = None
        elif self.item_uuid is not None:
            raise CommandError('Already in an item: use "cd .." first.')
        elif self.vault_uuid is None:
            self.vault_uuid = self._resolve_vault(target).uuid
        else:
            vault = self._vault()
            assert vault is not None
            self.item_uuid = self._resolve_item(target, vault).uuid

    def do_home(self, arg: str) -> None:
        """``home``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_unlocked()
        self._no_args(arg, "home")
        self.vault_uuid = self.item_uuid = None

    def do_ls(self, arg: str) -> None:
        """``ls``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_unlocked()
        self._no_args(arg, "ls")
        if self.item_uuid is not None:
            self.do_show("")
        elif self.vault_uuid is not None:
            self.do_items("")
        else:
            self.do_vaults("")

    def do_vaults(self, arg: str) -> None:
        """``vaults``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        manager = self._require_unlocked()
        self._no_args(arg, "vaults")
        if self.vault_uuid is not None:
            raise CommandError('"vaults" only works at the root: use "home" first.')
        fmt.print_vaults(self.out, manager.get_vaults())

    def do_items(self, arg: str) -> None:
        """``items``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_unlocked()
        self._no_args(arg, "items")
        vault = self._vault()
        if vault is None or self.item_uuid is not None:
            raise CommandError('"items" only works in a vault: use "cd <vault>" (or "cd .." '
                               "from an item).")
        fmt.print_items(self.out, vault.sorted_items())

    def do_show(self, arg: str) -> None:
        """``show``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        item = self._current_item()
        self._no_args(arg, "show")
        fmt.print_item(self.out, item)

    # ----------------
    # Secrets
    # ----------------

    def _print_secrets(self, field: FieldRef, number: str | None, render) -> None:
        """
        Decrypt and print the values of an encrypted field.

        Parameters
        ----------
        field : FieldRef
            Encrypted field of the current item.

        number : str or None
            Value number, or ``None`` for every value.

        render : callable
            Turns one clear value (``bytearray``) into the styled text
            printed after its label.
        """
        indexes = [field.index(number)] if number is not None else range(field.count())
        if not indexes:
            raise CommandError(f"{field.label!r} has no value.")
        with field.revealed(self._require_decrypted().data_key) as secrets:
            for i in indexes:
                self.out.line(self.out.style(f"{field.label} [{i + 1}]: ", "label")
                              + render(secrets[i]))

    def do_reveal(self, arg: str) -> None:
        """``reveal``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_decrypted()
        item = self._current_item()
        name, number = split_number(self._args(arg))
        if not name:
            raise CommandError("Usage: reveal <field> [number]")
        field = resolve_field(item, name)
        if not field.encrypted:
            raise CommandError(f'{field.label!r} is not encrypted: its values are shown by "show".')
        self._print_secrets(field, number,
                            lambda s: self.out.style(s.decode("utf-8", "replace"), "secret"))

    def do_totp(self, arg: str) -> None:
        """``totp``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._require_decrypted()
        item = self._current_item()
        args = self._args(arg)
        if len(args) > 1:
            raise CommandError("Usage: totp [number]")

        def render(secret: bytearray) -> str:
            code, remaining = generate_totp_code(secret)
            return (self.out.style(code, "code")
                    + self.out.style(f"  ({remaining} s left)",
                                     "urgent" if remaining <= 5 else "muted"))

        self._print_secrets(FieldRef(item, predefined="totps"), args[0] if args else None, render)

    def do_copy(self, arg: str) -> None:
        """``copy``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        item = self._current_item()
        name, number = split_number(self._args(arg))
        if not name:
            raise CommandError("Usage: copy <field> [number]")
        field = resolve_field(item, name)
        index = field.index(number)
        label = field.label
        if not field.encrypted:
            text = field.get()[index]
        else:
            with field.revealed(self._require_decrypted().data_key) as secrets:
                if field.predefined == "totps":
                    text, label = generate_totp_code(secrets[index])[0], "TOTP code"
                else:
                    text = secrets[index].decode("utf-8", "replace")
        self._clipboard.copy(text)
        shown = f"{label} [{number}]" if number else label
        self._print(f"Copied {shown} to the clipboard (cleared in "
                    f"{self._clipboard.clear_after_s:g} s).", "ok")

    # ----------------
    # Help and exit
    # ----------------

    def do_help(self, arg: str) -> None:
        """``help``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        name = arg.strip()
        if not name:
            help_texts.print_overview(self.out)
        elif not help_texts.print_details(self.out, name):
            raise CommandError(f'No command {name!r}: type "help".')

    def do_clear(self, arg: str) -> None:
        """``clear``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        self._no_args(arg, "clear")
        self.out.clear_screen()

    do_cls = do_clear

    def do_quit(self, arg: str) -> bool:
        """``quit``: see :data:`bippass.cli.help_texts.COMMANDS`."""
        if self._check_discard(self._args(arg), "quit"):
            raise CommandError("Usage: quit [--discard]")
        self._drop()
        return True

    do_exit = do_quit

    def do_EOF(self, arg: str) -> bool:
        """Leave on end of input (Ctrl-D); twice in a row if there are unsaved changes."""
        self._print()
        if self.dirty and not self._eof_warned:
            self._eof_warned = True
            raise CommandError('Unsaved changes: "save" first, or press Ctrl-D again to lose them.')
        self._drop()
        return True


def main(argv: Sequence[str] | None = None) -> int:
    """
    Run the interactive shell.

    Parameters
    ----------
    argv : Sequence of str, optional
        Command-line arguments (default: :data:`sys.argv` without the
        program name). An optional path loads that profile at start.

    Returns
    -------
    int
        Exit status: ``0``, or ``1`` if the profile given on the
        command line cannot be loaded (the shell is then not started).
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m bippass",
        description="Browse a bippass profile from the command line.",
    )
    parser.add_argument("path", nargs="?", help="profile file to load at start")
    parser.add_argument("--no-color", action="store_true",
                        help="plain output, even if rich is installed")
    args = parser.parse_args(argv)

    shell = BippassShell(color=False if args.no_color else None)
    if args.path:
        try:
            shell.do_load(shlex.quote(args.path))
        except USER_ERRORS as exc:
            shell._print(f"error: {exc}", "error")
            return 1
    try:
        shell.cmdloop()
    finally:
        shell._drop()
    return 0
