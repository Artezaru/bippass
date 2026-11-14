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

Help texts of the shell commands (see :mod:`bippass.cli.shell`).

Every command is described once, in :data:`COMMANDS`: its usage line,
a one-line summary, each of its arguments, and optional notes. Both the
``help`` overview (:func:`print_overview`: usage and summary only) and
``help <command>`` (:func:`print_details`: everything) are rendered
from it, so they can never disagree.

Usage lines follow the usual conventions: ``<arg>`` is required,
``[arg]`` is optional, ``a | b`` is a choice, ``...`` repeats.
"""

from __future__ import annotations

from dataclasses import dataclass

from .clipboard import CLEAR_AFTER_S
from .console import Output


@dataclass(frozen=True)
class CommandHelp:
    """
    Help of one shell command.

    Attributes
    ----------
    group : str
        Topic the command is listed under in the overview.

    usage : str
        Usage line, e.g. ``"load <path | number>"``.

    summary : str
        One-line description.

    args : tuple of (str, str)
        Every argument or option: its name as written in :attr:`usage`,
        and what it means.

    notes : str
        Further explanation, only shown by ``help <command>``.
    """

    group: str
    usage: str
    summary: str
    args: tuple[tuple[str, str], ...] = ()
    notes: str = ""


#: Help of every command, in overview order.
COMMANDS: dict[str, CommandHelp] = {
    # ---------------- Profile
    "profiles": CommandHelp(
        "Profile", "profiles",
        "List the profiles found in the default profile directory.",
        notes='Their numbers can be given to "load".',
    ),
    "create": CommandHelp(
        "Profile", "create [path] [--discard]",
        "Create a new profile, saved at once, and open it.",
        args=(
            ("path", "file to create (default: a new file in the profile folder, listed by \"profiles\")"),
            ("--discard", "lose the unsaved changes of the profile currently loaded"),
        ),
        notes="Asks the username (optional), the label shown without password (default: the\n"
              "username), then the primary password (opens the profile) and the secondary\n"
              "password (protects the secrets), each typed twice without echo.",
    ),
    "load": CommandHelp(
        "Profile", "load <path | number> [--discard]",
        "Read a profile file, without unlocking it.",
        args=(
            ("path", "profile file to read (~ is expanded; quote it if it has spaces)"),
            ("number", 'number of a profile listed by "profiles"'),
            ("--discard", "lose the unsaved changes of the profile currently loaded"),
        ),
        notes="Closes the profile currently loaded, if any.",
    ),
    "unlock": CommandHelp(
        "Profile", "unlock",
        "Unlock the profile with the primary password.",
        notes="Vaults, items and clear fields become readable; secrets stay encrypted.\n"
              "The password is typed without echo, never given as an argument.",
    ),
    "decrypt": CommandHelp(
        "Profile", "decrypt",
        "Get the data key with the secondary password, to show secrets on demand.",
        notes="Decrypts no secret by itself: each one is decrypted when asked for\n"
              '("reveal", "totp"), then erased. The password is typed without echo.',
    ),
    "info": CommandHelp(
        "Profile", "info",
        "Show the loaded profile: file, label, state, metadata and preferences.",
    ),
    "save": CommandHelp(
        "Profile", "save [path]",
        "Save the profile (requires \"unlock\").",
        args=(
            ("path", "destination file (default: the file it was loaded from)"),
        ),
    ),
    "encrypt": CommandHelp(
        "Profile", "encrypt",
        "Forget the data key: secrets can no longer be shown, until \"decrypt\".",
        notes="Counterpart of \"decrypt\". Vaults, items and clear fields stay readable.\n"
              "Nothing needs re-encrypting: secrets are never kept in clear. The screen and its\n"
              "scrollback are cleared, so that revealed secrets cannot be scrolled back to.",
    ),
    "lock": CommandHelp(
        "Profile", "lock",
        "Save the profile, close it, and clear the screen.",
        notes="Both keys are erased from memory. Unsaved changes are saved first, to the file\n"
              "the profile was loaded from; if that fails, the profile stays open. The screen\n"
              "and its scrollback are cleared. Use \"load\" to open a profile again.\n"
              "The same happens on its own after the auto-lock delay of the profile (see\n"
              "\"info\") without any command typed.",
    ),
    "passwd": CommandHelp(
        "Profile", "passwd <primary | secondary>",
        "Change the primary or the secondary password, then save at once.",
        args=(
            ("primary", "the password that opens the profile"),
            ("secondary", "the password that protects the secrets"),
        ),
        notes="Asks the current password, then the new one twice. Changing the secondary\n"
              "password needs the secrets: if they are encrypted, the current secondary\n"
              "password decrypts them first.",
    ),
    "close": CommandHelp(
        "Profile", "close [--discard]",
        "Close the profile: both keys are erased from memory.",
        args=(
            ("--discard", "close even if there are unsaved changes (they are lost)"),
        ),
    ),
    # ---------------- Navigation
    "ls": CommandHelp(
        "Navigation", "ls",
        "List the current location.",
        notes='At the root, same as "vaults"; in a vault, same as "items"; in an item, same\n'
              'as "show".',
    ),
    "cd": CommandHelp(
        "Navigation", "cd <vault | item | .. | />",
        "Move to a vault, an item, or back.",
        args=(
            ("vault", "at the root: a vault, by number, name or UUID (prefix)"),
            ("item", "in a vault: an item, by number, name or UUID (prefix)"),
            ("..", "go up one level"),
            ("/", 'go back to the root (same as "home")'),
        ),
        notes="Numbers follow the listing order (by name). A UUID prefix needs at least 4\n"
              "characters. Names ignore case and accents (cd securite finds Sécurité); names\n"
              "with spaces may be typed as is (cd My vault) or quoted.",
    ),
    "home": CommandHelp(
        "Navigation", "home",
        "Go back to the root of the profile, wherever you are.",
        notes='Same as "cd /": from an item, like "cd .." twice; from a vault, like "cd ..".',
    ),
    "pwd": CommandHelp(
        "Navigation", "pwd",
        "Show the current location: /, /<vault> or /<vault>/<item>.",
    ),
    "vaults": CommandHelp(
        "Navigation", "vaults",
        "At the root, list the vaults, sorted by name.",
        notes="Vaults and items are always listed by name (\"item2\" before \"item10\"); their\n"
              'numbers, given to "cd", follow that order.',
    ),
    "items": CommandHelp(
        "Navigation", "items",
        "In a vault, list its items, sorted by name.",
        notes="Vaults and items are always listed by name (\"item2\" before \"item10\"); their\n"
              'numbers, given to "cd", follow that order.',
    ),
    "show": CommandHelp(
        "Navigation", "show",
        "In an item, show every field, secrets masked.",
        notes='Every value is numbered ([1], [2]...): give that number to "reveal", "copy",\n'
              '"editfield" or "removefield". Custom fields are listed with a reference\n'
              "(c1, c2...), accepted by the same commands.",
    ),
    # ---------------- Editing
    "add": CommandHelp(
        "Editing", "add <name>",
        "At the root, add a vault; in a vault, add an item and enter it.",
        args=(("name", "name of the new vault or item (spaces allowed)"),),
        notes='Changes are kept in memory until "save"; the prompt shows * meanwhile.',
    ),
    "rename": CommandHelp(
        "Editing", "rename <new name>",
        "Rename the current item, or the current vault.",
        args=(("new name", "the new name (spaces allowed)"),),
        notes="Acts where you are: in an item, the item; in a vault, the vault.",
    ),
    "move": CommandHelp(
        "Editing", "move <vault>",
        "Move the current item to another vault.",
        args=(
            ("vault", "destination vault, by number, name or UUID (prefix)"),
        ),
        notes="Run it from inside the item. You follow the item into its new vault.",
    ),
    "remove": CommandHelp(
        "Editing", "remove [vault | item] [--force]",
        "Remove a vault (at the root), an item (in a vault), or the current item.",
        args=(
            ("vault", "at the root: the vault to remove"),
            ("item", "in a vault: the item to remove"),
            ("--force", "remove a vault even if it still holds items (they are removed too)"),
        ),
        notes='In an item, "remove" without argument removes that item and goes back to its vault.',
    ),
    "addfield": CommandHelp(
        "Editing", "addfield <clear | secret> <name> [--values <v1>; <v2>...] [--count <n>] [--generate [length]]",
        "Create a new custom field in the current item.",
        args=(
            ("clear", "a field whose values are stored in clear"),
            ("secret", "a field whose values are encrypted"),
            ("name", "name of the field: every word up to --values (spaces allowed, no quotes needed)"),
            ("--values", "clear fields only: initial values, separated by ';' (write \\; for a ';')"),
            ("--count <n>", "secret fields only: how many values to ask (default: 1)"),
            ("--generate [length]", "secret fields only: generate the values (default: 20 characters)"),
        ),
        notes="Always creates a new field, even if one has the same name: use \"addtofield\" to\n"
              "add values to an existing one. Secret values are asked without echo, twice.\n"
              "Examples: addfield clear Backup codes --values 1111; 2222; 3333\n"
              "          addfield secret Card PIN\n"
              "          addfield secret Recovery keys --count 3 --generate 32",
    ),
    "addtofield": CommandHelp(
        "Editing", "addtofield <field> [--values <v1>; <v2>...] [--count <n>] [--generate [length]]",
        "Add values to an existing field of the current item.",
        args=(
            ("field", "login, website, email, phone, password, totp, or a custom field (c1, c2... or name)"),
            ("--values", "clear fields only: values to add, separated by ';' (write \\; for a ';')"),
            ("--count <n>", "secret fields only: how many values to ask (default: 1)"),
            ("--generate [length]", "secret fields only: generate the values (default: 20 characters)"),
        ),
        notes="Secret values (password, totp, secret custom fields) are asked without echo, twice\n"
              "(once for totp), never typed on the command line.\n"
              "Examples: addtofield website --values https://a.example.com; https://b.example.com\n"
              "          addtofield password --generate\n"
              "          addtofield c3 --values another value",
    ),
    "editfield": CommandHelp(
        "Editing", "editfield <field> [number] [--value <new value>] [--generate [length]]",
        "Replace one value of a field of the current item.",
        args=(
            ("field", "login, website, email, phone, password, totp, or a custom field (c1, c2... or name)"),
            ("number", 'which value, as numbered by "show" (needed if the field has several)'),
            ("--value", "clear fields only: the new value, everything up to the end of the line"),
            ("--generate [length]", "secret fields only: generate the new value (default: 20 characters)"),
        ),
        notes="A secret value is asked without echo, unless --generate is given.\n"
              "Examples: editfield login --value bob2\n"
              "          editfield website 2 --value https://new.example.com\n"
              "          editfield password\n"
              "          editfield c3 2 --generate 32",
    ),
    "removefield": CommandHelp(
        "Editing", "removefield <field> [number]",
        "Remove one value of a field, or a whole custom field.",
        args=(
            ("field", "login, website, email, phone, password, totp, or a custom field (c1, c2... or name)"),
            ("number", 'which value, as numbered by "show" (needed if the field has several)'),
        ),
        notes="For a custom field, without number, the whole field is removed.",
    ),
    # ---------------- Secrets
    "reveal": CommandHelp(
        "Secrets", "reveal <field> [number]",
        "Print secrets of the current item in clear (requires \"decrypt\").",
        args=(
            ("field", "password, totp, or an encrypted custom field: its reference (c1, c2...) or its name, as shown by \"show\""),
            ("number", 'which value, as numbered by "show" (default: all of them)'),
        ),
        notes="password and totp always mean the predefined fields: use the reference of a\n"
              "custom field with the same name. A reference also picks one of several custom\n"
              "fields sharing a name.\n"
              "Names with spaces may be typed as is (reveal Card PIN) or quoted. A trailing\n"
              "number is read as the value number: quote the name if it ends with one\n"
              '(reveal "Code 2").\n'
              "Mind who can see your screen: the value stays in the terminal scrollback.",
    ),
    "copy": CommandHelp(
        "Secrets", "copy <field> [number]",
        f"Copy one value of the current item to the clipboard, cleared after {CLEAR_AFTER_S:g} s.",
        args=(
            ("field", "login, website, email, phone, password, totp, or a custom field (c1, c2... or name)"),
            ("number", 'which value, as numbered by "show" (needed if the field has several)'),
        ),
        notes="For totp, the current code is copied, not the secret. Secrets require \"decrypt\".\n"
              f"The clipboard is cleared after {CLEAR_AFTER_S:g} seconds if it still holds the value, and right\n"
              'away on "encrypt", "lock", "close" and "quit". Uses pyperclip if installed,\n'
              "otherwise the system tool (clip, pbcopy, wl-copy, xclip or xsel).",
    ),
    "totp": CommandHelp(
        "Secrets", "totp [number]",
        "Print the current TOTP codes of the current item (requires \"decrypt\").",
        args=(
            ("number", 'which TOTP secret, as numbered by "show" (default: all of them)'),
        ),
        notes="Also prints the seconds left before each code changes.",
    ),
    # ---------------- Shell
    "generate": CommandHelp(
        "Secrets", "generate [length] [--no-special] [--show]",
        "Generate a random password, copied to the clipboard.",
        args=(
            ("length", "number of characters (default: 20)"),
            ("--no-special", "letters and digits only"),
            ("--show", "print it instead of copying it"),
        ),
        notes=f"The clipboard is cleared after {CLEAR_AFTER_S:g} seconds if it still holds it. No profile is needed.",
    ),
    "export": CommandHelp(
        "Transfer", "export <path> [--force]",
        "Export items to a new, standalone file, with its own two passwords.",
        args=(
            ("path", "file to create"),
            ("--force", "replace the file if it exists"),
        ),
        notes="Exports where you are: the current item, every item of the current vault, or\n"
              'every item of the profile at the root. Needs "decrypt". The two passwords of\n'
              'the new file are asked twice; "import" reads it back.',
    ),
    "import": CommandHelp(
        "Transfer", "import <path>",
        "Import every item of a file made by \"export\".",
        args=(
            ("path", "file to import"),
        ),
        notes="In a vault, items go into it; at the root, into a new vault \"imported items\".\n"
              'Asks the two passwords of the file. Needs "decrypt"; then "save" to keep them.',
    ),
    "help": CommandHelp(
        "Shell", "help [command]",
        "List the commands, or describe one.",
        args=(
            ("command", "command to describe in detail"),
        ),
    ),
    "clear": CommandHelp(
        "Shell", "clear",
        "Clear the terminal, scrollback included.",
        notes='Also: "cls". Revealed secrets can then no longer be scrolled back to.\n'
              'Does nothing when the output is not a terminal (redirected to a file).',
    ),
    "quit": CommandHelp(
        "Shell", "quit [--discard]",
        "Close the profile (erasing its keys) and leave.",
        args=(
            ("--discard", "leave even if there are unsaved changes (they are lost)"),
        ),
        notes='Also: "exit", or Ctrl-D (twice in a row if there are unsaved changes).\n'
              "Ctrl-C never leaves: it cancels the line being typed, or the current input.",
    ),
}

#: Aliases: command name -> documented command.
ALIASES: dict[str, str] = {"exit": "quit", "cls": "clear"}

def _arg_display(name: str) -> str:
    """Show an argument as ``<name>``, options and literals (``..``, ``/``) as is."""
    if name.startswith("-") or not name[0].isalpha():
        return name
    return f"<{name.replace(' ', '-')}>"


def _usage(out: Output, usage: str) -> str:
    """Style a usage line: the command name, then its arguments."""
    name, _, args = usage.partition(" ")
    return out.style(name, "command") + (out.style(" " + args, "arg") if args else "")


def print_overview(out: Output) -> None:
    """
    Write the list of every command: usage line and one-line summary.

    Parameters
    ----------
    out : Output
        Where to write.
    """
    bullet = "\u2022" if out.rich else "*"
    group = None
    for help_ in COMMANDS.values():
        if help_.group != group:
            if group is not None:
                out.line()
            group = help_.group
            out.text(f"{group}:", "title")
        out.line(out.style(f"  {bullet} ") + _usage(out, help_.usage))
        out.line(out.style(f"      {help_.summary}"))
    out.line()
    out.text('Type "help <command>" for details.', "muted")


def print_details(out: Output, name: str) -> bool:
    """
    Write the full help of one command.

    Parameters
    ----------
    out : Output
        Where to write.

    name : str
        Command name (or alias).

    Returns
    -------
    bool
        ``False`` (and nothing written) if the command is unknown.

    Notes
    -----
    Usage line, summary and notes, then every argument with its
    description.
    """
    help_ = COMMANDS.get(ALIASES.get(name, name))
    if help_ is None:
        return False
    bullet = "\u2022" if out.rich else "*"
    out.line(_usage(out, help_.usage))
    out.line()
    out.text(help_.summary)
    for note in help_.notes.splitlines():
        out.text(note)
    if help_.args:
        out.line()
        out.text("Arguments:", "title")
        shown = [_arg_display(arg) for arg, _ in help_.args]
        width = max(len(arg) for arg in shown)
        for arg, (_, text) in zip(shown, help_.args):
            out.line(out.style(f"  {bullet} ") + out.style(f"{arg:<{width}}", "arg")
                     + out.style(f" : {text}"))
    return True
