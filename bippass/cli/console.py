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

Terminal output of the shell, in color with `rich` when possible.

Every piece of output goes through one :class:`Output` instance, which
writes either:

- **rich** output (colors, tables), when the ``rich`` package is
  installed, the output stream is an interactive terminal, and the
  ``NO_COLOR`` environment variable is not set;
- **plain** text otherwise (redirected output, tests, no ``rich``), with
  exactly the same content, just without styles.

Callers build styled text with :meth:`Output.style`, which escapes the
text (a vault named ``"[red]x"`` is shown as is, never interpreted as
markup) and only adds markup in rich mode, then print it with
:meth:`Output.line`.

Styles are named by role (see :data:`STYLES`), so that the palette can
be changed in one place.
"""

from __future__ import annotations

import os
import re
import sys
from typing import IO, Sequence

try:
    from rich.console import Console
    from rich.markup import escape as _rich_escape
    from rich.table import Table
    from rich import box as _rich_box
except ImportError:  # rich is optional
    Console = None


#: Style of each role, as rich style definitions.
STYLES: dict[str, str] = {
    "title": "bold",            # section titles, item names
    "command": "bold cyan",     # command names in help
    "arg": "cyan",              # arguments in help and usage lines
    "label": "dim",             # field labels in "show" and "info"
    "muted": "dim",             # numbers, UUIDs, dates, masked secrets
    "ref": "cyan",              # custom field references (c1, c2...)
    "secret": "bold yellow",    # revealed secrets
    "code": "bold green",       # TOTP codes
    "urgent": "bold red",       # a TOTP code about to change
    "ok": "green",              # success messages
    "warn": "yellow",           # needs-conversion profiles, warnings
    "error": "bold red",        # errors
    "locked": "bold red",       # prompt: locked state
    "unlocked": "bold yellow",  # prompt: profile unlocked, data key not available
    "decrypted": "bold green",  # prompt: data key available
    "path": "blue",             # prompt: current location
}

#: ANSI escape sequences, to be wrapped for readline (see :meth:`Output.prompt`).
_ANSI = re.compile(r"(\x1b\[[0-9;]*m)")


class Output:
    """
    Write the shell output, styled with rich when possible.

    Parameters
    ----------
    stream : file-like
        Where to write (typically :data:`sys.stdout`).

    color : bool or None, optional
        Force colors on (``True``) or off (``False``). ``None`` (the
        default) enables them only if rich is installed, ``stream`` is
        an interactive terminal, and ``NO_COLOR`` is not set.

    Notes
    -----
    With ``color=True`` but rich not installed, output stays plain.
    """

    def __init__(self, stream: IO[str], color: bool | None = None) -> None:
        self.stream = stream
        if color is None:
            isatty = getattr(stream, "isatty", None)
            color = bool(isatty and isatty()) and "NO_COLOR" not in os.environ
        self.rich: bool = bool(color) and Console is not None
        self._console = (
            Console(file=stream, highlight=False, soft_wrap=True, emoji=False)
            if self.rich else None
        )

    @property
    def _rich_console(self):
        """The rich console (only used when :attr:`rich` is true)."""
        assert self._console is not None
        return self._console

    # ----------------
    # Building styled text
    # ----------------

    def style(self, text: str, role: str | None = None) -> str:
        """
        Return ``text`` escaped and styled for :meth:`line`.

        Parameters
        ----------
        text : str
            Text to show as is, user data included.

        role : str or None, optional
            Key of :data:`STYLES`. ``None`` only escapes the text.

        Returns
        -------
        str
            Rich markup in rich mode, ``text`` unchanged in plain mode.
        """
        if not self.rich:
            return text
        escaped = _rich_escape(text)
        if role is None:
            return escaped
        return f"[{STYLES[role]}]{escaped}[/]"

    # ----------------
    # Writing
    # ----------------

    def line(self, markup: str = "") -> None:
        """
        Write one line built with :meth:`style`.

        Parameters
        ----------
        markup : str
            Pieces returned by :meth:`style`, concatenated.
        """
        if self.rich:
            self._rich_console.print(markup)
        else:
            self.stream.write(markup + "\n")

    def text(self, text: str = "", role: str | None = None) -> None:
        """
        Write one line of plain text (escaped), optionally styled.

        Parameters
        ----------
        text : str
            Text to show as is.

        role : str or None, optional
            Key of :data:`STYLES`.
        """
        self.line(self.style(text, role))

    def table(
        self,
        headers: Sequence[str],
        rows: Sequence[Sequence[str]],
        roles: Sequence[str | None] | None = None,
    ) -> None:
        """
        Write a table.

        Parameters
        ----------
        headers : Sequence of str
            Column titles.

        rows : Sequence of Sequence of str
            Cells, as plain text (escaped here).

        roles : Sequence of (str or None), optional
            Style role of each column (see :data:`STYLES`).

        Notes
        -----
        Writes ``(empty)`` if there is no row. In plain mode, columns
        are left-aligned and separated by two spaces, under a dashed
        header line.
        """
        if not rows:
            self.text("(empty)", "muted")
            return
        roles = list(roles or [None] * len(headers))

        if self.rich:
            table = Table(box=_rich_box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
            for header, role in zip(headers, roles):
                table.add_column(header, style=STYLES[role] if role else None)
            for row in rows:
                table.add_row(*(_rich_escape(cell) for cell in row))
            self._rich_console.print(table)
            return

        widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
        lines = [
            "  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip(),
            "  ".join("-" * w for w in widths),
        ]
        lines += ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows]
        self.stream.write("\n".join(lines) + "\n")

    def prompt(self, markup: str) -> str:
        """
        Render a prompt built with :meth:`style` to a string for :func:`input`.

        Returns
        -------
        str
            The prompt with ANSI color sequences in rich mode (wrapped
            so that readline computes the line width correctly), plain
            text otherwise.
        """
        if not self.rich:
            return markup
        with self._rich_console.capture() as capture:
            self._rich_console.print(markup, end="")
        rendered = capture.get()
        if sys.platform != "win32":
            rendered = _ANSI.sub("\001\\1\002", rendered)
        return rendered

    def clear_screen(self) -> None:
        """
        Clear the terminal, scrollback included, if it is interactive.

        Notes
        -----
        Uses ANSI sequences, supported by every modern terminal
        (Windows Terminal and the Windows 10+ console included).
        """
        isatty = getattr(self.stream, "isatty", None)
        if isatty is None or not isatty():
            return
        if self.rich:
            self._rich_console.clear()  # also enables ANSI on old Windows consoles
        self.stream.write("\033[3J\033[2J\033[H")
        self.stream.flush()
