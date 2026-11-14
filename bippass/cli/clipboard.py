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

System clipboard access for the shell, without any required dependency.

The first available backend is used:

1. ``pyperclip``, if installed;
2. the clipboard tool of the system:

   - Windows: ``clip`` (built in);
   - macOS: ``pbcopy`` / ``pbpaste`` (built in);
   - Linux: ``wl-copy`` / ``wl-paste`` (Wayland), ``xclip`` or ``xsel``
     (X11), which may need to be installed.

Notes
-----
The clipboard only accepts text, so a copied secret necessarily exists,
for as long as it stays in the clipboard, as an immutable ``str`` in
this process and as data owned by the system clipboard. This is why
:class:`ClipboardGuard` clears the clipboard again after
:data:`CLEAR_AFTER_S` seconds, or right away when the profile is
encrypted, locked or closed.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import threading

try:
    import pyperclip
except ImportError:  # optional
    pyperclip = None


#: Delay, in seconds, after which a copied value is cleared.
CLEAR_AFTER_S: float = 30.0


class ClipboardError(Exception):
    """Raised when no clipboard backend is available, or it fails."""


def _commands() -> tuple[list[str], list[str] | None]:
    """
    Return the system commands to write and read the clipboard.

    Returns
    -------
    tuple
        The write command, and the read command (or ``None`` if the
        clipboard cannot be read back on this system).

    Raises
    ------
    ClipboardError
        If no clipboard tool is available.
    """
    if sys.platform == "win32":
        return ["clip"], None
    if sys.platform == "darwin":
        return ["pbcopy"], ["pbpaste"]
    candidates = [
        (["wl-copy"], ["wl-paste", "--no-newline"]),
        (["xclip", "-selection", "clipboard"], ["xclip", "-selection", "clipboard", "-o"]),
        (["xsel", "--clipboard", "--input"], ["xsel", "--clipboard", "--output"]),
    ]
    for write, read in candidates:
        if shutil.which(write[0]):
            return write, read
    raise ClipboardError(
        "No clipboard tool found: install pyperclip, or wl-clipboard, xclip or xsel."
    )


def copy(text: str) -> None:
    """
    Put text in the system clipboard.

    Parameters
    ----------
    text : str
        Text to copy. An empty string empties the clipboard.

    Raises
    ------
    ClipboardError
        If no backend is available, or it fails.
    """
    if pyperclip is not None:
        try:
            pyperclip.copy(text)
            return
        except Exception as exc:  # pyperclip raises its own exception types
            raise ClipboardError(f"Clipboard error: {exc}") from exc

    write, _ = _commands()
    # clip.exe reads UTF-16 LE; every other tool reads UTF-8.
    data = text.encode("utf-16-le" if sys.platform == "win32" else "utf-8")
    try:
        subprocess.run(write, input=data, check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClipboardError(f"Clipboard error: {exc}") from exc


def paste() -> str | None:
    """
    Return the text currently in the clipboard, if it can be read.

    Returns
    -------
    str or None
        The clipboard content, or ``None`` if it cannot be read on this
        system (e.g. Windows without pyperclip) or reading fails.
    """
    if pyperclip is not None:
        try:
            return pyperclip.paste()
        except Exception:
            return None
    try:
        _, read = _commands()
        if read is None:
            return None
        result = subprocess.run(read, capture_output=True, check=True, timeout=5)
        return result.stdout.decode("utf-8", "replace")
    except (ClipboardError, OSError, subprocess.SubprocessError):
        return None


def clear_if(text: str) -> None:
    """
    Empty the clipboard if it still holds ``text``.

    Parameters
    ----------
    text : str
        What was copied earlier.

    Notes
    -----
    If the clipboard cannot be read back (see :func:`paste`), it is
    emptied anyway: better to lose something the user copied meanwhile
    than to leave a secret behind. Errors are ignored: this runs from a
    timer, with nobody to report them to.
    """
    current = paste()
    if current is None or current == text:
        try:
            copy("")
        except ClipboardError:
            pass


class ClipboardGuard:
    """
    Copy values to the clipboard, and clear them again later.

    Parameters
    ----------
    clear_after_s : float, optional
        Delay before a copied value is cleared (default:
        :data:`CLEAR_AFTER_S`).

    Notes
    -----
    Only the last copied value is guarded: a new :meth:`copy` replaces
    the pending clearing. Clearing only empties the clipboard if it
    still holds the value (see :func:`clear_if`).
    """

    def __init__(self, clear_after_s: float | None = None) -> None:
        self.clear_after_s = CLEAR_AFTER_S if clear_after_s is None else clear_after_s
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._text: str | None = None

    @property
    def pending(self) -> bool:
        """Whether a copied value is waiting to be cleared."""
        return self._text is not None

    def copy(self, text: str) -> None:
        """
        Copy ``text``, and clear it after :attr:`clear_after_s` seconds.

        Raises
        ------
        ClipboardError
            If no backend is available, or it fails.
        """
        with self._lock:
            self._cancel()
            copy(text)
            self._text = text
            self._timer = threading.Timer(self.clear_after_s, self._expire, (text,))
            self._timer.daemon = True
            self._timer.start()

    def clear_now(self) -> None:
        """Clear the guarded value right away (nothing happens if there is none)."""
        with self._lock:
            self._cancel()
            if self._text is not None:
                clear_if(self._text)
                self._text = None

    def _expire(self, text: str) -> None:
        """Timer callback: clear ``text``, unless another value was copied meanwhile."""
        with self._lock:
            if self._text is text:
                self._timer = None
                clear_if(text)
                self._text = None

    def _cancel(self) -> None:
        """Cancel the pending timer, if any (the lock must be held)."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
