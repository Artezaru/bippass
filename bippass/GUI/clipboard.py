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

# Copying secrets to the clipboard, and erasing them from it afterwards.
#
# A secret (password, TOTP code, encrypted custom value) copied with
# `copy_secret` is erased from the clipboard after `_CLIPBOARD_CLEAR_S`
# seconds, when the profile is encrypted or locked, and when the window closes --
# but only if the clipboard still holds it: anything copied since by the
# user is never touched. Only a hash of the copied value is kept, to
# recognize it, never the value itself.

from __future__ import annotations

import hashlib

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication


# Delay (s) after which a copied secret is erased from the clipboard.
_CLIPBOARD_CLEAR_S = 30

_timer: QTimer | None = None
_copied_hash: bytes | None = None


def _digest(text: str) -> bytes:
    """
    Hash a text, to recognize it later without keeping it.

    Parameters
    ----------
    text : str
        The text.

    Returns
    -------
    bytes
        Its SHA-256 digest.
    """
    return hashlib.sha256(text.encode("utf-8")).digest()


def copy_text(text: str) -> None:
    """
    Copy a clear value (login, website...) to the clipboard, for good.

    Parameters
    ----------
    text : str
        Value to copy.
    """
    QApplication.clipboard().setText(text)


def copy_secret(text: str) -> None:
    """
    Copy a secret to the clipboard, and erase it after a delay.

    Parameters
    ----------
    text : str
        Secret to copy. Erased from the clipboard after
        :data:`_CLIPBOARD_CLEAR_S` seconds, unless something
        else was copied meanwhile.
    """
    global _timer, _copied_hash
    QApplication.clipboard().setText(text)
    _copied_hash = _digest(text)
    if _timer is None:
        _timer = QTimer()
        _timer.setSingleShot(True)
        _timer.timeout.connect(clear_secret)
    _timer.start(_CLIPBOARD_CLEAR_S * 1000)


def clear_secret() -> None:
    """
    Erase the last copied secret from the clipboard, if it is still there.

    Notes
    -----
    Called by the timer of :func:`copy_secret`, and by the main window
    when the profile is encrypted or locked, or the window is closed.
    """
    global _copied_hash
    if _timer is not None:
        _timer.stop()
    if _copied_hash is None:
        return
    clipboard = QApplication.clipboard()
    if _digest(clipboard.text()) == _copied_hash:
        clipboard.clear()
    _copied_hash = None
