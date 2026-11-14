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

# Last-resort handling of unexpected errors.
#
# Since PyQt 5.5, a Python exception escaping a slot calls `qFatal`: the
# application stops at once, unsaved changes lost. `install_excepthook`
# replaces `sys.excepthook` (PyQt then calls it instead of aborting) by a
# handler that:
#
# - appends the traceback to `LOG_PATH` (and prints it on stderr);
# - shows the error, with the traceback as details;
# - offers to save the open profile if it has unsaved changes, to go on
#   (the application may be unstable), or to quit.
#
# Exceptions of other threads are logged only (no dialog outside the GUI
# thread): the workers of `tasks` and `save_worker` already hand theirs
# to the GUI thread.
#
# The log holds tracebacks only: file names, line numbers, code lines and
# exception messages, never local variables. The messages of bippass
# itself never contain a password or a secret.

from __future__ import annotations

import datetime
import sys
import threading
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt5.QtWidgets import QMessageBox

from .translate import translator
from .widgets import mark_danger

if TYPE_CHECKING:
    from .window import PasswordManagerWindow

#: File receiving the tracebacks of unexpected errors.
LOG_PATH = Path.home() / ".bippass" / "logs" / "bippass.log"

# Above this size (bytes), the log is restarted (the old one is kept as `.1`).
_LOG_MAX_BYTES = 1_000_000

# Set while the dialog is shown, so that an error raised by the dialog
# itself is only logged.
_handling = False


def _log(text: str) -> None:
    """
    Append a traceback to :data:`LOG_PATH`, best effort.

    Parameters
    ----------
    text : str
        The formatted traceback.
    """
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > _LOG_MAX_BYTES:
            LOG_PATH.replace(LOG_PATH.with_suffix(".log.1"))
        with LOG_PATH.open("a", encoding="utf-8") as log:
            log.write(f"--- {datetime.datetime.now().astimezone().isoformat()}\n{text}\n")
    except OSError:
        pass


def _tr(key: str, fallback: str, **kwargs) -> str:
    """Translate, falling back to English if the translator itself fails."""
    try:
        return translator.translate(key, **kwargs)
    except Exception:  # noqa: BLE001 -- the handler must never fail
        return fallback.format(**kwargs)


def _show(window: PasswordManagerWindow, text: str) -> None:
    """
    Show the error, then save, go on or quit as the user chooses.

    Parameters
    ----------
    window : PasswordManagerWindow
        The main window.

    text : str
        The formatted traceback, shown as details.
    """
    box = QMessageBox(window)
    box.setIcon(QMessageBox.Critical)
    box.setWindowTitle(_tr("crash.title", "Unexpected error"))
    box.setText(_tr(
        "crash.message",
        "An unexpected error occurred. It was written to:\n{path}\n\n"
        "The application may now be unstable: save your changes, then restart it.",
        path=str(LOG_PATH),
    ))
    box.setDetailedText(text)
    dirty = window.has_profile and window.is_dirty
    save = box.addButton(_tr("crash.save_button", "Save"), QMessageBox.AcceptRole) if dirty else None
    go_on = box.addButton(_tr("crash.continue_button", "Continue"), QMessageBox.RejectRole)
    quit_button = mark_danger(box.addButton(_tr("crash.quit_button", "Quit"), QMessageBox.DestructiveRole))
    box.setDefaultButton(save or go_on)
    box.setEscapeButton(go_on)
    box.exec_()

    clicked = box.clickedButton()
    if clicked is save:
        window.save_now()
    elif clicked is quit_button:
        window.quit_now()


def install_excepthook(window: PasswordManagerWindow) -> None:
    """
    Handle unexpected errors instead of letting PyQt stop the application.

    Parameters
    ----------
    window : PasswordManagerWindow
        The main window, offered to save its profile.
    """

    def handle(exc_type, exc, tb) -> None:
        global _handling
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        _log(text)
        sys.stderr.write(text)
        if _handling:
            return
        _handling = True
        try:
            _show(window, text)
        except Exception:  # noqa: BLE001 -- an error here is only logged
            _log("".join(traceback.format_exc()))
        finally:
            _handling = False

    def handle_thread(args: threading.ExceptHookArgs) -> None:
        text = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        _log(f"[thread {getattr(args.thread, 'name', '?')}]\n{text}")
        sys.stderr.write(text)

    sys.excepthook = handle
    threading.excepthook = handle_thread
