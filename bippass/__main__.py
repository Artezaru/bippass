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

import sys
from typing import Sequence


def __main__(argv: Sequence[str] | None = None) -> None:
    """
    Command-line entry point: runs the interactive shell.

    Parameters
    ----------
    argv : Sequence of str, optional
        Command-line arguments (default: :data:`sys.argv` without the
        program name). An optional profile file path loads it at start.

    Notes
    -----
    This is what ``python -m bippass`` runs (this module is
    ``bippass``'s ``__main__.py``)::

        python -m bippass                       # empty shell
        python -m bippass test_profile.bippass  # shell with that profile loaded

    It can also be declared as a console-script entry point, e.g. in
    ``pyproject.toml``: ``bippass = "bippass.__main__:__main__"``.

    Only the command-line interface is imported: PyQt5 is not needed.
    """
    from bippass.cli import main

    sys.exit(main(argv))


def __main_gui__() -> None:
    """
    Graphical entry point: opens the main window on its start page
    (open, create or switch profiles), which then shows the profile.

    Notes
    -----
    Not run by ``python -m bippass``, which starts the command-line
    interface (see :func:`__main__`).
    It can be declared as a GUI-script entry point, e.g. in
    ``pyproject.toml``: ``bippass-gui = "bippass.__main__:__main_gui__"``
    (also what a PyInstaller build's launcher can import and call).

    PyQt5 and the GUI package are imported here, not at module level,
    so that the command-line interface works without them.
    """
    from PyQt5.QtWidgets import QApplication

    from bippass.GUI import PasswordManagerWindow, install_excepthook

    app = QApplication(sys.argv)
    # The window applies the last chosen theme itself (see theme.py).
    window = PasswordManagerWindow()
    # Unexpected errors: logged and shown instead of stopping the
    # application (see GUI/crash.py).
    install_excepthook(window)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    __main_gui__()
