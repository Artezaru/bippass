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

from PyQt5.QtWidgets import QApplication, QDialog

from bippass.GUI import CredentialsWizard
from bippass.GUI.theme import apply_theme, load_theme


def main() -> None:
    """
    Application entry point: launches the credentials wizard (open an
    existing vault or create a new one) and, once accepted, hands
    control over to the main window it built.

    Runs via ``python -m bippass`` (this module is ``bippass``'s
    ``__main__.py``) as well as any console-script entry point
    declared for the package (e.g. in ``pyproject.toml``, so a
    PyInstaller build's launcher can import and call this directly).
    """
    app = QApplication(sys.argv)

    # Applies the last chosen theme (light/dark, remembered between
    # runs -- see theme.py) to the whole application, including every
    # widget the wizard and the main window create afterwards. The
    # main window's theme-toggle button switches this later on by
    # calling `apply_theme` again with the other theme.
    apply_theme(app, load_theme())

    wizard = CredentialsWizard()
    if wizard.exec_() != QDialog.Accepted:
        sys.exit(0)

    # The wizard already built and displayed the PasswordManagerWindow
    # (see CredentialsWizard._on_finished). Keep a reference here so it
    # isn't garbage-collected once the wizard object itself is gone.
    window = wizard.window  # noqa: F841

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()