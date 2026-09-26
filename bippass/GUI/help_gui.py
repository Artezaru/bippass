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

from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QTextBrowser,
    QVBoxLayout,
)

from .translate import translator, help_gui_translation


def _t(key: str, **kwargs: str) -> str:
    """Shorthand for ``translator.translate(key, help_gui_translation, **kwargs)``."""
    return translator.translate(key, help_gui_translation, **kwargs)


class HelpDialog(QDialog):
    """
    Read-only dialog showing how to use bippass and its keyboard
    shortcuts, in the current display language.

    Parameters
    ----------
    parent : QWidget, optional
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_t("help_dialog_title"))
        self.resize(560, 620)

        layout = QVBoxLayout(self)

        self.content = QTextBrowser()
        self.content.setOpenExternalLinks(True)
        self.content.setHtml(_t("help_content"))
        layout.addWidget(self.content)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(_t("close_button"))
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
