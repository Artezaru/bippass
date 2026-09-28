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

import logging
from importlib import resources

from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout

from ..translate import FALLBACK_LANGUAGE, translator

_HELP_DIR = "resources/help"

_logger = logging.getLogger(__name__)


def load_help_html(language: str) -> str:
    """
    Load the help page of a language.

    Parameters
    ----------
    language : str
        Language code, e.g. ``"fr"``.

    Returns
    -------
    str
        HTML of ``bippass/resources/help/<language>_help.html``, else
        of the :data:`FALLBACK_LANGUAGE` page, else ``""`` (with a
        logged error).
    """
    for code in dict.fromkeys((language, FALLBACK_LANGUAGE)):
        try:
            ref = resources.files("bippass").joinpath(_HELP_DIR, f"{code}_help.html")
            return ref.read_text(encoding="utf-8")
        except (ModuleNotFoundError, OSError):
            continue
    _logger.error("No help page found for %r.", language)
    return ""


class HelpDialog(QDialog):
    """
    Read-only dialog explaining the whole interface (buttons, menus,
    keyboard shortcuts) in the current display language.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("help.dialog_title"))
        self.resize(640, 720)

        layout = QVBoxLayout(self)

        self.content = QTextBrowser()
        self.content.setOpenExternalLinks(True)
        self.content.setHtml(load_help_html(translator.language))
        layout.addWidget(self.content)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(translator.translate("common.close"))
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)