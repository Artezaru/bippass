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

from typing import TYPE_CHECKING

from PyQt5.QtWidgets import QDialog, QFormLayout, QSpinBox

from ..translate import translator
from ..widgets import ok_cancel_buttons

if TYPE_CHECKING:
    from ...core.manager import PasswordManager


# Bounds (s) of the inactivity delay.
_LOCK_TIMER_RANGE_S = (10, 24 * 3600)


class AccountSettingsDialog(QDialog):
    """
    Dialog to edit the preferences of the profile that have no control
    of their own in the toolbar: the inactivity auto-lock delay.

    The theme and the language are chosen from the toolbar.

    Parameters
    ----------
    manager : PasswordManager
        Manager whose preferences are edited, read to pre-fill the fields.

    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("settings.dialog_title"))
        layout = QFormLayout(self)

        self.lock_timer_spin = QSpinBox()
        self.lock_timer_spin.setRange(*_LOCK_TIMER_RANGE_S)
        self.lock_timer_spin.setSuffix(" s")
        self.lock_timer_spin.setValue(manager.get_lock_timer_s())
        layout.addRow(tr("settings.lock_timer_label"), self.lock_timer_spin)

        layout.addRow(ok_cancel_buttons(self))

    def apply_to(self, manager: PasswordManager) -> None:
        """
        Write the dialog's fields back into the manager's preferences.

        Parameters
        ----------
        manager : PasswordManager
            Manager to update.
        """
        manager.set_lock_timer_s(self.lock_timer_spin.value())
