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

# Background writing of a profile file.

from __future__ import annotations

from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal

from ..core.manager import PasswordManager


class SaveWorker(QThread):
    """
    Thread writing an already serialized profile to disk.

    The worker never touches the manager: the caller serializes it in
    the GUI thread with :meth:`PasswordManager.to_bytes` (fast, no key
    derivation) and hands over the resulting bytes, which only
    :meth:`PasswordManager.write_file` uses (atomic write, see there).
    The manager can therefore keep being edited while the file is
    written.

    Parameters
    ----------
    path : Path
        Destination file.
    data : bytearray
        File content, as returned by :meth:`PasswordManager.to_bytes`.
    parent : QObject, optional
        Parent object.

    Attributes
    ----------
    save_failed : pyqtSignal(str)
        Emitted with a readable message if the file couldn't be written.
    """

    save_failed = pyqtSignal(str)

    def __init__(self, path: Path, data: bytearray, parent=None):
        super().__init__(parent)
        self._path = path
        self._data = data

    def run(self) -> None:
        """Write the file, reporting any error through :attr:`save_failed`."""
        try:
            PasswordManager.write_file(self._path, self._data)
        except Exception as exc:
            self.save_failed.emit(f"{type(exc).__name__}: {exc}")
