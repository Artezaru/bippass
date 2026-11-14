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

# Run slow operations (key derivations, file I/O) without freezing the interface.
#
# Unlocking, decrypting, changing a password, exporting and importing all
# run one or two full PBKDF2 derivations (several seconds by design).
# :func:`run_blocking` runs such an operation in a worker thread while a
# "please wait" veil covers the window: the interface stays painted and
# movable, but every input is ignored, so the manager is never touched by
# two threads at once.
#
# The veil is only a visual cue, so that a few seconds of waiting read as
# "loading" rather than as a frozen application: it measures nothing (its
# progress bar is an endless one, not a progress), and the operation
# would take exactly as long without it. It is painted *before* the
# operation starts (see `run_blocking`), so it is always shown; while the
# derivation runs, the window may still stop repainting (the bar stops
# moving) if the cryptography library keeps Python's GIL meanwhile -- the
# veil then simply stays on screen until the operation is done.

from __future__ import annotations

from typing import Callable, TypeVar

from PyQt5.QtCore import QEvent, QEventLoop, QObject, Qt, QThread
from PyQt5.QtGui import QColor, QPainter
from PyQt5.QtWidgets import (
    QApplication,
    QFrame,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

T = TypeVar("T")

# Number of operations currently running through `run_blocking`.
_busy_count = 0

# Input events ignored while an operation runs.
_BLOCKED_EVENTS = frozenset(
    {
        QEvent.MouseButtonPress,
        QEvent.MouseButtonRelease,
        QEvent.MouseButtonDblClick,
        QEvent.Wheel,
        QEvent.KeyPress,
        QEvent.KeyRelease,
        QEvent.ShortcutOverride,
        QEvent.Shortcut,
        QEvent.Close,
    }
)

# Opacity (0-255) of the veil darkening the window.
_VEIL_ALPHA = 110
_CARD_MIN_WIDTH_PX = 320


def is_busy() -> bool:
    """
    Tell whether a :func:`run_blocking` operation is running.

    Returns
    -------
    bool
        ``True`` while an operation runs. Timers (e.g. the inactivity
        auto-lock) must then postpone anything touching the manager.
    """
    return _busy_count > 0


class _Worker(QThread):
    """
    Thread running one function, keeping its result or exception.

    Parameters
    ----------
    func : callable
        Function to run, without arguments.
    parent : QObject, optional
        Parent object.
    """

    def __init__(self, func: Callable[[], object], parent=None):
        super().__init__(parent)
        self._func = func
        self.result: object = None
        self.error: BaseException | None = None

    def run(self) -> None:
        """Run the function, storing its result or the exception it raised."""
        try:
            self.result = self._func()
        except BaseException as exc:  # re-raised in the GUI thread
            self.error = exc


class _InputBlocker(QObject):
    """Application-wide event filter swallowing every user input."""

    def eventFilter(self, obj, event) -> bool:
        """
        Swallow input events.

        Parameters
        ----------
        obj : QObject
            Object receiving the event.
        event : QEvent
            The event.

        Returns
        -------
        bool
            ``True`` (event dropped) for mouse, keyboard, shortcut and
            close events; ``False`` for everything else (painting,
            resizing...).
        """
        return event.type() in _BLOCKED_EVENTS


class _BusyOverlay(QWidget):
    """
    Veil covering a window during a slow operation: the window is
    darkened, and a card in its middle shows the message and an endless
    progress bar.

    Parameters
    ----------
    message : str
        Text shown on the card.
    window : QWidget
        Window to cover; the overlay follows its size.

    Notes
    -----
    The card is styled by the application theme (``QFrame#busyCard``
    falls back on the palette), so it matches the light and dark themes.
    """

    def __init__(self, message: str, window: QWidget):
        super().__init__(window)
        self.setAttribute(Qt.WA_NoSystemBackground)
        layout = QVBoxLayout(self)
        layout.addStretch(1)

        card = QFrame()
        card.setObjectName("busyCard")
        card.setFrameShape(QFrame.StyledPanel)
        card.setAutoFillBackground(True)
        card.setMinimumWidth(_CARD_MIN_WIDTH_PX)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 18, 24, 18)
        card_layout.setSpacing(12)
        label = QLabel(message)
        label.setAlignment(Qt.AlignCenter)
        label.setWordWrap(True)
        card_layout.addWidget(label)
        bar = QProgressBar()
        bar.setRange(0, 0)
        bar.setTextVisible(False)
        bar.setFixedHeight(6)
        card_layout.addWidget(bar)

        layout.addWidget(card, alignment=Qt.AlignHCenter)
        layout.addStretch(1)

        window.installEventFilter(self)
        self.setGeometry(window.rect())

    def eventFilter(self, obj, event) -> bool:
        """
        Follow the size of the covered window.

        Parameters
        ----------
        obj : QObject
            The window.
        event : QEvent
            The event.

        Returns
        -------
        bool
            Always ``False``: the event keeps propagating.
        """
        if event.type() == QEvent.Resize:
            self.setGeometry(obj.rect())
        return False

    def paintEvent(self, event) -> None:
        """Darken the whole window under the card."""
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0, _VEIL_ALPHA))
        painter.end()


def run_blocking(parent: QWidget | None, message: str, func: Callable[[], T]) -> T:
    """
    Run a slow function in a worker thread, behind a "please wait" veil.

    Parameters
    ----------
    parent : QWidget or None
        Any widget of the window to cover (the veil covers its whole
        window); ``None`` covers nothing, inputs are still blocked.
    message : str
        Text of the veil, already translated.
    func : callable
        Function to run, without arguments (use a ``lambda`` or
        :func:`functools.partial`).

    Returns
    -------
    object
        What ``func`` returned.

    Raises
    ------
    BaseException
        Whatever ``func`` raised, re-raised in the calling thread.

    Notes
    -----
    Returns only once ``func`` is done, like a direct call, so callers
    stay sequential. Meanwhile, a local event loop keeps the interface
    painted, every user input of the application is dropped, and
    :func:`is_busy` tells timers to wait.

    The veil is purely visual (see the module comment): it is painted
    before ``func`` starts, and shows no real progress. ``parent``
    should belong to the main window, not to a small dialog the veil
    would hardly cover: close the dialog first.
    """
    global _busy_count
    app = QApplication.instance()
    worker = _Worker(func)
    blocker = _InputBlocker()
    overlay = _BusyOverlay(message, parent.window()) if parent is not None else None
    loop = QEventLoop()
    worker.finished.connect(loop.quit)

    _busy_count += 1
    app.installEventFilter(blocker)
    try:
        if overlay is not None:
            overlay.show()
            overlay.raise_()
            # Paint the veil now, before the worker starts: once the
            # derivation runs, the event loop may get no chance to.
            overlay.repaint()
            app.processEvents(QEventLoop.ExcludeUserInputEvents)
        worker.start()
        loop.exec_()
        worker.wait()
    finally:
        app.removeEventFilter(blocker)
        _busy_count -= 1
        if overlay is not None:
            overlay.hide()
            overlay.deleteLater()

    if worker.error is not None:
        raise worker.error
    return worker.result  # type: ignore[return-value]
