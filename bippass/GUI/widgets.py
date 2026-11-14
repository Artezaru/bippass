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

# Small widgets and helpers shared by every screen of the interface:
# message boxes, buttons, password inputs, color swatches.

from __future__ import annotations

from typing import Callable

from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .translate import LANGUAGE_NAME_KEYS, translator


# ---------------------------------------------------------------------------
# Style
# ---------------------------------------------------------------------------

#: Side (px) of a color swatch.
_SWATCH_SIZE_PX = 28

# Hidden line edit measured by `single_line_height`, created on first use.
_probe: QLineEdit | None = None


def refresh_style(widget: QWidget) -> None:
    """
    Re-apply the QSS of a widget after one of its dynamic properties
    changed.

    Parameters
    ----------
    widget : QWidget
        Widget whose style must be re-evaluated.
    """
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def mark_danger(button: QPushButton) -> QPushButton:
    """
    Paint a button in red: one that cancels, refuses or throws changes away.

    Parameters
    ----------
    button : QPushButton
        The button. Its object name (``smallButton``...) is kept: red
        comes from the ``danger`` property (``QPushButton[danger="true"]``
        in ``theme.py``), which combines with any other style.

    Returns
    -------
    QPushButton
        ``button``, for chaining.
    """
    button.setProperty("danger", True)
    refresh_style(button)
    return button


def single_line_height() -> int:
    """
    Return the height of a one-line input under the current theme and zoom.

    Returns
    -------
    int
        Height (px) of a :class:`QLineEdit`, so that other widgets
        (multi-line editors...) can line up with it.

    Notes
    -----
    Measured on a hidden line edit, polished again on every call: the
    application stylesheet changes with the theme and the zoom.
    """
    global _probe
    if _probe is None:
        _probe = QLineEdit()
    _probe.ensurePolished()
    return _probe.sizeHint().height()


def small_button(text: str = "", tooltip_key: str = "", *, square: bool = False) -> QPushButton:
    """
    Build a secondary button, of the height of every other control.

    Parameters
    ----------
    text : str, optional
        Button text.

    tooltip_key : str, optional
        Translation key of the tooltip, none if empty.

    square : bool, optional
        Whether the button is a square holding a symbol (✕, ▲...):
        styled ``squareButton`` (see ``theme.py``), as wide as high.

    Returns
    -------
    QPushButton
        The new button. It is never the dialog's default button, so
        Enter in a nearby field still hits OK.
    """
    button = QPushButton(text)
    button.setObjectName("squareButton" if square else "smallButton")
    button.setAutoDefault(False)
    if tooltip_key:
        button.setToolTip(translator.translate(tooltip_key))
    return button


# ---------------------------------------------------------------------------
# Message boxes
# ---------------------------------------------------------------------------

# Qt's standard buttons (OK, Yes, Save...) are labelled in the language
# of the system, not of the interface: every message box is built here,
# with buttons labelled through the translator. Buttons that cancel,
# refuse or throw changes away (Cancel, No, Discard) are red, see
# `mark_danger`.

def _message(parent: QWidget | None, icon: QMessageBox.Icon, title_key: str, text: str) -> None:
    """
    Show a message with a translated OK button.

    Parameters
    ----------
    parent : QWidget or None
        Parent of the message box.

    icon : QMessageBox.Icon
        Icon of the message.

    title_key : str
        Translation key of the title.

    text : str
        Message, already translated.
    """
    box = QMessageBox(icon, translator.translate(title_key), text, QMessageBox.NoButton, parent)
    box.addButton(translator.translate("common.ok"), QMessageBox.AcceptRole)
    box.exec_()


def warn(parent: QWidget | None, message_key: str, title_key: str = "common.error_title", **kwargs) -> None:
    """
    Show a warning.

    Parameters
    ----------
    parent : QWidget or None
        Parent of the message box.

    message_key : str
        Translation key of the message.

    title_key : str, optional
        Translation key of the title. Default is ``"common.error_title"``.

    **kwargs
        Placeholders of the message.
    """
    _message(parent, QMessageBox.Warning, title_key, translator.translate(message_key, **kwargs))


def show_error(parent: QWidget | None, message_key: str = "common.error_detail", **kwargs) -> None:
    """
    Show an error.

    Parameters
    ----------
    parent : QWidget or None
        Parent of the message box.

    message_key : str, optional
        Translation key of the message. The default,
        ``"common.error_detail"``, shows the ``error`` placeholder as is.

    **kwargs
        Placeholders of the message, typically ``error=str(exc)``.
    """
    _message(parent, QMessageBox.Critical, "common.error_title", translator.translate(message_key, **kwargs))


def inform(parent: QWidget | None, title_key: str, message_key: str, **kwargs) -> None:
    """
    Show an information message.

    Parameters
    ----------
    parent : QWidget or None
        Parent of the message box.

    title_key, message_key : str
        Translation keys of the title and of the message.

    **kwargs
        Placeholders of the message.
    """
    _message(parent, QMessageBox.Information, title_key, translator.translate(message_key, **kwargs))


def show_rich_text(parent: QWidget | None, title_key: str, html: str) -> None:
    """
    Show a message written in HTML (links...), with a translated OK button.

    Parameters
    ----------
    parent : QWidget or None
        Parent of the message box.

    title_key : str
        Translation key of the title.

    html : str
        Message, already translated.
    """
    box = QMessageBox(QMessageBox.Information, translator.translate(title_key), "",
                      QMessageBox.NoButton, parent)
    box.setTextFormat(Qt.RichText)
    box.setText(html)
    box.addButton(translator.translate("common.ok"), QMessageBox.AcceptRole)
    box.exec_()


def confirm(parent: QWidget | None, title_key: str, prompt: str) -> bool:
    """
    Ask a yes/no question.

    Parameters
    ----------
    parent : QWidget or None
        Parent of the message box.

    title_key : str
        Translation key of the title.

    prompt : str
        Question, already translated.

    Returns
    -------
    bool
        ``True`` if the user answered yes.
    """
    tr = translator.translate
    box = QMessageBox(QMessageBox.Question, tr(title_key), prompt, QMessageBox.NoButton, parent)
    yes = box.addButton(tr("common.yes"), QMessageBox.YesRole)
    no = mark_danger(box.addButton(tr("common.no"), QMessageBox.NoRole))
    box.setDefaultButton(no)
    box.setEscapeButton(no)
    box.exec_()
    return box.clickedButton() is yes


#: Answers of :func:`ask_unsaved`.
SAVE, DISCARD, CANCEL = "save", "discard", "cancel"


def ask_unsaved(parent: QWidget | None, title_key: str, message_key: str) -> str:
    """
    Ask what to do with unsaved changes: save, discard or cancel.

    Parameters
    ----------
    parent : QWidget or None
        Parent of the message box.

    title_key, message_key : str
        Translation keys of the title and of the question.

    Returns
    -------
    str
        :data:`SAVE`, :data:`DISCARD` (the red button), or
        :data:`CANCEL` (also on Escape or when the box is closed).
    """
    tr = translator.translate
    box = QMessageBox(QMessageBox.Question, tr(title_key), tr(message_key), QMessageBox.NoButton, parent)
    save = box.addButton(tr("common.save"), QMessageBox.AcceptRole)
    discard = box.addButton(tr("common.discard"), QMessageBox.DestructiveRole)
    mark_danger(discard)
    cancel = box.addButton(tr("common.cancel"), QMessageBox.RejectRole)
    box.setDefaultButton(save)
    box.setEscapeButton(cancel)
    box.exec_()
    clicked = box.clickedButton()
    if clicked is save:
        return SAVE
    if clicked is discard:
        return DISCARD
    return CANCEL


def ask_text(parent: QWidget | None, title_key: str, prompt: str, text: str = "") -> str | None:
    """
    Ask for one line of text, with translated OK/Cancel buttons (Cancel in red).

    Parameters
    ----------
    parent : QWidget or None
        Parent of the dialog.

    title_key : str
        Translation key of the title.

    prompt : str
        Question, already translated.

    text : str, optional
        Pre-filled text.

    Returns
    -------
    str or None
        The stripped text (possibly empty), or ``None`` if cancelled.
    """
    dialog = QDialog(parent)
    dialog.setWindowTitle(translator.translate(title_key))
    layout = QVBoxLayout(dialog)
    label = QLabel(prompt)
    label.setWordWrap(True)
    layout.addWidget(label)
    edit = QLineEdit(text)
    edit.selectAll()
    layout.addWidget(edit)
    layout.addWidget(ok_cancel_buttons(dialog))
    edit.setFocus()
    if dialog.exec_() != QDialog.Accepted:
        return None
    return edit.text().strip()


def ok_cancel_buttons(
    dialog: QDialog,
    on_accept: Callable[[], None] | None = None,
    ok_key: str = "common.ok",
) -> QDialogButtonBox:
    """
    Build a translated OK/Cancel button box wired to a dialog, Cancel in red.

    Parameters
    ----------
    dialog : QDialog
        Dialog the buttons belong to; Cancel calls its ``reject``.

    on_accept : callable, optional
        Called on OK, typically to validate the fields before calling
        ``dialog.accept()``. Default is ``dialog.accept``.

    ok_key : str, optional
        Translation key of the OK button, e.g. ``"common.apply"``.

    Returns
    -------
    QDialogButtonBox
        The button box, to be added to the dialog's layout.
    """
    buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    buttons.button(QDialogButtonBox.Ok).setText(translator.translate(ok_key))
    cancel = buttons.button(QDialogButtonBox.Cancel)
    cancel.setText(translator.translate("common.cancel"))
    mark_danger(cancel)
    buttons.accepted.connect(on_accept or dialog.accept)
    buttons.rejected.connect(dialog.reject)
    return buttons


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

class PasswordField(QWidget):
    """
    Masked :class:`QLineEdit` with a "Show"/"Hide" toggle button.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    edit : QLineEdit
        The password input, masked by default.

    toggle_button : QPushButton
        Button switching :attr:`edit` between masked and plain text.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.Password)
        self.toggle_button = small_button(tooltip_key="common.show_hide_tooltip")
        self.toggle_button.clicked.connect(self._toggle_mask)

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self.edit, stretch=1)
        row.addWidget(self.toggle_button)

        self.retranslate()
        translator.language_changed.connect(self.retranslate)

    @pyqtSlot()
    def retranslate(self) -> None:
        """Refresh the toggle button's text and tooltip."""
        masked = self.edit.echoMode() == QLineEdit.Password
        self.toggle_button.setText(translator.translate("common.show" if masked else "common.hide"))
        self.toggle_button.setToolTip(translator.translate("common.show_hide_tooltip"))

    def _toggle_mask(self) -> None:
        """Switch :attr:`edit` between masked and plain text."""
        masked = self.edit.echoMode() == QLineEdit.Password
        self.edit.setEchoMode(QLineEdit.Normal if masked else QLineEdit.Password)
        self.retranslate()

    def clear(self) -> None:
        """Erase the entered password."""
        self.edit.clear()

    def text(self) -> str:
        """
        Return the entered password.

        Returns
        -------
        str
            The password as typed, without stripping.
        """
        return self.edit.text()

    def to_bytearray(self) -> bytearray:
        """
        Return the entered password as a mutable buffer.

        Returns
        -------
        bytearray
            The UTF-8 encoded password, so the caller can wipe it
            after use.
        """
        return bytearray(self.edit.text().encode("utf-8"))


class NewPasswordFields:
    """
    A new password and its confirmation, as two rows of a form.

    Parameters
    ----------
    form : QFormLayout
        Form receiving both rows.

    label : str
        Label of the password row, already translated.

    confirm_label : str
        Label of the confirmation row, already translated.

    Attributes
    ----------
    password, confirmation : PasswordField
        Both inputs.
    """

    def __init__(self, form: QFormLayout, label: str, confirm_label: str):
        self.password = PasswordField()
        self.confirmation = PasswordField()
        self.label = QLabel(label)
        self.confirm_label = QLabel(confirm_label)
        form.addRow(self.label, self.password)
        form.addRow(self.confirm_label, self.confirmation)

    def problem(self) -> str | None:
        """
        Tell what is wrong with the typed password, if anything.

        Returns
        -------
        str or None
            ``"empty"`` if no password was typed, ``"mismatch"`` if the
            confirmation differs, ``None`` if both are fine.
        """
        if not self.password.text():
            return "empty"
        if self.password.text() != self.confirmation.text():
            return "mismatch"
        return None

    def text(self) -> str:
        """Return the typed password."""
        return self.password.text()

    def to_bytearray(self) -> bytearray:
        """Return the typed password as a mutable buffer (see :meth:`PasswordField.to_bytearray`)."""
        return self.password.to_bytearray()

    def clear(self) -> None:
        """Erase both inputs."""
        self.password.clear()
        self.confirmation.clear()


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

class ColorSwatch(QLabel):
    """
    Square showing a color, or "∅" for none.

    Parameters
    ----------
    color : str or None, optional
        Color shown first, ``"#rrggbb"``.

    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, color: str | None = None, parent=None):
        super().__init__(parent)
        self.setFixedSize(_SWATCH_SIZE_PX, _SWATCH_SIZE_PX)
        self.setAlignment(Qt.AlignCenter)
        self.set_color(color)

    def set_color(self, color: str | None) -> None:
        """
        Show a color.

        Parameters
        ----------
        color : str or None
            ``"#rrggbb"``, or ``None`` for no color (a dashed "∅").
        """
        if color is None:
            self.setText("∅")
            self.setStyleSheet("border: 1px dashed #888888; border-radius: 4px;")
        else:
            self.setText("")
            self.setStyleSheet(
                f"background-color: {color}; border: 1px solid #888888; border-radius: 4px;"
            )


# ---------------------------------------------------------------------------
# Languages
# ---------------------------------------------------------------------------

class LanguageComboBox(QComboBox):
    """
    Combo box of the supported languages, each named in the current
    display language.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Notes
    -----
    Starts on the current display language. Picking an entry doesn't
    change the language by itself: the owner reacts to
    ``currentIndexChanged``.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        for code, name_key in LANGUAGE_NAME_KEYS.items():
            self.addItem(translator.translate(name_key), code)
        self.set_language(translator.language)
        translator.language_changed.connect(self.retranslate)

    def language(self) -> str:
        """
        Return the selected language.

        Returns
        -------
        str
            Language code.
        """
        return self.currentData()

    def set_language(self, language: str) -> None:
        """
        Select a language without emitting ``currentIndexChanged``.

        Parameters
        ----------
        language : str
            Language code; nothing is selected if unsupported.
        """
        self.blockSignals(True)
        self.setCurrentIndex(self.findData(language))
        self.blockSignals(False)

    @pyqtSlot()
    def retranslate(self) -> None:
        """Rename every language in the current display language."""
        for index, name_key in enumerate(LANGUAGE_NAME_KEYS.values()):
            self.setItemText(index, translator.translate(name_key))
