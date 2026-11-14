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

import datetime
import re
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, cast

import pyaescbc
from PyQt5.QtCore import QSize, Qt, QTimer, QUrl, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..core.exceptions import PasswordManagerError
from ..core.item import _FIELDS, FieldKind
from ..core.types import ClearField, ItemField, SecretField
from ..core.totp import generate_totp_code
from .clipboard import copy_secret, copy_text
from .common import _item_icon_or_default
from .dialogs import CustomFieldDialog, GeneratorDialog, ask_item_icon
from .translate import translator
from .widgets import (
    CANCEL,
    SAVE,
    ask_unsaved,
    confirm,
    mark_danger,
    refresh_style,
    show_error,
    single_line_height,
    small_button,
    warn,
)

if TYPE_CHECKING:
    from ..core.item import Item
    from ..core.manager import PasswordManager


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Predefined fields, in display order: (field, label key).
_STANDARD_FIELDS: tuple[tuple[ItemField, str], ...] = (
    ("logins", "viewer.field_logins"),
    ("passwords", "viewer.field_passwords"),
    ("totps", "viewer.field_totps"),
    ("websites", "viewer.field_websites"),
    ("emails", "viewer.field_emails"),
    ("phones", "viewer.field_phones"),
)

# Keys of the rows in `ItemViewer._rows`: one namespace per origin, so a
# custom field can never collide with a predefined one, whatever its name.
# A custom field added during an edit has no id until saved: "new:<n>".
_FIELD_PREFIX = "field:"
_CUSTOM_PREFIX = "custom:"
_NEW_PREFIX = "new:"

_ICON_PREVIEW_SIZE_PX = 56
_FLASH_DURATION_MS = 350
_TOTP_REFRESH_MS = 1000

# Lines shown at most by a multi-line value editor before it scrolls.
_EDITOR_MAX_LINES = 10

# Masked secrets always show this many bullets, not to leak their length.
_MASK = "•" * 12
_TOTP_MASK = "•" * 6

# Loose shape checks, only used to flag values that obviously aren't an
# email, a phone number or a website -- not strict validators.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s.\-()]{5,}$")
_WEBSITE_RE = re.compile(
    r"^(https?://)?" r"([\w-]+(\.[\w-]+)+|localhost)" r"(:\d+)?" r"([/?#].*)?$"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clear_layout(layout: QLayout) -> None:
    """
    Remove and delete every widget of a layout.

    Parameters
    ----------
    layout : QLayout
        Layout to empty.
    """
    while layout.count():
        widget = layout.takeAt(0).widget()
        if widget is not None:
            widget.deleteLater()


def _format_date(value: str) -> str:
    """
    Format a stored date for display.

    Parameters
    ----------
    value : str
        ISO 8601 date, as stored by the core.

    Returns
    -------
    str
        ``"YYYY-MM-DD HH:MM"`` in local time, or ``value`` unchanged if
        it can't be parsed.
    """
    try:
        date = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return str(value)
    if date.tzinfo is not None:
        date = date.astimezone()
    return date.strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------------------
# Value labels
# ---------------------------------------------------------------------------
#
# No widget below sets its own colors: `theme.py` styles them by class
# name (FieldRow, ClickToCopyLabel, IconPreview...) or object name
# ("smallButton", "mutedLabel"...), so `apply_theme` re-styles them all.


class ClickToCopyLabel(QLabel):
    """
    Label copying a value to the clipboard when clicked.

    The copied value may differ from the displayed text, e.g. when the
    latter is masked. A click briefly switches the QSS ``state``
    property to ``"flash"`` as feedback.

    Parameters
    ----------
    display_text : str, optional
        Text shown in the label.
    copy_text : str, optional
        Value copied on click. Nothing is copied if empty.
    parent : QWidget, optional
        Parent widget.
    copy_provider : callable, optional
        Called on click to get the value to copy, instead of
        ``copy_text``: lets a masked secret be decrypted only when
        actually copied. Returns ``None`` to copy nothing.
    sensitive : bool, optional
        Whether the value is a secret, erased from the clipboard after
        a delay (see :func:`clipboard.copy_secret`). Default is
        ``False``.
    """

    def __init__(
        self,
        display_text: str = "",
        copy_text: str = "",
        parent=None,
        *,
        copy_provider: Callable[[], str | None] | None = None,
        sensitive: bool = False,
    ):
        super().__init__(display_text, parent)
        self._copy_text = copy_text
        self._copy_provider = copy_provider
        self._sensitive = sensitive
        self._base_state = ""
        self.setWordWrap(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)

    def set_base_state(self, state: str) -> None:
        """
        Set the persistent QSS ``state`` of the label.

        Parameters
        ----------
        state : str
            ``""`` or ``"warning"``. It is restored after the transient
            ``"flash"`` state of a click.
        """
        self._base_state = state
        self.setProperty("state", state)
        refresh_style(self)

    def mousePressEvent(self, event) -> None:
        """
        Copy the value on a left click.

        Parameters
        ----------
        event : QMouseEvent
            The press event.
        """
        if event.button() == Qt.LeftButton:
            value = self._copy_provider() if self._copy_provider else self._copy_text
            if value:
                (copy_secret if self._sensitive else copy_text)(value)
                self._flash_feedback()
        super().mousePressEvent(event)

    def _flash_feedback(self) -> None:
        """Briefly switch to the ``"flash"`` state, then restore the base one."""
        self.setProperty("state", "flash")
        refresh_style(self)
        QTimer.singleShot(_FLASH_DURATION_MS, self._restore_state)

    def _restore_state(self) -> None:
        """Restore the persistent QSS state after a flash."""
        self.setProperty("state", self._base_state)
        refresh_style(self)


class ActionableLabel(ClickToCopyLabel):
    """
    :class:`ClickToCopyLabel` that can also be opened with an external
    application (browser, mail, phone).

    A click copies the value; a double click asks for confirmation and
    opens ``url_prefix + value``.

    Parameters
    ----------
    value : str
        Value shown, copied on click and opened on double click.

    url_prefix : str
        Prefix of the URL opening the value: ``""`` for a website,
        ``"mailto:"`` or ``"tel:"``.

    open_prompt_key : str
        Translation key of the confirmation question.

    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, value: str, url_prefix: str, open_prompt_key: str, parent=None):
        super().__init__(value, value, parent)
        self._url_prefix = url_prefix
        self._open_prompt_key = open_prompt_key

    def mouseDoubleClickEvent(self, event) -> None:
        """
        Ask for confirmation, then open the value, on a left double click.

        Parameters
        ----------
        event : QMouseEvent
            The double-click event.
        """
        if event.button() != Qt.LeftButton or not self._copy_text:
            super().mouseDoubleClickEvent(event)
            return
        prompt = f"{translator.translate(self._open_prompt_key)}\n\n{self._copy_text}"
        if not confirm(self, "viewer.open_link_title", prompt):
            return
        if not QDesktopServices.openUrl(QUrl(self._url_prefix + self._copy_text)):
            warn(self, "viewer.link_unavailable_message", "viewer.link_unavailable_title")


# Actionable fields: (URL prefix, confirmation key, shape check, tooltip key if invalid).
_ACTIONABLE_FIELDS: dict[str, tuple[str, str, re.Pattern, str]] = {
    "websites": ("", "viewer.open_website_prompt", _WEBSITE_RE, "viewer.invalid_website_tooltip"),
    "emails": ("mailto:", "viewer.open_email_prompt", _EMAIL_RE, "viewer.invalid_email_tooltip"),
    "phones": ("tel:", "viewer.open_phone_prompt", _PHONE_RE, "viewer.invalid_phone_tooltip"),
}


# ---------------------------------------------------------------------------
# Value editors
# ---------------------------------------------------------------------------

class _GrowingTextEdit(QPlainTextEdit):
    """
    Plain-text editor growing with its content, for custom values,
    which may span several lines (notes, recovery codes...).

    With one line, it is exactly as high as a :class:`QLineEdit`, so it
    lines up with the editors of the predefined fields; each further
    line adds one line height, up to :data:`_EDITOR_MAX_LINES`.

    Parameters
    ----------
    text : str, optional
        Initial text.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, text: str = "", parent=None):
        super().__init__(text, parent)
        # The QSS padding is the only margin, as in a QLineEdit.
        self.document().setDocumentMargin(0)
        self.textChanged.connect(self._fit_height)
        self._fit_height()

    def text(self) -> str:
        """
        Return the text, like :meth:`QLineEdit.text`.

        Returns
        -------
        str
            The whole content.
        """
        return self.toPlainText()

    def resizeEvent(self, event) -> None:
        """Fit the height again when the width changes (lines may wrap differently)."""
        super().resizeEvent(event)
        self._fit_height()

    def _line_count(self) -> int:
        """Return the number of displayed lines, wrapped lines included."""
        count = 0
        block = self.document().firstBlock()
        while block.isValid():
            layout = block.layout()
            count += max(1, layout.lineCount() if layout is not None else 1)
            block = block.next()
        return max(1, count)

    def _fit_height(self) -> None:
        """Fit the height to the content, between one line and :data:`_EDITOR_MAX_LINES`."""
        spacing = self.fontMetrics().lineSpacing()
        # One line: a QLineEdit's height, but never less than the text
        # plus the QSS padding (2 x 6 px) and border (2 x 1 px).
        one_line = max(single_line_height(), spacing + 14)
        lines = min(_EDITOR_MAX_LINES, self._line_count())
        self.setFixedHeight(one_line + (lines - 1) * spacing)


# ---------------------------------------------------------------------------
# Field rows
# ---------------------------------------------------------------------------

class FieldRow(QFrame):
    """
    Row showing one field (predefined or custom) in VIEW mode, or
    editing it in EDIT mode.

    The mode is fixed at construction: :class:`ItemViewer` rebuilds its
    rows whenever it switches mode.

    **VIEW mode.** Every value is a click-to-copy label. Secret values
    are never decrypted to build the row: it only knows how many there
    are, shows them masked, and asks the viewer to decrypt them when
    "Show" is clicked or a value is copied (which may ask for the
    secondary password). Copied secrets are erased from the clipboard
    after a delay.

    **EDIT mode.** One editor per value (multi-line for custom fields),
    each removable, plus "Add value" (and "Generate" for passwords).
    A custom field also gets an editable name, move and remove buttons.

    Parameters
    ----------
    viewer : ItemViewer
        Viewer owning the row, decrypting secrets on demand.
    key : str
        Key of the row: ``"field:<name>"`` or ``"custom:<id>"``.
    label : str
        Label (or custom name) shown above the values.
    editing : bool
        ``True`` for EDIT mode, ``False`` for VIEW mode.
    values : list of str, optional
        Clear values: of a clear field in VIEW mode, of any field in
        EDIT mode (secrets already decrypted).
    count : int, optional
        Number of values of a secret field, in VIEW mode.
    secret : bool, optional
        Whether the values are encrypted. Default is ``False``.
    custom : bool, optional
        Whether the field is a custom field. Default is ``False``.
    field_name : str, optional
        Predefined field name, to pick the label class (website,
        email, phone) and the "Generate" button (password).

    Attributes
    ----------
    remove_requested : pyqtSignal(str)
        Emitted with :attr:`key` when the remove button of a custom
        field is clicked.
    move_requested : pyqtSignal(str, int)
        Emitted with :attr:`key` and ``-1``/``1`` when a move button of
        a custom field is clicked.
    """

    remove_requested = pyqtSignal(str)
    move_requested = pyqtSignal(str, int)

    def __init__(
        self,
        viewer: ItemViewer,
        key: str,
        label: str,
        editing: bool,
        *,
        values: list[str] | None = None,
        count: int = 0,
        secret: bool = False,
        custom: bool = False,
        field_name: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self.viewer = viewer
        self.key = key
        self.editing = editing
        self.secret = secret
        self.custom = custom
        self.field_name = field_name
        self._values = list(values or [])
        self._count = count if secret and not editing else len(self._values)
        self._shown = False
        self._labels: list[ClickToCopyLabel] = []
        self._editors: list[QLineEdit | _GrowingTextEdit] = []

        self.setFrameShape(QFrame.StyledPanel)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(4)

        header = QHBoxLayout()
        suffix = " 🔒" if secret and custom else ""
        self.name_edit: QLineEdit | None = None
        if editing and custom:
            self.name_edit = QLineEdit(label)
            self.name_edit.setPlaceholderText(translator.translate("viewer.custom_name_placeholder"))
            header.addWidget(self.name_edit, stretch=1)
            if suffix:
                header.addWidget(QLabel(suffix.strip()))
        else:
            title = QLabel(label + suffix)
            title.setObjectName("fieldLabelHeader")
            header.addWidget(title)
            header.addStretch()

        self.eye_btn: QPushButton | None = None
        if not editing and secret and self._count and not isinstance(self, TotpFieldRow):
            self.eye_btn = small_button(translator.translate("common.show"), "common.show_hide_tooltip")
            self.eye_btn.clicked.connect(self._toggle_shown)
            header.addWidget(self.eye_btn)
        if editing and custom:
            for text, step, tooltip in (("▲", -1, "viewer.move_field_up_tooltip"), ("▼", 1, "viewer.move_field_down_tooltip")):
                button = small_button(text, tooltip, square=True)
                button.clicked.connect(lambda _c=False, step=step: self.move_requested.emit(self.key, step))
                header.addWidget(button)
            remove_btn = small_button("✕", "viewer.remove_field_tooltip", square=True)
            remove_btn.clicked.connect(lambda: self.remove_requested.emit(self.key))
            header.addWidget(remove_btn)
        outer.addLayout(header)

        self.values_layout = QVBoxLayout()
        self.values_layout.setSpacing(4)
        outer.addLayout(self.values_layout)

        if editing:
            self._build_edit(outer)
        else:
            self._build_view()

    def release(self) -> None:
        """
        Erase whatever clear secret the row keeps, before it is deleted.

        Notes
        -----
        A plain row keeps none (secrets are decrypted on demand, then
        dropped); see :meth:`TotpFieldRow.release`.
        """

    # -- VIEW mode ----------------------------------------------------------

    def _build_view(self) -> None:
        """Build one label per value (masked for secrets)."""
        if not self._count:
            placeholder = QLabel(translator.translate("viewer.empty_value_placeholder"))
            placeholder.setObjectName("mutedLabel")
            self.values_layout.addWidget(placeholder)
            return
        for index in range(self._count):
            label = self._make_label(index)
            self._labels.append(label)
            self.values_layout.addWidget(label)

    def _make_label(self, index: int) -> ClickToCopyLabel:
        """
        Build the VIEW-mode label of one value.

        Parameters
        ----------
        index : int
            Index of the value.

        Returns
        -------
        ClickToCopyLabel
            A masked label decrypting on click for a secret; for a
            website, email or phone, a label that can also be opened,
            flagged when the value doesn't look like one.
        """
        if self.secret:
            label = ClickToCopyLabel(
                _MASK,
                copy_provider=lambda index=index: self.viewer.reveal_one(self.key, index),  # type: ignore[misc]
                sensitive=True,
            )
            label.setToolTip(translator.translate("viewer.copy_secret_tooltip"))
            return label
        value = self._values[index]
        if self.field_name not in _ACTIONABLE_FIELDS:
            return ClickToCopyLabel(value, value)
        url_prefix, prompt_key, pattern, tooltip_key = _ACTIONABLE_FIELDS[self.field_name]
        label = ActionableLabel(value, url_prefix, prompt_key)
        if value and not pattern.match(value.strip()):
            label.setText(f"⚠ {value}")
            label.setToolTip(translator.translate(tooltip_key))
            label.set_base_state("warning")
        return label

    def _toggle_shown(self) -> None:
        """
        Show the secret values in clear, or mask them again.

        Notes
        -----
        Showing decrypts them (asking for the secondary password if
        needed); masking drops the clear text from the labels.
        """
        if self._shown:
            self.hide_secrets()
            return
        values = self.viewer.reveal(self.key)
        if values is None:
            return
        for label, value in zip(self._labels, values):
            label.setText(value)
        self._shown = True
        if self.eye_btn is not None:
            self.eye_btn.setText(translator.translate("common.hide"))

    def hide_secrets(self) -> None:
        """Mask the secret values again, if shown."""
        if not self.secret or self.editing:
            return
        for label in self._labels:
            label.setText(_MASK)
        self._shown = False
        if self.eye_btn is not None:
            self.eye_btn.setText(translator.translate("common.show"))

    # -- EDIT mode ----------------------------------------------------------

    def _build_edit(self, outer: QVBoxLayout) -> None:
        """
        Build one editor per value and the buttons below them.

        Parameters
        ----------
        outer : QVBoxLayout
            Layout of the row, receiving the buttons.
        """
        for value in self._values:
            self._add_editor(value)
        buttons = QHBoxLayout()
        add_btn = small_button(translator.translate("viewer.add_value_button"))
        add_btn.clicked.connect(lambda: self._add_editor("", focus=True))
        buttons.addWidget(add_btn)
        if self.field_name == "passwords":
            generate_btn = small_button(translator.translate("viewer.generate_password"))
            generate_btn.clicked.connect(self._open_generator)
            buttons.addWidget(generate_btn)
        buttons.addStretch()
        outer.addLayout(buttons)

    def _add_editor(self, text: str, focus: bool = False) -> None:
        """
        Append one value editor, with its own remove button.

        Parameters
        ----------
        text : str
            Initial value.
        focus : bool, optional
            Whether to give it the keyboard focus.
        """
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)
        editor: QLineEdit | _GrowingTextEdit
        editor = _GrowingTextEdit(text) if self.custom else QLineEdit(text)
        row_layout.addWidget(editor)
        remove_btn = small_button("✕", "viewer.remove_value_tooltip", square=True)
        remove_btn.clicked.connect(lambda: self._remove_editor(row_widget, editor))
        row_layout.addWidget(remove_btn, alignment=Qt.AlignTop)
        self.values_layout.addWidget(row_widget)
        self._editors.append(editor)
        if focus:
            editor.setFocus()

    def _remove_editor(self, row_widget: QWidget, editor) -> None:
        """
        Remove one value editor.

        Parameters
        ----------
        row_widget : QWidget
            The editor's row.
        editor : QLineEdit or _GrowingTextEdit
            The editor.
        """
        if editor in self._editors:
            self._editors.remove(editor)
        self.values_layout.removeWidget(row_widget)
        row_widget.deleteLater()

    def _open_generator(self) -> None:
        """Open the password generator and add its result as a new value."""
        dialog = GeneratorDialog(parent=self)
        if dialog.exec_() == QDialog.Accepted:
            self._add_editor(dialog.get_password())

    def get_edit_values(self) -> list[str]:
        """
        Return the values entered in EDIT mode.

        Returns
        -------
        list of str
            One entry per non-empty editor. Values of clear predefined
            fields are stripped; secrets and custom values are kept as
            typed (a password may start or end with a space).
        """
        values = []
        for editor in self._editors:
            text = editor.text()
            if not self.secret and not self.custom:
                text = text.strip()
            if text.strip():
                values.append(text)
        return values

    def get_edit_name(self) -> str | None:
        """
        Return the name entered for a custom field.

        Returns
        -------
        str or None
            The stripped name, ``None`` for a predefined field.
        """
        return self.name_edit.text().strip() if self.name_edit is not None else None

    def set_edit_state(self, name: str | None, values: list[str]) -> None:
        """
        Restore unsaved edits after the row was rebuilt.

        Parameters
        ----------
        name : str or None
            Custom name, as returned by :meth:`get_edit_name`.
        values : list of str
            Values, as returned by :meth:`get_edit_values`.
        """
        if self.name_edit is not None and name is not None:
            self.name_edit.setText(name)
        for editor in list(self._editors):
            self._remove_editor(editor.parentWidget(), editor)
        for value in values:
            self._add_editor(value)


class TotpFieldRow(FieldRow):
    """
    Row of the TOTP secrets, in VIEW mode.

    Each secret is shown as its current code and the seconds left
    before renewal, refreshed every second; clicking copies the code,
    never the secret. In EDIT mode, the Base32 secrets are edited as a
    regular secret field (use :class:`FieldRow`).

    Parameters
    ----------
    viewer : ItemViewer
        Viewer owning the row.
    key : str
        Key of the row, ``"field:totps"``.
    label : str
        Label shown above the codes.
    count : int
        Number of secrets.

    Notes
    -----
    The secrets are decrypted once, as soon as the profile is decrypted
    (on opening, or later with the Decrypt button or a click), and kept
    as ``bytearray`` while the row is shown: every second, the codes are
    computed from them, so only the 6-digit codes, obsolete within 30
    seconds, ever exist as ``str``. They are erased by :meth:`release`
    (row rebuilt, viewer closed) and as soon as the profile is
    encrypted; codes are then masked, and a click asks for the
    secondary password.
    """

    def __init__(self, viewer: ItemViewer, key: str, label: str, count: int, parent=None):
        super().__init__(viewer, key, label, False, count=count, secret=True, field_name="totps", parent=parent)
        self._secrets: list[bytearray] | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(_TOTP_REFRESH_MS)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self._tick()

    def release(self) -> None:
        """Stop refreshing the codes, and erase the decrypted secrets."""
        self._timer.stop()
        self._erase()

    def _erase(self) -> None:
        """Erase the decrypted secrets, if any."""
        for secret in self._secrets or ():
            pyaescbc.delete_bytearray(secret)
        self._secrets = None

    def _load(self, ask: bool) -> bool:
        """
        Make sure the secrets are decrypted.

        Parameters
        ----------
        ask : bool
            Whether the secondary password may be asked.

        Returns
        -------
        bool
            ``True`` if :attr:`_secrets` holds them.
        """
        if not self.viewer.manager.is_decrypted:
            # Encrypted meanwhile: the data key is gone, so are the secrets.
            self._erase()
        if self._secrets is None:
            self._secrets = self.viewer.decrypt_values(self.key, ask=ask)
        return self._secrets is not None

    def _code(self, index: int, ask: bool) -> tuple[str, int] | None:
        """
        Compute the current code of one secret.

        Parameters
        ----------
        index : int
            Index of the secret.
        ask : bool
            Whether the secondary password may be asked.

        Returns
        -------
        tuple of (str, int) or None
            The code and the seconds left, or ``None`` if the secret
            can't be decrypted or isn't valid Base32.
        """
        if not self._load(ask) or self._secrets is None or not 0 <= index < len(self._secrets):
            return None
        try:
            return generate_totp_code(self._secrets[index])
        except ValueError:
            return None

    def _make_label(self, index: int) -> ClickToCopyLabel:
        """
        Build the label of one code.

        Parameters
        ----------
        index : int
            Index of the secret.

        Returns
        -------
        ClickToCopyLabel
            A label copying the current code, computed at click time.
        """
        def current_code() -> str | None:
            code = self._code(index, ask=True)
            return code[0] if code is not None else None

        return ClickToCopyLabel(_TOTP_MASK, copy_provider=current_code, sensitive=True)

    def _tick(self) -> None:
        """
        Refresh every code, or mask them while the profile is encrypted.

        Notes
        -----
        Labels are updated in place rather than rebuilt, so a click's
        flash feedback isn't cut short by the next tick.
        """
        tr = translator.translate
        decrypted = self._load(ask=False)
        for index, label in enumerate(self._labels):
            if not decrypted:
                label.setText(f"{_TOTP_MASK}   🔒")
                label.setToolTip(tr("viewer.totp_locked_tooltip"))
                continue
            code = self._code(index, ask=False)
            if code is None:
                label.setText(tr("viewer.invalid_totp_secret"))
                continue
            label.setText(f"{code[0]}   ({code[1]}s)")
            label.setToolTip(tr("viewer.copy_code_tooltip"))


class IconPreview(QLabel):
    """
    Preview of the item's icon, shown in the viewer's header.

    Shows the bundled default icon when the item has no readable icon.
    While editable, a double click emits :attr:`edit_requested`.

    Parameters
    ----------
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    edit_requested : pyqtSignal()
        Emitted on a double click while editable.
    """

    edit_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(_ICON_PREVIEW_SIZE_PX, _ICON_PREVIEW_SIZE_PX)
        self.setScaledContents(True)
        self.setVisible(False)
        self._editable = False

    def set_icon(self, value: str | None, color: str | None = None) -> None:
        """
        Show a stored icon.

        Parameters
        ----------
        value : str or None
            Base64 icon (``Item.get_icon()``), or ``None``. The preview
            is hidden if even the default icon is missing.
        color : str or None, optional
            Background color (``Item.get_color()``) painted behind the
            icon's transparent pixels; ``None`` for none.
        """
        icon = _item_icon_or_default(value, color)
        if icon is None:
            self.clear()
            self.setVisible(False)
            return
        self.setPixmap(icon.pixmap(_ICON_PREVIEW_SIZE_PX, _ICON_PREVIEW_SIZE_PX))
        self.setVisible(True)

    def set_editable(self, editable: bool) -> None:
        """
        Enable or disable double-click-to-edit.

        Parameters
        ----------
        editable : bool
            Whether a double click emits :attr:`edit_requested`.
        """
        self._editable = editable
        self.setCursor(Qt.PointingHandCursor if editable else Qt.ArrowCursor)
        self.setToolTip(translator.translate("viewer.icon_edit_tooltip") if editable else "")

    def mouseDoubleClickEvent(self, event) -> None:
        """
        Emit :attr:`edit_requested` on a left double click, if editable.

        Parameters
        ----------
        event : QMouseEvent
            The double-click event.
        """
        if self._editable and event.button() == Qt.LeftButton:
            self.edit_requested.emit()
            return
        super().mouseDoubleClickEvent(event)


# ---------------------------------------------------------------------------
# Item viewer
# ---------------------------------------------------------------------------

@dataclass
class _DraftCustom:
    """
    A custom field as edited, in EDIT mode, until "Save".

    Attributes
    ----------
    key : str
        Key of its row: ``"custom:<id>"``, or ``"new:<n>"`` for a field
        added during this edit.

    cid : str or None
        Id of the custom field in the item; ``None`` until a new field
        is saved.

    secret : bool
        Whether its values are encrypted.
    """

    key: str
    cid: str | None
    secret: bool


class ItemViewer(QWidget):
    """
    Widget showing and editing an :class:`Item`.

    - **VIEW** mode: only non-empty fields are shown, every value is
      copied on click. Secrets stay encrypted until asked for: "Show"
      or a click decrypts them (the secondary password is asked the
      first time), and copied secrets leave the clipboard after a
      delay. TOTP codes are shown while the profile is decrypted.
      Websites, emails and phone numbers open on double click.
    - **EDIT** mode (needs the profile decrypted): every field is
      shown, in clear and editable; fields can gain or lose values,
      custom fields can be added, renamed, moved or removed, and the
      icon changed.

    Parameters
    ----------
    manager : PasswordManager
        Unlocked manager; its data key is taken from it at each use,
        never kept.
    item : Item
        Item to show and edit.
    ensure_decrypted : callable
        Called before any use of the data key; asks for the secondary
        password if needed and returns ``False`` if the user cancelled
        (see :meth:`PasswordManagerWindow.ensure_decrypted`).
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    close_requested : pyqtSignal()
        Emitted when "Close" is clicked; the owner decides what to do.
    item_changed : pyqtSignal()
        Emitted whenever "Save" wrote changes into the item, so the
        owner can refresh its lists and mark the profile as modified.

    Notes
    -----
    Every change made in EDIT mode -- name, values, custom fields
    added, renamed, moved or removed, icon -- is only a draft until
    "Save", which writes them all; "Cancel" discards them all. Saving
    only writes what actually changed, so the item's modification date
    isn't touched by a save without changes.
    """

    close_requested = pyqtSignal()
    item_changed = pyqtSignal()

    def __init__(
        self,
        manager: PasswordManager,
        item: Item,
        ensure_decrypted: Callable[[], bool],
        parent=None,
    ):
        super().__init__(parent)
        self.manager = manager
        self.item = item
        self._ensure_decrypted = ensure_decrypted
        self._edit_mode = False
        self._rows: dict[str, FieldRow] = {}

        # EDIT mode drafts: the values (and custom names) as they were
        # when editing started, to write only what changed; the custom
        # fields in their edited order; the edited icon and color.
        self._original_values: dict[str, list[str]] = {}
        self._original_names: dict[str, str] = {}
        self._draft_customs: list[_DraftCustom] = []
        self._draft_icon: str | None = None
        self._draft_color: str | None = None
        self._new_count = 0

        self._init_ui()
        self.retranslate()
        translator.language_changed.connect(self.retranslate)

    # -- Public API ---------------------------------------------------------

    @property
    def is_editing(self) -> bool:
        """
        Tell whether the viewer is in EDIT mode.

        Returns
        -------
        bool
            ``True`` in EDIT mode, ``False`` in VIEW mode.
        """
        return self._edit_mode

    @pyqtSlot()
    def retranslate(self) -> None:
        """Refresh every text after a language change, keeping unsaved edits."""
        tr = translator.translate
        self.edit_btn.setText(tr("viewer.edit"))
        self.close_btn.setText(tr("common.close"))
        self.add_custom_btn.setText(tr("viewer.add_custom_field_button"))
        self.cancel_btn.setText(tr("common.cancel"))
        self.save_btn.setText(tr("common.save"))
        self.title_edit.setPlaceholderText(tr("viewer.item_name_placeholder"))
        self.refresh()

    def confirm_close(self) -> bool:
        """
        Ask what to do with unsaved edits before the viewer is closed.

        Returns
        -------
        bool
            ``True`` if the viewer may close: VIEW mode, or the edits
            were saved or discarded. ``False`` if the user cancelled,
            or saving failed.
        """
        if not self._edit_mode:
            return True
        reply = ask_unsaved(self, "window.unsaved_changes_title", "viewer.unsaved_changes_warning")
        if reply == CANCEL:
            return False
        if reply == SAVE:
            self.save()
            return not self._edit_mode
        return True

    def release(self) -> None:
        """Erase the clear secrets kept by the rows (TOTP), before the viewer is deleted."""
        for row in self._rows.values():
            row.release()

    # -- Secrets ------------------------------------------------------------

    def _locate(self, key: str) -> tuple[ItemField | None, str | None]:
        """
        Return the field a row key designates.

        Parameters
        ----------
        key : str
            ``"field:<name>"`` or ``"custom:<id>"``.

        Returns
        -------
        tuple of (str or None, str or None)
            ``(predefined field, None)`` or ``(None, custom field id)``.
        """
        if key.startswith(_CUSTOM_PREFIX):
            return None, key.removeprefix(_CUSTOM_PREFIX)
        return cast(ItemField, key.removeprefix(_FIELD_PREFIX)), None

    def _revealed(self, key: str) -> AbstractContextManager:
        """
        Return the context manager decrypting the values of a field.

        Parameters
        ----------
        key : str
            Row key of an encrypted field.

        Returns
        -------
        context manager
            :meth:`Item.revealed` or :meth:`Item.revealed_custom`,
            erasing the decrypted buffers on exit.
        """
        field, cid = self._locate(key)
        data_key = self.manager.data_key
        if cid is not None:
            return self.item.revealed_custom(cid, data_key)
        return self.item.revealed(cast(SecretField, field), data_key)

    def _can_decrypt(self, ask: bool) -> bool:
        """Tell whether the data key is available, asking for it if ``ask``."""
        return self.manager.is_decrypted or (ask and self._ensure_decrypted())

    def reveal(self, key: str, *, ask: bool = True) -> list[str] | None:
        """
        Decrypt every value of an encrypted field, as text.

        Parameters
        ----------
        key : str
            Row key of an encrypted field.
        ask : bool, optional
            Whether the secondary password may be asked if the profile
            isn't decrypted. Default is ``True``; ``False`` just
            returns ``None``.

        Returns
        -------
        list of str or None
            The clear values, or ``None`` if the profile isn't
            decrypted (and the user cancelled) or a value can't be
            decrypted (an error is shown if ``ask``).

        Notes
        -----
        The decrypted buffers are erased right away; only the returned
        ``str`` remain, for the caller to display or copy and drop.
        """
        if not self._can_decrypt(ask):
            return None
        try:
            with self._revealed(key) as clears:
                return [bytes(clear).decode("utf-8") for clear in clears]
        except (PasswordManagerError, UnicodeDecodeError, ValueError) as exc:
            if ask:
                show_error(self, "viewer.reveal_error", error=str(exc))
            return None

    def reveal_one(self, key: str, index: int, *, ask: bool = True) -> str | None:
        """
        Decrypt one value of an encrypted field, as text.

        Parameters
        ----------
        key : str
            Row key of an encrypted field.
        index : int
            Index of the value.
        ask : bool, optional
            See :meth:`reveal`.

        Returns
        -------
        str or None
            The clear value, or ``None`` (see :meth:`reveal`).
        """
        values = self.reveal(key, ask=ask)
        if values is None or not 0 <= index < len(values):
            return None
        return values[index]

    def decrypt_values(self, key: str, *, ask: bool = True) -> list[bytearray] | None:
        """
        Decrypt every value of an encrypted field, as erasable buffers.

        Parameters
        ----------
        key : str
            Row key of an encrypted field.
        ask : bool, optional
            See :meth:`reveal`.

        Returns
        -------
        list of bytearray or None
            Clear copies, owned (and to be erased) by the caller, or
            ``None`` (see :meth:`reveal`).
        """
        if not self._can_decrypt(ask):
            return None
        field, cid = self._locate(key)
        data_key = self.manager.data_key
        try:
            if cid is not None:
                return cast(list[bytearray], self.item.get_custom(cid, data_key=data_key))
            return self.item.get(cast(SecretField, field), data_key=data_key)
        except (PasswordManagerError, ValueError) as exc:
            if ask:
                show_error(self, "viewer.reveal_error", error=str(exc))
            return None

    # -- UI -----------------------------------------------------------------

    def _init_ui(self) -> None:
        """Build the toolbar, the header, the field list and the action bar."""
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        layout.addWidget(toolbar)

        self.edit_btn = QPushButton()
        self.edit_btn.setObjectName("editButton")
        self.edit_btn.clicked.connect(self.enter_edit_mode)
        toolbar.addWidget(self.edit_btn)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

        self.close_btn = QPushButton()
        self.close_btn.clicked.connect(self.close_requested.emit)
        toolbar.addWidget(self.close_btn)

        header = QHBoxLayout()
        header.setContentsMargins(8, 8, 8, 8)
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.title_edit = QLineEdit()
        self.title_edit.setObjectName("itemTitleEdit")
        self.title_edit.setFrame(False)
        title_box.addWidget(self.title_edit)
        self.date_label = QLabel()
        self.date_label.setObjectName("mutedLabel")
        title_box.addWidget(self.date_label)
        header.addLayout(title_box, stretch=1)
        self.icon_preview = IconPreview()
        self.icon_preview.edit_requested.connect(self._edit_icon)
        header.addWidget(self.icon_preview, alignment=Qt.AlignTop)
        layout.addLayout(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setAlignment(Qt.AlignTop)
        self.content_layout.setSpacing(6)
        scroll.setWidget(self.content_widget)
        layout.addWidget(scroll, stretch=1)

        bottom = QHBoxLayout()
        bottom.setContentsMargins(8, 6, 8, 6)
        bottom.setSpacing(8)
        self.add_custom_btn = QPushButton()
        self.add_custom_btn.clicked.connect(self._add_custom_field)
        bottom.addWidget(self.add_custom_btn)
        bottom.addStretch()
        self.cancel_btn = mark_danger(QPushButton())
        self.cancel_btn.clicked.connect(self._leave_edit_mode)
        bottom.addWidget(self.cancel_btn)
        self.save_btn = QPushButton()
        self.save_btn.clicked.connect(self.save)
        bottom.addWidget(self.save_btn)
        layout.addLayout(bottom)

    # -- Display ------------------------------------------------------------

    def _refresh_display(self) -> None:
        """Rebuild the header and every field row from the item (or the drafts), in the current mode."""
        self.release()
        _clear_layout(self.content_layout)
        self._rows.clear()
        tr = translator.translate

        self.title_edit.setText(self.item.get_name() or "")
        self.title_edit.setReadOnly(not self._edit_mode)
        self.date_label.setText(
            tr(
                "viewer.dates",
                created=_format_date(self.item.creation_date),
                modified=_format_date(self.item.modification_date),
            )
        )
        if self._edit_mode:
            self.icon_preview.set_icon(self._draft_icon, self._draft_color)
        else:
            self.icon_preview.set_icon(self.item.get_icon(), self.item.get_color())
        self.icon_preview.set_editable(self._edit_mode)

        for field, label_key in _STANDARD_FIELDS:
            self._add_standard_row(field, tr(label_key))
        self._add_custom_rows()

        self.edit_btn.setEnabled(not self._edit_mode)
        self.add_custom_btn.setVisible(self._edit_mode)
        self.cancel_btn.setVisible(self._edit_mode)
        self.save_btn.setVisible(self._edit_mode)

    def _add_standard_row(self, field: ItemField, label: str) -> None:
        """
        Append the row of a predefined field, if it should be shown.

        Parameters
        ----------
        field : str
            Predefined field name.
        label : str
            Translated label of the field.
        """
        key = f"{_FIELD_PREFIX}{field}"
        secret = _FIELDS[field] is FieldKind.ENCRYPTED
        if self._edit_mode:
            row = FieldRow(
                self, key, label, True,
                values=self._original_values.get(key, []), secret=secret, field_name=field,
            )
        else:
            count = self.item.count(field)
            if not count:
                return
            if field == "totps":
                row = TotpFieldRow(self, key, label, count)
            elif secret:
                row = FieldRow(self, key, label, False, count=count, secret=True, field_name=field)
            else:
                row = FieldRow(self, key, label, False, values=self.item.get(cast(ClearField, field)),
                               field_name=field)
        self._add_row(key, row)

    def _add_custom_rows(self) -> None:
        """Append the custom fields section, if it has rows to show."""
        if self._edit_mode:
            rows = [
                FieldRow(
                    self, draft.key, self._original_names[draft.key], True,
                    values=self._original_values.get(draft.key, []), secret=draft.secret, custom=True,
                )
                for draft in self._draft_customs
            ]
        else:
            rows = []
            for cid in self.item.custom_ids():
                count = self.item.custom_count(cid)
                if not count:
                    continue
                key, name = f"{_CUSTOM_PREFIX}{cid}", self.item.custom_name(cid)
                if self.item.custom_kind(cid) is FieldKind.ENCRYPTED:
                    rows.append(FieldRow(self, key, name, False, count=count, secret=True, custom=True))
                else:
                    clear_values = cast(list[str], self.item.get_custom(cid))
                    rows.append(FieldRow(self, key, name, False, values=clear_values, custom=True))
        if not rows:
            return

        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        self.content_layout.addWidget(separator)
        # QSS-driven font (not `setFont`), so the title follows the zoom.
        title = QLabel(translator.translate("custom_field.custom_fields_section"))
        title.setObjectName("sectionTitle")
        title.setContentsMargins(0, 6, 0, 6)
        self.content_layout.addWidget(title)

        for row in rows:
            if self._edit_mode:
                row.remove_requested.connect(self._remove_custom_field)
                row.move_requested.connect(self._move_custom_field)
            self._add_row(row.key, row)

    def _add_row(self, key: str, row: FieldRow) -> None:
        """
        Append a field row to the field list.

        Parameters
        ----------
        key : str
            Key of the row in :attr:`_rows`.
        row : FieldRow
            The row.
        """
        self.content_layout.addWidget(row)
        self._rows[key] = row

    def refresh(self) -> None:
        """
        Rebuild the display, keeping the unsaved edits of EDIT mode.

        Notes
        -----
        In VIEW mode, shown secrets are masked again and the decrypted
        TOTP secrets erased: this is also how the window hides them
        after :meth:`PasswordManager.encrypt`.
        """
        if not self._edit_mode:
            self._refresh_display()
            return
        name_snapshot = self.title_edit.text()
        snapshot = {
            key: (row.get_edit_name(), row.get_edit_values()) for key, row in self._rows.items()
        }
        self._refresh_display()
        self.title_edit.setText(name_snapshot)
        for key, (name, values) in snapshot.items():
            row = self._rows.get(key)
            if row is not None:
                row.set_edit_state(name, values)

    # -- Edit mode ----------------------------------------------------------

    def enter_edit_mode(self) -> None:
        """
        Switch to EDIT mode, decrypting every secret of the item.

        Notes
        -----
        Asks for the secondary password if needed; nothing happens if
        the user cancels or a secret can't be decrypted.
        """
        if self._edit_mode or not self._ensure_decrypted():
            return
        values: dict[str, list[str]] = {}
        names: dict[str, str] = {}
        for field, _label_key in _STANDARD_FIELDS:
            key = f"{_FIELD_PREFIX}{field}"
            if _FIELDS[field] is FieldKind.ENCRYPTED:
                revealed = self.reveal(key)
                if revealed is None:
                    return
                values[key] = revealed
            else:
                values[key] = self.item.get(cast(ClearField, field))
        drafts = []
        for cid in self.item.custom_ids():
            key = f"{_CUSTOM_PREFIX}{cid}"
            names[key] = self.item.custom_name(cid)
            secret = self.item.custom_kind(cid) is FieldKind.ENCRYPTED
            if secret:
                revealed = self.reveal(key)
                if revealed is None:
                    return
                values[key] = revealed
            else:
                values[key] = cast(list[str], self.item.get_custom(cid))
            drafts.append(_DraftCustom(key, cid, secret))
        self._original_values, self._original_names = values, names
        self._draft_customs = drafts
        self._draft_icon, self._draft_color = self.item.get_icon(), self.item.get_color()
        self._edit_mode = True
        self._refresh_display()
        self.title_edit.setFocus()

    def _leave_edit_mode(self) -> None:
        """Switch back to VIEW mode, discarding every draft (also the "Cancel" button)."""
        self._edit_mode = False
        self._original_values, self._original_names = {}, {}
        self._draft_customs = []
        self._draft_icon = self._draft_color = None
        self._refresh_display()

    def save(self) -> None:
        """
        Write every draft into the item, then switch to VIEW mode.

        Notes
        -----
        Only what changed is written: name, values, custom fields
        removed, added, renamed or moved, icon and color. A custom
        field whose name was cleared keeps its previous name (a name
        can't be blank). Secrets are encrypted with the data key; their
        clear buffers are erased by the item once encrypted.

        If an error occurs partway, what was already written stays
        written (and reported through :attr:`item_changed`), and the
        viewer stays in EDIT mode: saving again writes the rest.
        """
        if not self._edit_mode:
            return
        changed = False
        try:
            changed |= self._save_name_and_fields()
            changed |= self._save_customs()
            if self._draft_icon != self.item.get_icon():
                self.item.set_icon(self._draft_icon)
                changed = True
            if self._draft_color != self.item.get_color():
                self.item.set_color(self._draft_color)
                changed = True
        except (PasswordManagerError, ValueError) as exc:
            show_error(self, "viewer.save_error", error=str(exc))
            if changed:
                self.item_changed.emit()
            return
        self._leave_edit_mode()
        if changed:
            self.item_changed.emit()

    @staticmethod
    def _encode(values: list[str], secret: bool) -> list:
        """Return values as the item expects them: clear ``bytearray`` for secrets."""
        return [bytearray(v, "utf-8") for v in values] if secret else values

    def _save_name_and_fields(self) -> bool:
        """
        Write the edited name and predefined fields.

        Returns
        -------
        bool
            Whether anything was written.
        """
        changed = False
        name = self.title_edit.text().strip() or None
        if name != self.item.get_name():
            self.item.set_name(name)
            changed = True
        data_key = self.manager.data_key
        for field, _label_key in _STANDARD_FIELDS:
            key = f"{_FIELD_PREFIX}{field}"
            values = self._rows[key].get_edit_values()
            if values != self._original_values.get(key, []):
                secret = _FIELDS[field] is FieldKind.ENCRYPTED
                self.item.set(field, self._encode(values, secret), data_key=data_key)
                changed = True
        return changed

    def _save_customs(self) -> bool:
        """
        Write the edited custom fields: removals, additions, names,
        values and order.

        Returns
        -------
        bool
            Whether anything was written.
        """
        changed = False
        data_key = self.manager.data_key
        kept = {draft.cid for draft in self._draft_customs if draft.cid is not None}
        for cid in self.item.custom_ids():
            if cid not in kept:
                self.item.remove_custom(cid)
                changed = True

        for index, draft in enumerate(self._draft_customs):
            row = self._rows[draft.key]
            name = row.get_edit_name() or self._original_names[draft.key]
            values = row.get_edit_values()
            if draft.cid is None:
                kind = FieldKind.ENCRYPTED if draft.secret else FieldKind.CLEAR
                draft.cid = self.item.add_custom(
                    name, kind, self._encode(values, draft.secret),
                    data_key=data_key if draft.secret else None,
                )
                # Saved: a retry after an error must not add it twice.
                self._original_values[draft.key] = values
                self._original_names[draft.key] = name
                changed = True
            else:
                if name != self.item.custom_name(draft.cid):
                    self.item.rename_custom(draft.cid, name)
                    changed = True
                if values != self._original_values.get(draft.key, []):
                    self.item.set_custom(
                        draft.cid, self._encode(values, draft.secret),
                        data_key=data_key if draft.secret else None,
                    )
                    changed = True
            if self.item.custom_ids().index(draft.cid) != index:
                self.item.move_custom(draft.cid, index)
                changed = True
        return changed

    def _edit_icon(self) -> None:
        """Pick a new icon and background color (a draft until "Save")."""
        if not self._edit_mode:
            return
        choice = ask_item_icon(self._draft_icon, self._draft_color, self)
        if choice is None:
            return
        self._draft_icon, self._draft_color = choice
        self.icon_preview.set_icon(self._draft_icon, self._draft_color)

    def _add_custom_field(self) -> None:
        """Add a custom field through :class:`CustomFieldDialog` (a draft until "Save")."""
        dialog = CustomFieldDialog(parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        data = dialog.get_data()
        self._new_count += 1
        key = f"{_NEW_PREFIX}{self._new_count}"
        self._draft_customs.append(_DraftCustom(key, None, data["kind"] is FieldKind.ENCRYPTED))
        self._original_values[key] = []
        self._original_names[key] = data["name"]
        self.refresh()

    def _draft_index(self, key: str) -> int:
        """Return the position of a custom field among the drafts."""
        return next(i for i, draft in enumerate(self._draft_customs) if draft.key == key)

    def _move_custom_field(self, key: str, step: int) -> None:
        """
        Move a custom field one place up or down (a draft until "Save").

        Parameters
        ----------
        key : str
            Key of the field's row.
        step : int
            ``-1`` to move up, ``1`` to move down.
        """
        index = self._draft_index(key)
        target = index + step
        if not 0 <= target < len(self._draft_customs):
            return
        drafts = self._draft_customs
        drafts[index], drafts[target] = drafts[target], drafts[index]
        self.refresh()

    def _remove_custom_field(self, key: str) -> None:
        """
        Remove a custom field after confirmation (a draft until "Save").

        Parameters
        ----------
        key : str
            Key of the field's row.
        """
        name = self._rows[key].get_edit_name() or self._original_names[key]
        prompt = translator.translate("viewer.remove_field_prompt", name=name)
        if not confirm(self, "viewer.remove_field_title", prompt):
            return
        del self._draft_customs[self._draft_index(key)]
        # The row must not be snapshotted by refresh().
        self._rows.pop(key).release()
        self.refresh()

    def closeEvent(self, event) -> None:
        """
        Offer to save or discard unsaved edits before closing.

        Parameters
        ----------
        event : QCloseEvent
            The close event, ignored if the user cancels.
        """
        if not self.confirm_close():
            event.ignore()
            return
        self.release()
        event.accept()
