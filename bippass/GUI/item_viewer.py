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

import re
from typing import TYPE_CHECKING, Callable

from PyQt5.QtCore import QSize, Qt, QTimer, QUrl, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..core.totp import generate_totp_code
from .common import _item_icon_or_default
from .dialogs import CustomFieldDialog, GeneratorDialog, ItemIconDialog
from .translate import translator
from .widgets import refresh_style

if TYPE_CHECKING:
    from ..core.credentials import Credentials
    from ..core.item import Item
    from ..core.manager import PasswordManager


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Standard fields, in display order: (field, label key, is_secret).
# All of them are lists; "totps" gets its own row class.
_STANDARD_FIELDS = (
    ("logins", "viewer.field_logins", False),
    ("passwords", "viewer.field_passwords", True),
    ("totps", "viewer.field_totps", True),
    ("websites", "viewer.field_websites", False),
    ("emails", "viewer.field_emails", False),
    ("phones", "viewer.field_phones", False),
)

# Prefix of a custom field's key in `ItemViewer._field_rows`.
_CUSTOM_PREFIX = "custom:"

_ACTION_BUTTON_HEIGHT = 32
_SMALL_BUTTON_SIZE_PX = 28
_ICON_PREVIEW_SIZE_PX = 56
_FLASH_DURATION_MS = 350
_TOTP_REFRESH_MS = 1000

# Masked secrets always show this many bullets, not to leak their length.
_MASK_LENGTH = 12

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


def _to_clear_lines(value) -> list[str]:
    """
    Normalize a value returned by :class:`Item` into clear-text lines.

    Parameters
    ----------
    value : None, str, bytearray or list of those
        Scalar or list value, clear or decrypted.

    Returns
    -------
    list of str
        One string per value, empty if ``value`` is ``None``.
    """
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return [
        bytes(v).decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v) for v in values
    ]


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
    """

    def __init__(self, display_text: str = "", copy_text: str = "", parent=None):
        super().__init__(display_text, parent)
        self._copy_text = copy_text
        self._base_state = ""
        self.setWordWrap(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)

    def set_copy_text(self, text: str) -> None:
        """
        Set the value copied on click.

        Parameters
        ----------
        text : str
            Value to copy, never the masked text.
        """
        self._copy_text = text

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
        if event.button() == Qt.LeftButton and self._copy_text:
            QApplication.clipboard().setText(self._copy_text)
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
    application.

    A click copies the value; a double click asks for confirmation and
    opens the URL built by :meth:`_build_url`. Subclasses set
    :attr:`_open_prompt_key` and implement :meth:`_build_url`.

    Parameters
    ----------
    display_text : str, optional
        Text shown in the label.
    copy_text : str, optional
        Value copied on click and opened on double click.
    parent : QWidget, optional
        Parent widget.
    """

    _open_prompt_key = "viewer.open_website_prompt"

    def _build_url(self, value: str) -> str:
        """
        Build the URL opening a value.

        Parameters
        ----------
        value : str
            The label's value.

        Returns
        -------
        str
            URL passed to :meth:`QDesktopServices.openUrl`.
        """
        raise NotImplementedError

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
        reply = QMessageBox.question(
            self,
            translator.translate("viewer.open_link_title"),
            f"{translator.translate(self._open_prompt_key)}\n\n{self._copy_text}",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        if not QDesktopServices.openUrl(QUrl(self._build_url(self._copy_text))):
            QMessageBox.warning(
                self,
                translator.translate("viewer.link_unavailable_title"),
                translator.translate("viewer.link_unavailable_message"),
            )


class WebsiteLabel(ActionableLabel):
    """Website value, opened in the browser on double click."""

    _open_prompt_key = "viewer.open_website_prompt"

    def _build_url(self, value: str) -> str:
        """
        Build the URL of a website.

        Parameters
        ----------
        value : str
            Website address.

        Returns
        -------
        str
            The address unchanged.
        """
        return value


class EmailLabel(ActionableLabel):
    """Email value, opened in the mail application on double click."""

    _open_prompt_key = "viewer.open_email_prompt"

    def _build_url(self, value: str) -> str:
        """
        Build the ``mailto:`` URL of an email address.

        Parameters
        ----------
        value : str
            Email address.

        Returns
        -------
        str
            ``"mailto:<value>"``.
        """
        return f"mailto:{value}"


class PhoneLabel(ActionableLabel):
    """Phone value, called with the phone application on double click."""

    _open_prompt_key = "viewer.open_phone_prompt"

    def _build_url(self, value: str) -> str:
        """
        Build the ``tel:`` URL of a phone number.

        Parameters
        ----------
        value : str
            Phone number.

        Returns
        -------
        str
            ``"tel:<value>"``.
        """
        return f"tel:{value}"


# Actionable fields: (label class, shape check, tooltip key if invalid).
_ACTIONABLE_FIELDS: dict[str, tuple[type[ActionableLabel], re.Pattern, str]] = {
    "websites": (WebsiteLabel, _WEBSITE_RE, "viewer.invalid_website_tooltip"),
    "emails": (EmailLabel, _EMAIL_RE, "viewer.invalid_email_tooltip"),
    "phones": (PhoneLabel, _PHONE_RE, "viewer.invalid_phone_tooltip"),
}


# ---------------------------------------------------------------------------
# Field rows
# ---------------------------------------------------------------------------


class FieldRow(QFrame):
    """
    Row showing and editing one item field, standard or custom.

    In VIEW mode, each value is a read-only, click-to-copy label, and
    secrets are masked behind a "Show"/"Hide" button. In EDIT mode, the
    field is edited as:

    - a list of value rows, each removable, plus "Add value" (and
      "Generate" for passwords) buttons, for a standard list field;
    - a multi-line text box, for a custom field;
    - a single line, otherwise.

    Parameters
    ----------
    field_name : str
        Standard field name, or ``"custom:<name>"`` for a custom field.
    label_text : str
        Label shown above the values.
    is_list : bool, optional
        Whether the field holds several values. Default is ``False``.
    is_secret : bool, optional
        Whether the values are masked in VIEW mode. Default is ``False``.
    is_custom : bool, optional
        Whether the field is a custom field, removable in EDIT mode.
        Default is ``False``.
    is_password : bool, optional
        Whether to offer the password generator in EDIT mode. Default
        is ``False``.
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    remove_requested : pyqtSignal(str)
        Emitted with :attr:`field_name` when the remove button of a
        custom field is clicked.
    """

    remove_requested = pyqtSignal(str)

    def __init__(
        self,
        field_name: str,
        label_text: str,
        *,
        is_list: bool = False,
        is_secret: bool = False,
        is_custom: bool = False,
        is_password: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self.field_name = field_name
        self.is_list = is_list
        self.is_secret = is_secret
        self.is_custom = is_custom
        self.is_password = is_password

        self._masked = is_secret
        self._clear_lines: list[str] = []
        self._use_textarea_edit = is_custom
        self._use_list_edit = is_list and not is_custom
        self._entry_edits: list[QLineEdit] = []
        self._view_widgets: list[QWidget] = []
        self._edit_mode_active = False

        self.setFrameShape(QFrame.StyledPanel)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(4)

        header = QHBoxLayout()
        self.label = QLabel(label_text)
        self.label.setObjectName("fieldLabelHeader")
        header.addWidget(self.label)
        header.addStretch()

        self.eye_btn = self._small_button(
            translator.translate("common.show"), "common.show_hide_tooltip"
        )
        self.eye_btn.clicked.connect(self._toggle_mask)
        header.addWidget(self.eye_btn)

        self.remove_btn = self._small_button("✕", "viewer.remove_field_tooltip", square=True)
        self.remove_btn.clicked.connect(lambda: self.remove_requested.emit(self.field_name))
        header.addWidget(self.remove_btn)

        outer.addLayout(header)

        self.view_container = QVBoxLayout()
        self.view_container.setSpacing(4)
        outer.addLayout(self.view_container)

        self.edit_line = QLineEdit()
        self.edit_line.setVisible(False)
        outer.addWidget(self.edit_line)

        self.edit_text = QTextEdit()
        self.edit_text.setAcceptRichText(False)
        self.edit_text.setVisible(False)
        self.edit_text.textChanged.connect(self._auto_resize_edit_text)
        outer.addWidget(self.edit_text)

        self.entries_container = QVBoxLayout()
        self.entries_container.setSpacing(4)
        outer.addLayout(self.entries_container)

        entry_buttons_row = QHBoxLayout()
        self.add_entry_btn = self._small_button(translator.translate("viewer.add_value_button"))
        self.add_entry_btn.clicked.connect(lambda: self._add_entry_row(""))
        entry_buttons_row.addWidget(self.add_entry_btn)

        self.generate_btn = self._small_button(translator.translate("viewer.generate_password"))
        self.generate_btn.clicked.connect(self._open_generator)
        entry_buttons_row.addWidget(self.generate_btn)
        entry_buttons_row.addStretch()
        outer.addLayout(entry_buttons_row)

    @staticmethod
    def _small_button(text: str, tooltip_key: str = "", square: bool = False) -> QPushButton:
        """
        Build a hidden "smallButton" styled button.

        Parameters
        ----------
        text : str
            Button text.
        tooltip_key : str, optional
            Translation key of the tooltip, none if empty.
        square : bool, optional
            Whether to give the button a fixed square size.

        Returns
        -------
        QPushButton
            The new, hidden button.
        """
        button = QPushButton(text)
        button.setObjectName("smallButton")
        if tooltip_key:
            button.setToolTip(translator.translate(tooltip_key))
        if square:
            button.setFixedSize(_SMALL_BUTTON_SIZE_PX, _SMALL_BUTTON_SIZE_PX)
        button.setVisible(False)
        return button

    # -- Value --------------------------------------------------------------

    def set_value(self, clear_lines: list[str]) -> None:
        """
        Set the clear-text value(s) of the field.

        Parameters
        ----------
        clear_lines : list of str
            One entry for a scalar field, one per value for a list
            field, empty if the field has no value.
        """
        self._clear_lines = list(clear_lines)
        self._refresh_view()
        self.set_edit_values(self._clear_lines)

    def get_edit_values(self) -> list[str]:
        """
        Return the value(s) entered in EDIT mode.

        Returns
        -------
        list of str
            One entry per non-empty value row for a list field, a
            single entry otherwise.
        """
        if self._use_list_edit:
            return [edit.text().strip() for edit in self._entry_edits if edit.text().strip()]
        if self._use_textarea_edit:
            return [self.edit_text.toPlainText()]
        return [self.edit_line.text()]

    def set_edit_values(self, values: list[str]) -> None:
        """
        Fill the EDIT-mode widgets, leaving the VIEW-mode value unchanged.

        Parameters
        ----------
        values : list of str
            Same shape as returned by :meth:`get_edit_values`.

        Notes
        -----
        Also used to restore unsaved edits after the row was rebuilt,
        see :meth:`ItemViewer.refresh`.
        """
        if self._use_list_edit:
            _clear_layout(self.entries_container)
            self._entry_edits.clear()
            for value in values:
                self._add_entry_row(value)
        elif self._use_textarea_edit:
            self.edit_text.blockSignals(True)
            self.edit_text.setPlainText("\n".join(values))
            self.edit_text.blockSignals(False)
            self._auto_resize_edit_text()
        else:
            self.edit_line.setText("\n".join(values))

    def is_empty(self) -> bool:
        """
        Tell whether the field has no value.

        Returns
        -------
        bool
            ``True`` if the field holds no value.
        """
        return not self._clear_lines

    # -- VIEW mode ----------------------------------------------------------

    def _view_entries(self) -> list[tuple[str, str]]:
        """
        Return the values to show in VIEW mode.

        Returns
        -------
        list of (str, str)
            ``(display_text, copy_text)`` per value; the display text
            is a fixed-length mask while the secret is masked.
        """
        if self.is_secret and self._masked:
            return [("•" * _MASK_LENGTH, line) for line in self._clear_lines]
        return [(line, line) for line in self._clear_lines]

    def _refresh_view(self) -> None:
        """Rebuild the VIEW-mode widgets from the current value."""
        _clear_layout(self.view_container)
        self._view_widgets.clear()

        entries = self._view_entries()
        if not entries:
            placeholder = QLabel(translator.translate("viewer.empty_value_placeholder"))
            placeholder.setObjectName("mutedLabel")
            self._view_widgets.append(placeholder)
        for display_text, copy_text in entries:
            self._view_widgets.append(self._make_view_widget(display_text, copy_text))

        for widget in self._view_widgets:
            self.view_container.addWidget(widget)
            widget.setVisible(not self._edit_mode_active)

        self.eye_btn.setVisible(self.is_secret and not self._edit_mode_active)
        self.eye_btn.setText(translator.translate("common.show" if self._masked else "common.hide"))

    def _make_view_widget(self, display_text: str, copy_text: str) -> QWidget:
        """
        Build the VIEW-mode widget of one value.

        Websites, emails and phone numbers can also be opened, and are
        flagged with a warning when they don't look like one.

        Parameters
        ----------
        display_text : str
            Text shown.
        copy_text : str
            Value copied on click.

        Returns
        -------
        QWidget
            The label of the value.
        """
        if self.field_name not in _ACTIONABLE_FIELDS:
            return ClickToCopyLabel(display_text, copy_text)

        label_cls, pattern, tooltip_key = _ACTIONABLE_FIELDS[self.field_name]
        widget = label_cls(display_text, copy_text)
        if copy_text and not pattern.match(copy_text.strip()):
            widget.setText(f"⚠ {display_text}")
            widget.setToolTip(translator.translate(tooltip_key))
            widget.set_base_state("warning")
        return widget

    def _toggle_mask(self) -> None:
        """Switch the secret values between masked and clear."""
        self._masked = not self._masked
        self._refresh_view()

    # -- EDIT mode ----------------------------------------------------------

    def _auto_resize_edit_text(self) -> None:
        """Fit the multi-line editor's height to its content, within bounds."""
        doc = self.edit_text.document()
        doc.setTextWidth(max(self.edit_text.viewport().width(), 50))
        height = int(doc.size().height()) + 12
        self.edit_text.setFixedHeight(max(34, min(height, 220)))

    def _add_entry_row(self, text: str = "") -> None:
        """
        Append one editable value row, with its own remove button.

        Parameters
        ----------
        text : str, optional
            Initial value of the row.
        """
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        line_edit = QLineEdit(text)
        row_layout.addWidget(line_edit)

        remove_btn = self._small_button("✕", "viewer.remove_value_tooltip", square=True)
        remove_btn.setVisible(True)
        remove_btn.clicked.connect(lambda: self._remove_entry_row(row_widget, line_edit))
        row_layout.addWidget(remove_btn)

        # Parent the row before changing its visibility: showing an
        # unparented widget briefly opens it as a top-level window.
        self.entries_container.addWidget(row_widget)
        row_widget.setVisible(self._edit_mode_active)
        self._entry_edits.append(line_edit)

    def _remove_entry_row(self, row_widget: QWidget, line_edit: QLineEdit) -> None:
        """
        Remove one value row.

        Parameters
        ----------
        row_widget : QWidget
            The row to remove.
        line_edit : QLineEdit
            The row's input.
        """
        if line_edit in self._entry_edits:
            self._entry_edits.remove(line_edit)
        self.entries_container.removeWidget(row_widget)
        row_widget.deleteLater()

    def _open_generator(self) -> None:
        """Open the password generator and add its result as a new value row."""
        dialog = GeneratorDialog(parent=self)
        if dialog.exec_() == QDialog.Accepted:
            self._add_entry_row(dialog.get_password())

    def set_edit_mode(self, editable: bool) -> None:
        """
        Switch the row between VIEW and EDIT mode.

        Parameters
        ----------
        editable : bool
            ``True`` for EDIT mode, ``False`` for VIEW mode.
        """
        self._edit_mode_active = editable
        for widget in self._view_widgets:
            widget.setVisible(not editable)
        self.eye_btn.setVisible(self.is_secret and not editable)
        self.remove_btn.setVisible(self.is_custom and editable)

        use_line_edit = not self._use_list_edit and not self._use_textarea_edit
        self.edit_line.setVisible(editable and use_line_edit)
        self.edit_text.setVisible(editable and self._use_textarea_edit)
        if editable and self._use_textarea_edit:
            self._auto_resize_edit_text()

        for i in range(self.entries_container.count()):
            widget = self.entries_container.itemAt(i).widget()
            if widget is not None:
                widget.setVisible(editable)
        self.add_entry_btn.setVisible(editable and self._use_list_edit)
        self.generate_btn.setVisible(editable and self._use_list_edit and self.is_password)


class TotpFieldRow(FieldRow):
    """
    Row of the TOTP secrets.

    In VIEW mode, each secret is shown as its current code and the
    seconds left before renewal, refreshed every second; clicking
    copies the code, never the secret. In EDIT mode, the Base32
    secrets are edited in clear as a regular list field.

    Parameters
    ----------
    field_name : str
        Field name, ``"totps"``.
    label_text : str
        Label shown above the codes.
    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, field_name: str, label_text: str, parent=None):
        # Not `is_secret`: secrets are never shown in VIEW mode, so
        # there is nothing to mask or unmask.
        super().__init__(field_name, label_text, is_list=True, parent=parent)
        self._timer = QTimer(self)
        self._timer.setInterval(_TOTP_REFRESH_MS)
        self._timer.timeout.connect(self._refresh_view)
        self._timer.start()

    def _view_entries(self) -> list[tuple[str, str]]:
        """
        Return the current codes to show in VIEW mode.

        Returns
        -------
        list of (str, str)
            ``(display_text, code)`` per secret; an invalid secret
            shows an error and copies nothing.
        """
        entries = []
        for secret in self._clear_lines:
            try:
                code, remaining = generate_totp_code(bytearray(secret, "utf-8"))
            except ValueError:
                entries.append((translator.translate("viewer.invalid_totp_secret"), ""))
            else:
                entries.append((f"{code}   ({remaining}s)", code))
        return entries

    def _refresh_view(self) -> None:
        """
        Refresh the codes, in VIEW mode only.

        Existing labels are updated in place rather than rebuilt, so a
        click's flash feedback isn't cut short by the next tick.
        """
        if self._edit_mode_active:
            return
        entries = self._view_entries()
        labels = [w for w in self._view_widgets if isinstance(w, ClickToCopyLabel)]
        if entries and len(labels) == len(self._view_widgets) == len(entries):
            for label, (display_text, code) in zip(labels, entries):
                label.setText(display_text)
                label.set_copy_text(code)
        else:
            super()._refresh_view()


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

    def set_path(self, path: str | None) -> None:
        """
        Show the icon of a stored icon value.

        Parameters
        ----------
        path : str or None
            Bare bundled filename, path to an image, or ``None``. The
            preview is hidden if even the default icon is missing.
        """
        icon = _item_icon_or_default(path)
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


class ItemViewer(QWidget):
    """
    Widget showing and editing an :class:`Item`.

    - **VIEW** mode: only non-empty fields are shown, every value is
      copied on click, secrets are masked by default and TOTP codes
      are shown with their countdown. Websites, emails and phone
      numbers open on double click.
    - **EDIT** mode: every field is shown, in clear and editable. List
      fields can gain or lose values, custom fields can be added or
      removed, and "Save" writes the changes into the item.

    The item's name and icon are shown in the header; the name is
    edited in place, the icon through :class:`ItemIconDialog` on a
    double click.

    Parameters
    ----------
    manager : PasswordManager
        Manager holding the credentials used to decrypt and encrypt
        the item's secrets.
    item : Item
        Item to show and edit.
    parent : QWidget, optional
        Parent widget.

    Attributes
    ----------
    close_requested : pyqtSignal()
        Emitted when "Close" is clicked; the owner decides what to do.
    item_changed : pyqtSignal()
        Emitted whenever a change is written into the item (save, icon,
        custom field added or removed), so the owner can refresh its
        lists and mark the manager as modified.

    Notes
    -----
    Custom field additions/removals and icon changes are applied to
    the item right away; only the name and the field values wait for
    "Save", and are the only changes "Cancel" discards.
    """

    close_requested = pyqtSignal()
    item_changed = pyqtSignal()

    def __init__(self, manager: PasswordManager, item: Item, parent=None):
        super().__init__(parent)
        self.manager = manager
        self.item = item
        self._edit_mode = False
        self._field_rows: dict[str, FieldRow] = {}

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
        self.edit_btn.setText(translator.translate("viewer.edit"))
        self.close_btn.setText(translator.translate("common.close"))
        self.add_custom_btn.setText(translator.translate("viewer.add_custom_field_button"))
        self.cancel_btn.setText(translator.translate("common.cancel"))
        self.save_btn.setText(translator.translate("common.save"))
        self.title_edit.setPlaceholderText(translator.translate("viewer.item_name_placeholder"))
        self.refresh()

    def confirm_close(self) -> bool:
        """
        Ask what to do with unsaved edits before the viewer is closed.

        Returns
        -------
        bool
            ``True`` if the viewer may close: VIEW mode, or the edits
            were saved or discarded. ``False`` if the user cancelled.
        """
        if not self._edit_mode:
            return True
        reply = QMessageBox.question(
            self,
            translator.translate("common.confirmation_title"),
            translator.translate("viewer.unsaved_changes_warning"),
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
        )
        if reply == QMessageBox.Cancel:
            return False
        if reply == QMessageBox.Save:
            self.save()
        return True

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

        self.edit_btn = self._action_button("viewer.edit", self.enter_edit_mode)
        self.edit_btn.setObjectName("editButton")
        self.edit_btn.setVisible(True)
        toolbar.addWidget(self.edit_btn)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

        self.close_btn = self._action_button("common.close", self.close_requested.emit)
        self.close_btn.setVisible(True)
        toolbar.addWidget(self.close_btn)

        header = QHBoxLayout()
        header.setContentsMargins(8, 8, 8, 8)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.title_edit = QLineEdit()
        self.title_edit.setObjectName("itemTitleEdit")
        self.title_edit.setPlaceholderText(translator.translate("viewer.item_name_placeholder"))
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

        self.add_custom_btn = self._action_button(
            "viewer.add_custom_field_button", self._add_custom_field
        )
        bottom.addWidget(self.add_custom_btn)
        bottom.addStretch()

        self.cancel_btn = self._action_button("common.cancel", self._cancel_changes)
        self.cancel_btn.setObjectName("dangerButton")
        bottom.addWidget(self.cancel_btn)

        self.save_btn = self._action_button("common.save", self.save)
        bottom.addWidget(self.save_btn)
        layout.addLayout(bottom)

    @staticmethod
    def _action_button(text_key: str, slot: Callable[[], None]) -> QPushButton:
        """
        Build a hidden action button of the shared height.

        Parameters
        ----------
        text_key : str
            Translation key of the button text.
        slot : callable
            Called when the button is clicked.

        Returns
        -------
        QPushButton
            The new, hidden button.
        """
        button = QPushButton(translator.translate(text_key))
        button.setFixedHeight(_ACTION_BUTTON_HEIGHT)
        button.setVisible(False)
        button.clicked.connect(slot)
        return button

    # -- Display ------------------------------------------------------------

    def _refresh_display(self) -> None:
        """Rebuild the header and every field row from the item, in the current mode."""
        _clear_layout(self.content_layout)
        self._field_rows.clear()
        credentials = self.manager.get_credentials()

        self.title_edit.setText(self.item.get("item_name") or "")
        self.title_edit.setReadOnly(not self._edit_mode)

        raw_date = self.item.get("item_date")
        self.date_label.setText(
            translator.translate("viewer.last_modified", date=raw_date) if raw_date else ""
        )

        self.icon_preview.set_path(self.item.get("icon"))
        self.icon_preview.set_editable(self._edit_mode)

        for field, label_key, is_secret in _STANDARD_FIELDS:
            self._add_standard_row(field, translator.translate(label_key), is_secret, credentials)
        self._add_custom_rows(credentials)

        self.edit_btn.setEnabled(not self._edit_mode)
        self.add_custom_btn.setVisible(self._edit_mode)
        self.cancel_btn.setVisible(self._edit_mode)
        self.save_btn.setVisible(self._edit_mode)

    def _add_standard_row(
        self,
        field: str,
        label: str,
        is_secret: bool,
        credentials: Credentials,
    ) -> None:
        """
        Append the row of a standard field, if it should be shown.

        Parameters
        ----------
        field : str
            Standard field name.
        label : str
            Translated label of the field.
        is_secret : bool
            Whether the field is encrypted.
        credentials : Credentials
            Credentials decrypting the field, if encrypted.
        """
        try:
            value = self.item.get(field, credentials=credentials if is_secret else None)
        except Exception as exc:
            self._add_error_row(label, exc)
            return

        clear_lines = _to_clear_lines(value)
        if not self._should_show(clear_lines):
            return
        if field == "totps":
            row = TotpFieldRow(field, label)
        else:
            row = FieldRow(
                field,
                label,
                is_list=True,
                is_secret=is_secret,
                is_password=(field == "passwords"),
            )
        self._add_row(field, row, clear_lines)

    def _add_custom_rows(self, credentials: Credentials) -> None:
        """
        Append the custom fields section, if it has rows to show.

        Parameters
        ----------
        credentials : Credentials
            Credentials decrypting the encrypted custom fields.
        """
        custom_names = self.item.custom_fields()
        if not custom_names:
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

        custom_store = self.item.to_dict().get("custom") or {}
        for name in custom_names:
            is_secret = custom_store[name][0] == "ENCRYPTED"
            try:
                value = self.item.get_custom(name, credentials=credentials if is_secret else None)
            except Exception as exc:
                self._add_error_row(name, exc)
                continue

            clear_lines = _to_clear_lines(value)
            if not self._should_show(clear_lines):
                continue
            field_key = f"{_CUSTOM_PREFIX}{name}"
            row = FieldRow(field_key, name, is_secret=is_secret, is_custom=True)
            row.remove_requested.connect(self._remove_custom_field)
            self._add_row(field_key, row, clear_lines)

    def _should_show(self, clear_lines: list[str]) -> bool:
        """
        Tell whether a field gets a row in the current mode.

        Parameters
        ----------
        clear_lines : list of str
            Clear-text value(s) of the field.

        Returns
        -------
        bool
            ``True`` in EDIT mode, or if the field has a value.
        """
        return self._edit_mode or bool(clear_lines)

    def _add_row(self, key: str, row: FieldRow, clear_lines: list[str]) -> None:
        """
        Fill a field row and append it to the field list.

        Parameters
        ----------
        key : str
            Key of the row in :attr:`_field_rows`.
        row : FieldRow
            The row to add.
        clear_lines : list of str
            Clear-text value(s) of the field.
        """
        row.set_value(clear_lines)
        row.set_edit_mode(self._edit_mode)
        self.content_layout.addWidget(row)
        self._field_rows[key] = row

    def _add_error_row(self, label: str, exc: Exception) -> None:
        """
        Append an error message in place of a field that couldn't be read.

        Parameters
        ----------
        label : str
            Label of the field.
        exc : Exception
            The error raised while reading the field.
        """
        error = QLabel(translator.translate("viewer.field_error_row", label=label, error=str(exc)))
        error.setWordWrap(True)
        error.setObjectName("errorLabel")
        self.content_layout.addWidget(error)

    def refresh(self) -> None:
        """
        Rebuild the display, keeping the unsaved edits of EDIT mode.

        Notes
        -----
        Adding or removing a custom field rebuilds every row from the
        item, which would otherwise drop the name and values typed but
        not yet saved.
        """
        if not self._edit_mode:
            self._refresh_display()
            return

        name_snapshot = self.title_edit.text()
        field_snapshot = {field: row.get_edit_values() for field, row in self._field_rows.items()}

        self._refresh_display()

        self.title_edit.setText(name_snapshot)
        for field, values in field_snapshot.items():
            row = self._field_rows.get(field)
            if row is not None:
                row.set_edit_values(values)

    # -- Actions ------------------------------------------------------------

    def enter_edit_mode(self) -> None:
        """Switch to EDIT mode."""
        self._edit_mode = True
        self._refresh_display()

    def _edit_icon(self) -> None:
        """Pick a new icon through :class:`ItemIconDialog` and apply it right away."""
        dialog = ItemIconDialog(self.item.get("icon") or "", parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        new_path = dialog.get_path() or None
        self.item.set("icon", new_path)
        self.icon_preview.set_path(new_path)
        self.item_changed.emit()

    def save(self) -> None:
        """Write the name and the edited field values into the item, then switch to VIEW mode."""
        credentials = self.manager.get_credentials()
        self.item.set("item_name", self.title_edit.text().strip() or None)

        secret_fields = {field for field, _key, is_secret in _STANDARD_FIELDS if is_secret}
        for field, _label_key, _is_secret in _STANDARD_FIELDS:
            row = self._field_rows.get(field)
            if row is None:
                continue
            values = row.get_edit_values()
            if field in secret_fields:
                encrypted = [bytearray(v, "utf-8") for v in values] or None
                self.item.set(field, encrypted, credentials=credentials)
            else:
                self.item.set(field, values or None)

        custom_store = self.item.to_dict().get("custom") or {}
        for name in self.item.custom_fields():
            row = self._field_rows.get(f"{_CUSTOM_PREFIX}{name}")
            if row is None:
                continue
            kind = custom_store[name][0]
            values = row.get_edit_values()
            raw = values[0] if values else ""
            if kind == "ENCRYPTED":
                self.item.set_custom(name, bytearray(raw, "utf-8"), kind, credentials=credentials)
            else:
                self.item.set_custom(name, raw, kind)

        self._edit_mode = False
        self._refresh_display()
        self.item_changed.emit()

    def _cancel_changes(self) -> None:
        """Discard the unsaved edits and switch back to VIEW mode."""
        self._edit_mode = False
        self._refresh_display()

    def _add_custom_field(self) -> None:
        """Create a custom field through :class:`CustomFieldDialog`, applied right away."""
        dialog = CustomFieldDialog(existing_names=self.item.custom_fields(), parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()
        try:
            if data["kind"] == "ENCRYPTED":
                self.item.set_custom(
                    data["name"],
                    bytearray(),
                    data["kind"],
                    credentials=self.manager.get_credentials(),
                )
            else:
                self.item.set_custom(data["name"], "", data["kind"])
        except Exception as exc:
            QMessageBox.critical(
                self,
                translator.translate("common.error_title"),
                translator.translate("viewer.add_field_error", error=str(exc)),
            )
            return

        self.refresh()
        self.item_changed.emit()

    def _remove_custom_field(self, field_key: str) -> None:
        """
        Remove a custom field after confirmation, applied right away.

        Parameters
        ----------
        field_key : str
            Key of the field's row, ``"custom:<name>"``.
        """
        name = field_key.removeprefix(_CUSTOM_PREFIX)
        reply = QMessageBox.question(
            self,
            translator.translate("viewer.remove_field_title"),
            translator.translate("viewer.remove_field_prompt", name=name),
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            self.item.remove_custom(name)
        except Exception as exc:
            QMessageBox.critical(
                self,
                translator.translate("common.error_title"),
                translator.translate("viewer.remove_field_error", error=str(exc)),
            )
            return

        self.refresh()
        self.item_changed.emit()

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
        super().closeEvent(event)