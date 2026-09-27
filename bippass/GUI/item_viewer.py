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

import os
import re
from importlib import resources

from ..core.item import Item
from ..core.manager import PasswordManager
from ..core.credentials import Credentials
from ..core.totp import generate_totp_code

from .translate import translator
from .generator_dialog import GeneratorDialog

from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTextEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QMessageBox,
    QFrame,
    QScrollArea,
    QToolBar,
    QSizePolicy,
    QComboBox,
    QApplication,
    QFileDialog,
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QSize, QUrl
from PyQt5.QtGui import QPixmap, QDesktopServices

#: Loose email/phone/website shape checks, used only to flag a
#: VIEW-mode value that clearly doesn't look like one -- not strict
#: validators.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s.\-()]{5,}$")
#: Optional scheme, a host with at least one dot (or "localhost"),
#: optional port, optional path/query/fragment. Loose on purpose --
#: this only flags values that obviously aren't a website address
#: (e.g. a stray word or an unrelated note), not a strict URL grammar.
_WEBSITE_RE = re.compile(
    r"^(https?://)?"
    r"([\w-]+(\.[\w-]+)+|localhost)"
    r"(:\d+)?"
    r"([/?#].*)?$"
)


def _looks_like_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value.strip()))


def _looks_like_phone(value: str) -> bool:
    return bool(_PHONE_RE.match(value.strip()))


def _looks_like_website(value: str) -> bool:
    return bool(_WEBSITE_RE.match(value.strip()))


# ---------------------------------------------------------------------------
# Icon resolution
# ---------------------------------------------------------------------------


def _icons_directory() -> str:
    """
    Path to the package's bundled ``resources/item_icons`` directory.

    Returns
    -------
    str
        The directory path, or ``""`` if the package's resources
        cannot be located.
    """
    try:
        ref = resources.files("bippass").joinpath("resources/item_icons")
        with resources.as_file(ref) as path:
            return str(path)
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return ""


def _resolve_icon_path(path: str) -> str:
    """
    Resolve a bare icon filename against the bundled icons directory.

    A path that already has a directory component is returned
    unchanged. A path that is only a filename (e.g. ``"github.png"``)
    is looked up inside ``resources/item_icons`` instead of being treated
    as relative to the current working directory.

    Parameters
    ----------
    path : str
        Stored icon path or filename.

    Returns
    -------
    str
        The resolved path, or ``path`` unchanged if it isn't a bare
        filename or the package's resources can't be located.
    """
    head, tail = os.path.split(path)
    if head:
        return path
    try:
        ref = resources.files("bippass").joinpath("resources/item_icons", tail)
        with resources.as_file(ref) as resolved:
            return str(resolved)
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return path


def _valid_icon_pixmap(path: str | None) -> QPixmap | None:
    """
    Load an icon pixmap if, and only if, ``path`` points to an
    existing file that Qt can interpret as a valid image.

    Returns
    -------
    QPixmap or None
        The loaded pixmap, or ``None`` if the path is empty,
        nonexistent, or does not correspond to a readable image.
    """
    if not path:
        return None
    try:
        if not os.path.isfile(path):
            return None
        pixmap = QPixmap(path)
    except OSError:
        # e.g. WinError 59 (unexpected network error) when `path`
        # sits on a network drive/share that hiccups mid-lookup --
        # treated the same as "unreadable", never a crash.
        return None
    if pixmap.isNull():
        return None
    return pixmap


def _default_icon_pixmap() -> QPixmap | None:
    """
    Load the package's bundled fallback icon
    (``bippass/resources/item_icons/_default.png``).

    Uses ``importlib.resources`` rather than a path computed from
    ``__file__``: it goes through the import system's own loader
    instead of manual path arithmetic, so it doesn't care how the
    package is laid out on disk (plain directory, zipped, etc.) and
    doesn't do its own filesystem resolution at import time -- see
    the ``.resolve()`` crash this replaced.

    Returns
    -------
    QPixmap or None
        The bundled icon, or ``None`` if the package's resources are
        missing or unreadable (e.g. removed from the install, or a
        transient network error if the package itself sits on a
        network drive/share).
    """
    try:
        ref = resources.files("bippass").joinpath("resources/item_icons/_default.png")
        with resources.as_file(ref) as path:
            return _valid_icon_pixmap(str(path))
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return None


def _icon_pixmap_or_default(path: str | None) -> QPixmap | None:
    """
    Load the icon at ``path``, falling back to the bundled default
    icon if ``path`` is empty or does not point to a readable image.

    A bare filename (no directory component) is first resolved
    against the bundled ``resources/item_icons`` directory (see
    :func:`_resolve_icon_path`).

    Returns
    -------
    QPixmap or None
        The loaded pixmap for ``path``, the bundled default icon, or
        ``None`` if neither can be read (e.g. the package's own
        resources are missing -- callers should still handle this).
    """
    resolved = _resolve_icon_path(path) if path else path
    pixmap = _valid_icon_pixmap(resolved)
    if pixmap is not None:
        return pixmap
    return _default_icon_pixmap()


# ---------------------------------------------------------------------------
# Basic widgets
# ---------------------------------------------------------------------------
#
# None of the widgets below set their own colors: they're styled by
# the app-wide QSS in `theme.py`, keyed on their Python class name
# (FieldRow, ClickToCopyLabel, WebsiteLabel, IconPreview) or on an
# object name for plain Qt widgets (e.g. "smallButton", "mutedLabel").
# This is what lets a single `apply_theme(app, ...)` call re-style the
# whole item viewer, not just the top-level window.


class ClickToCopyLabel(QLabel):
    """
    Clickable label that copies a value (which may differ from the
    displayed text, e.g. when the latter is masked) to the clipboard
    on click.
    """

    def __init__(self, display_text: str = "", copy_text: str = "", parent=None):
        super().__init__(display_text, parent)
        self._copy_text = copy_text
        # The state this label sits at once the flash feedback below
        # fades -- "" normally, "warning" for a value flagged by
        # `_make_view_widget` as not looking like a valid
        # email/phone/website. Tracked separately from the QSS
        # "state" property itself because `_flash_feedback` briefly
        # overrides that property and must restore *this*, not
        # unconditionally clear it.
        self._base_state = ""
        self.setWordWrap(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)

    def set_copy_text(self, text: str) -> None:
        """Sets the value actually copied on click (never the masked text)."""
        self._copy_text = text

    def set_base_state(self, state: str) -> None:
        """
        Sets the persistent QSS ``state`` (e.g. ``"warning"``), as
        opposed to the transient ``"flash"`` state applied on click --
        see :attr:`_base_state`.
        """
        self._base_state = state
        self.setProperty("state", state)
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self._copy_text:
            QApplication.clipboard().setText(self._copy_text)
            self._flash_feedback()
        super().mousePressEvent(event)

    def _flash_feedback(self) -> None:
        # Briefly switch to the `[state="flash"]` QSS rule (a themed
        # "success" color) instead of hardcoding one here, then
        # restore `_base_state` (not unconditionally clear it --
        # that would wipe out a "warning" state set by
        # `_make_view_widget`) -- `unpolish`/`polish` forces Qt to
        # re-evaluate the QSS for this widget after the dynamic
        # property changes.
        self.setProperty("state", "flash")
        self.style().unpolish(self)
        self.style().polish(self)

        def _clear_flash() -> None:
            self.setProperty("state", self._base_state)
            self.style().unpolish(self)
            self.style().polish(self)

        QTimer.singleShot(350, _clear_flash)


class ActionableLabel(ClickToCopyLabel):
    """
    Base class for a :class:`ClickToCopyLabel` that can also be
    opened with an external application.

    A single click still copies the value, as inherited from
    :class:`ClickToCopyLabel`. A double click asks for confirmation
    and, if accepted, opens the URL built by :meth:`_build_url`.
    Subclasses set :attr:`_open_prompt_key` (a
    ``translate.item_viewer_translation`` key) and implement
    :meth:`_build_url`.
    """

    _open_prompt_key = "open_website_prompt"

    def _build_url(self, value: str) -> str:
        raise NotImplementedError

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton and self._copy_text:
            reply = QMessageBox.question(
                self,
                translator.translate("open_link_title"),
                f"{translator.translate(self._open_prompt_key)}\n\n{self._copy_text}",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                url = self._build_url(self._copy_text)
                if not QDesktopServices.openUrl(QUrl(url)):
                    QMessageBox.warning(
                        self,
                        translator.translate("link_unavailable_title"),
                        translator.translate("link_unavailable_message"),
                    )
            return
        super().mouseDoubleClickEvent(event)


class WebsiteLabel(ActionableLabel):
    """Website value: double click asks to open the link in a browser."""

    _open_prompt_key = "open_website_prompt"

    def _build_url(self, value: str) -> str:
        return value


class EmailLabel(ActionableLabel):
    """Email value: double click asks to open it in the mail application."""

    _open_prompt_key = "open_email_prompt"

    def _build_url(self, value: str) -> str:
        return f"mailto:{value}"


class PhoneLabel(ActionableLabel):
    """Phone value: double click asks to call it with the phone application."""

    _open_prompt_key = "open_phone_prompt"

    def _build_url(self, value: str) -> str:
        return f"tel:{value}"


class FieldRow(QFrame):
    """
    A row representing an item field (standard or custom), handling
    both the VIEW mode display (read-only, copyable, secret masking)
    and EDIT mode editing.

    A list field (``is_list=True``, not custom) is edited as a
    dynamic set of individual value rows in EDIT mode, each with its
    own remove button, plus an "Add value" button to append a new
    one -- values can be added or removed freely, not just those
    already present.

    Parameters
    ----------
    field_name : str
        Internal identifier of the field (standard field name, or
        ``"custom:<name>"`` for a custom field).
    label_text : str
        Label shown to the user.
    is_list : bool, optional
        Field that can hold several values, each individually
        addable/removable in EDIT mode.
    is_secret : bool, optional
        Encrypted field: masked by default in VIEW, with a
        show/hide toggle button.
    is_custom : bool, optional
        Custom field: always edited as a ``QTextEdit`` (multi-line
        notes allowed) and a remove button shown in EDIT mode.
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
        # A custom field is edited as a multi-line QTextEdit (notes);
        # a non-custom list field gets its own per-value rows instead
        # (see `_add_entry_row`); a standard scalar is a QLineEdit.
        self._use_textarea_edit = is_custom
        self._use_list_edit = is_list and not is_custom
        self._entry_edits: list[QLineEdit] = []
        self._view_widgets: list[QWidget] = []
        self._edit_mode_active = False

        self.setFrameShape(QFrame.StyledPanel)
        # Colors/border come from the `FieldRow { ... }` rule in
        # theme.py, matched by this class's name.

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(4)

        header = QHBoxLayout()
        self.label = QLabel(label_text)
        self.label.setObjectName("fieldLabelHeader")
        header.addWidget(self.label)
        header.addStretch()

        self.eye_btn = QPushButton(translator.translate("show"))
        self.eye_btn.setObjectName("smallButton")
        self.eye_btn.setToolTip(translator.translate("show_hide_tooltip"))
        self.eye_btn.setVisible(False)
        self.eye_btn.clicked.connect(self._toggle_mask)
        header.addWidget(self.eye_btn)

        self.remove_btn = QPushButton("✕")
        self.remove_btn.setObjectName("smallButton")
        self.remove_btn.setFixedSize(28, 28)
        self.remove_btn.setToolTip(translator.translate("remove_field_tooltip"))
        self.remove_btn.setVisible(False)
        self.remove_btn.clicked.connect(
            lambda: self.remove_requested.emit(self.field_name)
        )
        header.addWidget(self.remove_btn)

        outer.addLayout(header)

        # One widget per value in VIEW mode, so each value can be
        # copied (or, for a website/email/phone, opened) independently.
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

        # Per-value rows for a (non-custom) list field in EDIT mode.
        self.entries_container = QVBoxLayout()
        self.entries_container.setSpacing(4)
        outer.addLayout(self.entries_container)

        entry_buttons_row = QHBoxLayout()

        self.add_entry_btn = QPushButton(translator.translate("add_value_button"))
        self.add_entry_btn.setObjectName("smallButton")
        self.add_entry_btn.setVisible(False)
        self.add_entry_btn.clicked.connect(lambda: self._add_entry_row(""))
        entry_buttons_row.addWidget(self.add_entry_btn)

        # Only the "passwords" field gets a "Generate" button: it
        # opens `GeneratorDialog` and, if a password is produced, adds
        # it as one more entry row -- same effect as typing it in by
        # hand into a fresh "+ Add value" row.
        self.generate_btn = QPushButton(
            translator.translate("generate_password_button")
        )
        self.generate_btn.setObjectName("smallButton")
        self.generate_btn.setVisible(False)
        self.generate_btn.clicked.connect(self._open_generator)
        entry_buttons_row.addWidget(self.generate_btn)

        entry_buttons_row.addStretch()
        outer.addLayout(entry_buttons_row)

    # -- Value -----------------------------------------------------------

    def set_value(self, clear_lines: list[str]) -> None:
        """
        Sets the clear-text value of the field.

        Parameters
        ----------
        clear_lines : list of str
            A single entry for a scalar field, several for a list
            field. Empty list if the field has no value.
        """
        self._clear_lines = list(clear_lines)
        self._refresh_view()
        self._refresh_edit()

    def get_edit_values(self) -> list[str]:
        """
        Retrieves the value(s) entered in edit mode.

        Returns
        -------
        list of str
            For a list field: one entry per non-empty per-value row.
            For a scalar field (including custom multi-line notes):
            a single-element list.
        """
        if self._use_list_edit:
            return [
                edit.text().strip()
                for edit in self._entry_edits
                if edit.text().strip() != ""
            ]
        raw = (
            self.edit_text.toPlainText()
            if self._use_textarea_edit
            else self.edit_line.text()
        )
        return [raw]

    def set_edit_values(self, values: list[str]) -> None:
        """
        Populate the EDIT-mode widget(s) directly with ``values``,
        without touching :attr:`_clear_lines` (the VIEW-mode data).
 
        Parameters
        ----------
        values : list of str
            Same shape :meth:`get_edit_values` returns: one entry per
            row for a list field, a single-element list otherwise.
 
        Notes
        -----
        Used to restore in-progress, unsaved edits after the row is
        rebuilt for an unrelated reason -- see
        :meth:`ItemViewer._refresh_display_preserving_edits`, which
        this is the counterpart of.
        """
        if self._use_list_edit:
            self._clear_entries()
            for value in values:
                self._add_entry_row(value)
        elif self._use_textarea_edit:
            self.edit_text.blockSignals(True)
            self.edit_text.setPlainText(values[0] if values else "")
            self.edit_text.blockSignals(False)
            self._auto_resize_edit_text()
        else:
            self.edit_line.setText(values[0] if values else "")
            self._apply_edit_mask()

    def is_empty(self) -> bool:
        return len(self._clear_lines) == 0

    # -- Display -----------------------------------------------------------

    def _display_lines(self) -> list[str]:
        if not self._clear_lines:
            return []
        if self.is_secret and self._masked:
            # Fixed length so as not to leak the real length of the secret.
            return ["•" * 12 for _ in self._clear_lines]
        return self._clear_lines

    def _refresh_view(self) -> None:
        self._clear_view_widgets()
        lines = self._display_lines()

        if not lines:
            self.view_container.addWidget(self._make_empty_placeholder())
        else:
            for i, line in enumerate(lines):
                copy_text = self._clear_lines[i] if i < len(self._clear_lines) else line
                widget = self._make_view_widget(line, copy_text)
                self.view_container.addWidget(widget)
                self._view_widgets.append(widget)

        self.eye_btn.setVisible(self.is_secret)
        self.eye_btn.setText(translator.translate("show" if self._masked else "hide"))

    def _clear_view_widgets(self) -> None:
        while self.view_container.count():
            item = self.view_container.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._view_widgets.clear()

    def _make_empty_placeholder(self) -> QWidget:
        placeholder = QLabel(translator.translate("empty_value_placeholder"))
        placeholder.setObjectName("mutedLabel")
        self._view_widgets.append(placeholder)
        return placeholder

    def _make_view_widget(self, display_text: str, copy_text: str) -> QWidget:
        """
        Build the VIEW-mode widget for a single value, one call per
        line so each value can be copied (or opened) independently of
        the others.
        """
        if self.field_name == "websites":
            widget = WebsiteLabel(display_text, copy_text)
        elif self.field_name == "emails":
            widget = EmailLabel(display_text, copy_text)
        elif self.field_name == "phones":
            widget = PhoneLabel(display_text, copy_text)
        else:
            return ClickToCopyLabel(display_text, copy_text)

        if not self._masked and copy_text:
            if self.field_name == "emails":
                is_valid = _looks_like_email(copy_text)
                tooltip_key = "invalid_email_tooltip"
            elif self.field_name == "phones":
                is_valid = _looks_like_phone(copy_text)
                tooltip_key = "invalid_phone_tooltip"
            else:
                is_valid = _looks_like_website(copy_text)
                tooltip_key = "invalid_website_tooltip"
            if not is_valid:
                widget.setText(f"⚠ {display_text}")
                widget.setToolTip(translator.translate(tooltip_key))
                # Themed via the `ClickToCopyLabel[state="warning"]`
                # QSS rule. Uses `set_base_state` (not a raw
                # `setProperty`) so the warning survives a
                # click-to-copy's transient "flash" state -- see
                # `ClickToCopyLabel._flash_feedback`.
                widget.set_base_state("warning")
        return widget

    def _set_view_widgets_visible(self, visible: bool) -> None:
        for widget in self._view_widgets:
            widget.setVisible(visible)

    def _refresh_edit(self) -> None:
        joined = "\n".join(self._clear_lines)
        if self._use_list_edit:
            self._clear_entries()
            for value in self._clear_lines:
                self._add_entry_row(value)
        elif self._use_textarea_edit:
            self.edit_text.blockSignals(True)
            self.edit_text.setPlainText(joined)
            self.edit_text.blockSignals(False)
            self._auto_resize_edit_text()
        else:
            self.edit_line.setText(joined)

    def _toggle_mask(self) -> None:
        self._masked = not self._masked
        self._refresh_view()

    def _auto_resize_edit_text(self) -> None:
        doc = self.edit_text.document()
        doc.setTextWidth(max(self.edit_text.viewport().width(), 50))
        height = int(doc.size().height()) + 12
        self.edit_text.setFixedHeight(max(34, min(height, 220)))

    # -- Per-value rows (list fields) ---------------------------------------

    def _clear_entries(self) -> None:
        while self.entries_container.count():
            item = self.entries_container.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._entry_edits.clear()

    def _add_entry_row(self, text: str = "") -> None:
        """Append one editable value row, with its own remove button."""
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        line_edit = QLineEdit(text)
        row_layout.addWidget(line_edit)

        entry_remove_btn = QPushButton("✕")
        entry_remove_btn.setObjectName("smallButton")
        entry_remove_btn.setFixedSize(28, 28)
        entry_remove_btn.setToolTip(translator.translate("remove_value_tooltip"))
        entry_remove_btn.clicked.connect(lambda: self._remove_entry_row(row_widget))
        row_layout.addWidget(entry_remove_btn)

        row_widget.line_edit = line_edit
        # IMPORTANT: reparent into the layout *before* touching
        # visibility. `row_widget` has no parent yet at this point,
        # so an unparented QWidget is a genuine top-level window --
        # calling setVisible(True) on it first (as this used to do)
        # briefly creates and shows a real OS window before addWidget
        # reparents it into the layout, one flicker per row.
        self.entries_container.addWidget(row_widget)
        row_widget.setVisible(self._edit_mode_active)
        self._entry_edits.append(line_edit)

    def _open_generator(self) -> None:
        """Open :class:`GeneratorDialog` and, if accepted, add the result as a new value row."""
        dialog = GeneratorDialog(parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        self._add_entry_row(dialog.get_password())

    def _remove_entry_row(self, row_widget: QWidget) -> None:
        """Remove a single value row (does not touch the others)."""
        if row_widget.line_edit in self._entry_edits:
            self._entry_edits.remove(row_widget.line_edit)
        self.entries_container.removeWidget(row_widget)
        row_widget.deleteLater()

    # -- Mode --------------------------------------------------------------

    def set_edit_mode(self, editable: bool) -> None:
        """Switches the row between read-only display and editing."""
        self._edit_mode_active = editable
        self._set_view_widgets_visible(not editable)
        self.eye_btn.setVisible((not editable) and self.is_secret)
        self.remove_btn.setVisible(editable and self.is_custom)

        if self._use_list_edit:
            self.edit_line.setVisible(False)
            self.edit_text.setVisible(False)
            for i in range(self.entries_container.count()):
                widget = self.entries_container.itemAt(i).widget()
                if widget is not None:
                    widget.setVisible(editable)
            self.add_entry_btn.setVisible(editable)
            self.generate_btn.setVisible(editable and self.is_password)
        elif self._use_textarea_edit:
            self.edit_line.setVisible(False)
            self.edit_text.setVisible(editable)
            self.add_entry_btn.setVisible(False)
            self.generate_btn.setVisible(False)
            if editable:
                self._auto_resize_edit_text()
        else:
            self.edit_text.setVisible(False)
            self.edit_line.setVisible(editable)
            self.add_entry_btn.setVisible(False)
            self.generate_btn.setVisible(False)


class TotpFieldRow(FieldRow):
    """
    Specialized row for TOTP codes.

    In VIEW mode, shows for each secret the current 6-digit code and
    the time remaining before renewal, recomputed every second. The
    raw secret is never shown in clear text in VIEW mode. In EDIT
    mode, behaves like a regular list of secret fields: the Base32
    secret(s) are shown in clear text and editable, each as its own
    row that can be added or removed.
    """

    def __init__(self, field_name: str, label_text: str, parent=None):
        super().__init__(
            field_name, label_text, is_list=True, is_secret=True, parent=parent
        )
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh_view)
        self._timer.start()

    def _display_lines(self) -> list[str]:
        if not self._clear_lines:
            return []
        lines = []
        for secret in self._clear_lines:
            try:
                code, remaining = generate_totp_code(bytearray(secret, "utf-8"))
                lines.append(f"{code}   ({remaining}s)")
            except ValueError:
                lines.append(translator.translate("invalid_totp_secret"))
        return lines

    def _refresh_view(self) -> None:
        # Only meaningful while the row is actually in VIEW mode;
        # no need to recompute/rebuild otherwise (widgets hidden in
        # EDIT mode).
        if not self._edit_mode_active:
            self._clear_view_widgets()
            lines = self._display_lines()

            if not lines:
                self.view_container.addWidget(self._make_empty_placeholder())
            else:
                for line in lines:
                    # Copy the current *code*, never the raw secret.
                    invalid = translator.translate("invalid_totp_secret")
                    code = line.split()[0] if line != invalid else ""
                    widget = ClickToCopyLabel(line, code)
                    self.view_container.addWidget(widget)
                    self._view_widgets.append(widget)

        self.eye_btn.setVisible(False)

    def set_edit_mode(self, editable: bool) -> None:
        super().set_edit_mode(editable)
        # Never show a mask-toggle button for a TOTP: the raw secret
        # is only ever exposed while editing, never unmasked in
        # read-only mode.
        self.eye_btn.setVisible(False)


class IconPreview(QLabel):
    """
    Preview of the item's icon, shown at the top of the viewer.

    Falls back to the package's bundled default icon
    (``resources/item_icons/_default.png``) when the item has no icon
    path, or the path is unreadable. When made editable (EDIT mode),
    a double click emits :attr:`edit_requested` instead of doing
    nothing.
    """

    edit_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(56, 56)
        self.setScaledContents(True)
        # Border/background come from the `IconPreview { ... }` rule
        # in theme.py, matched by this class's name.
        self.setVisible(False)
        self._editable = False

    def set_path(self, path: str | None) -> None:
        pixmap = _icon_pixmap_or_default(path)
        if pixmap is None:
            # Only reached if even the bundled default icon is missing.
            self.setVisible(False)
            self.clear()
        else:
            self.setPixmap(pixmap)
            self.setVisible(True)

    def set_editable(self, editable: bool) -> None:
        """Enables or disables double-click-to-edit."""
        self._editable = editable
        self.setCursor(Qt.PointingHandCursor if editable else Qt.ArrowCursor)
        self.setToolTip(translator.translate("icon_edit_tooltip") if editable else "")

    def mouseDoubleClickEvent(self, event):
        if self._editable and event.button() == Qt.LeftButton:
            self.edit_requested.emit()
            return
        super().mouseDoubleClickEvent(event)


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------


class IconEditDialog(QDialog):
    """
    Small dialog to change an item's icon, by typing a path directly
    or browsing for a file (defaulting to the bundled
    ``resources/item_icons`` directory).
    """

    def __init__(self, current_path: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("icon_dialog_title"))
        self.setModal(True)

        layout = QVBoxLayout(self)

        row = QHBoxLayout()
        self.path_edit = QLineEdit(current_path or "")
        self.path_edit.setPlaceholderText(translator.translate("icon_path_placeholder"))
        row.addWidget(self.path_edit)

        browse_btn = QPushButton(translator.translate("browse_button"))
        browse_btn.setObjectName("smallButton")
        browse_btn.clicked.connect(self._browse)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            translator.translate("select_icon_dialog_title"),
            _icons_directory(),
            f"{translator.translate('image_files_filter')};;{translator.translate('all_files_filter')}",
        )
        if filename:
            self.path_edit.setText(self._shorten_if_bundled(filename))

    @staticmethod
    def _shorten_if_bundled(filename: str) -> str:
        """
        Reduce ``filename`` to a bare filename (e.g. ``"github.png"``)
        when it sits directly inside the bundled ``resources/item_icons``
        directory -- the folder :meth:`_browse`'s dialog opens in by
        default -- so a selection made there is stored the same way
        as an icon referenced by name elsewhere (see
        :func:`_resolve_icon_path`), rather than as an absolute path
        tied to this particular machine's install location.

        Parameters
        ----------
        filename : str
            The absolute path returned by the file picker.

        Returns
        -------
        str
            ``os.path.basename(filename)`` if it lives directly in
            the bundled icons directory, otherwise ``filename``
            unchanged (e.g. a user-picked icon that lives elsewhere
            on disk keeps its full, absolute path).
        """
        icons_dir = _icons_directory()
        if not icons_dir:
            return filename
        try:
            same_dir = os.path.samefile(os.path.dirname(filename), icons_dir)
        except OSError:
            # e.g. the bundled directory or the selected file's
            # parent doesn't exist / isn't resolvable on this
            # install -- treat as "not the bundled directory".
            same_dir = False
        if same_dir:
            return os.path.basename(filename)
        return filename

    def get_path(self) -> str:
        """Returns the entered path, stripped of leading/trailing spaces."""
        return self.path_edit.text().strip()


class CustomFieldDialog(QDialog):
    """
    Dialog to create a new custom field.

    Only the ``SCALAR`` (clear-text) and ``ENCRYPTED`` (secret) kinds
    are offered: multi-value custom fields are not supported by this
    interface.
    """

    def __init__(self, existing_names: tuple[str, ...] = (), parent=None):
        super().__init__(parent)
        self.setWindowTitle(translator.translate("custom_field_dialog_title"))
        self.setModal(True)
        self._existing_names = existing_names

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText(
            translator.translate("field_name_placeholder")
        )
        form.addRow(translator.translate("name_label"), self.name_edit)

        self.kind_combo = QComboBox()
        self.kind_combo.addItems(["SCALAR", "ENCRYPTED"])
        form.addRow(translator.translate("type_label"), self.kind_combo)

        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(
                self,
                translator.translate("error_title"),
                translator.translate("field_name_required"),
            )
            return
        if name in self._existing_names:
            QMessageBox.warning(
                self,
                translator.translate("error_title"),
                translator.translate("field_already_exists", name=name),
            )
            return
        self.accept()

    def get_data(self) -> dict:
        """Returns ``{'name': str, 'kind': "SCALAR" | "ENCRYPTED"}``."""
        return {
            "name": self.name_edit.text().strip(),
            "kind": self.kind_combo.currentText(),
        }


# ---------------------------------------------------------------------------
# Main widget
# ---------------------------------------------------------------------------

#: Fixed height shared by the bottom-row action buttons, so equivalent
#: buttons (Save, Cancel, + Custom field) always line up.
_ACTION_BUTTON_HEIGHT = 32


class ItemViewer(QWidget):
    """
    Main widget to display and edit an :class:`Item`.

    Two modes:

    - **VIEW** (read-only): only non-empty fields are shown, every
      value is copyable on click, secrets are masked by default (a
      "Show" button reveals them), TOTP codes are shown in clear text
      along with their countdown timer. Websites, emails and phone
      numbers can also be opened with a double click.
    - **EDIT**: all fields are shown (including ``None`` ones,
      displayed empty), all values are in clear text and editable.
      List fields (logins, passwords, phones, emails, websites,
      TOTP secrets) can have individual values added or removed, not
      just those already present. Custom fields can be added or
      removed too. A "Save" button pushes the changes to the
      :class:`Item`.

    The item's name is shown as a title above the field list, next to
    its icon; both stay editable while in EDIT mode. The icon itself
    is changed through a double click (see :class:`IconEditDialog`)
    rather than through a field row.
    """

    def __init__(self, manager: "PasswordManager", item: "Item", parent=None):
        super().__init__(parent)
        self.manager = manager
        self.item = item
        self._edit_mode = False
        self._field_rows: dict[str, FieldRow] = {}

        self._init_ui()
        self._refresh_display()

    # -- UI construction ---------------------------------------------------

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        layout.addWidget(toolbar)

        self.edit_btn = QPushButton(translator.translate("edit_button"))
        self.edit_btn.clicked.connect(self._enter_edit_mode)
        # `QToolBar.addWidget` wraps the widget in an internal
        # `QWidgetAction`: the toolbar's layout consults *that
        # action's* visibility to decide whether to show/collapse the
        # slot, not the widget's own `isVisible()`. Toggling only
        # `self.edit_btn.setVisible(...)` (as for `cancel_btn`/
        # `save_btn`, which sit in a plain QHBoxLayout and don't have
        # this problem) can therefore leave the button visibly stuck
        # in the toolbar even after being hidden -- toggling the
        # returned action instead (see `_refresh_display`) is what
        # actually makes the toolbar hide/reclaim its slot.
        self.edit_btn_action = toolbar.addWidget(self.edit_btn)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

        header = QHBoxLayout()
        header.setContentsMargins(8, 8, 8, 8)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        self.title_edit = QLineEdit()
        self.title_edit.setObjectName("itemTitleEdit")
        self.title_edit.setPlaceholderText(
            translator.translate("item_name_placeholder")
        )
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
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setAlignment(Qt.AlignTop)
        self.content_layout.setSpacing(6)
        scroll.setWidget(self.content_widget)
        layout.addWidget(scroll, stretch=1)

        bottom = QHBoxLayout()
        bottom.setContentsMargins(8, 6, 8, 6)
        bottom.setSpacing(8)

        self.add_custom_btn = QPushButton(
            translator.translate("add_custom_field_button")
        )
        self.add_custom_btn.setFixedHeight(_ACTION_BUTTON_HEIGHT)
        self.add_custom_btn.setVisible(False)
        self.add_custom_btn.clicked.connect(self._add_custom_field)
        bottom.addWidget(self.add_custom_btn)

        bottom.addStretch()

        self.cancel_btn = QPushButton(translator.translate("cancel_button"))
        self.cancel_btn.setObjectName("dangerButton")
        self.cancel_btn.setFixedHeight(_ACTION_BUTTON_HEIGHT)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel_changes)
        bottom.addWidget(self.cancel_btn)

        self.save_btn = QPushButton(translator.translate("save_button"))
        self.save_btn.setFixedHeight(_ACTION_BUTTON_HEIGHT)
        self.save_btn.setVisible(False)
        self.save_btn.clicked.connect(self._save_changes)
        bottom.addWidget(self.save_btn)

        layout.addLayout(bottom)

    # -- Data ----------------------------------------------------------------

    def _get_credentials(self) -> Credentials:
        # `Item.get`/`Item.set` take the whole `Credentials` instance
        # rather than a separate password/iterations pair -- this is
        # exactly the shared object the manager itself encrypts and
        # decrypts with (see `PasswordManager.get_credentials`).
        return self.manager.get_credentials()

    @staticmethod
    def _to_clear_lines(value, is_secret: bool) -> list[str]:
        """
        Normalizes a value returned by :class:`Item` (scalar, list,
        ``str`` or ``bytearray``) into a list of clear-text strings.
        """
        if value is None:
            return []
        items = value if isinstance(value, list) else [value]
        lines: list[str] = []
        for v in items:
            if isinstance(v, (bytes, bytearray)):
                lines.append(bytes(v).decode("utf-8"))
            else:
                lines.append(str(v))
        return lines

    def _add_error_row(self, label: str, exc: Exception) -> None:
        err = QLabel(translator.translate("field_error_row", label=label, error=exc))
        err.setWordWrap(True)
        err.setObjectName("errorLabel")
        self.content_layout.addWidget(err)

    def _clear_content(self) -> None:
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._field_rows.clear()

    # -- Display ---------------------------------------------------------------

    def _add_standard_row(
        self,
        field: str,
        label: str,
        *,
        is_list: bool,
        is_secret: bool,
        credentials: Credentials,
    ) -> None:
        """Build and append one standard :class:`FieldRow`, if it should be shown."""
        try:
            value = self.item.get(field, credentials=credentials if is_secret else None)
        except Exception as exc:
            self._add_error_row(label, exc)
            return

        clear_lines = self._to_clear_lines(value, is_secret)
        if not self._edit_mode and not clear_lines:
            return

        row = FieldRow(
            field,
            label,
            is_list=is_list,
            is_secret=is_secret,
            is_password=(field == "passwords"),
        )
        row.set_value(clear_lines)
        row.set_edit_mode(self._edit_mode)
        self.content_layout.addWidget(row)
        self._field_rows[field] = row

    def _add_totp_row(self, credentials: Credentials) -> None:
        """Build and append the :class:`TotpFieldRow`, if it should be shown."""
        label = translator.translate("field_totps")
        try:
            totp_value = self.item.get("totps", credentials=credentials)
        except Exception as exc:
            self._add_error_row(label, exc)
            totp_value = None

        clear_totps = self._to_clear_lines(totp_value, True)
        if not self._edit_mode and not clear_totps:
            return

        row = TotpFieldRow("totps", label)
        row.set_value(clear_totps)
        row.set_edit_mode(self._edit_mode)
        self.content_layout.addWidget(row)
        self._field_rows["totps"] = row

    def _refresh_display(self) -> None:
        self._clear_content()
        credentials = self._get_credentials()

        self.title_edit.setText(self.item.get("item_name") or "")
        self.title_edit.setReadOnly(not self._edit_mode)

        raw_date = self.item.get("item_date")
        self.date_label.setText(
            translator.translate("last_modified", date=raw_date) if raw_date else ""
        )

        self.icon_preview.set_path(self.item.get("icon"))
        self.icon_preview.set_editable(self._edit_mode)

        self._add_standard_row(
            "logins",
            translator.translate("field_logins"),
            is_list=True,
            is_secret=False,
            credentials=credentials,
        )
        self._add_standard_row(
            "passwords",
            translator.translate("field_passwords"),
            is_list=True,
            is_secret=True,
            credentials=credentials,
        )
        self._add_totp_row(credentials)
        self._add_standard_row(
            "websites",
            translator.translate("field_websites"),
            is_list=True,
            is_secret=False,
            credentials=credentials,
        )
        self._add_standard_row(
            "emails",
            translator.translate("field_emails"),
            is_list=True,
            is_secret=False,
            credentials=credentials,
        )
        self._add_standard_row(
            "phones",
            translator.translate("field_phones"),
            is_list=True,
            is_secret=False,
            credentials=credentials,
        )

        custom_names = self.item.custom_fields()
        if custom_names or self._edit_mode:
            if custom_names:
                separator = QFrame()
                separator.setFrameShape(QFrame.HLine)
                separator.setFrameShadow(QFrame.Sunken)
                self.content_layout.addWidget(separator)

                title = QLabel(translator.translate("custom_fields_section"))
                # Reuses the same "sectionTitle" QSS rule as e.g. the
                # "Vaults" title in `manager_gui.py`, rather than an
                # explicit `setFont(...)`: an explicitly-set font
                # detaches a widget from the application's font, so it
                # would stop following the interface zoom the moment
                # `_apply_zoom` next changes it -- staying on the
                # inherited/QSS-driven font (whose `theme.py` rule is
                # itself kept in step with the zoom's `text_scale`) is
                # what keeps this title in sync going forward, not
                # just at the instant it was created.
                title.setObjectName("sectionTitle")
                title.setContentsMargins(0, 6, 0, 6)
                self.content_layout.addWidget(title)

            custom_store = self.item.to_dict().get("custom") or {}
            for name in custom_names:
                kindstr = custom_store[name][0]
                is_secret = kindstr == "ENCRYPTED"
                try:
                    value = self.item.get_custom(
                        name,
                        credentials=credentials if is_secret else None,
                    )
                except Exception as exc:
                    self._add_error_row(name, exc)
                    continue

                clear_lines = self._to_clear_lines(value, is_secret)
                if not self._edit_mode and not clear_lines:
                    continue

                field_key = f"custom:{name}"
                row = FieldRow(
                    field_key, name, is_list=False, is_secret=is_secret, is_custom=True
                )
                row.set_value(clear_lines)
                row.set_edit_mode(self._edit_mode)
                row.remove_requested.connect(self._remove_custom_field)
                self.content_layout.addWidget(row)
                self._field_rows[field_key] = row

        self.edit_btn_action.setVisible(not self._edit_mode)
        self.add_custom_btn.setVisible(self._edit_mode)
        self.cancel_btn.setVisible(self._edit_mode)
        self.save_btn.setVisible(self._edit_mode)

    def _refresh_display_preserving_edits(self) -> None:
        """
        Like :meth:`_refresh_display`, but preserves whatever is
        currently sitting -- typed but not yet saved -- in the item
        name box and every field's EDIT-mode widgets, across the
        rebuild.
 
        Notes
        -----
        Adding or removing a custom field (see :meth:`_add_custom_field`/
        :meth:`_remove_custom_field`) applies right away and is
        followed by a full :meth:`_refresh_display`, which rebuilds
        every row from the underlying :class:`Item` -- including the
        standard fields and the name, whose in-progress edits would
        otherwise be silently discarded even though the viewer stays
        in EDIT mode the whole time. A no-op (falls back to a plain
        :meth:`_refresh_display`) outside EDIT mode, where there is
        nothing unsaved to preserve.
        """
        if not self._edit_mode:
            self._refresh_display()
            return
 
        name_snapshot = self.title_edit.text()
        field_snapshot = {
            field: row.get_edit_values() for field, row in self._field_rows.items()
        }
 
        self._refresh_display()
 
        self.title_edit.setText(name_snapshot)
        for field, values in field_snapshot.items():
            row = self._field_rows.get(field)
            if row is not None:
                row.set_edit_values(values)

    # -- VIEW / EDIT mode --------------------------------------------------

    def _enter_edit_mode(self) -> None:
        self._edit_mode = True
        self._refresh_display()

    # -- Icon ----------------------------------------------------------------

    def _edit_icon(self) -> None:
        """
        Open :class:`IconEditDialog` and, if accepted, apply the new
        icon path right away.

        Unlike the other fields, the icon is not deferred to Save:
        this mirrors custom field add/remove (see
        :meth:`_cancel_changes`).
        """
        current = self.item.get("icon") or ""
        dialog = IconEditDialog(current, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        new_path = dialog.get_path() or None
        self.item.set("icon", new_path)
        self.icon_preview.set_path(new_path)

    # -- Saving --------------------------------------------------------------

    def _save_changes(self) -> None:
        credentials = self._get_credentials()

        name = self.title_edit.text().strip()
        self.item.set("item_name", name or None)

        for field, row in list(self._field_rows.items()):
            if field.startswith("custom:"):
                continue
            values = row.get_edit_values()

            if field in ("logins", "websites", "phones", "emails"):
                # SCALAR_LIST fields in item.py's `_FIELDS` (and
                # `types.py`'s `ItemData`): stored as clear strings,
                # no credentials involved.
                self.item.set(field, values if values else None)
            else:
                # Only "passwords" and "totps" are ENCRYPTED_LIST in
                # item.py's `_FIELDS`, and need bytearray values +
                # credentials.
                crypted = [bytearray(v, "utf-8") for v in values if v] or None
                self.item.set(field, crypted, credentials=credentials)

        custom_store = self.item.to_dict().get("custom") or {}
        for name in list(self.item.custom_fields()):
            row = self._field_rows.get(f"custom:{name}")
            if row is None:
                continue
            kindstr = custom_store[name][0]
            values = row.get_edit_values()
            raw = values[0] if values else ""
            if kindstr == "ENCRYPTED":
                self.item.set_custom(
                    name,
                    bytearray(raw, "utf-8"),
                    kindstr,
                    credentials=credentials,
                )
            else:
                self.item.set_custom(name, raw, kindstr)

        self._edit_mode = False
        self._refresh_display()

    def _cancel_changes(self) -> None:
        """
        Discard in-progress edits and switch back to VIEW mode,
        without touching the underlying :class:`Item`.

        Note
        ----
        Custom fields added or removed via the "+ Custom field" button
        and its per-field remove button, and the icon changed through
        :meth:`_edit_icon`, are applied to the item right away (not
        deferred to Save), so Cancel does not undo those -- only the
        name and field-row value edits.
        """
        self._edit_mode = False
        self._refresh_display()

    # -- Custom fields ---------------------------------------------------------

    def _add_custom_field(self) -> None:
        dialog = CustomFieldDialog(
            existing_names=self.item.custom_fields(), parent=self
        )
        if dialog.exec_() != QDialog.Accepted:
            return

        data = dialog.get_data()
        credentials = self._get_credentials()

        try:
            if data["kind"] == "ENCRYPTED":
                self.item.set_custom(
                    data["name"],
                    bytearray("", "utf-8"),
                    data["kind"],
                    credentials=credentials,
                )
            else:
                self.item.set_custom(data["name"], "", data["kind"])
        except Exception as exc:
            QMessageBox.critical(
                self,
                translator.translate("error_title"),
                translator.translate("add_field_error", error=exc),
            )
            return

        self._refresh_display_preserving_edits()

    def _remove_custom_field(self, field_key: str) -> None:
        name = (
            field_key.split(":", 1)[1] if field_key.startswith("custom:") else field_key
        )
        reply = QMessageBox.question(
            self,
            translator.translate("remove_field_title"),
            translator.translate("remove_field_prompt", name=name),
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            self.item.remove_custom(name)
        except Exception as exc:
            QMessageBox.critical(
                self,
                translator.translate("error_title"),
                translator.translate("remove_field_error", error=exc),
            )
            return

        self._refresh_display_preserving_edits()

    # -- Closing -----------------------------------------------------------

    def closeEvent(self, event) -> None:
        if self._edit_mode:
            reply = QMessageBox.question(
                self,
                translator.translate("confirmation_title"),
                translator.translate("unsaved_changes_warning"),
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
            )
            if reply == QMessageBox.Save:
                self._save_changes()
            elif reply == QMessageBox.Cancel:
                event.ignore()
                return
        super().closeEvent(event)