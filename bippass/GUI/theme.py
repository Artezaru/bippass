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

import json
from pathlib import Path

from PyQt5.QtWidgets import QApplication

from .common import _gui_icon_path


LIGHT = "light"
DARK = "dark"
THEMES = (LIGHT, DARK)
DEFAULT_THEME = DARK

# Remembers the theme between runs, for the unlock wizard shown before
# any manager (and its own theme setting) is decrypted.
_SETTINGS_FILE_PATH = Path.home() / ".bippass" / "settings.json"

_PALETTES: dict[str, dict[str, str]] = {
    LIGHT: {
        "bg": "#F4F5F7",
        "bg_alt": "#FFFFFF",
        "panel_bg": "#FFFFFF",
        "border": "#E4E7EC",
        "border_strong": "#CDD2DA",
        "text": "#1F2937",
        "text_muted": "#6B7280",
        "disabled": "#A3AAB5",
        "hover": "#F2F4F7",
        "pressed": "#E8EBF0",
        "accent": "#4F46E5",
        "accent_hover": "#4338CA",
        "accent_pressed": "#3730A3",
        "accent_soft": "#EEF2FF",
        "accent_disabled": "#A5B4FC",
        "accent_text": "#FFFFFF",
        "input_bg": "#FFFFFF",
        "field_bg": "#FFFFFF",
        "value_bg": "#F9FAFB",
        "error_bg": "#FEF2F2",
        "error_text": "#DC2626",
        "warning_bg": "#FFFBEB",
        "warning_border": "#F59E0B",
        "success_bg": "#DCFCE7",
        "danger": "#DC2626",
        "danger_hover": "#B91C1C",
        "danger_text": "#FFFFFF",
        "unsaved": "#F59E0B",
        "unsaved_hover": "#D97706",
        "unsaved_text": "#1F2937",
        "scroll": "#CDD2DA",
    },
    DARK: {
        "bg": "#0F1115",
        "bg_alt": "#181B21",
        "panel_bg": "#181B21",
        "border": "#2A2F38",
        "border_strong": "#3A404B",
        "text": "#E6E8EC",
        "text_muted": "#9AA3AF",
        "disabled": "#5B6270",
        "hover": "#222630",
        "pressed": "#2A2F3A",
        "accent": "#6366F1",
        "accent_hover": "#7C7FF5",
        "accent_pressed": "#5558E3",
        "accent_soft": "#23264A",
        "accent_disabled": "#3B3E73",
        "accent_text": "#FFFFFF",
        "input_bg": "#12151A",
        "field_bg": "#181B21",
        "value_bg": "#1D2128",
        "error_bg": "#2A1618",
        "error_text": "#F87171",
        "warning_bg": "#2E2715",
        "warning_border": "#F59E0B",
        "success_bg": "#14301F",
        "danger": "#EF4444",
        "danger_hover": "#DC2626",
        "danger_text": "#FFFFFF",
        "unsaved": "#F59E0B",
        "unsaved_hover": "#D97706",
        "unsaved_text": "#111827",
        "scroll": "#3A404B",
    },
}


def _valid_theme(theme: str | None) -> str:
    """
    Return a theme name, falling back to the default for unknown ones.

    Parameters
    ----------
    theme : str or None
        Theme name to check.

    Returns
    -------
    str
        ``theme`` if it is one of :data:`THEMES`, :data:`DEFAULT_THEME`
        otherwise.
    """
    return theme if theme in THEMES else DEFAULT_THEME


def _arrow_rule(theme: str) -> str:
    """
    Build the QSS rule drawing the themed combo box arrow.

    Parameters
    ----------
    theme : str
        Theme name.

    Returns
    -------
    str
        The rule, or ``""`` if the arrow image is missing, leaving Qt's
        default arrow.

    Notes
    -----
    QSS ``url()`` needs a file on disk and forward slashes, even on
    Windows, hence ``as_posix()``.
    """
    path = _gui_icon_path(f"arrow_down_{theme}.svg")
    if path is None:
        return ""
    return f"""
        QComboBox::down-arrow {{
            image: url({Path(path).as_posix()});
            width: 10px;
            height: 6px;
            margin-right: 6px;
        }}
        QComboBox::down-arrow:on {{
            top: 1px;
        }}
    """


def stylesheet(theme: str, text_scale: float = 1.0) -> str:
    """
    Build the application's QSS for a theme.

    Covers the generic Qt widgets and the item viewer's own widgets
    (``FieldRow``, ``ClickToCopyLabel``, ``IconPreview``), matched by
    class name; subclasses such as ``TotpFieldRow`` or ``WebsiteLabel``
    inherit their base class's rules.

    Parameters
    ----------
    theme : str
        ``"light"`` or ``"dark"``; any other value gives the default.
    text_scale : float, optional
        Interface zoom, applied to the few ``font-size`` values fixed
        in ``px`` below, which would otherwise override the zoomed
        application font. Default is ``1.0``.

    Returns
    -------
    str
        The complete stylesheet.
    """
    theme = _valid_theme(theme)
    c = _PALETTES[theme]

    def px(base: float) -> int:
        return max(1, round(base * text_scale))

    return f"""
        QMainWindow, QWidget, QDialog, QWizard {{
            background-color: {c['bg']};
            color: {c['text']};
        }}

        /* --- Group boxes ---------------------------------------------- */
        QGroupBox {{
            border: 1px solid {c['border']};
            border-radius: 12px;
            margin-top: 14px;
            padding-top: 12px;
            color: {c['text_muted']};
            font-weight: bold;
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 4px;
        }}

        /* --- Inputs --------------------------------------------------- */
        QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox {{
            background-color: {c['input_bg']};
            border: 1px solid {c['border']};
            border-radius: 8px;
            padding: 6px 8px;
            color: {c['text']};
            selection-background-color: {c['accent']};
            selection-color: {c['accent_text']};
        }}
        QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover,
        QComboBox:hover, QSpinBox:hover {{
            border-color: {c['border_strong']};
        }}
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
        QComboBox:focus, QSpinBox:focus {{
            border-color: {c['accent']};
        }}
        QLineEdit:disabled, QComboBox:disabled {{
            color: {c['disabled']};
        }}

        /* --- Combo boxes ---------------------------------------------- */
        QComboBox {{
            padding-right: 28px;
            min-height: 20px;
        }}
        QComboBox:on {{
            border-color: {c['accent']};
        }}
        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: center right;
            border: none;
            width: 28px;
        }}
        {_arrow_rule(theme)}
        QComboBox QAbstractItemView {{
            background-color: {c['panel_bg']};
            color: {c['text']};
            border: 1px solid {c['border']};
            border-radius: 8px;
            padding: 4px;
            outline: 0;
            selection-background-color: {c['accent_soft']};
            selection-color: {c['accent']};
        }}
        QComboBox QAbstractItemView::item {{
            min-height: 24px;
            padding: 4px 8px;
            border-radius: 6px;
        }}
        QComboBox QAbstractItemView::item:hover {{
            background-color: {c['hover']};
        }}
        QComboBox QAbstractItemView::item:selected {{
            background-color: {c['accent_soft']};
            color: {c['accent']};
        }}

        /* --- Buttons -------------------------------------------------- */
        QPushButton {{
            background-color: {c['accent']};
            color: {c['accent_text']};
            border: 1px solid {c['accent']};
            border-radius: 8px;
            padding: 7px 14px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background-color: {c['accent_hover']};
            border-color: {c['accent_hover']};
        }}
        QPushButton:pressed {{
            background-color: {c['accent_pressed']};
            border-color: {c['accent_pressed']};
        }}
        QPushButton:disabled {{
            background-color: {c['accent_disabled']};
            border-color: {c['accent_disabled']};
            color: {c['text_muted']};
        }}
        QPushButton#smallButton {{
            padding: 2px;
        }}
        QPushButton#dangerButton {{
            background-color: {c['danger']};
            border-color: {c['danger']};
            color: {c['danger_text']};
        }}
        QPushButton#dangerButton:hover {{
            background-color: {c['danger_hover']};
            border-color: {c['danger_hover']};
        }}
        QPushButton#saveButton[dirty="true"] {{
            background-color: {c['unsaved']};
            border-color: {c['unsaved']};
            color: {c['unsaved_text']};
        }}
        QPushButton#saveButton[dirty="true"]:hover {{
            background-color: {c['unsaved_hover']};
            border-color: {c['unsaved_hover']};
        }}
        QPushButton#editButton:disabled {{
            background-color: {c['pressed']};
            border-color: {c['border']};
            color: {c['disabled']};
        }}
        QToolButton {{
            background: transparent;
            border: none;
            border-radius: 8px;
            padding: 6px 10px;
            color: {c['text_muted']};
        }}
        QToolButton:hover {{
            background-color: {c['hover']};
            color: {c['text']};
        }}
        QToolButton:pressed {{
            background-color: {c['pressed']};
        }}
        QToolButton:checked {{
            color: {c['accent']};
        }}

        /* --- Lists ---------------------------------------------------- */
        QListWidget {{
            background-color: {c['bg_alt']};
            border: 1px solid {c['border']};
            border-radius: 12px;
            padding: 4px;
            color: {c['text']};
            outline: 0;
        }}
        QListWidget::item {{
            padding: 6px 8px;
            border-radius: 8px;
        }}
        QListWidget::item:hover {{
            background-color: {c['hover']};
        }}
        QListWidget::item:selected {{
            background-color: {c['accent_soft']};
            color: {c['accent']};
        }}

        /* --- Containers ----------------------------------------------- */
        QScrollArea {{
            background-color: transparent;
            border: 1px solid {c['border']};
            border-radius: 12px;
        }}
        QToolBar {{
            background-color: {c['bg_alt']};
            border: none;
            border-bottom: 1px solid {c['border']};
            spacing: 4px;
            padding: 4px;
        }}
        QMenu {{
            background-color: {c['panel_bg']};
            color: {c['text']};
            border: 1px solid {c['border']};
            border-radius: 8px;
            padding: 4px;
        }}
        QMenu::item {{
            padding: 6px 14px;
            border-radius: 6px;
        }}
        QMenu::item:selected {{
            background-color: {c['accent_soft']};
            color: {c['accent']};
        }}
        QToolTip {{
            background-color: {c['panel_bg']};
            color: {c['text']};
            border: 1px solid {c['border']};
            border-radius: 6px;
            padding: 4px 8px;
        }}

        /* --- Scrollbars ----------------------------------------------- */
        QScrollBar:vertical {{
            background: transparent;
            width: 10px;
            margin: 2px;
        }}
        QScrollBar::handle:vertical {{
            background: {c['scroll']};
            border-radius: 3px;
            min-height: 32px;
        }}
        QScrollBar:horizontal {{
            background: transparent;
            height: 10px;
            margin: 2px;
        }}
        QScrollBar::handle:horizontal {{
            background: {c['scroll']};
            border-radius: 3px;
            min-width: 32px;
        }}
        QScrollBar::add-line, QScrollBar::sub-line {{
            width: 0;
            height: 0;
        }}
        QScrollBar::add-page, QScrollBar::sub-page {{
            background: none;
        }}

        /* --- Labels --------------------------------------------------- */
        QLabel {{
            color: {c['text']};
            background: transparent;
        }}
        QLabel#sectionTitle {{
            font-size: {px(16)}px;
            font-weight: 600;
        }}
        QLabel#fieldLabelHeader {{
            font-weight: 600;
            color: {c['text_muted']};
            border: none;
            background: transparent;
        }}
        QLabel#mutedLabel {{
            color: {c['text_muted']};
            font-size: {px(11)}px;
        }}
        QLabel#errorLabel {{
            color: {c['error_text']};
            background-color: {c['error_bg']};
            padding: 8px 10px;
            border-radius: 8px;
        }}
        QLineEdit#itemTitleEdit {{
            background: transparent;
            border: none;
            border-bottom: 1px solid transparent;
            border-radius: 0;
            font-size: {px(18)}px;
            font-weight: 600;
            padding: 4px 2px;
        }}
        QLineEdit#itemTitleEdit:focus {{
            border-bottom: 1px solid {c['accent']};
        }}

        /* --- Item viewer ---------------------------------------------- */
        FieldRow {{
            background-color: {c['field_bg']};
            border: 1px solid {c['border']};
            border-radius: 10px;
            margin: 2px;
        }}
        ClickToCopyLabel {{
            padding: 6px 8px;
            background-color: {c['value_bg']};
            border: 1px solid transparent;
            border-radius: 8px;
            color: {c['text']};
        }}
        ClickToCopyLabel:hover {{
            border-color: {c['border_strong']};
        }}
        ClickToCopyLabel[state="flash"] {{
            background-color: {c['success_bg']};
        }}
        ClickToCopyLabel[state="warning"] {{
            background-color: {c['warning_bg']};
            border: 1px solid {c['warning_border']};
        }}
        IconPreview {{
            border: 1px solid {c['border']};
            border-radius: 10px;
            background-color: {c['bg_alt']};
        }}
    """


def apply_theme(app: QApplication, theme: str, text_scale: float = 1.0) -> None:
    """
    Apply a theme to the whole application.

    Can be called again at any time (theme toggle, zoom): Qt
    re-polishes every widget.

    Parameters
    ----------
    app : QApplication
        The application.
    theme : str
        ``"light"`` or ``"dark"``.
    text_scale : float, optional
        Current interface zoom, see :func:`stylesheet`. Default is
        ``1.0``.
    """
    app.setStyleSheet(stylesheet(theme, text_scale))


def _read_settings() -> dict:
    """
    Read the settings file.

    Returns
    -------
    dict
        The stored settings, empty if the file is missing, unreadable
        or not a JSON object.
    """
    try:
        settings = json.loads(_SETTINGS_FILE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return settings if isinstance(settings, dict) else {}


def load_theme() -> str:
    """
    Return the last theme chosen.

    Returns
    -------
    str
        The stored theme, or :data:`DEFAULT_THEME` if none is stored
        or it isn't valid.
    """
    return _valid_theme(_read_settings().get("theme"))


def save_theme(theme: str) -> None:
    """
    Remember a theme for the next run, keeping the other settings.

    Parameters
    ----------
    theme : str
        ``"light"`` or ``"dark"``.

    Notes
    -----
    Best effort: a write failure (e.g. read-only home folder) is
    ignored, the theme just isn't remembered.
    """
    settings = _read_settings()
    settings["theme"] = _valid_theme(theme)
    try:
        _SETTINGS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _SETTINGS_FILE_PATH.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    except OSError:
        pass