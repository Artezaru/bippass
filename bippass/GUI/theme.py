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

#: Where the chosen theme is remembered between runs.
_SETTINGS_FILE_PATH = Path.home() / ".password_manager" / "settings.json"

#: Theme used the first time the app runs, or if the setting can't be read.
DEFAULT_THEME = "dark"


def _palette(theme: str) -> dict[str, str]:
    """Named colors for ``theme`` ("light" or "dark"), consumed by :func:`stylesheet`."""
    if theme == "light":
        return {
            "bg": "#f5f5f7",
            "bg_alt": "#ffffff",
            "panel_bg": "#ffffff",
            "border": "#d0d0d5",
            "text": "#1e1e2e",
            "text_muted": "#6b6b76",
            "accent": "#6d4aff",
            "accent_hover": "#5a40d4",
            "accent_text": "#ffffff",
            "input_bg": "#f0f0f3",
            "field_bg": "#ffffff",
            "value_bg": "#f5f5f5",
            "error_bg": "#fdecea",
            "error_text": "#b00020",
            "warning_bg": "#fff3cd",
            "warning_border": "#e0a800",
            "success_bg": "#d8ffd8",
            "danger": "#e5484d",
            "danger_hover": "#c53030",
            "danger_text": "#ffffff",
            "unsaved": "#e0a800",
            "unsaved_hover": "#c48f00",
            "unsaved_text": "#1e1e2e",
        }
    # dark (default)
    return {
        "bg": "#1e1e2e",
        "bg_alt": "#181825",
        "panel_bg": "#24243a",
        "border": "#45475a",
        "text": "#cdd6f4",
        "text_muted": "#8a8fa3",
        "accent": "#89b4fa",
        "accent_hover": "#74c7ec",
        "accent_text": "#1e1e2e",
        "input_bg": "#313244",
        "field_bg": "#2a2a40",
        "value_bg": "#2f2f47",
        "error_bg": "#3a1f22",
        "error_text": "#f38ba8",
        "warning_bg": "#3a3320",
        "warning_border": "#e0a800",
        "success_bg": "#1f3a26",
        "danger": "#f38ba8",
        "danger_hover": "#eb6f92",
        "danger_text": "#1e1e2e",
        "unsaved": "#f9c74f",
        "unsaved_hover": "#f4b942",
        "unsaved_text": "#1e1e2e",
    }


def stylesheet(theme: str, text_scale: float = 1.0) -> str:
    """
    Build the full application QSS for ``theme`` ("light" or "dark").

    Covers both the generic Qt widgets used by the wizard/main window
    (``QMainWindow``, ``QGroupBox``, ``QLineEdit``, ``QPushButton``,
    ``QListWidget``, ...) and the item viewer's own widgets
    (``FieldRow``, ``ClickToCopyLabel``, ``WebsiteLabel``,
    ``IconPreview``), matched by Python class name -- Qt style sheets
    resolve class selectors through the whole inheritance chain, so
    e.g. ``WebsiteLabel`` (a ``ClickToCopyLabel`` subclass) and
    ``TotpFieldRow`` (a ``FieldRow`` subclass) pick up their base
    class's rules automatically.

    Parameters
    ----------
    text_scale : float, optional
        Multiplier applied to the few ``font-size`` values hardcoded
        below in ``px`` (default 1.0, i.e. unscaled). Every other
        widget's text follows the application's own font instead, so
        changing that font (see
        ``PasswordManagerWindow._apply_zoom``) already scales it --
        these ``px`` rules are the only text sizes that would
        otherwise stay fixed and ignore the interface zoom, since an
        explicit QSS ``font-size`` always overrides the inherited
        widget font.
    """
    c = _palette(theme)

    def _px(base: float) -> int:
        return max(1, round(base * text_scale))

    return f"""
        QMainWindow, QWidget {{
            background-color: {c['bg']};
            color: {c['text']};
        }}
        QDialog, QWizard {{
            background-color: {c['bg']};
            color: {c['text']};
        }}
        QGroupBox {{
            border: 1px solid {c['border']};
            border-radius: 6px;
            margin-top: 12px;
            padding-top: 10px;
            color: {c['text']};
            font-weight: bold;
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
        }}
        QLineEdit, QTextEdit, QComboBox {{
            background-color: {c['input_bg']};
            border: 1px solid {c['border']};
            border-radius: 4px;
            padding: 6px;
            color: {c['text']};
        }}
        QPushButton {{
            background-color: {c['accent']};
            color: {c['accent_text']};
            border: none;
            border-radius: 4px;
            padding: 6px 12px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background-color: {c['accent_hover']};
        }}
        QPushButton:disabled {{
            background-color: {c['border']};
            color: {c['text_muted']};
        }}
        QPushButton#smallButton {{
            padding: 2px;
        }}
        QPushButton#dangerButton {{
            background-color: {c['danger']};
            color: {c['danger_text']};
        }}
        QPushButton#dangerButton:hover {{
            background-color: {c['danger_hover']};
        }}
        QPushButton#saveButton[dirty="true"] {{
            background-color: {c['unsaved']};
            color: {c['unsaved_text']};
        }}
        QPushButton#saveButton[dirty="true"]:hover {{
            background-color: {c['unsaved_hover']};
        }}
        QListWidget {{
            background-color: {c['bg_alt']};
            border: 1px solid {c['border']};
            border-radius: 4px;
            color: {c['text']};
        }}
        QScrollArea {{
            background-color: transparent;
            border: 1px solid {c['border']};
            border-radius: 4px;
        }}
        QToolBar {{
            background-color: {c['bg_alt']};
            border: none;
            spacing: 4px;
        }}
        QMenu {{
            background-color: {c['panel_bg']};
            color: {c['text']};
            border: 1px solid {c['border']};
        }}
        QMenu::item:selected {{
            background-color: {c['accent']};
            color: {c['accent_text']};
        }}
        QLabel {{
            color: {c['text']};
        }}
        QLabel#sectionTitle {{
            font-size: {_px(16)}px;
            font-weight: bold;
        }}
        QLabel#fieldLabelHeader {{
            font-weight: bold;
            color: {c['text_muted']};
            border: none;
            background: transparent;
        }}
        QLabel#mutedLabel {{
            color: {c['text_muted']};
            font-size: {_px(11)}px;
        }}
        QLabel#errorLabel {{
            color: {c['error_text']};
            background-color: {c['error_bg']};
            padding: 6px;
            border-radius: 4px;
        }}
        QLineEdit#itemTitleEdit {{
            background: transparent;
            border: none;
            border-bottom: 1px solid transparent;
            border-radius: 0;
            font-size: {_px(18)}px;
            font-weight: bold;
            padding: 4px 2px;
        }}
        QLineEdit#itemTitleEdit:focus {{
            border-bottom: 1px solid {c['accent']};
        }}
        FieldRow {{
            background-color: {c['field_bg']};
            border: 1px solid {c['border']};
            border-radius: 6px;
            margin: 2px;
        }}
        ClickToCopyLabel {{
            padding: 4px;
            background-color: {c['value_bg']};
            border-radius: 4px;
            color: {c['text']};
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
            border-radius: 6px;
            background-color: {c['bg_alt']};
        }}
    """


def load_theme() -> str:
    """
    Return the last chosen theme.

    Returns
    -------
    str
        ``"light"`` or ``"dark"``, from the settings file, or
        :data:`DEFAULT_THEME` if there is no settings file yet or it
        can't be read/parsed.
    """
    try:
        raw = json.loads(_SETTINGS_FILE_PATH.read_text(encoding="utf-8"))
        theme = raw.get("theme")
        if theme in ("light", "dark"):
            return theme
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return DEFAULT_THEME


def save_theme(theme: str) -> None:
    """
    Best-effort persist of ``theme`` ("light" or "dark") for next launch.

    Silently does nothing on a write failure (e.g. read-only home
    directory): the theme toggle still works for the current session,
    it just won't be remembered.
    """
    try:
        _SETTINGS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _SETTINGS_FILE_PATH.write_text(
            json.dumps({"theme": theme}),
            encoding="utf-8",
        )
    except OSError:
        pass


def apply_theme(app: QApplication, theme: str, text_scale: float = 1.0) -> None:
    """
    Apply ``theme`` ("light" or "dark") as the whole application's
    stylesheet. Safe to call again later (e.g. from a toggle button,
    or the interface zoom) to switch themes/text scale at runtime --
    Qt re-polishes every widget.

    Parameters
    ----------
    text_scale : float, optional
        Forwarded to :func:`stylesheet` -- pass the interface's
        current zoom scale so re-applying the theme (e.g. on a theme
        or language change) doesn't reset the few hardcoded ``px``
        font sizes back to their unzoomed size.
    """
    app.setStyleSheet(stylesheet(theme, text_scale))
