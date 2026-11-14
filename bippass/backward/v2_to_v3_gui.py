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

# BACKWARD COMPATIBILITY -- see `bippass/backward/__init__.py`.
#
# The version 2 conversion (see `v2_to_v3`), as a dialog opened from the
# Settings menu of the start page: pick the `*.encrypted` file, type its
# two passwords, convert. Nothing is opened afterwards: the new
# `<uuid>.bippass` profile just appears in the list of the start page.
#
# Self-contained on purpose: its texts are registered here into the
# translator (not in `resources/i18n`), and the main window only knows
# `menu_entries`, through the two lines marked "BACKWARD" in
# `GUI/window.py`. Removing this package and those two lines removes the
# whole feature.

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pyaescbc
from PyQt5.QtWidgets import QDialog, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit

from ..core.profiles import PROFILES_DIR
from ..GUI.common import _file_to_base64
from ..GUI.tasks import run_blocking
from ..GUI.translate import translator
from ..GUI.widgets import PasswordField, inform, ok_cancel_buttons, show_error, small_button, warn
from .v2_to_v3 import (
    ConversionError,
    WrongPrimaryPasswordError,
    WrongSecondaryPasswordError,
    convert,
)

if TYPE_CHECKING:
    from ..GUI.window import PasswordManagerWindow


# Texts of this dialog, by language (registered by `_register_texts`).
_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "backward.menu_action": "Convert a version 2 profile…",
        "backward.dialog_title": "Convert a version 2 profile",
        "backward.hint": "Creates a new profile from an old one (.encrypted), with the same passwords. "
                         "The old file is left unchanged. The new profile then appears on the start screen.",
        "backward.file_label": "Version 2 file:",
        "backward.select_title": "Select a version 2 profile",
        "backward.file_filter": "Version 2 profiles (*.encrypted);;All files (*)",
        "backward.primary_label": "Primary password:",
        "backward.secondary_label": "Secondary password:",
        "backward.convert_button": "Convert",
        "backward.converting": "Converting the profile…",
        "backward.missing_fields": "Choose a file and type both passwords.",
        "backward.file_not_found": "This file doesn't exist.",
        "backward.wrong_title": "Wrong password",
        "backward.wrong_primary": "The primary password is wrong.",
        "backward.wrong_secondary": "The secondary password is wrong.",
        "backward.error": "The profile couldn't be converted:\n\n{error}",
        "backward.success_title": "Profile converted",
        "backward.success_message": "The new profile was created:\n\n{path}\n\nIt is listed on the start screen.",
    },
    "fr": {
        "backward.menu_action": "Convertir un profil version 2…",
        "backward.dialog_title": "Convertir un profil version 2",
        "backward.hint": "Crée un nouveau profil à partir d'un ancien (.encrypted), avec les mêmes mots de passe. "
                         "L'ancien fichier n'est pas modifié. Le nouveau profil apparaît ensuite sur l'écran d'accueil.",
        "backward.file_label": "Fichier version 2 :",
        "backward.select_title": "Sélectionner un profil version 2",
        "backward.file_filter": "Profils version 2 (*.encrypted);;Tous les fichiers (*)",
        "backward.primary_label": "Mot de passe primaire :",
        "backward.secondary_label": "Mot de passe secondaire :",
        "backward.convert_button": "Convertir",
        "backward.converting": "Conversion du profil…",
        "backward.missing_fields": "Choisissez un fichier et saisissez les deux mots de passe.",
        "backward.file_not_found": "Ce fichier n'existe pas.",
        "backward.wrong_title": "Mot de passe incorrect",
        "backward.wrong_primary": "Le mot de passe primaire est incorrect.",
        "backward.wrong_secondary": "Le mot de passe secondaire est incorrect.",
        "backward.error": "Le profil n'a pas pu être converti :\n\n{error}",
        "backward.success_title": "Profil converti",
        "backward.success_message": "Le nouveau profil a été créé :\n\n{path}\n\nIl apparaît sur l'écran d'accueil.",
    },
    "es": {
        "backward.menu_action": "Convertir un perfil de la versión 2…",
        "backward.dialog_title": "Convertir un perfil de la versión 2",
        "backward.hint": "Crea un perfil nuevo a partir de uno antiguo (.encrypted), con las mismas contraseñas. "
                         "El archivo antiguo no se modifica. El perfil nuevo aparece luego en la pantalla de inicio.",
        "backward.file_label": "Archivo de la versión 2:",
        "backward.select_title": "Seleccionar un perfil de la versión 2",
        "backward.file_filter": "Perfiles de la versión 2 (*.encrypted);;Todos los archivos (*)",
        "backward.primary_label": "Contraseña primaria:",
        "backward.secondary_label": "Contraseña secundaria:",
        "backward.convert_button": "Convertir",
        "backward.converting": "Convirtiendo el perfil…",
        "backward.missing_fields": "Elija un archivo y escriba las dos contraseñas.",
        "backward.file_not_found": "Este archivo no existe.",
        "backward.wrong_title": "Contraseña incorrecta",
        "backward.wrong_primary": "La contraseña primaria es incorrecta.",
        "backward.wrong_secondary": "La contraseña secundaria es incorrecta.",
        "backward.error": "No se pudo convertir el perfil:\n\n{error}",
        "backward.success_title": "Perfil convertido",
        "backward.success_message": "Se ha creado el perfil nuevo:\n\n{path}\n\nAparece en la pantalla de inicio.",
    },
}


def _register_texts() -> None:
    """
    Add the texts of this dialog to the translator's catalogs.

    Notes
    -----
    Uses the translator's private catalog loader on purpose, so that
    no text of this temporary feature lives in `resources/i18n`.
    """
    for language, texts in _TEXTS.items():
        translator._catalog(language).update(texts)


_register_texts()


class V2ToV3Dialog(QDialog):
    """
    Dialog collecting a version 2 file and its two passwords.

    It only collects them: :func:`run` closes it, then converts behind
    the "please wait" veil of the main window.

    Parameters
    ----------
    path : str, optional
        File pre-filled (kept when the dialog is shown again after a
        wrong password).

    parent : QWidget, optional
        Parent widget.
    """

    def __init__(self, path: str = "", parent=None):
        super().__init__(parent)
        tr = translator.translate
        self.setWindowTitle(tr("backward.dialog_title"))
        self.setMinimumWidth(480)
        layout = QFormLayout(self)

        hint = QLabel(tr("backward.hint"))
        hint.setObjectName("mutedLabel")
        hint.setWordWrap(True)
        layout.addRow(hint)

        file_row = QHBoxLayout()
        self.file_edit = QLineEdit(path)
        file_row.addWidget(self.file_edit, stretch=1)
        browse = small_button(tr("common.browse"))
        browse.clicked.connect(self._browse)
        file_row.addWidget(browse)
        layout.addRow(tr("backward.file_label"), file_row)

        self.primary_field = PasswordField()
        self.secondary_field = PasswordField()
        layout.addRow(tr("backward.primary_label"), self.primary_field)
        layout.addRow(tr("backward.secondary_label"), self.secondary_field)
        layout.addRow(ok_cancel_buttons(self, self._on_accept, ok_key="backward.convert_button"))

        (self.primary_field if path else self.file_edit).setFocus()

    def _browse(self) -> None:
        """Pick the version 2 file, starting in the profile folder."""
        start = PROFILES_DIR if PROFILES_DIR.is_dir() else Path.home()
        filename, _filter = QFileDialog.getOpenFileName(
            self,
            translator.translate("backward.select_title"),
            str(start),
            translator.translate("backward.file_filter"),
        )
        if filename:
            self.file_edit.setText(filename)
            self.primary_field.edit.setFocus()

    def path(self) -> Path:
        """Return the chosen file."""
        return Path(self.file_edit.text().strip()).expanduser()

    def _on_accept(self) -> None:
        """Accept once a file and both passwords are given."""
        if not self.file_edit.text().strip() or not self.primary_field.text() \
                or not self.secondary_field.text():
            warn(self, "backward.missing_fields")
        elif not self.path().is_file():
            warn(self, "backward.file_not_found")
        else:
            self.accept()

    def take_passwords(self) -> tuple[bytearray, bytearray]:
        """Return both passwords (owned, and to be erased, by the caller), and erase the fields."""
        passwords = self.primary_field.to_bytearray(), self.secondary_field.to_bytearray()
        self._clear()
        return passwords

    def _clear(self) -> None:
        """Erase both password fields."""
        self.primary_field.clear()
        self.secondary_field.clear()

    def reject(self) -> None:
        """Erase the typed passwords, then close."""
        self._clear()
        super().reject()


def run(window: PasswordManagerWindow) -> None:
    """
    Convert a version 2 profile, from the start page.

    Parameters
    ----------
    window : PasswordManagerWindow
        The main window: parent of the dialog, covered by the veil
        during the conversion, and whose start page lists the new
        profile afterwards.

    Notes
    -----
    A wrong password is reported, then the dialog is shown again with
    the same file. Nothing is opened: the new profile is only listed.
    """
    tr = translator.translate
    path = ""
    while True:
        dialog = V2ToV3Dialog(path, window)
        if dialog.exec_() != QDialog.Accepted:
            return
        source = dialog.path()
        path = str(source)
        primary, secondary = dialog.take_passwords()
        try:
            new_path = run_blocking(
                window,
                tr("backward.converting"),
                lambda: convert(source, primary, secondary, icon_encoder=_file_to_base64),
            )
        except WrongPrimaryPasswordError:
            warn(window, "backward.wrong_primary", "backward.wrong_title")
            continue
        except WrongSecondaryPasswordError:
            warn(window, "backward.wrong_secondary", "backward.wrong_title")
            continue
        except ConversionError as exc:
            show_error(window, "backward.error", error=str(exc))
            return
        finally:
            pyaescbc.delete_bytearray(primary)
            pyaescbc.delete_bytearray(secondary)
        window.start_page.refresh_profiles()
        inform(window, "backward.success_title", "backward.success_message", path=str(new_path))
        return


def menu_entries(window: PasswordManagerWindow) -> list:
    """
    Return the entries this feature adds to the Settings menu of the start page.

    Parameters
    ----------
    window : PasswordManagerWindow
        The main window.

    Returns
    -------
    list
        Menu entries (see ``window.MenuEntry``): the conversion, then a
        separator.
    """
    return [("backward.menu_action", lambda: run(window), None), None]
