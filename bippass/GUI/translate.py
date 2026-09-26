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

#: Supported language codes.
ENGLISH = "en"
FRENCH = "fr"
SPANISH = "es"

SUPPORTED_LANGUAGES = (ENGLISH, FRENCH, SPANISH)


#: Translations for the strings shown by `item_viewer.py`.
item_viewer_translation: dict[str, dict[str, str]] = {
    # -- Toolbar / mode ----------------------------------------------------
    "edit_button": {
        "en": "Edit",
        "fr": "Modifier",
        "es": "Editar",
    },
    "cancel_button": {
        "en": "Cancel",
        "fr": "Annuler",
        "es": "Cancelar",
    },
    "save_button": {
        "en": "Save",
        "fr": "Enregistrer",
        "es": "Guardar",
    },

    # -- Title / header ------------------------------------------------------
    "item_name_placeholder": {
        "en": "Item name",
        "fr": "Nom de l'élément",
        "es": "Nombre del elemento",
    },
    "last_modified": {
        "en": "Last modified: {date}",
        "fr": "Dernière modification : {date}",
        "es": "Última modificación: {date}",
    },
    "icon_edit_tooltip": {
        "en": "Double-click to change the icon",
        "fr": "Double-cliquez pour changer l'icône",
        "es": "Haga doble clic para cambiar el icono",
    },

    # -- Field labels --------------------------------------------------------
    "field_logins": {
        "en": "Logins",
        "fr": "Identifiants",
        "es": "Nombres de usuario",
    },
    "field_passwords": {
        "en": "Passwords",
        "fr": "Mots de passe",
        "es": "Contraseñas",
    },
    "field_totps": {
        "en": "TOTP codes",
        "fr": "Codes TOTP",
        "es": "Códigos TOTP",
    },
    "field_websites": {
        "en": "Websites",
        "fr": "Sites web",
        "es": "Sitios web",
    },
    "field_emails": {
        "en": "Emails",
        "fr": "Emails",
        "es": "Correos electrónicos",
    },
    "field_phones": {
        "en": "Phone numbers",
        "fr": "Numéros de téléphone",
        "es": "Números de teléfono",
    },
    "custom_fields_section": {
        "en": "Custom fields",
        "fr": "Champs personnalisés",
        "es": "Campos personalizados",
    },

    # -- Field row controls --------------------------------------------------
    "show": {
        "en": "Show",
        "fr": "Afficher",
        "es": "Mostrar",
    },
    "hide": {
        "en": "Hide",
        "fr": "Masquer",
        "es": "Ocultar",
    },
    "show_hide_tooltip": {
        "en": "Show / hide",
        "fr": "Afficher / masquer",
        "es": "Mostrar / ocultar",
    },
    "remove_field_tooltip": {
        "en": "Remove this field",
        "fr": "Supprimer ce champ",
        "es": "Eliminar este campo",
    },
    "remove_value_tooltip": {
        "en": "Remove this value",
        "fr": "Supprimer cette valeur",
        "es": "Eliminar este valor",
    },
    "add_value_button": {
        "en": "+ Add value",
        "fr": "+ Ajouter une valeur",
        "es": "+ Añadir un valor",
    },
    "add_custom_field_button": {
        "en": "+ Custom field",
        "fr": "+ Champ personnalisé",
        "es": "+ Campo personalizado",
    },
    "generate_password_button": {
        "en": "Generate",
        "fr": "Générer",
        "es": "Generar",
    },
    "empty_value_placeholder": {
        "en": "-",
        "fr": "-",
        "es": "-",
    },

    # -- Format warnings -------------------------------------------------------
    "invalid_email_tooltip": {
        "en": "Doesn't look like a valid email address",
        "fr": "Ne ressemble pas à une adresse email valide",
        "es": "No parece una dirección de correo válida",
    },
    "invalid_phone_tooltip": {
        "en": "Doesn't look like a valid phone number",
        "fr": "Ne ressemble pas à un numéro de téléphone valide",
        "es": "No parece un número de teléfono válido",
    },
    "invalid_website_tooltip": {
        "en": "Doesn't look like a valid website address",
        "fr": "Ne ressemble pas à une adresse de site web valide",
        "es": "No parece una dirección de sitio web válida",
    },

    # -- Open-link confirmation ------------------------------------------------
    "open_link_title": {
        "en": "Open link",
        "fr": "Ouvrir le lien",
        "es": "Abrir enlace",
    },
    "open_website_prompt": {
        "en": "Open this link in your browser?",
        "fr": "Ouvrir ce lien dans votre navigateur ?",
        "es": "¿Abrir este enlace en su navegador?",
    },
    "open_email_prompt": {
        "en": "Open this address in your mail application?",
        "fr": "Ouvrir cette adresse dans votre application de messagerie ?",
        "es": "¿Abrir esta dirección en su aplicación de correo?",
    },
    "open_phone_prompt": {
        "en": "Call this number?",
        "fr": "Appeler ce numéro ?",
        "es": "¿Llamar a este número?",
    },
    "link_unavailable_title": {
        "en": "Unavailable",
        "fr": "Indisponible",
        "es": "No disponible",
    },
    "link_unavailable_message": {
        "en": "No application is available to open this link.",
        "fr": "Aucune application n'est disponible pour ouvrir ce lien.",
        "es": "No hay ninguna aplicación disponible para abrir este enlace.",
    },

    # -- Icon edit dialog --------------------------------------------------------
    "icon_dialog_title": {
        "en": "Edit icon",
        "fr": "Modifier l'icône",
        "es": "Editar icono",
    },
    "icon_path_placeholder": {
        "en": "Icon path, or filename in resources/icons",
        "fr": "Chemin de l'icône, ou nom de fichier dans resources/icons",
        "es": "Ruta del icono, o nombre de archivo en resources/icons",
    },
    "browse_button": {
        "en": "Browse…",
        "fr": "Parcourir…",
        "es": "Examinar…",
    },
    "select_icon_dialog_title": {
        "en": "Select an icon",
        "fr": "Sélectionner une icône",
        "es": "Seleccionar un icono",
    },
    "image_files_filter": {
        "en": "Images (*.png *.jpg *.jpeg *.bmp *.gif *.svg *.ico)",
        "fr": "Images (*.png *.jpg *.jpeg *.bmp *.gif *.svg *.ico)",
        "es": "Imágenes (*.png *.jpg *.jpeg *.bmp *.gif *.svg *.ico)",
    },
    "all_files_filter": {
        "en": "All files (*)",
        "fr": "Tous les fichiers (*)",
        "es": "Todos los archivos (*)",
    },

    # -- Custom field dialog -----------------------------------------------------
    "custom_field_dialog_title": {
        "en": "New custom field",
        "fr": "Nouveau champ personnalisé",
        "es": "Nuevo campo personalizado",
    },
    "field_name_placeholder": {
        "en": "Field name",
        "fr": "Nom du champ",
        "es": "Nombre del campo",
    },
    "name_label": {
        "en": "Name:",
        "fr": "Nom :",
        "es": "Nombre:",
    },
    "type_label": {
        "en": "Type:",
        "fr": "Type :",
        "es": "Tipo:",
    },
    "field_name_required": {
        "en": "The field name is required.",
        "fr": "Le nom du champ est requis.",
        "es": "El nombre del campo es obligatorio.",
    },
    "field_already_exists": {
        "en": 'The field "{name}" already exists.',
        "fr": 'Le champ "{name}" existe déjà.',
        "es": 'El campo "{name}" ya existe.',
    },

    # -- Remove custom field -------------------------------------------------------
    "remove_field_title": {
        "en": "Remove field",
        "fr": "Supprimer le champ",
        "es": "Eliminar campo",
    },
    "remove_field_prompt": {
        "en": 'Remove the custom field "{name}"?',
        "fr": 'Supprimer le champ personnalisé "{name}" ?',
        "es": '¿Eliminar el campo personalizado "{name}"?',
    },

    # -- Errors / confirmations --------------------------------------------------
    "error_title": {
        "en": "Error",
        "fr": "Erreur",
        "es": "Error",
    },
    "add_field_error": {
        "en": "Could not add the field:\n{error}",
        "fr": "Impossible d'ajouter le champ :\n{error}",
        "es": "No se pudo añadir el campo:\n{error}",
    },
    "remove_field_error": {
        "en": "Could not remove the field:\n{error}",
        "fr": "Impossible de supprimer le champ :\n{error}",
        "es": "No se pudo eliminar el campo:\n{error}",
    },
    "success_title": {
        "en": "Success",
        "fr": "Succès",
        "es": "Éxito",
    },
    "changes_saved": {
        "en": "Changes saved.",
        "fr": "Modifications enregistrées.",
        "es": "Cambios guardados.",
    },
    "confirmation_title": {
        "en": "Confirmation",
        "fr": "Confirmation",
        "es": "Confirmación",
    },
    "unsaved_changes_warning": {
        "en": "Unsaved changes will be lost.",
        "fr": "Les modifications non enregistrées seront perdues.",
        "es": "Los cambios no guardados se perderán.",
    },
    "invalid_totp_secret": {
        "en": "Invalid secret",
        "fr": "Secret invalide",
        "es": "Secreto no válido",
    },
    "field_error_row": {
        "en": "❌ {label}: {error}",
        "fr": "❌ {label} : {error}",
        "es": "❌ {label}: {error}",
    },
}


#: Translations for the strings shown by `manager_gui.py`. Kept in
#: its own table (rather than merged into `item_viewer_translation`)
#: so the two modules' keys can never collide.
manager_gui_translation: dict[str, dict[str, str]] = {
    # -- Toolbar -------------------------------------------------------------
    "toolbar_theme_tooltip": {
        "en": "Toggle light / dark theme",
        "fr": "Basculer thème clair / sombre",
        "es": "Cambiar tema claro / oscuro",
    },
    "toolbar_language_tooltip": {
        "en": "Display language",
        "fr": "Langue d'affichage",
        "es": "Idioma de la interfaz",
    },
    "toolbar_save_tooltip_dirty": {
        "en": "Unsaved changes -- click to save",
        "fr": "Modifications non enregistrées -- cliquer pour enregistrer",
        "es": "Cambios sin guardar -- haga clic para guardar",
    },
    "toolbar_save_tooltip_clean": {
        "en": "Everything is saved",
        "fr": "Tout est enregistré",
        "es": "Todo está guardado",
    },
    "toolbar_save_button": {
        "en": "Save",
        "fr": "Enregistrer",
        "es": "Guardar",
    },
    "toolbar_metadata_tooltip": {
        "en": "Edit account metadata",
        "fr": "Modifier les métadonnées du compte",
        "es": "Editar los metadatos de la cuenta",
    },
    "toolbar_metadata_button": {
        "en": "Metadata",
        "fr": "Métadonnées",
        "es": "Metadatos",
    },
    "toolbar_credentials_tooltip": {
        "en": "Change primary or secondary credentials",
        "fr": "Changer les identifiants primaires ou secondaires",
        "es": "Cambiar las credenciales primarias o secundarias",
    },
    "toolbar_credentials_button": {
        "en": "Credentials",
        "fr": "Identifiants",
        "es": "Credenciales",
    },
    "toolbar_settings_tooltip": {
        "en": "Metadata, credentials, preferences, help…",
        "fr": "Métadonnées, identifiants, préférences, aide…",
        "es": "Metadatos, credenciales, preferencias, ayuda…",
    },
    "toolbar_settings_button": {
        "en": "Settings",
        "fr": "Paramètres",
        "es": "Ajustes",
    },

    # -- Settings menu (opened from the toolbar's Settings button) -----------------
    "menu_metadata_action": {
        "en": "Metadata",
        "fr": "Métadonnées",
        "es": "Metadatos",
    },
    "menu_credentials_action": {
        "en": "Credentials",
        "fr": "Identifiants",
        "es": "Credenciales",
    },
    "menu_preferences_action": {
        "en": "Preferences",
        "fr": "Préférences",
        "es": "Preferencias",
    },
    "menu_help_action": {
        "en": "Help",
        "fr": "Aide",
        "es": "Ayuda",
    },
    "menu_zoom_in_action": {
        "en": "Zoom in",
        "fr": "Zoom avant",
        "es": "Acercar",
    },
    "menu_zoom_out_action": {
        "en": "Zoom out",
        "fr": "Zoom arrière",
        "es": "Alejar",
    },
    "menu_zoom_reset_action": {
        "en": "Reset zoom",
        "fr": "Réinitialiser le zoom",
        "es": "Restablecer zoom",
    },

    # -- Main window -----------------------------------------------------------
    "window_title": {
        "en": "bippass, {filename}",
        "fr": "bippass, {filename}",
        "es": "bippass, {filename}",
    },
    "vaults_title": {
        "en": "Vaults",
        "fr": "Coffres",
        "es": "Cajas fuertes",
    },
    "no_vault": {
        "en": "No vault.",
        "fr": "Aucun coffre.",
        "es": "Ninguna caja fuerte.",
    },
    "add_vault_button": {
        "en": "+ New vault",
        "fr": "+ Nouveau coffre",
        "es": "+ Nueva caja fuerte",
    },
    "add_item_button": {
        "en": "+ New item",
        "fr": "+ Nouvel élément",
        "es": "+ Nuevo elemento",
    },
    "search_placeholder": {
        "en": "Search an item…",
        "fr": "Rechercher un élément…",
        "es": "Buscar un elemento…",
    },
    "sort_alphabetic": {
        "en": "Alphabetic",
        "fr": "Alphabétique",
        "es": "Alfabético",
    },
    "sort_alphanumeric": {
        "en": "Alphanumeric",
        "fr": "Alphanumérique",
        "es": "Alfanumérico",
    },
    "sort_date": {
        "en": "Date",
        "fr": "Date",
        "es": "Fecha",
    },
    "reverse_sort_tooltip": {
        "en": "Reverse sort order",
        "fr": "Inverser l'ordre de tri",
        "es": "Invertir el orden",
    },
    "close_viewer_button": {
        "en": "Close",
        "fr": "Fermer",
        "es": "Cerrar",
    },
    "unnamed_item": {
        "en": "(Unnamed)",
        "fr": "(Sans nom)",
        "es": "(Sin nombre)",
    },
    "vault_info": {
        "en": "<b>{vault}</b><br>{shown} / {total} item(s)",
        "fr": "<b>{vault}</b><br>{shown} / {total} élément(s)",
        "es": "<b>{vault}</b><br>{shown} / {total} elemento(s)",
    },

    # -- Vaults ----------------------------------------------------------------
    "new_vault_title": {
        "en": "New vault",
        "fr": "Nouveau coffre",
        "es": "Nueva caja fuerte",
    },
    "new_vault_prompt": {
        "en": "Vault name:",
        "fr": "Nom du coffre :",
        "es": "Nombre de la caja fuerte:",
    },
    "vault_already_exists_title": {
        "en": "Vault already exists",
        "fr": "Le coffre existe déjà",
        "es": "La caja fuerte ya existe",
    },
    "vault_already_exists_message": {
        "en": 'A vault named "{name}" already exists.',
        "fr": 'Un coffre nommé "{name}" existe déjà.',
        "es": 'Ya existe una caja fuerte llamada "{name}".',
    },
    "no_vault_title": {
        "en": "No vault",
        "fr": "Aucun coffre",
        "es": "Ninguna caja fuerte",
    },
    "no_vault_message": {
        "en": "Select a vault first.",
        "fr": "Sélectionnez d'abord un coffre.",
        "es": "Seleccione primero una caja fuerte.",
    },

    # -- Items -------------------------------------------------------------------
    "open_action": {
        "en": "Open",
        "fr": "Ouvrir",
        "es": "Abrir",
    },
    "delete_action": {
        "en": "Delete",
        "fr": "Supprimer",
        "es": "Eliminar",
    },
    "delete_item_title": {
        "en": "Delete item",
        "fr": "Supprimer l'élément",
        "es": "Eliminar elemento",
    },
    "delete_item_prompt": {
        "en": 'Permanently delete "{item}" from vault "{vault}"?\nThis action cannot be undone.',
        "fr": 'Supprimer définitivement "{item}" du coffre "{vault}" ?\nCette action est irréversible.',
        "es": '¿Eliminar permanentemente "{item}" de la caja fuerte "{vault}"?\nEsta acción no se puede deshacer.',
    },
    "move_item_title": {
        "en": "Move item",
        "fr": "Déplacer l'élément",
        "es": "Mover elemento",
    },
    "move_item_prompt": {
        "en": 'Move "{item}" from "{source}" to "{target}"?',
        "fr": 'Déplacer "{item}" de "{source}" vers "{target}" ?',
        "es": '¿Mover "{item}" de "{source}" a "{target}"?',
    },
    "could_not_open_item": {
        "en": "Could not open the item:\n{error}",
        "fr": "Impossible d'ouvrir l'élément :\n{error}",
        "es": "No se pudo abrir el elemento:\n{error}",
    },

    # -- Errors ------------------------------------------------------------------
    "error_title": {
        "en": "Error",
        "fr": "Erreur",
        "es": "Error",
    },
    "save_error_title": {
        "en": "Save error",
        "fr": "Erreur d'enregistrement",
        "es": "Error al guardar",
    },
    "save_error_message": {
        "en": "Could not save changes to disk:\n\n{error}",
        "fr": "Impossible d'enregistrer les modifications sur le disque :\n\n{error}",
        "es": "No se pudieron guardar los cambios en el disco:\n\n{error}",
    },

    # -- Unsaved-changes confirmation ----------------------------------------------
    "unsaved_changes_title": {
        "en": "Unsaved changes",
        "fr": "Modifications non enregistrées",
        "es": "Cambios sin guardar",
    },
    "unsaved_changes_close_prompt": {
        "en": "You have unsaved changes. Save them before closing?",
        "fr": "Des modifications ne sont pas enregistrées. Les enregistrer avant de fermer ?",
        "es": "Tiene cambios sin guardar. ¿Guardarlos antes de cerrar?",
    },

    # -- Metadata dialog -----------------------------------------------------------
    "metadata_dialog_title": {
        "en": "Account metadata",
        "fr": "Métadonnées du compte",
        "es": "Metadatos de la cuenta",
    },
    "username_label": {
        "en": "Username:",
        "fr": "Nom d'utilisateur :",
        "es": "Nombre de usuario:",
    },
    "username_already_taken": {
        "en": 'A profile named "{username}" already exists. Choose a different username.',
        "fr": 'Un profil nommé "{username}" existe déjà. Choisissez un autre nom d\'utilisateur.',
        "es": 'Ya existe un perfil llamado "{username}". Elija otro nombre de usuario.',
    },
    "profile_rename_error": {
        "en": "Could not rename the profile file:\n{error}",
        "fr": "Impossible de renommer le fichier du profil :\n{error}",
        "es": "No se pudo renombrar el archivo del perfil:\n{error}",
    },
    "version_label": {
        "en": "Format version:",
        "fr": "Version du format :",
        "es": "Versión del formato:",
    },

    # -- Account settings dialog -----------------------------------------------------
    "settings_dialog_title": {
        "en": "Account settings",
        "fr": "Paramètres du compte",
        "es": "Configuración de la cuenta",
    },
    "settings_theme_label": {
        "en": "Theme:",
        "fr": "Thème :",
        "es": "Tema:",
    },
    "settings_language_label": {
        "en": "Language:",
        "fr": "Langue :",
        "es": "Idioma:",
    },
    "settings_close_timer_label": {
        "en": "Auto-close after (seconds of inactivity):",
        "fr": "Fermeture automatique après (secondes d'inactivité) :",
        "es": "Cierre automático tras (segundos de inactividad):",
    },
    "theme_light": {
        "en": "Light",
        "fr": "Clair",
        "es": "Claro",
    },
    "theme_dark": {
        "en": "Dark",
        "fr": "Sombre",
        "es": "Oscuro",
    },
    "language_en": {
        "en": "English",
        "fr": "Anglais",
        "es": "Inglés",
    },
    "language_fr": {
        "en": "French",
        "fr": "Français",
        "es": "Francés",
    },
    "language_es": {
        "en": "Spanish",
        "fr": "Espagnol",
        "es": "Español",
    },
    "invalid_close_timer": {
        "en": "The auto-close delay must be a whole number of seconds.",
        "fr": "Le délai de fermeture automatique doit être un nombre entier de secondes.",
        "es": "El retraso de cierre automático debe ser un número entero de segundos.",
    },

    # -- Change credentials dialog -----------------------------------------------------
    "credentials_dialog_title": {
        "en": "Change credentials",
        "fr": "Changer les identifiants",
        "es": "Cambiar credenciales",
    },
    "credentials_change_primary": {
        "en": "Change primary credentials",
        "fr": "Changer les identifiants primaires",
        "es": "Cambiar las credenciales primarias",
    },
    "credentials_change_secondary": {
        "en": "Change secondary credentials",
        "fr": "Changer les identifiants secondaires",
        "es": "Cambiar las credenciales secundarias",
    },
    "credentials_password_label": {
        "en": "New password:",
        "fr": "Nouveau mot de passe :",
        "es": "Nueva contraseña:",
    },
    "credentials_confirm_password_label": {
        "en": "Confirm password:",
        "fr": "Confirmer le mot de passe :",
        "es": "Confirmar contraseña:",
    },
    "credentials_password_mismatch": {
        "en": "The password and its confirmation do not match.",
        "fr": "Le mot de passe et sa confirmation ne correspondent pas.",
        "es": "La contraseña y su confirmación no coinciden.",
    },
    "credentials_empty_password": {
        "en": "The password cannot be empty.",
        "fr": "Le mot de passe ne peut pas être vide.",
        "es": "La contraseña no puede estar vacía.",
    },
    "credentials_changed_title": {
        "en": "Credentials changed",
        "fr": "Identifiants modifiés",
        "es": "Credenciales cambiadas",
    },
    "credentials_changed_message": {
        "en": "The credentials were changed. Remember to save.",
        "fr": "Les identifiants ont été modifiés. Pensez à enregistrer.",
        "es": "Las credenciales se han cambiado. Recuerde guardar.",
    },
    "credentials_change_error": {
        "en": "Could not change credentials:\n{error}",
        "fr": "Impossible de changer les identifiants :\n{error}",
        "es": "No se pudieron cambiar las credenciales:\n{error}",
    },

    # -- Generic dialog buttons ------------------------------------------------------
    "ok_button": {
        "en": "OK",
        "fr": "OK",
        "es": "Aceptar",
    },
    "cancel_button": {
        "en": "Cancel",
        "fr": "Annuler",
        "es": "Cancelar",
    },
}


#: Translations for the strings shown by `generator_qt.py`.
generator_translation: dict[str, dict[str, str]] = {
    "dialog_title": {
        "en": "Generate a password",
        "fr": "Générer un mot de passe",
        "es": "Generar una contraseña",
    },
    "type_label": {
        "en": "Type:",
        "fr": "Type :",
        "es": "Tipo:",
    },
    "type_random": {
        "en": "Random",
        "fr": "Aléatoire",
        "es": "Aleatoria",
    },
    "type_memorable": {
        "en": "Easy to remember",
        "fr": "Facile à retenir",
        "es": "Fácil de recordar",
    },

    # -- Random panel ------------------------------------------------------
    "length_label": {
        "en": "Length:",
        "fr": "Longueur :",
        "es": "Longitud:",
    },
    "lowercase_label": {
        "en": "Lowercase (a-z)",
        "fr": "Minuscules (a-z)",
        "es": "Minúsculas (a-z)",
    },
    "uppercase_label": {
        "en": "Uppercase (A-Z)",
        "fr": "Majuscules (A-Z)",
        "es": "Mayúsculas (A-Z)",
    },
    "digits_label": {
        "en": "Digits (0-9)",
        "fr": "Chiffres (0-9)",
        "es": "Dígitos (0-9)",
    },
    "special_characters_label": {
        "en": "Special characters:",
        "fr": "Caractères spéciaux :",
        "es": "Caracteres especiales:",
    },
    "special_characters_reset_tooltip": {
        "en": "Reset to the default character list",
        "fr": "Réinitialiser la liste par défaut",
        "es": "Restablecer la lista por defecto",
    },

    # -- Memorable panel -----------------------------------------------------
    "language_label": {
        "en": "Word language:",
        "fr": "Langue des mots :",
        "es": "Idioma de las palabras:",
    },
    "word_count_label": {
        "en": "Number of words:",
        "fr": "Nombre de mots :",
        "es": "Número de palabras:",
    },
    "digit_count_label": {
        "en": "Digits per word:",
        "fr": "Chiffres par mot :",
        "es": "Dígitos por palabra:",
    },
    "separator_label": {
        "en": "Separator:",
        "fr": "Séparateur :",
        "es": "Separador:",
    },
    "capitalize_label": {
        "en": "Capitalize each word",
        "fr": "Mettre une majuscule à chaque mot",
        "es": "Poner mayúscula a cada palabra",
    },
    "language_en": {
        "en": "English",
        "fr": "Anglais",
        "es": "Inglés",
    },
    "language_fr": {
        "en": "French",
        "fr": "Français",
        "es": "Francés",
    },
    "language_es": {
        "en": "Spanish",
        "fr": "Espagnol",
        "es": "Español",
    },

    # -- Result & actions ------------------------------------------------------
    "generate_button": {
        "en": "Generate",
        "fr": "Générer",
        "es": "Generar",
    },
    "copy_button": {
        "en": "Copy",
        "fr": "Copier",
        "es": "Copiar",
    },
    "use_button": {
        "en": "Use this password",
        "fr": "Utiliser ce mot de passe",
        "es": "Usar esta contraseña",
    },
    "cancel_button": {
        "en": "Cancel",
        "fr": "Annuler",
        "es": "Cancelar",
    },
    "result_placeholder": {
        "en": "Click \"Generate\"…",
        "fr": "Cliquez sur « Générer »…",
        "es": "Haga clic en «Generar»…",
    },
    "error_title": {
        "en": "Error",
        "fr": "Erreur",
        "es": "Error",
    },
    "generation_error": {
        "en": "Could not generate a password:\n{error}",
        "fr": "Impossible de générer un mot de passe :\n{error}",
        "es": "No se pudo generar una contraseña:\n{error}",
    },
    "nothing_generated": {
        "en": "Generate a password first.",
        "fr": "Générez d'abord un mot de passe.",
        "es": "Genere primero una contraseña.",
    },
}


#: Translations for the strings shown by `credentials_gui.py` (the
#: unlock/create wizard). Kept in its own table for the same reason
#: as the other modules': so its keys can never collide with theirs.
credentials_gui_translation: dict[str, dict[str, str]] = {
    "language_label": {
        "en": "Language:",
        "fr": "Langue :",
        "es": "Idioma:",
    },
    "language_en": {
        "en": "English",
        "fr": "Anglais",
        "es": "Inglés",
    },
    "language_fr": {
        "en": "French",
        "fr": "Français",
        "es": "Francés",
    },
    "language_es": {
        "en": "Spanish",
        "fr": "Espagnol",
        "es": "Español",
    },

    # -- File page (launch screen) --------------------------------------------
    "file_page_title": {
        "en": "Vault file",
        "fr": "Fichier du coffre",
        "es": "Archivo de la caja fuerte",
    },
    "file_page_subtitle_open": {
        "en": "Choose an existing profile, or browse for a vault file.",
        "fr": "Choisissez un profil existant, ou parcourez pour un fichier.",
        "es": "Elija un perfil existente, o busque un archivo.",
    },
    "file_page_subtitle_create": {
        "en": "Choose a username for the new profile.",
        "fr": "Choisissez un nom d'utilisateur pour le nouveau profil.",
        "es": "Elija un nombre de usuario para el nuevo perfil.",
    },
    "open_radio": {
        "en": "Open an existing vault",
        "fr": "Ouvrir un coffre existant",
        "es": "Abrir una caja fuerte existente",
    },
    "create_radio": {
        "en": "Create a new profile",
        "fr": "Créer un nouveau profil",
        "es": "Crear un nuevo perfil",
    },
    "existing_profiles_label": {
        "en": "Existing profiles:",
        "fr": "Profils existants :",
        "es": "Perfiles existentes:",
    },
    "browse_label": {
        "en": "Or choose a vault file:",
        "fr": "Ou choisissez un fichier :",
        "es": "O elija un archivo:",
    },
    "file_path_placeholder": {
        "en": "Vault file path…",
        "fr": "Chemin du fichier…",
        "es": "Ruta del archivo…",
    },
    "browse_button": {
        "en": "Browse…",
        "fr": "Parcourir…",
        "es": "Examinar…",
    },
    "username_label": {
        "en": "Username:",
        "fr": "Nom d'utilisateur :",
        "es": "Nombre de usuario:",
    },
    "destination_label": {
        "en": "Will be saved as: {path}",
        "fr": "Sera enregistré sous : {path}",
        "es": "Se guardará como: {path}",
    },
    "select_vault_file_dialog_title": {
        "en": "Select vault file",
        "fr": "Sélectionner le fichier du coffre",
        "es": "Seleccionar el archivo de la caja fuerte",
    },
    "vault_files_filter": {
        "en": "Vault files (*.vault *.pm *.bin *.encrypted);;All files (*)",
        "fr": "Fichiers de coffre (*.vault *.pm *.bin *.encrypted);;Tous les fichiers (*)",
        "es": "Archivos de caja fuerte (*.vault *.pm *.bin *.encrypted);;Todos los archivos (*)",
    },

    # -- File page errors ------------------------------------------------------
    "missing_username_title": {
        "en": "Missing username",
        "fr": "Nom d'utilisateur manquant",
        "es": "Falta el nombre de usuario",
    },
    "missing_username_message": {
        "en": "Please choose a username.",
        "fr": "Veuillez choisir un nom d'utilisateur.",
        "es": "Elija un nombre de usuario.",
    },
    "profile_exists_title": {
        "en": "Profile already exists",
        "fr": "Le profil existe déjà",
        "es": "El perfil ya existe",
    },
    "profile_exists_message": {
        "en": 'A profile named "{username}" already exists.\n\n'
              "Choose a different username, or open the existing profile instead.",
        "fr": 'Un profil nommé "{username}" existe déjà.\n\n'
              "Choisissez un autre nom d'utilisateur, ou ouvrez plutôt le profil existant.",
        "es": 'Ya existe un perfil llamado "{username}".\n\n'
              "Elija otro nombre de usuario, o abra el perfil existente.",
    },
    "folder_error_title": {
        "en": "Error",
        "fr": "Erreur",
        "es": "Error",
    },
    "folder_error_message": {
        "en": "Could not create the profiles folder:\n{error}",
        "fr": "Impossible de créer le dossier des profils :\n{error}",
        "es": "No se pudo crear la carpeta de perfiles:\n{error}",
    },
    "unexpected_error_title": {
        "en": "Unexpected error",
        "fr": "Erreur inattendue",
        "es": "Error inesperado",
    },
    "unexpected_error_message": {
        "en": "{error_type}: {error}",
        "fr": "{error_type} : {error}",
        "es": "{error_type}: {error}",
    },
    "missing_file_title": {
        "en": "Missing file",
        "fr": "Fichier manquant",
        "es": "Falta el archivo",
    },
    "missing_file_message": {
        "en": "Please choose a profile, or browse for a vault file.",
        "fr": "Veuillez choisir un profil, ou parcourir pour un fichier.",
        "es": "Elija un perfil, o busque un archivo.",
    },
    "file_not_found_title": {
        "en": "File not found",
        "fr": "Fichier introuvable",
        "es": "Archivo no encontrado",
    },
    "file_not_found_message": {
        "en": "The following file does not exist:\n\n{path}",
        "fr": "Le fichier suivant n'existe pas :\n\n{path}",
        "es": "El siguiente archivo no existe:\n\n{path}",
    },
    "read_error_title": {
        "en": "Read error",
        "fr": "Erreur de lecture",
        "es": "Error de lectura",
    },
    "read_error_message": {
        "en": "Could not read the file:\n\n{error}",
        "fr": "Impossible de lire le fichier :\n\n{error}",
        "es": "No se pudo leer el archivo:\n\n{error}",
    },

    # -- Primary / secondary credentials pages ---------------------------------
    "primary_page_title": {
        "en": "Primary credentials",
        "fr": "Identifiants primaires",
        "es": "Credenciales primarias",
    },
    "primary_subtitle_create": {
        "en": "Choose a primary password for this new vault.",
        "fr": "Choisissez un mot de passe primaire pour ce nouveau coffre.",
        "es": "Elija una contraseña primaria para esta nueva caja fuerte.",
    },
    "primary_subtitle_open": {
        "en": "Enter the primary password to unlock this vault.",
        "fr": "Entrez le mot de passe primaire pour déverrouiller ce coffre.",
        "es": "Introduzca la contraseña primaria para desbloquear esta caja fuerte.",
    },
    "secondary_page_title": {
        "en": "Secondary credentials",
        "fr": "Identifiants secondaires",
        "es": "Credenciales secundarias",
    },
    "secondary_subtitle_create": {
        "en": "Choose a secondary password, used to encrypt "
              "individual secrets (passwords, TOTP codes, …).",
        "fr": "Choisissez un mot de passe secondaire, utilisé "
              "pour chiffrer les secrets individuels (mots de passe, codes TOTP, …).",
        "es": "Elija una contraseña secundaria, usada para cifrar "
              "los secretos individuales (contraseñas, códigos TOTP, …).",
    },
    "secondary_subtitle_open": {
        "en": "Enter the secondary password.",
        "fr": "Entrez le mot de passe secondaire.",
        "es": "Introduzca la contraseña secundaria.",
    },
    "password_label": {
        "en": "Password:",
        "fr": "Mot de passe :",
        "es": "Contraseña:",
    },
    "confirm_password_label": {
        "en": "Confirm password:",
        "fr": "Confirmer le mot de passe :",
        "es": "Confirmar contraseña:",
    },
    "missing_fields_title": {
        "en": "Missing fields",
        "fr": "Champs manquants",
        "es": "Campos incompletos",
    },
    "missing_fields_message": {
        "en": "Please fill in both fields.",
        "fr": "Veuillez remplir les deux champs.",
        "es": "Complete ambos campos.",
    },
    "mismatch_title": {
        "en": "Mismatch",
        "fr": "Non concordance",
        "es": "No coinciden",
    },
    "mismatch_message": {
        "en": "Password confirmation does not match.",
        "fr": "La confirmation du mot de passe ne correspond pas.",
        "es": "La confirmación de la contraseña no coincide.",
    },
    "wrong_credentials_title": {
        "en": "Wrong credentials",
        "fr": "Identifiants incorrects",
        "es": "Credenciales incorrectas",
    },
    "wrong_primary_credentials_message": {
        "en": "The primary password is incorrect.",
        "fr": "Le mot de passe primaire est incorrect.",
        "es": "La contraseña primaria es incorrecta.",
    },
    "wrong_secondary_credentials_message": {
        "en": "The secondary password is incorrect.",
        "fr": "Le mot de passe secondaire est incorrect.",
        "es": "La contraseña secundaria es incorrecta.",
    },
    "invalid_vault_title": {
        "en": "Invalid vault",
        "fr": "Coffre invalide",
        "es": "Caja fuerte no válida",
    },
    "invalid_vault_message": {
        "en": "The decrypted data is invalid.\n\n{error}",
        "fr": "Les données déchiffrées sont invalides.\n\n{error}",
        "es": "Los datos descifrados no son válidos.\n\n{error}",
    },
    "write_error_title": {
        "en": "Write error",
        "fr": "Erreur d'écriture",
        "es": "Error de escritura",
    },
    "write_error_message": {
        "en": "Could not create the vault file:\n\n{error}",
        "fr": "Impossible de créer le fichier du coffre :\n\n{error}",
        "es": "No se pudo crear el archivo de la caja fuerte:\n\n{error}",
    },
    "corrupted_vault_title": {
        "en": "Corrupted vault",
        "fr": "Coffre corrompu",
        "es": "Caja fuerte dañada",
    },
    "corrupted_vault_message": {
        "en": "The secondary authentication data in this vault is invalid.",
        "fr": "Les données d'authentification secondaires de ce coffre sont invalides.",
        "es": "Los datos de autenticación secundaria de esta caja fuerte no son válidos.",
    },
}


#: Translations for the strings shown by `help_gui.py`.
help_gui_translation: dict[str, dict[str, str]] = {
    "help_dialog_title": {
        "en": "bippass -- Help",
        "fr": "bippass -- Aide",
        "es": "bippass -- Ayuda",
    },
    "close_button": {
        "en": "Close",
        "fr": "Fermer",
        "es": "Cerrar",
    },
    "help_content": {
        "en": """
            <h2>Vaults</h2>
            <p>Logins, passwords, and everything else are organized into <b>vaults</b>.
            Vaults are listed on the left side of the window; click one to open it and
            see its items on the right.</p>
            <p>To create a new vault, click the add button at the bottom of the vault
            list, on the left.</p>
    
            <h2>Items</h2>
            <p>Each vault holds a list of <b>items</b> -- one entry per account or
            credential set. Click an item to open it in read-only view; click
            <b>Edit</b> to modify its fields.</p>
            <ul>
                <li>To add a new item to the open vault, click the add button at the
                bottom of the item list, on the right.</li>
                <li>Right-click an item for a quick "Open" / "Delete" menu.</li>
                <li>In Edit mode, a password field has a <b>Generate</b> button to
                create a random or memorable password.</li>
                <li>Each item can carry its own icon, shown next to its name in the list.</li>
            </ul>
    
            <h2>Search and sort</h2>
            <p>Use the search box above the item list to filter items by name. The
            sort controls next to it let you order items alphabetically,
            alphanumerically, or by last-modified date.</p>
    
            <h2>Moving items between vaults</h2>
            <p>Drag an item from the list and drop it onto another vault, on the
            left, to move it there.</p>
    
            <h2>Saving and auto-lock</h2>
            <p>Changes are kept in memory until you click <b>Save</b> in the toolbar,
            or close the window. The application also auto-saves and locks itself
            after a period of inactivity, configurable in Preferences.</p>
    
            <h2>The Settings menu</h2>
            <ul>
                <li><b>Metadata</b> -- edit the account username.</li>
                <li><b>Credentials</b> -- change the primary or secondary password.</li>
                <li><b>Preferences</b> -- theme, language, and the auto-close delay.</li>
                <li><b>Help</b> -- this window.</li>
            </ul>
    
            <h2>Keyboard shortcuts</h2>
            <ul>
                <li><b>Ctrl +</b> / <b>Ctrl =</b> -- Zoom in</li>
                <li><b>Ctrl -</b> -- Zoom out</li>
                <li><b>Ctrl 0</b> -- Reset zoom</li>
            </ul>
        """,
        "fr": """
            <h2>Coffres-forts</h2>
            <p>Les identifiants, mots de passe et le reste sont organisés en
            <b>coffres-forts</b>. Les coffres sont listés sur la partie gauche de la
            fenêtre ; cliquez sur l'un d'eux pour l'ouvrir et voir ses éléments à
            droite.</p>
            <p>Pour créer un nouveau coffre, cliquez sur le bouton d'ajout en bas de
            la liste des coffres, à gauche.</p>
    
            <h2>Éléments</h2>
            <p>Chaque coffre-fort contient une liste d'<b>éléments</b> -- une entrée
            par compte ou jeu d'identifiants. Cliquez sur un élément pour l'ouvrir en
            lecture seule, ou sur <b>Modifier</b> pour éditer ses champs.</p>
            <ul>
                <li>Pour ajouter un nouvel élément au coffre ouvert, cliquez sur le
                bouton d'ajout en bas de la liste des éléments, à droite.</li>
                <li>Clic droit sur un élément pour un menu rapide "Ouvrir" / "Supprimer".</li>
                <li>En mode édition, un champ mot de passe possède un bouton
                <b>Générer</b> pour créer un mot de passe aléatoire ou facile à
                retenir.</li>
                <li>Chaque élément peut avoir sa propre icône, affichée à côté de son
                nom dans la liste.</li>
            </ul>
    
            <h2>Recherche et tri</h2>
            <p>Utilisez le champ de recherche au-dessus de la liste des éléments pour
            les filtrer par nom. Les contrôles de tri juste à côté permettent de les
            ordonner par ordre alphabétique, alphanumérique, ou par date de dernière
            modification.</p>
    
            <h2>Déplacer un élément entre coffres</h2>
            <p>Glissez un élément de la liste et déposez-le sur un autre coffre, à
            gauche, pour l'y déplacer.</p>
    
            <h2>Enregistrement et verrouillage automatique</h2>
            <p>Les modifications restent en mémoire jusqu'à ce que vous cliquiez sur
            <b>Enregistrer</b> dans la barre d'outils, ou que vous fermiez la
            fenêtre. L'application s'enregistre et se verrouille aussi
            automatiquement après une période d'inactivité, réglable dans les
            Préférences.</p>
    
            <h2>Le menu Paramètres</h2>
            <ul>
                <li><b>Métadonnées</b> -- modifier le nom d'utilisateur du compte.</li>
                <li><b>Identifiants</b> -- changer le mot de passe primaire ou secondaire.</li>
                <li><b>Préférences</b> -- thème, langue, et délai de fermeture automatique.</li>
                <li><b>Aide</b> -- cette fenêtre.</li>
            </ul>
    
            <h2>Raccourcis clavier</h2>
            <ul>
                <li><b>Ctrl +</b> / <b>Ctrl =</b> -- Zoom avant</li>
                <li><b>Ctrl -</b> -- Zoom arrière</li>
                <li><b>Ctrl 0</b> -- Réinitialiser le zoom</li>
            </ul>
        """,
        "es": """
            <h2>Cajas fuertes</h2>
            <p>Los inicios de sesión, contraseñas y demás se organizan en <b>cajas
            fuertes</b>. Las cajas fuertes se listan en la parte izquierda de la
            ventana; haga clic en una para abrirla y ver sus elementos a la
            derecha.</p>
            <p>Para crear una nueva caja fuerte, haga clic en el botón de añadir en
            la parte inferior de la lista de cajas fuertes, a la izquierda.</p>
    
            <h2>Elementos</h2>
            <p>Cada caja fuerte contiene una lista de <b>elementos</b> -- una entrada
            por cuenta o conjunto de credenciales. Haga clic en un elemento para
            abrirlo en modo solo lectura, o en <b>Editar</b> para modificar sus
            campos.</p>
            <ul>
                <li>Para añadir un nuevo elemento a la caja fuerte abierta, haga clic
                en el botón de añadir en la parte inferior de la lista de elementos,
                a la derecha.</li>
                <li>Clic derecho sobre un elemento para un menú rápido "Abrir" /
                "Eliminar".</li>
                <li>En modo edición, un campo de contraseña tiene un botón
                <b>Generar</b> para crear una contraseña aleatoria o fácil de
                recordar.</li>
                <li>Cada elemento puede tener su propio icono, mostrado junto a su
                nombre en la lista.</li>
            </ul>
    
            <h2>Búsqueda y orden</h2>
            <p>Use el campo de búsqueda encima de la lista de elementos para
            filtrarlos por nombre. Los controles de orden justo al lado permiten
            ordenarlos alfabéticamente, alfanuméricamente, o por fecha de última
            modificación.</p>
    
            <h2>Mover elementos entre cajas fuertes</h2>
            <p>Arrastre un elemento de la lista y suéltelo sobre otra caja fuerte, a
            la izquierda, para moverlo allí.</p>
    
            <h2>Guardado y bloqueo automático</h2>
            <p>Los cambios permanecen en memoria hasta que hace clic en
            <b>Guardar</b> en la barra de herramientas, o cierra la ventana. La
            aplicación también se guarda y se bloquea automáticamente tras un
            período de inactividad, configurable en Preferencias.</p>
    
            <h2>El menú Ajustes</h2>
            <ul>
                <li><b>Metadatos</b> -- editar el nombre de usuario de la cuenta.</li>
                <li><b>Credenciales</b> -- cambiar la contraseña primaria o
                secundaria.</li>
                <li><b>Preferencias</b> -- tema, idioma, y el retraso de cierre
                automático.</li>
                <li><b>Ayuda</b> -- esta ventana.</li>
            </ul>
    
            <h2>Atajos de teclado</h2>
            <ul>
                <li><b>Ctrl +</b> / <b>Ctrl =</b> -- Acercar</li>
                <li><b>Ctrl -</b> -- Alejar</li>
                <li><b>Ctrl 0</b> -- Restablecer zoom</li>
            </ul>
        """,
    },
}


class Translator:
    """
    Resolves translation keys to strings in the current language.

    Parameters
    ----------
    language : str, optional
        Initial display language, one of :data:`SUPPORTED_LANGUAGES`
        (default: :data:`ENGLISH`). Silently falls back to
        :data:`ENGLISH` if not supported.

    Attributes
    ----------
    language : str
        Currently selected display language. Assign directly (or
        through :meth:`set_language`) to switch languages -- every
        subsequent :meth:`translate` call picks it up immediately.
    """

    def __init__(self, language: str = ENGLISH):
        self.language = language if language in SUPPORTED_LANGUAGES else ENGLISH

    def set_language(self, language: str) -> None:
        """
        Change the current display language.

        Raises
        ------
        ValueError
            If ``language`` is not one of :data:`SUPPORTED_LANGUAGES`.
        """
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language: {language!r}")
        self.language = language

    def translate(
        self,
        key: str,
        translations: dict[str, dict[str, str]] = item_viewer_translation,
        **kwargs: str,
    ) -> str:
        """
        Translate ``key`` to the current language.

        Parameters
        ----------
        key : str
            Translation key looked up in ``translations``.

            Notes
            -----
            Named ``key`` (not ``item``) specifically so that callers
            can freely pass an ``item=...`` substitution kwarg (e.g.
            ``translate("move_item_prompt", item=item_name, ...)``)
            without colliding with this positional parameter --
            that exact collision used to raise ``TypeError:
            translate() got multiple values for argument 'item'``.
        translations : dict, optional
            Translation table to use (defaults to
            :data:`item_viewer_translation`; pass another module's
            table, e.g. a future ``manager_gui_translation``, to
            translate its strings instead).
        **kwargs
            Values substituted into the resolved string with
            ``str.format`` (e.g. ``translate("last_modified",
            date=raw_date)``), for entries containing placeholders
            such as ``{date}``.

        Returns
        -------
        str
            The string for :attr:`language`, falling back to
            :data:`ENGLISH` and then to ``key`` itself if neither is
            defined for this key.
        """
        entry = translations.get(key)
        text = (entry.get(self.language) or entry.get(ENGLISH) or key) if entry else key
        return text.format(**kwargs) if kwargs else text


#: Shared instance, importable by every GUI module so they all follow
#: the same display language (e.g. a future language-switch button in
#: `manager_gui.py`, the same way `theme.py`'s theme toggle applies
#: everywhere through `apply_theme`).
translator = Translator()