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
import logging
from importlib import resources

from PyQt5.QtCore import QObject, pyqtSignal


ENGLISH = "en"
FRENCH = "fr"
SPANISH = "es"
SUPPORTED_LANGUAGES = (ENGLISH, FRENCH, SPANISH)

# Translation key of each supported language's name, in display order.
LANGUAGE_NAME_KEYS = {
    ENGLISH: "common.language_en",
    FRENCH: "common.language_fr",
    SPANISH: "common.language_es",
}

# Language whose catalog is the reference, used when a key is missing
# from the current language.
FALLBACK_LANGUAGE = ENGLISH

_CATALOG_DIR = "resources/i18n"

_logger = logging.getLogger(__name__)


def load_catalog(language: str) -> dict[str, str]:
    """
    Load the translation catalog of a language.

    Parameters
    ----------
    language : str
        Language code, e.g. ``"fr"``.

    Returns
    -------
    dict of str to str
        Key to translated text, read from
        ``bippass/resources/i18n/<language>.json``. Empty (with a
        logged error) if the file is missing or invalid.
    """
    try:
        ref = resources.files("bippass").joinpath(_CATALOG_DIR, f"{language}.json")
        catalog = json.loads(ref.read_text(encoding="utf-8"))
    except (ModuleNotFoundError, OSError, ValueError) as exc:
        _logger.error("Cannot load the %r translation catalog: %s", language, exc)
        return {}
    if not isinstance(catalog, dict):
        _logger.error("The %r translation catalog is not a JSON object.", language)
        return {}
    return catalog


class Translator(QObject):
    """
    Resolve translation keys to texts in the current language.

    Keys are namespaced by screen (``"window.vaults_title"``,
    ``"viewer.edit"``...), and texts shared by several screens live
    under ``"common."``. Catalogs are loaded on first use.

    Parameters
    ----------
    language : str, optional
        Initial language, one of :data:`SUPPORTED_LANGUAGES`; any
        other value gives :data:`ENGLISH`. Default is :data:`ENGLISH`.
    parent : QObject, optional
        Parent object.

    Attributes
    ----------
    language_changed : pyqtSignal(str)
        Emitted with the new language code after a change, so every
        widget showing text can retranslate itself.
    """

    language_changed = pyqtSignal(str)

    def __init__(self, language: str = ENGLISH, parent=None):
        super().__init__(parent)
        self._language = language if language in SUPPORTED_LANGUAGES else ENGLISH
        self._catalogs: dict[str, dict[str, str]] = {}
        self._reported_missing: set[str] = set()

    @property
    def language(self) -> str:
        """
        Return the current language.

        Returns
        -------
        str
            Language code, one of :data:`SUPPORTED_LANGUAGES`.
        """
        return self._language

    def set_language(self, language: str) -> None:
        """
        Change the current language.

        Parameters
        ----------
        language : str
            Language code, one of :data:`SUPPORTED_LANGUAGES`.
            :attr:`language_changed` is only emitted if it differs from
            the current one.

        Raises
        ------
        ValueError
            If ``language`` is not supported.
        """
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language: {language!r}")
        if language == self._language:
            return
        self._language = language
        self.language_changed.emit(language)

    def _catalog(self, language: str) -> dict[str, str]:
        """
        Return the catalog of a language, loading it on first use.

        Parameters
        ----------
        language : str
            Language code.

        Returns
        -------
        dict of str to str
            The catalog.
        """
        if language not in self._catalogs:
            self._catalogs[language] = load_catalog(language)
        return self._catalogs[language]

    def translate(self, key: str, **kwargs: object) -> str:
        """
        Translate a key into the current language.

        Parameters
        ----------
        key : str
            Namespaced key, e.g. ``"viewer.last_modified"``.
        **kwargs : object
            Values substituted into the text's ``{placeholders}``.

        Returns
        -------
        str
            The text in the current language, else in
            :data:`FALLBACK_LANGUAGE`, else ``key`` itself; a missing
            key is logged once as a warning.
        """
        text = self._catalog(self._language).get(key)
        if text is None:
            text = self._catalog(FALLBACK_LANGUAGE).get(key)
        if text is None:
            if key not in self._reported_missing:
                self._reported_missing.add(key)
                _logger.warning("Missing translation key: %r", key)
            return key
        if not kwargs:
            return text
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError, ValueError) as exc:
            _logger.warning("Cannot format translation %r: %s", key, exc)
            return text


# Shared instance: every widget follows the same language.
translator = Translator()