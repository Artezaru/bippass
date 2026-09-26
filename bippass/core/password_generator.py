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

import secrets
import string
from enum import Enum, auto
from importlib import resources


class GeneratorType(Enum):
    """Kind of password :func:`generate` produces."""

    RANDOM = auto()
    MEMORABLE = auto()


#: Special characters offered by default to the random generator.
#: Editable by the caller (e.g. the generator dialog lets the user
#: edit this set before generating) -- passed through as
#: ``special_characters`` to :func:`generate_random_password`.
DEFAULT_SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:,.<>?/"

#: Supported memorable-passphrase languages, one bundled word list
#: file per language under ``resources/words/<language>.txt``.
WORDLIST_LANGUAGES = ("en", "fr", "es")

#: Separator joining words (and the trailing digit run, if any) in a
#: generated memorable passphrase.
DEFAULT_WORD_SEPARATOR = "-"


# ---------------------------------------------------------------------------
# Word list loading
# ---------------------------------------------------------------------------


def _wordlist_path(language: str) -> str:
    """
    Resolve the bundled word list file path for ``language``.

    Parameters
    ----------
    language : str
        One of :data:`WORDLIST_LANGUAGES`.

    Returns
    -------
    str
        Path to ``resources/words/<language>.txt`` inside the
        installed package.

    Raises
    ------
    ValueError
        If ``language`` is not one of :data:`WORDLIST_LANGUAGES`.
    """
    if language not in WORDLIST_LANGUAGES:
        raise ValueError(f"Unsupported wordlist language: {language!r}")

    ref = resources.files("bippass").joinpath("resources/words", f"{language}.txt")
    with resources.as_file(ref) as path:
        return str(path)


def load_wordlist(language: str) -> tuple[str, ...]:
    """
    Load the bundled word list for ``language``.

    Parameters
    ----------
    language : str
        One of :data:`WORDLIST_LANGUAGES`.

    Returns
    -------
    tuple of str
        Every non-empty, stripped line of the word list file, in
        file order (duplicates, if any, are not removed here -- the
        bundled files are expected to already be deduplicated).

    Raises
    ------
    ValueError
        If ``language`` is not one of :data:`WORDLIST_LANGUAGES`, or
        the file is empty.

    OSError
        If the word list file cannot be found or read.
    """
    path = _wordlist_path(language)
    with open(path, "r", encoding="utf-8") as f:
        words = tuple(line.strip() for line in f if line.strip())

    if not words:
        raise ValueError(f"The {language!r} word list is empty.")

    return words


# ---------------------------------------------------------------------------
# Random password
# ---------------------------------------------------------------------------


def generate_random_password(
    length: int,
    *,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_special: bool = False,
    special_characters: str = DEFAULT_SPECIAL_CHARACTERS,
) -> str:
    """
    Generate a password by drawing ``length`` characters uniformly
    (with replacement, independently of one another) from the union
    of every enabled character class.

    Parameters
    ----------
    length : int
        Number of characters to draw. Must be strictly positive.

    use_lowercase : bool, optional
        Include ``a``-``z`` in the draw pool (default: ``True``).

    use_uppercase : bool, optional
        Include ``A``-``Z`` in the draw pool (default: ``True``).

    use_digits : bool, optional
        Include ``0``-``9`` in the draw pool (default: ``True``).

    use_special : bool, optional
        Include ``special_characters`` in the draw pool
        (default: ``False``).

    special_characters : str, optional
        The special character set to draw from when ``use_special``
        is ``True`` (default: :data:`DEFAULT_SPECIAL_CHARACTERS`).
        Passing a caller-edited string is how the character list
        becomes configurable without this function needing to know
        about any particular set.

    Returns
    -------
    str
        The generated password.

    Raises
    ------
    ValueError
        If ``length`` is not strictly positive, or every character
        class is disabled (or ``use_special`` is enabled with an
        empty ``special_characters``), leaving nothing to draw from.

    Notes
    -----
    Draws with :func:`secrets.choice`, a cryptographically secure
    source of randomness (unlike the :mod:`random` module), which
    matters here since the output is meant to be used as an actual
    secret.

    Because each character is drawn independently from the *combined*
    pool rather than guaranteeing at least one character from each
    enabled class, a (astronomically unlikely, but possible) draw
    could technically miss a class entirely for a short password.
    This mirrors how most password generators work and keeps the
    distribution genuinely uniform over the whole pool.
    """
    if length <= 0:
        raise ValueError("length must be strictly positive.")

    charset = ""
    if use_lowercase:
        charset += string.ascii_lowercase
    if use_uppercase:
        charset += string.ascii_uppercase
    if use_digits:
        charset += string.digits
    if use_special:
        charset += special_characters

    if not charset:
        raise ValueError(
            "At least one character class must be enabled, with a "
            "non-empty character set."
        )

    return "".join(secrets.choice(charset) for _ in range(length))


# ---------------------------------------------------------------------------
# Memorable passphrase
# ---------------------------------------------------------------------------


def generate_memorable_password(
    word_count: int,
    *,
    language: str = "en",
    digit_count: int = 0,
    separator: str = DEFAULT_WORD_SEPARATOR,
    capitalize: bool = True,
) -> str:
    """
    Generate a passphrase from ``word_count`` random words drawn (with
    replacement) from the bundled word list for ``language``, each
    immediately followed by its own run of ``digit_count`` random
    digits (not one single trailing digit group).

    Parameters
    ----------
    word_count : int
        Number of words to draw. Must be strictly positive.

    language : str, optional
        One of :data:`WORDLIST_LANGUAGES` (default: ``"en"``).

    digit_count : int, optional
        Number of random digits appended directly after *each* word
        (default: ``0``, no digits appended). Must not be negative.

    separator : str, optional
        String joining the words (each already carrying its own
        digits, if any) together (default:
        :data:`DEFAULT_WORD_SEPARATOR`).

    capitalize : bool, optional
        Capitalize the first letter of each drawn word (default:
        ``True``).

    Returns
    -------
    str
        The generated passphrase, e.g. ``"River42-Falcon17-Marble88"``
        for ``word_count=3, digit_count=2`` -- not
        ``"River-Falcon-Marble-42"``: the digits belong to each word,
        not to one trailing block.

    Raises
    ------
    ValueError
        If ``word_count`` is not strictly positive, ``digit_count`` is
        negative, ``language`` is not one of
        :data:`WORDLIST_LANGUAGES`, or that language's word list is
        empty.

    OSError
        If the word list file cannot be found or read.

    Notes
    -----
    Both the word draws and the digit draws use
    :func:`secrets.choice`, for the same reason as
    :func:`generate_random_password`.
    """
    if word_count <= 0:
        raise ValueError("word_count must be strictly positive.")
    if digit_count < 0:
        raise ValueError("digit_count must not be negative.")

    words = load_wordlist(language)

    chosen = [secrets.choice(words) for _ in range(word_count)]
    if capitalize:
        chosen = [word.capitalize() for word in chosen]

    segments = [
        word + "".join(secrets.choice(string.digits) for _ in range(digit_count))
        for word in chosen
    ]

    return separator.join(segments)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def generate(generator_type: GeneratorType, **kwargs) -> str:
    """
    Generate a password of the requested kind.

    Parameters
    ----------
    generator_type : GeneratorType
        :attr:`GeneratorType.RANDOM` or :attr:`GeneratorType.MEMORABLE`.

    **kwargs
        Forwarded to :func:`generate_random_password` or
        :func:`generate_memorable_password`, matching
        ``generator_type``.

    Returns
    -------
    str
        The generated password.

    Raises
    ------
    ValueError
        If ``generator_type`` is not a :class:`GeneratorType` member,
        or is raised by the underlying generator (see its own
        docstring for the exact conditions).

    Notes
    -----
    Thin convenience wrapper so a caller holding a
    :class:`GeneratorType` (e.g. from a combo box) doesn't need an
    ``if``/``else`` of its own to pick the right function.
    """
    if generator_type is GeneratorType.RANDOM:
        return generate_random_password(**kwargs)
    if generator_type is GeneratorType.MEMORABLE:
        return generate_memorable_password(**kwargs)
    raise ValueError(f"Unknown generator type: {generator_type!r}")
