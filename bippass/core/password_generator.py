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

import functools
import math
import re
import secrets
import string
from dataclasses import dataclass
from enum import Enum, auto
from importlib import resources
from types import MappingProxyType
from typing import Mapping


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


#: A dice-indexed line: a run of dice faces (1-6), whitespace, a word.
_DICE_LINE = re.compile(r"^([1-6]+)\s+(\S+)$")


@dataclass(frozen=True)
class Wordlist:
    """
    A parsed word list.

    Two file formats are supported (see :func:`parse_wordlist`):

    - **dice-indexed** (EFF / diceware format): every line is
      ``<dice faces><whitespace><word>``, e.g. ``11111\tabacus`` or
      ``11111 abaisse``. Words are then drawn by rolling
      :attr:`dice_count` virtual six-sided dice and looking the result
      up, exactly as the diceware method does with real dice;
    - **plain**: one word per line, drawn uniformly with
      :func:`secrets.choice`.

    Attributes
    ----------
    words : tuple of str
        Every word, in file order.

    dice_count : int or None
        Number of dice per word for a dice-indexed list (5 for the
        EFF large list), ``None`` for a plain list.

    by_dice : Mapping of str to str or None
        Dice faces (e.g. ``"43463"``) to word, for a dice-indexed
        list; ``None`` for a plain list.
    """

    words: tuple[str, ...]
    dice_count: int | None = None
    by_dice: Mapping[str, str] | None = None

    @property
    def size(self) -> int:
        """Number of distinct words that can be drawn."""
        return len(self.words)

    @property
    def bits_per_word(self) -> float:
        """Entropy contributed by one uniformly drawn word, in bits."""
        return math.log2(self.size)

    def draw(self) -> str:
        """
        Draw one word uniformly at random.

        Returns
        -------
        str
            For a dice-indexed list, the word matching
            :attr:`dice_count` rolls of :func:`roll_dice`; for a plain
            list, :func:`secrets.choice` over :attr:`words`.
        """
        if self.by_dice is not None:
            assert self.dice_count is not None  # set together with by_dice
            return self.by_dice[roll_dice(self.dice_count)]
        return secrets.choice(self.words)


def roll_dice(count: int) -> str:
    """
    Roll ``count`` virtual six-sided dice.

    Parameters
    ----------
    count : int
        Number of dice. Must be strictly positive.

    Returns
    -------
    str
        The faces, e.g. ``"43463"`` for ``count=5``.

    Notes
    -----
    Uses :func:`secrets.randbelow`, a cryptographically secure source
    of randomness, so every face (and therefore every word of a
    dice-indexed list) is exactly equally likely.
    """
    if count <= 0:
        raise ValueError("count must be strictly positive.")
    return "".join(str(secrets.randbelow(6) + 1) for _ in range(count))


def parse_wordlist(text: str, name: str = "word list") -> Wordlist:
    """
    Parse the content of a word list file.

    Parameters
    ----------
    text : str
        File content. Empty lines and surrounding whitespace are ignored.

    name : str, optional
        Name used in error messages.

    Returns
    -------
    Wordlist
        Dice-indexed if *every* line starts with dice faces, plain if
        *none* does.

    Raises
    ------
    ValueError
        If the list is empty, mixes both formats, a plain line holds
        more than one word, a word appears twice, or (dice-indexed)
        the dice runs don't all have the same length or don't cover
        every one of the ``6 ** dice_count`` combinations exactly once
        -- any of which would make some words likelier than others.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"The {name} is empty.")

    matches = [m for m in (_DICE_LINE.match(line) for line in lines) if m is not None]

    if len(matches) == len(lines):
        keys = [m.group(1) for m in matches]
        words = tuple(m.group(2) for m in matches)
        dice_count = len(keys[0])
        if any(len(key) != dice_count for key in keys):
            raise ValueError(f"The {name} mixes dice runs of different lengths.")
        if len(set(keys)) != len(keys) or len(keys) != 6 ** dice_count:
            raise ValueError(
                f"The {name} must list each of the {6 ** dice_count} "
                f"combinations of {dice_count} dice exactly once "
                f"({len(set(keys))} distinct found)."
            )
        by_dice = MappingProxyType(dict(zip(keys, words)))
    elif not any(matches):
        if any(len(line.split()) != 1 for line in lines):
            raise ValueError(f"The {name} must hold one word per line.")
        words = tuple(lines)
        dice_count, by_dice = None, None
    else:
        raise ValueError(
            f"The {name} mixes dice-indexed lines and plain lines."
        )

    if len(set(words)) != len(words):
        raise ValueError(f"The {name} contains duplicate words.")

    return Wordlist(words=words, dice_count=dice_count, by_dice=by_dice)


@functools.lru_cache(maxsize=None)
def get_wordlist(language: str) -> Wordlist:
    """
    Load and parse the bundled word list for ``language`` (cached).

    Parameters
    ----------
    language : str
        One of :data:`WORDLIST_LANGUAGES`.

    Returns
    -------
    Wordlist
        The parsed list, read from disk only on the first call.

    Raises
    ------
    ValueError
        If ``language`` is not one of :data:`WORDLIST_LANGUAGES`, or
        the file is invalid (see :func:`parse_wordlist`).

    OSError
        If the word list file cannot be found or read.
    """
    path = _wordlist_path(language)
    with open(path, "r", encoding="utf-8") as f:
        return parse_wordlist(f.read(), name=f"{language!r} word list")


def load_wordlist(language: str) -> tuple[str, ...]:
    """
    Return every word of the bundled word list for ``language``.

    Parameters
    ----------
    language : str
        One of :data:`WORDLIST_LANGUAGES`.

    Returns
    -------
    tuple of str
        The words in file order, without their dice numbers.

    Raises
    ------
    ValueError, OSError
        See :func:`get_wordlist`.
    """
    return get_wordlist(language).words


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
    replacement) from the bundled word list for ``language`` (by rolling
    virtual dice for a dice-indexed EFF-style list, see
    :class:`Wordlist`), each
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

    wordlist = get_wordlist(language)

    chosen = [wordlist.draw() for _ in range(word_count)]
    if capitalize:
        chosen = [word.capitalize() for word in chosen]

    segments = [
        word + "".join(secrets.choice(string.digits) for _ in range(digit_count))
        for word in chosen
    ]

    return separator.join(segments)


def memorable_password_entropy(
    word_count: int,
    *,
    language: str = "en",
    digit_count: int = 0,
) -> float:
    """
    Entropy, in bits, of a passphrase from :func:`generate_memorable_password`.

    Parameters
    ----------
    word_count, language, digit_count
        Same meaning as in :func:`generate_memorable_password`.

    Returns
    -------
    float
        ``word_count * (log2(word list size) + digit_count * log2(10))``.
        Capitalization and the separator are fixed, so they add nothing.
        The attacker is assumed to know the word list and the settings.

    Raises
    ------
    ValueError
        Same conditions as :func:`generate_memorable_password`.
    """
    if word_count <= 0:
        raise ValueError("word_count must be strictly positive.")
    if digit_count < 0:
        raise ValueError("digit_count must not be negative.")
    bits_per_word = get_wordlist(language).bits_per_word
    return word_count * (bits_per_word + digit_count * math.log2(10))


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
