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

import base64
import binascii
import hashlib
import hmac
import struct
import time


def generate_totp_code(
    secret: bytearray, digits: int = 6, period: int = 30
) -> tuple[str, int]:
    """
    Compute the current TOTP code from a decrypted secret.

    Parameters
    ----------
    secret : bytearray
        Decrypted TOTP secret, UTF-8 encoded, in Base32 format
        (e.g. ``b"JBSWY3DPEHPK3PXP"``).
    digits : int, optional
        Number of digits in the generated code (default: 6).
    period : int, optional
        Validity duration of a code, in seconds (default: 30).

    Returns
    -------
    tuple of (str, int)
        The current TOTP code (zero-padded if needed) and the number
        of seconds remaining before the next renewal.

    Raises
    ------
    ValueError
        If the secret is not valid Base32.

    Notes
    -----
    Implementation of RFC 6238 (TOTP) on top of RFC 4226 (HOTP),
    using SHA1, with no external dependency (standard library only:
    ``hmac``, ``hashlib``, ``struct``, ``base64``).
    """
    try:
        secret_str = bytes(secret).decode("utf-8").strip().replace(" ", "").upper()
        padding = (-len(secret_str)) % 8
        key = base64.b32decode(secret_str + "=" * padding)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid TOTP secret (Base32 expected).") from exc

    now = int(time.time())
    counter = now // period
    remaining = period - (now % period)

    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (
        10**digits
    )

    return str(code_int).zfill(digits), remaining
