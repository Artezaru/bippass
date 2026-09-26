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

class PasswordManagerError(Exception):
    """Base exception for password manager errors."""

class VaultNotFoundError(PasswordManagerError):
    """Raised when a requested vault does not exist."""

class VaultAlreadyExistsError(PasswordManagerError):
    """Raised when attempting to add a vault with a name that already exists."""

class ItemNotFoundError(PasswordManagerError):
    """Raised when a requested item does not exist."""

class ItemAlreadyExistsError(PasswordManagerError):
    """Raised when attempting to add an item with a UUID that already exists."""

class PrimaryPasswordError(PasswordManagerError):
    """Raised when the primary credentials are invalid."""

class SecondaryPasswordError(PasswordManagerError):
    """Raised when the secondary credentials are invalid."""

class CorruptedBase64Error(PasswordManagerError):
    """Raised when Base64 data is malformed or cannot be decoded."""

class CorruptedUtf8Error(PasswordManagerError):
    """Raised when data cannot be encoded to or decoded from UTF-8."""
