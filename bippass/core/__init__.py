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

from .credentials import Credentials
from .item import Item
from .vault import Vault
from .manager import PasswordManager
from .profiles import profile_path, list_existing_profiles
from .password_generator import generate_random_password, generate_memorable_password
from .totp import generate_totp_code
from .exceptions import (
    PasswordManagerError,
    PrimaryPasswordError,
    SecondaryPasswordError,
    ItemNotFoundError,
    VaultNotFoundError,
    ItemAlreadyExistsError,
    VaultAlreadyExistsError,
    CorruptedBase64Error,
    CorruptedUtf8Error,
)
from .types import (
    ClearString,
    ClearStringList,
    ClearSecretBytes,
    ClearSecretBytesList,
    CryptedBase64String,
    CryptedBase64StringList,
    ItemKind,
    CustomFieldData,
    CustomFieldsMap,
    ItemData,
    VaultData,
    Metadata,
    PasswordManagerData,
)