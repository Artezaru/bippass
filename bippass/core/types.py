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

from typing import TypeAlias, TypedDict, Dict, Tuple, Literal, List

ClearString: TypeAlias = str
ClearSecretBytes: TypeAlias = bytearray # Secrets to erase
CryptedBase64String: TypeAlias = str

ClearStringList: TypeAlias = List[ClearString]
ClearSecretBytesList: TypeAlias = List[ClearSecretBytes]
CryptedBase64StringList: TypeAlias = List[CryptedBase64String]

ItemKind: TypeAlias = Literal[
    "SCALAR", "ENCRYPTED",
    "SCALAR LIST", "ENCRYPTED LIST"
]

CustomFieldData: TypeAlias = Tuple[
    ItemKind,
    ClearString
    | CryptedBase64String
    | ClearStringList
    | CryptedBase64StringList,
]
CustomFieldsMap: TypeAlias = Dict[str, CustomFieldData]

class ItemData(TypedDict):
    item_name: ClearString | None
    item_date: ClearString | None
    icon: ClearString | None
    logins: ClearStringList | None
    passwords: CryptedBase64StringList | None
    totps: CryptedBase64StringList | None
    websites: ClearStringList | None
    phones: ClearStringList | None
    emails: ClearStringList | None
    custom: CustomFieldsMap | None

class VaultData(TypedDict):
    icon: ClearString | None
    icon_color: ClearString | None
    items: dict[str, ItemData]

class Metadata(TypedDict):
    version: int
    username: ClearString | None
    theme: ClearString | None
    language: ClearString | None
    close_timer_s: int | None

class PasswordManagerData(TypedDict):
    metadata: Metadata
    auth: CryptedBase64String
    vaults: dict[str, VaultData]