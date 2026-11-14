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

from typing import TypeAlias, TypedDict, Literal, List

ClearString: TypeAlias = str
ClearSecretBytes: TypeAlias = bytearray # Secrets to erase
CryptedBase64String: TypeAlias = str

ClearStringList: TypeAlias = List[ClearString]
ClearSecretBytesList: TypeAlias = List[ClearSecretBytes]
CryptedBase64StringList: TypeAlias = List[CryptedBase64String]

#: Predefined clear fields of an item (see :class:`Item`).
ClearField: TypeAlias = Literal["logins", "websites", "emails", "phones"]

#: Predefined encrypted fields of an item.
SecretField: TypeAlias = Literal["passwords", "totps"]

#: Predefined fields of an item.
ItemField: TypeAlias = Literal[
    "logins", "websites", "emails", "phones",
    "passwords", "totps",
]

#: Kind of a custom field, as serialized (see :class:`FieldKind`).
CustomKind: TypeAlias = Literal["clear", "encrypted"]

class ItemMetadataData(TypedDict):
    uuid: str
    name: ClearString | None
    creation_date: ClearString
    modification_date: ClearString

class ItemFieldsData(TypedDict):
    logins: ClearStringList
    websites: ClearStringList
    emails: ClearStringList
    phones: ClearStringList
    passwords: CryptedBase64StringList
    totps: CryptedBase64StringList

class CustomFieldData(TypedDict):
    id: str
    name: ClearString
    kind: CustomKind
    values: ClearStringList | CryptedBase64StringList

class ItemGuiData(TypedDict):
    icon: ClearString | None
    color: ClearString | None

class ItemData(TypedDict):
    """Serialized item, format version 3 (see :meth:`Item.to_dict`)."""
    metadata: ItemMetadataData
    fields: ItemFieldsData
    customs: List[CustomFieldData]
    gui: ItemGuiData

class VaultMetadataData(TypedDict):
    uuid: str
    name: ClearString | None
    creation_date: ClearString
    modification_date: ClearString

class VaultGuiData(TypedDict):
    icon: ClearString | None
    color: ClearString | None

class VaultData(TypedDict):
    """Serialized vault, format version 3 (see :meth:`Vault.to_dict`)."""
    metadata: VaultMetadataData
    items: List[ItemData]
    gui: VaultGuiData

class ManagerMetadataData(TypedDict):
    uuid: str
    username: ClearString | None
    creation_date: ClearString
    modification_date: ClearString

class PreferencesData(TypedDict):
    theme: ClearString | None
    language: ClearString | None
    lock_timer_s: int

class PayloadData(TypedDict):
    """Decrypted content of a file, format version 3 (see :meth:`PasswordManager.to_bytes`)."""
    metadata: ManagerMetadataData
    secondary_key: CryptedBase64String
    vaults: List[VaultData]
    preferences: PreferencesData

class EnvelopeData(TypedDict):
    """Outer, unencrypted structure of a file, format version 3."""
    format: Literal["bippass"]
    version: int
    label: ClearString | None
    primary_key: CryptedBase64String
    payload: CryptedBase64String
