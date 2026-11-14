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

# BACKWARD COMPATIBILITY -- tests of `v2_to_v3`, removed with this package.
# Run with: python -m pytest bippass/backward

from __future__ import annotations

import base64
import json

import pyaescbc
import pytest

from bippass.backward import v2_to_v3
from bippass.core.manager import PasswordManager


def P(text: str) -> bytearray:
    return bytearray(text, "utf-8")


def _secret(value: str) -> str:
    return base64.b64encode(pyaescbc.encrypt(P(value), P("sec"))).decode("ascii")


@pytest.fixture
def v2_file(tmp_path):
    content = {
        "metadata": {"version": 1, "username": "alice", "theme": "light", "language": "fr",
                     "close_timer_s": 120},
        "auth": base64.b64encode(pyaescbc.encrypt(bytearray(v2_to_v3._AUTH_MESSAGE), P("sec"))).decode(),
        "vaults": {
            "Perso": {"icon": "missing.png", "icon_color": "#ff0000", "items": {"u1": {
                "item_name": "GitHub", "item_date": "2025-03-01T10:00:00", "icon": None,
                "logins": ["bob"], "passwords": [_secret("hunter2")], "totps": None,
                "websites": ["https://github.com"], "phones": None, "emails": [],
                "custom": {"PIN": ["ENCRYPTED", _secret("1234")],
                           "Codes": ["ENCRYPTED LIST", [_secret("a"), _secret("b")]],
                           "Note": ["SCALAR", "hello"], "Tags": ["SCALAR LIST", ["x", "y"]]},
            }}},
            "Pro": {"icon": None, "icon_color": None, "items": {}},
        },
    }
    path = tmp_path / "old.encrypted"
    path.write_bytes(pyaescbc.encrypt(P(json.dumps(content)), P("prim")))
    return path


def test_wrong_passwords_write_nothing(v2_file, tmp_path):
    with pytest.raises(v2_to_v3.WrongPrimaryPasswordError):
        v2_to_v3.convert(v2_file, P("bad"), P("sec"), destination=tmp_path / "x.bippass")
    with pytest.raises(v2_to_v3.WrongSecondaryPasswordError):
        v2_to_v3.convert(v2_file, P("prim"), P("bad"), destination=tmp_path / "x.bippass")
    assert not (tmp_path / "x.bippass").exists()


def test_convert(v2_file, tmp_path):
    new = v2_to_v3.convert(v2_file, P("prim"), P("sec"), destination=tmp_path / "new.bippass")
    assert v2_file.exists()
    manager = PasswordManager.read(new)
    assert manager.label == "alice"
    manager.unlock(P("prim"))
    manager.decrypt(P("sec"))
    assert (manager.get_username(), manager.get_theme(), manager.get_language(),
            manager.get_lock_timer_s()) == ("alice", "light", "fr", 120)
    perso, pro = manager.get_vaults()
    assert perso.get_name() == "Perso" and perso.get_icon() is None and len(pro) == 0
    (item,) = list(perso)
    key = manager.data_key
    assert item.get_name() == "GitHub" and item.creation_date.startswith("2025-03-01T10:00:00")
    assert item.get("logins") == ["bob"] and item.get("passwords", data_key=key) == [b"hunter2"]
    customs = {item.custom_name(c): c for c in item.custom_ids()}
    assert item.get_custom(customs["Codes"], data_key=key) == [b"a", b"b"]
    assert item.get_custom(customs["PIN"], data_key=key) == [b"1234"]
    assert item.get_custom(customs["Note"]) == ["hello"] and item.get_custom(customs["Tags"]) == ["x", "y"]


def test_not_a_v2_file(tmp_path):
    path = tmp_path / "bad.encrypted"
    path.write_bytes(pyaescbc.encrypt(P("[]"), P("prim")))
    with pytest.raises(v2_to_v3.ConversionError):
        v2_to_v3.convert(path, P("prim"), P("sec"), destination=tmp_path / "x.bippass")
