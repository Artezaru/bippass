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

Generate a test profile filled with fake data and edge cases.

The profile is protected by the primary password ``1234`` and the
secondary password ``5678``.

Besides ordinary items, the profile deliberately holds the cases that
are easy to get wrong:

- **multiple values**: items with several logins, websites, emails,
  phones, passwords and TOTP secrets;
- **name conflicts**: two vaults named ``Personal``; two items named
  ``Example Mail`` in the same vault; custom fields sharing a name
  (``PIN`` twice), named like a predefined field (``password``,
  ``totp``) or like a reference (``c2``), a name ending with a number
  (``Code 2``), the same name for a clear and an encrypted field;
- **names that look like something else**: items named ``1``, ``2`` and
  ``42``, a vault named ``3``, a vault named ``..``, an item named
  ``cafe`` (hexadecimal, like a UUID prefix);
- **unusual names**: no name at all, spaces, accents, rich markup
  (``[red]not red[/]``), an emoji, a very long name;
- **empty things**: an empty vault, an item with no field, custom fields
  with no value (clear and encrypted);
- **display settings**: colors and a tiny icon.

Usage::

    python examples/make_test_profile.py                 # ./test_profile.bippass
    python examples/make_test_profile.py out.bippass     # chosen path
    python examples/make_test_profile.py --install       # into ~/.bippass/profiles/

"""

from __future__ import annotations

import argparse
from pathlib import Path

from bippass.core.manager import PasswordManager
from bippass.core.profiles import ensure_profiles_dir, profile_path
from bippass.core.types import SecretField


PRIMARY_PASSWORD = "1234"
SECONDARY_PASSWORD = "5678"

#: A 1x1 transparent PNG, as a data URL, to have at least one icon.
TINY_ICON = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)

#: Fake content, as a list of (vault name, items) so that two vaults can
#: share a name. Each item is a dict with an optional "name" (``None``
#: for no name), the predefined fields as lists, "customs" as
#: (name, kind, values), and optional "color" / "icon".
DATA: list[tuple[str | None, list[dict]]] = [
    ("Personal", [
        {
            "name": "Example Mail",
            "logins": ["alice"],
            "websites": ["https://mail.example.com"],
            "emails": ["alice@example.com"],
            "passwords": ["correct-horse-battery-staple"],
            "totps": ["JBSWY3DPEHPK3PXP"],
            "customs": [
                ("Recovery codes", "encrypted", ["1111-2222", "3333-4444", "5555-6666"]),
                ("Note", "clear", ["Main personal mailbox"]),
            ],
            "color": "#3B82F6",
            "icon": TINY_ICON,
        },
        {
            # Same name as the previous item, same vault.
            "name": "Example Mail",
            "logins": ["alice.old"],
            "websites": ["https://old-mail.example.com"],
            "passwords": ["old-mail-password"],
            "customs": [("Note", "clear", ["Old mailbox, same name on purpose"])],
        },
        {
            "name": "Multi Everything",
            "logins": ["alice", "alice.martin", "a.martin"],
            "websites": ["https://one.example.com", "https://two.example.com",
                         "three.example.com", "https://four.example.com/login?next=/"],
            "emails": ["alice@example.com", "alice.martin@example.org"],
            "phones": ["+33 1 23 45 67 89", "+33 6 12 34 56 78"],
            "passwords": ["first-password", "second-password", "third-password"],
            "totps": ["JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                      "MFRGGZDFMZTWQ2LK"],
            "customs": [
                ("password", "encrypted", ["custom-named-password"]),
                ("c2", "encrypted", ["custom-named-c2"]),
                ("PIN", "encrypted", ["1111"]),
                ("PIN", "encrypted", ["2222"]),
                ("Code", "encrypted", ["code-1", "code-2"]),
                ("Code 2", "encrypted", ["field-named-code-2"]),
                ("Security question", "clear", ["First pet?"]),
                ("Security question", "encrypted", ["Rex"]),
                ("totp", "clear", ["custom named totp, in clear"]),
                ("Empty secret", "encrypted", []),
                ("Empty note", "clear", []),
            ],
            "color": "#F59E0B",
        },
        {
            "name": "Example Bank",
            "logins": ["alice.martin"],
            "websites": ["https://bank.example.com"],
            "phones": ["+33 1 23 45 67 89"],
            "passwords": ["Tr0ub4dor&3"],
            "customs": [
                ("Card PIN", "encrypted", ["0000"]),
                ("Advisor", "clear", ["M. Dupont"]),
            ],
            "color": "#10B981",
        },
        {
            "name": "Été Streaming",
            "logins": ["alice@example.com"],
            "websites": ["https://stream.example.org"],
            "passwords": ["summer-2026", "old-summer-2025"],
        },
        # Names that look like numbers: "cd 1" means "the 1st item".
        {"name": "1", "logins": ["item-named-1"], "passwords": ["pw-of-item-named-1"]},
        {"name": "2", "logins": ["item-named-2"]},
        {"name": "42", "logins": ["item-named-42"], "passwords": ["pw-of-item-named-42"]},
        # Hexadecimal name, like a UUID prefix.
        {"name": "cafe", "logins": ["item-named-cafe"]},
        # No name at all, and no field at all.
        {"name": None, "logins": ["nameless"]},
        {"name": "Empty item"},
    ]),
    ("Work", [
        {
            "name": "Example Git",
            "logins": ["amartin", "alice-bot"],
            "websites": ["https://git.example.com"],
            "emails": ["alice.martin@corp.example.com"],
            "passwords": ["git-Pa55word!"],
            "totps": ["GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"],
            "customs": [
                ("SSH key passphrase", "encrypted", ["ssh-passphrase-42"]),
                ("Team", "clear", ["Platform", "Infra"]),
            ],
        },
        {
            "name": "Example VPN",
            "logins": ["amartin"],
            "websites": ["vpn.corp.example.com"],
            "passwords": ["vpn-secret"],
        },
        # Same name as an item of another vault: allowed, and fine.
        {"name": "Example Mail", "logins": ["a.martin@corp.example.com"],
         "passwords": ["work-mail-password"]},
        # Unusual characters.
        {"name": "[red]not red[/]", "logins": ["markup-in-name"]},
        {"name": "\U0001F511 Keys", "logins": ["emoji-in-name"]},
        {"name": "A very long item name that keeps going to check how tables cope "
                 "with it in the terminal", "logins": ["long-name"]},
    ]),
    # Same name as the first vault.
    ("Personal", [
        {"name": "Second Personal Item", "logins": ["in-the-second-personal-vault"],
         "passwords": ["second-vault-password"]},
    ]),
    # A vault named like a number, one named like "cd ..", one with no name.
    ("3", [{"name": "In vault named 3", "logins": ["vault-named-3"]}]),
    ("..", [{"name": "In vault named ..", "logins": ["vault-named-dotdot"]}]),
    (None, [{"name": "In nameless vault", "logins": ["nameless-vault"]}]),
    ("Empty vault", []),
]


def build() -> PasswordManager:
    """
    Build the test manager in memory.

    Returns
    -------
    PasswordManager
        An unlocked and decrypted manager holding :data:`DATA`.
    """
    manager = PasswordManager.create(
        "alice",
        bytearray(PRIMARY_PASSWORD, "utf-8"),
        bytearray(SECONDARY_PASSWORD, "utf-8"),
        label="Test profile",
    )
    manager.set_language("fr")

    for vault_name, items in DATA:
        vault = manager.add_empty_vault(vault_name)
        for spec in items:
            item = manager.add_empty_item(vault.uuid)
            if spec.get("name") is not None:
                item.set_name(spec["name"])
            for field in ("logins", "websites", "emails", "phones"):
                item.set(field, spec.get(field, []))
            secret_fields: tuple[SecretField, ...] = ("passwords", "totps")
            for secret_field in secret_fields:
                item.set(
                    secret_field,
                    [bytearray(v, "utf-8") for v in spec.get(secret_field, [])],
                    data_key=manager.data_key,
                )
            for name, kind, values in spec.get("customs", []):
                if kind == "encrypted":
                    item.add_custom(name, kind, [bytearray(v, "utf-8") for v in values],
                                    data_key=manager.data_key)
                else:
                    item.add_custom(name, kind, values)
            if "color" in spec:
                item.set_color(spec["color"])
            if "icon" in spec:
                item.set_icon(spec["icon"])
    return manager


def main() -> None:
    """Parse the command line, build the profile and save it."""
    parser = argparse.ArgumentParser(
        description="Generate a bippass test profile with edge cases (passwords 1234 / 5678)."
    )
    parser.add_argument("path", nargs="?", default="test_profile.bippass",
                        help="destination file (default: ./test_profile.bippass)")
    parser.add_argument("--install", action="store_true",
                        help="save into the default profile directory instead")
    args = parser.parse_args()

    print("Generating the test profile (key derivation takes a few seconds)...")
    manager = build()
    try:
        if args.install:
            ensure_profiles_dir()
            path = profile_path(manager.uuid)
        else:
            path = Path(args.path)
        manager.save(path)
        counts = (len(manager.vault_uuids()), len(manager.item_uuids()))
    finally:
        manager.close()

    print(f"Saved to {path} ({counts[0]} vaults, {counts[1]} items)")
    print(f"Primary password  : {PRIMARY_PASSWORD}")
    print(f"Secondary password: {SECONDARY_PASSWORD}")


if __name__ == "__main__":
    main()
