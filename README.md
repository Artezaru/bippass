# bippass

bippass is a local, offline password manager with a PyQt5 desktop interface, built on top of [Artezaru/pyaescbc](https://github.com/Artezaru/pyaescbc) (AES-CBC encryption with HMAC integrity checking).

Everything is stored in a single encrypted file on your own machine: nothing is sent to a server, and no internet connection is required.

![bippass interface](https://raw.githubusercontent.com/Artezaru/bippass/master/bippass/resources/ui.png)

## Features

- **Profiles, vaults and items**: each profile is one encrypted file, organized into vaults (with their own icon and color) holding your items.
- **Rich items**: logins, passwords, websites, email addresses, phone numbers, TOTP secrets and custom fields, each with as many values as you need.
- **Two layers of encryption**: the whole file is encrypted with your primary password, and passwords, TOTP secrets and secret custom fields are encrypted again with your secondary password.
- **Password generator**: random passwords (length and character classes of your choice) or memorable passphrases (words and digits) in English, French or Spanish.
- **TOTP codes**: live 6-digit codes with their countdown, computed locally.
- **Click to copy**: click any value to copy it; double-click a website, email address or phone number to open it in your browser, mail client or dialer.
- **Organize quickly**: search, sort (alphabetic, alphanumeric or by date), duplicate, and drag & drop items between vaults.
- **Item icons**: pick a bundled logo from a searchable list, or use any image of your own.
- **Export & import**: share a selection of items as a standalone encrypted file, protected by its own passwords.
- **Auto-lock**: after a configurable period of inactivity, bippass saves your changes and closes, clearing its keys from memory.
- **Light/dark theme**, adjustable zoom and **3 languages** (English, French, Spanish), switchable on the fly.
- **Built-in help**: a complete guide to every button, menu and keyboard shortcut, in your language.

## How your data is protected

A profile is protected by two passwords:

- the **primary password** decrypts the profile file;
- the **secondary password** decrypts the individual secrets inside it (passwords, TOTP secrets, secret custom fields), which stay encrypted in memory until you display or copy them.

Nothing is written to disk until you save (the Save button turns orange while there are unsaved changes), close the window, or the inactivity timer fires. When bippass closes, the credentials are cleared from memory.

> **There is no password recovery.** If you lose your primary or secondary password, the profile cannot be decrypted. Keep them safe, and back up your profile files regularly.

## Installing

### Prebuilt executables (recommended)

Download the latest release for your platform from the [Releases page](https://github.com/Artezaru/bippass/releases):

- **Windows**: download and run `bippass-windows.exe` directly, no installation needed.
- **Linux (Debian/Ubuntu)**: download the `.deb` package and install it with:
  ```bash
  sudo dpkg -i bippass_*.deb
  ```
  bippass then appears in your applications menu, or can be launched from a terminal with `bippass`.

### From source (developers)

Requires Python 3.10 or later.

```bash
git clone https://github.com/Artezaru/bippass.git
cd bippass
pip install .
```

Run it with:

```bash
python -m bippass
```

## Getting started

1. On first launch, choose **Create a new profile** and pick a username: the profile is saved as `~/bippass/<username>.encrypted`.
2. Choose a primary password, then a secondary password.
3. Create a vault with **+ New vault**, then add items to it with **+ New item**.

Next time, pick your profile from the list (or browse for a profile file stored elsewhere) and enter both passwords.

## Help

The complete user guide is built into bippass: open **⚙ Settings → Help** in the toolbar. It details every button, menu and keyboard shortcut, and is shown in the language of the interface (English, French or Spanish), so it works offline like the rest of the application.

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+S` | Save |
| `Ctrl+K` | Save and exit |
| `Ctrl +` / `Ctrl =` | Zoom in |
| `Ctrl -` | Zoom out |
| `Ctrl 0` | Reset zoom |
| `Ctrl+A` | Select every item of the list (to drag them to another vault) |
| `Enter` / double-click | Open the selected item |

## Where your files are

| Path | Content |
| --- | --- |
| `~/.bippass/profiles/<username>.encrypted` | Your profiles: **back up this folder**. |
| `~/.bippass/recent.json` | The last profile opened, to pre-fill the launch screen. |
| `~/.bippass/settings.json` | The theme shown on the launch screen. |

Theme, language and auto-lock delay are otherwise stored inside each profile, encrypted with it.

## License

bippass is free software, licensed under the **GNU General Public License v3.0 or later**. See [LICENSE](LICENSE) for the full text.

## Contributing

Bug reports and pull requests are welcome. Please open an issue on the [tracker](https://github.com/Artezaru/bippass/issues) first to discuss any significant change.
