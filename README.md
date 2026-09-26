# Bippass

Bippass is a local, offline password manager with a PyQt5 desktop interface, built on top of [Artezaru/pyaescbc](https://github.com/Artezaru/pyaescbc) (AES-CBC encryption with HMAC integrity checking).

Everything is stored in a single encrypted vault file on your own machine — nothing is sent to a server, nothing requires an internet connection.

## Features

- **Vaults**: create or open one or more encrypted vault files, each protected by its own credentials.
- **Items**: store logins, passwords, websites, email addresses, phone numbers, TOTP (two-factor) secrets, and custom fields per entry.
- **Encryption where it matters**: passwords and TOTP secrets are encrypted at rest; only decrypted in memory when you actually view or copy them.
- **Password generator**: random passwords (configurable character classes and length) or memorable passphrases (dictionary words + digits), in English, French or Spanish.
- **TOTP codes**: live 6-digit codes with a countdown timer, computed locally (no external service).
- **Click-to-copy fields**: click any value to copy it to the clipboard; double-click a website, email or phone to open it directly in your browser, mail client or dialer.
- **Light/dark theme** and an adjustable interface zoom level, remembered between runs.
- **Per-item icons**, with a bundled default icon and support for your own image files.

## Installing

### Prebuilt executables (recommended for most users)

Download the latest release for your platform from the [Releases page](https://github.com/Artezaru/bippass/releases):

- **Windows**: download and run `bippass-windows.exe` directly — no installation needed.
- **Linux (Debian/Ubuntu)**: download the `.deb` package and install it with:
  ```bash
  sudo dpkg -i bippass_*.deb
  ```
  Bippass will then appear in your applications menu, or can be launched from a terminal with `bippass`.

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

## Building the executables yourself

Bippass uses [PyInstaller](https://pyinstaller.org/) to produce standalone executables. From the project root:

```bash
pip install pyinstaller
pyinstaller --name bippass --windowed --onefile \
    --add-data "bippass/resources:bippass/resources" \
    --collect-all PyQt5 \
    bippass/__main__.py
```

(On Windows, replace the `:` in `--add-data` with `;`.)

A GitHub Actions workflow is included (`.github/workflows/build.yml`) that builds Windows and Linux executables automatically and publishes them to a GitHub Release whenever a `v*` tag is pushed.

## License

Bippass is free software, licensed under the **GNU General Public License v3.0 or later** — see [LICENSE](LICENSE) for the full text.

## Contributing

Bug reports and pull requests are welcome — please open an issue on the [tracker](https://github.com/Artezaru/bippass/issues) first to discuss any significant change.
