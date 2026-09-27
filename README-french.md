# Bippass

Bippass est un gestionnaire de mots de passe local et hors ligne, avec une interface de bureau PyQt5, construit au-dessus de [Artezaru/pyaescbc](https://github.com/Artezaru/pyaescbc) (chiffrement AES-CBC avec contrôle d'intégrité HMAC).

Tout est stocké dans un unique fichier de coffre-fort chiffré, sur votre propre machine — rien n'est envoyé vers un serveur, aucune connexion internet n'est nécessaire.

## Fonctionnalités

- **Coffres-forts** : créez ou ouvrez un ou plusieurs fichiers de coffre-fort chiffrés, chacun protégé par ses propres identifiants.
- **Éléments** : stockez des identifiants de connexion, mots de passe, sites web, adresses email, numéros de téléphone, secrets TOTP (double authentification), et champs personnalisés par entrée.
- **Chiffrement là où c'est important** : les mots de passe et les secrets TOTP sont chiffrés au repos, et déchiffrés en mémoire uniquement lorsque vous les consultez ou les copiez réellement.
- **Générateur de mots de passe** : mots de passe aléatoires (classes de caractères et longueur configurables) ou phrases de passe faciles à retenir (mots de dictionnaire + chiffres), en anglais, français ou espagnol.
- **Codes TOTP** : codes à 6 chiffres en direct avec compte à rebours, calculés localement (sans service externe).
- **Champs à copie en un clic** : cliquez sur une valeur pour la copier dans le presse-papiers ; double-cliquez sur un site web, un email ou un numéro de téléphone pour l'ouvrir directement dans votre navigateur, client mail ou numéroteur.
- **Thème clair/sombre** et niveau de zoom de l'interface ajustable, mémorisés entre les sessions.
- **Icônes par élément**, avec une icône par défaut intégrée et la possibilité d'utiliser vos propres images.

## Installation

### Exécutables préconstruits (recommandé pour la plupart des utilisateurs)

Téléchargez la dernière version pour votre plateforme depuis la [page des Releases](https://github.com/Artezaru/bippass/releases) :

- **Windows** : téléchargez et lancez directement `bippass-windows.exe` — aucune installation nécessaire.
- **Linux (Debian/Ubuntu)** : téléchargez le paquet `.deb` et installez-le avec :
  ```bash
  sudo dpkg -i bippass_*.deb
  ```
  Bippass apparaîtra alors dans votre menu d'applications, ou peut être lancé depuis un terminal avec `bippass`.

### Depuis les sources (développeurs)

Nécessite Python 3.10 ou une version ultérieure.

```bash
git clone https://github.com/Artezaru/bippass.git
cd bippass
pip install .
```

Lancez-le avec :

```bash
python -m bippass
```

## Construire les exécutables vous-même

Bippass utilise [PyInstaller](https://pyinstaller.org/) pour produire des exécutables autonomes. Depuis la racine du projet :

```bash
pip install pyinstaller
pyinstaller --name bippass --windowed --onefile \
    --add-data "bippass/resources:bippass/resources" \
    --collect-all PyQt5 \
    bippass/__main__.py
```

(Sur Windows, remplacez le `:` dans `--add-data` par `;`.)

Un workflow GitHub Actions est inclus (`.github/workflows/build.yml`) qui construit automatiquement les exécutables Windows et Linux et les publie dans une Release GitHub à chaque poussée d'un tag `v*`.

## Licence

Bippass est un logiciel libre, sous licence **GNU General Public License v3.0 ou ultérieure** — voir [LICENSE](LICENSE) pour le texte complet.

## Contribuer

Les rapports de bugs et les pull requests sont les bienvenus — merci d'ouvrir d'abord une issue sur le [tracker](https://github.com/Artezaru/bippass/issues) pour discuter de tout changement significatif.