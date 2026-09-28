# bippass

bippass est un gestionnaire de mots de passe local et hors ligne, doté d'une interface de bureau PyQt5 et construit sur [Artezaru/pyaescbc](https://github.com/Artezaru/pyaescbc) (chiffrement AES-CBC avec contrôle d'intégrité HMAC).

Tout est stocké dans un seul fichier chiffré, sur votre propre machine : rien n'est envoyé à un serveur, et aucune connexion internet n'est nécessaire.

![Interface de bippass](https://raw.githubusercontent.com/Artezaru/bippass/master/bippass/resources/ui.png)

## Fonctionnalités

- **Profils, coffres et éléments** : chaque profil est un fichier chiffré, organisé en coffres (chacun avec son icône et sa couleur) qui contiennent vos éléments.
- **Des éléments complets** : identifiants, mots de passe, sites web, adresses email, numéros de téléphone, secrets TOTP et champs personnalisés, avec autant de valeurs que nécessaire.
- **Deux niveaux de chiffrement** : le fichier entier est chiffré avec votre mot de passe primaire, et les mots de passe, secrets TOTP et champs personnalisés secrets sont chiffrés une seconde fois avec votre mot de passe secondaire.
- **Générateur de mots de passe** : mots de passe aléatoires (longueur et types de caractères au choix) ou phrases de passe faciles à retenir (mots et chiffres), en anglais, français ou espagnol.
- **Codes TOTP** : codes à 6 chiffres affichés en direct avec leur compte à rebours, calculés localement.
- **Copie en un clic** : cliquez sur une valeur pour la copier ; double-cliquez sur un site web, une adresse email ou un numéro de téléphone pour l'ouvrir dans votre navigateur, votre messagerie ou votre application d'appel.
- **Organisation rapide** : recherche, tri (alphabétique, alphanumérique ou par date), duplication, et glisser-déposer des éléments d'un coffre à l'autre.
- **Icônes des éléments** : choisissez un logo fourni dans une liste avec recherche, ou utilisez n'importe quelle image.
- **Export et import** : partagez une sélection d'éléments sous forme de fichier chiffré indépendant, protégé par ses propres mots de passe.
- **Verrouillage automatique** : après une période d'inactivité réglable, bippass enregistre vos modifications et se ferme, en effaçant ses clés de la mémoire.
- **Thème clair/sombre**, zoom réglable et **3 langues** (anglais, français, espagnol), modifiables à la volée.
- **Aide intégrée** : un guide complet de chaque bouton, menu et raccourci clavier, dans votre langue.

## Comment vos données sont protégées

Un profil est protégé par deux mots de passe :

- le **mot de passe primaire** déchiffre le fichier du profil ;
- le **mot de passe secondaire** déchiffre les secrets qu'il contient (mots de passe, secrets TOTP, champs personnalisés secrets), qui restent chiffrés en mémoire jusqu'à ce que vous les affichiez ou les copiiez.

Rien n'est écrit sur le disque tant que vous n'enregistrez pas (le bouton Enregistrer devient orange quand des modifications ne sont pas enregistrées), que vous ne fermez pas la fenêtre, ou que le délai d'inactivité n'est pas écoulé. À la fermeture, bippass efface les identifiants de la mémoire.

> **Aucune récupération de mot de passe n'est possible.** Si vous perdez votre mot de passe primaire ou secondaire, le profil ne peut plus être déchiffré. Conservez-les précieusement, et sauvegardez régulièrement vos fichiers de profil.

## Installation

### Exécutables prêts à l'emploi (recommandé)

Téléchargez la dernière version pour votre système sur la [page des versions](https://github.com/Artezaru/bippass/releases) :

- **Windows** : téléchargez et lancez directement `bippass-windows.exe`, sans installation.
- **Linux (Debian/Ubuntu)** : téléchargez le paquet `.deb` et installez-le avec :
  ```bash
  sudo dpkg -i bippass_*.deb
  ```
  bippass apparaît alors dans le menu des applications, et peut aussi être lancé depuis un terminal avec `bippass`.

### Depuis les sources (développeurs)

Nécessite Python 3.10 ou plus récent.

```bash
git clone https://github.com/Artezaru/bippass.git
cd bippass
pip install .
```

Lancez-le avec :

```bash
python -m bippass
```

## Premiers pas

1. Au premier lancement, choisissez **Créer un nouveau profil** et indiquez un nom d'utilisateur : le profil est enregistré sous `~/bippass/<nom>.encrypted`.
2. Choisissez un mot de passe primaire, puis un mot de passe secondaire.
3. Créez un coffre avec **+ Nouveau coffre**, puis ajoutez-y des éléments avec **+ Nouvel élément**.

Les fois suivantes, choisissez votre profil dans la liste (ou parcourez vos dossiers pour un fichier de profil rangé ailleurs) et saisissez vos deux mots de passe.

## Aide

Le guide d'utilisation complet est intégré à bippass : ouvrez **⚙ Paramètres → Aide** dans la barre d'outils. Il détaille chaque bouton, menu et raccourci clavier, et s'affiche dans la langue de l'interface (anglais, français ou espagnol) ; comme le reste de l'application, il fonctionne hors ligne.

## Raccourcis clavier

| Raccourci | Action |
| --- | --- |
| `Ctrl+S` | Enregistrer |
| `Ctrl+K` | Enregistrer et quitter |
| `Ctrl +` / `Ctrl =` | Zoom avant |
| `Ctrl -` | Zoom arrière |
| `Ctrl 0` | Réinitialiser le zoom |
| `Ctrl+A` | Sélectionner tous les éléments de la liste (pour les déplacer vers un autre coffre) |
| `Entrée` / double-clic | Ouvrir l'élément sélectionné |

## Où sont vos fichiers

| Chemin | Contenu |
| --- | --- |
| `~/.bippass/profiles/<nom>.encrypted` | Vos profils : **sauvegardez ce dossier**. |
| `~/.bippass/recent.json` | Le dernier profil ouvert, pour préremplir l'écran de démarrage. |
| `~/.bippass/settings.json` | Le thème affiché sur l'écran de démarrage. |

Le thème, la langue et le délai de verrouillage sont par ailleurs stockés dans chaque profil, chiffrés avec lui.

## Licence

bippass est un logiciel libre, distribué sous licence **GNU General Public License v3.0 ou ultérieure**. Voir [LICENSE](LICENSE) pour le texte complet.

## Contribuer

Les signalements de bugs et les pull requests sont les bienvenus. Pour tout changement important, ouvrez d'abord un ticket sur le [tracker](https://github.com/Artezaru/bippass/issues) pour en discuter.
