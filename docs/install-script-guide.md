# Guide du Script d'Installation WebSec

Guide complet d'utilisation du script d'installation automatique `install.sh`.

---

## 📋 Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Fonctionnalités](#fonctionnalités)
3. [Utilisation](#utilisation)
4. [Étapes détaillées](#étapes-détaillées)
5. [Options et personnalisation](#options-et-personnalisation)
6. [Dépannage](#dépannage)
7. [FAQ](#faq)

---

## 🎯 Vue d'ensemble

Le script `install.sh` est un installeur interactif qui automatise le déploiement complet de WebSec en production avec une configuration sécurisée (Linux capabilities, utilisateur non-root).

### Ce que le script fait :

✅ **Vérification des dépendances** système (git, gcc, pkg-config, openssl, redis)
✅ **Installation de Rust** via rustup (si non présent)
✅ **Création de l'utilisateur système** `websec` (non-privilegié)
✅ **Clonage du repository** depuis GitHub ou URL personnalisée
✅ **Compilation avec TLS** (`cargo build --release --features tls`)
✅ **Application des permissions** (chown websec:websec)
✅ **Configuration des capabilities** (`CAP_NET_BIND_SERVICE`)
✅ **Vérification complète** (ownership, capabilities, exécution)
✅ **Installation système optionnelle** (copie vers `/usr/local/bin`)

### Ce que le script NE fait PAS :

❌ Configuration de `/etc/websec/websec.toml` (à faire manuellement)
❌ Configuration des certificats SSL (à faire manuellement)
❌ Installation du service systemd (à faire manuellement)
❌ Configuration d'Apache/Nginx backend (à faire manuellement)

Le script se concentre sur l'installation du binaire. La configuration du système reste manuelle pour vous laisser le contrôle.

---

## ✨ Fonctionnalités

### Mode Interactif

Le script demande **confirmation avant chaque action** :

```
[INFO] Missing dependencies: redis-server libssl-dev

Command to install dependencies:
apt-get update && apt-get install -y redis-server libssl-dev

Do you want to install these dependencies now? [y/N]:
```

Vous pouvez :
- ✅ Accepter l'installation automatique
- ❌ Refuser et installer manuellement
- 📋 Copier la commande affichée pour l'exécuter vous-même

### Détection Automatique

- **Package manager** : Détecte `apt`, `dnf`, `yum`, ou `pacman`
- **Rust existant** : Vérifie l'installation pour l'utilisateur courant
- **Repository existant** : Propose de mettre à jour si déjà cloné
- **User websec** : Vérifie si l'utilisateur existe déjà

### Gestion des Erreurs

- Vérification **root/sudo** obligatoire
- Validation de chaque étape avant de continuer
- **Exit immédiat** en cas d'erreur critique
- Messages d'erreur **clairs et colorés**

---

## 🚀 Utilisation

### Méthode 1 : Depuis le Repository Cloné

Si vous avez déjà cloné WebSec :

```bash
cd /path/to/websec
sudo bash install.sh
```

### Méthode 2 : Installation Directe (curl)

Pour une installation rapide depuis GitHub :

```bash
curl -sSL https://raw.githubusercontent.com/yrbane/websec/main/install.sh | sudo bash
```

### Méthode 3 : Téléchargement puis Exécution

Pour inspecter le script avant exécution :

```bash
curl -sSL https://raw.githubusercontent.com/yrbane/websec/main/install.sh -o install.sh
cat install.sh  # Inspecter le script
chmod +x install.sh
sudo ./install.sh
```

---

## 📝 Étapes Détaillées

### Étape 1 : Vérification Root

```
[INFO] This script must be run as root (use sudo)
```

Le script nécessite `sudo` car il doit :
- Installer des packages système
- Créer un utilisateur système
- Modifier des permissions système

### Étape 2 : Vérification des Dépendances

```
[INFO] Checking system dependencies...
[✓] All dependencies are already installed
```

**Dépendances vérifiées** :
- `git` : Clonage du repository
- `gcc` / `build-essential` : Compilation Rust
- `pkg-config` : Détection des bibliothèques
- `libssl-dev` / `openssl-devel` : Support TLS
- `redis-server` : Stockage distribué (optionnel mais recommandé)

**Si manquant** :
```
[!] Missing dependencies: redis-server libssl-dev
Command to install dependencies:
apt-get update && apt-get install -y redis-server libssl-dev

Do you want to install these dependencies now? [y/N]:
```

### Étape 3 : Installation de Rust

```
[INFO] Checking Rust installation...
[✓] Rust is already installed: rustc 1.75.0
```

Si Rust n'est pas installé :
```
[!] Rust is not installed
Command to install Rust:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

Do you want to install Rust now? [y/N]:
```

**Important** : Le script installe Rust pour l'utilisateur qui exécute sudo (via `$SUDO_USER`), pas pour root.

### Étape 4 : Création de l'Utilisateur

```
[INFO] Checking websec system user...
[✓] User 'websec' already exists
```

Si l'utilisateur n'existe pas :
```
[!] User 'websec' does not exist
Command to create user:
useradd -r -s /bin/false -d /opt/websec websec

Do you want to create the websec user now? [Y/n]:
```

**Caractéristiques de l'utilisateur** :
- `-r` : Utilisateur système (UID < 1000)
- `-s /bin/false` : Pas de shell interactif (sécurité)
- `-d /opt/websec` : Home directory = installation directory

### Étape 5 : Clonage du Repository

```
[INFO] Cloning WebSec repository to /opt/websec...
[✓] Repository cloned successfully
```

**Comportements** :
- Si `/opt/websec` existe déjà **avec .git** : Propose `git pull` pour mise à jour
- Si `/opt/websec` existe **sans .git** : Demande suppression avant clone
- Utilise l'URL du repository courant si disponible

### Étape 6 : Compilation

```
[INFO] Compiling WebSec...
[INFO] Compiling as user: your-user
[✓] WebSec compiled successfully
```

**Commande exécutée** :
```bash
cargo build --release --features tls
```

**Important** : La compilation se fait avec l'utilisateur qui a exécuté sudo (`$SUDO_USER`), **pas avec root ou websec**. Ceci est critique car :
- L'utilisateur `websec` n'a pas accès à Rust
- Rust est installé dans `~/.cargo/` de l'utilisateur

### Étape 7 : Application des Permissions

```
[INFO] Applying ownership and capabilities...
[INFO] Setting ownership to websec:websec...
[✓] Ownership applied
[INFO] Applying CAP_NET_BIND_SERVICE capability...
[✓] Capability applied
```

**Actions réalisées** :
```bash
chown -R websec:websec /opt/websec
setcap 'cap_net_bind_service=+ep' /opt/websec/target/release/websec
```

### Étape 8 : Vérification

```
[INFO] Verifying installation...
[✓] Binary exists: /opt/websec/target/release/websec
[✓] Ownership correct: websec:websec
[✓] Capability set: /opt/websec/target/release/websec cap_net_bind_service=ep
[INFO] Testing binary version...
websec 0.2.0
[✓] Binary executes correctly
[✓] Installation verification complete
```

**Vérifications effectuées** :
1. Binaire présent à `/opt/websec/target/release/websec`
2. Ownership = `websec:websec`
3. Capability `cap_net_bind_service` appliquée
4. Exécution réussie de `websec --version` en tant qu'utilisateur `websec`

### Étape 9 : Installation Système (Optionnelle)

```
[INFO] System installation option

This will copy the binary to /usr/local/bin/websec
Note: You will need to reapply the capability after each recompilation

Do you want to install websec to system path? [y/N]:
```

Si vous acceptez :
```bash
cp /opt/websec/target/release/websec /usr/local/bin/websec
setcap 'cap_net_bind_service=+ep' /usr/local/bin/websec
chown root:root /usr/local/bin/websec
chmod 755 /usr/local/bin/websec
```

**Avantages** :
- Commande `websec` disponible dans le PATH
- Plus facile à utiliser

**Inconvénients** :
- Après recompilation, vous devez **recopier et réappliquer la capability**
- Duplication du binaire (espace disque)

### Étape 10 : Prochaines Étapes

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ WebSec Installation Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[INFO] Next Steps:

1. Create configuration directory:
   sudo mkdir -p /etc/websec
   sudo chown root:websec /etc/websec
   sudo chmod 750 /etc/websec
...
```

Le script affiche un guide complet des étapes restantes (configuration, SSL, systemd).

---

## ⚙️ Options et Personnalisation

### Variables de Configuration

Vous pouvez modifier ces variables au début du script :

```bash
# Configuration
WEBSEC_USER="websec"          # Nom de l'utilisateur système
INSTALL_DIR="/opt/websec"     # Répertoire d'installation
RUST_VERSION="stable"         # Version Rust (stable/beta/nightly)
```

### Exemple : Installation dans un Répertoire Personnalisé

```bash
#!/bin/bash
# Modifier le script
sed -i 's|INSTALL_DIR="/opt/websec"|INSTALL_DIR="/srv/websec"|g' install.sh
sudo bash install.sh
```

### Exemple : Utilisateur Personnalisé

```bash
sed -i 's|WEBSEC_USER="websec"|WEBSEC_USER="webproxy"|g' install.sh
sudo bash install.sh
```

---

## 🔧 Dépannage

### Erreur : "This script must be run as root"

**Problème** : Script exécuté sans `sudo`

**Solution** :
```bash
sudo bash install.sh
```

### Erreur : "Unknown package manager"

**Problème** : Votre distribution n'utilise ni apt, dnf, yum, ni pacman

**Solution** : Installer manuellement les dépendances :
```bash
# Debian/Ubuntu
sudo apt install -y git build-essential pkg-config libssl-dev redis-server

# RHEL/CentOS/Fedora
sudo dnf install -y git gcc pkg-config openssl-devel redis

# Arch Linux
sudo pacman -S --noconfirm git base-devel pkg-config openssl redis
```

Puis relancer le script.

### Erreur : "Compilation failed - binary not found"

**Problème** : La compilation Rust a échoué

**Solutions** :

1. **Vérifier Rust** :
   ```bash
   rustc --version
   cargo --version
   ```

2. **Vérifier les dépendances** :
   ```bash
   pkg-config --exists openssl
   pkg-config --modversion openssl
   ```

3. **Logs de compilation** :
   ```bash
   cd /opt/websec
   cargo build --release --features tls 2>&1 | tee build.log
   ```

4. **Nettoyer et recompiler** :
   ```bash
   cd /opt/websec
   cargo clean
   cargo build --release --features tls
   ```

### Avertissement : "Capability not set correctly"

**Problème** : La capability n'a pas été appliquée

**Solution manuelle** :
```bash
sudo setcap 'cap_net_bind_service=+ep' /opt/websec/target/release/websec
getcap /opt/websec/target/release/websec
```

**Vérifier support capabilities** :
```bash
# Tester si le système supporte les capabilities
sudo setcap cap_net_bind_service=+ep /bin/ping
getcap /bin/ping
sudo setcap -r /bin/ping  # Cleanup
```

### Erreur : "Binary execution failed"

**Problème** : Le binaire ne peut pas s'exécuter en tant qu'utilisateur websec

**Solutions** :

1. **Vérifier permissions** :
   ```bash
   ls -la /opt/websec/target/release/websec
   # Attendu : -rwxr-xr-x websec websec
   ```

2. **Vérifier capability** :
   ```bash
   getcap /opt/websec/target/release/websec
   ```

3. **Tester exécution** :
   ```bash
   sudo -u websec /opt/websec/target/release/websec --version
   ```

4. **Logs d'erreur** :
   ```bash
   sudo -u websec /opt/websec/target/release/websec --version 2>&1
   ```

---

## ❓ FAQ

### Le script est-il idempotent ?

**Oui, partiellement**. Vous pouvez l'exécuter plusieurs fois :
- Si les dépendances sont déjà installées → Skip
- Si Rust est déjà installé → Skip
- Si l'utilisateur websec existe → Skip
- Si le repository existe → Propose mise à jour

**Mais** : La recompilation écrase le binaire, donc la capability doit être réappliquée.

### Le script modifie-t-il ma configuration système ?

**Oui, avec votre permission** :
- ✅ Installation de packages système (après confirmation)
- ✅ Création d'un utilisateur système `websec`
- ✅ Installation de Rust dans `~/.cargo/` de l'utilisateur

**Non** :
- ❌ Pas de modification de Apache/Nginx
- ❌ Pas de modification des certificats SSL
- ❌ Pas d'installation de service systemd automatique

### Que faire après l'installation ?

Suivez les "Next Steps" affichés par le script :

1. **Configuration** : Créer `/etc/websec/websec.toml`
2. **SSL** : Configurer les permissions Let's Encrypt
3. **Backend** : Configurer Apache pour écouter sur 8080
4. **Systemd** : Installer le service systemd
5. **Test** : Dry-run puis démarrage

Voir `docs/deployment-checklist.md` pour le guide complet.

### Le script fonctionne-t-il sur Docker ?

**Non recommandé**. Docker nécessite une configuration différente :
- Pas besoin de systemd
- Pas besoin d'utilisateur système séparé
- Image déjà construite

Utilisez `docker-compose.yml` à la place :
```bash
docker compose up -d
```

### Comment désinstaller WebSec ?

```bash
# Arrêter le service
sudo systemctl stop websec
sudo systemctl disable websec

# Supprimer les fichiers
sudo rm -rf /opt/websec
sudo rm -f /usr/local/bin/websec
sudo rm -f /etc/systemd/system/websec.service

# Supprimer la configuration (optionnel)
sudo rm -rf /etc/websec

# Supprimer l'utilisateur (optionnel)
sudo userdel websec

# Systemd reload
sudo systemctl daemon-reload
```

### Peut-on utiliser le script sur un serveur de production ?

**Oui**, le script est conçu pour production avec :
- ✅ Configuration sécurisée (capabilities, non-root)
- ✅ Vérifications à chaque étape
- ✅ Mode interactif (pas d'actions automatiques dangereuses)
- ✅ Logs clairs et vérification finale

**Recommandations** :
1. Tester sur un environnement de staging d'abord
2. Inspecter le script avant exécution
3. Faire un backup de votre configuration actuelle
4. Exécuter pendant une fenêtre de maintenance

### Que se passe-t-il après une recompilation ?

Après chaque `cargo build --release`, vous **devez** :

```bash
# 1. Réappliquer ownership (si compilation faite en tant que root)
sudo chown -R websec:websec /opt/websec

# 2. Réappliquer capability (OBLIGATOIRE)
sudo setcap 'cap_net_bind_service=+ep' /opt/websec/target/release/websec

# 3. Recopier si installé dans /usr/local/bin
sudo cp /opt/websec/target/release/websec /usr/local/bin/
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/websec

# 4. Redémarrer le service
sudo systemctl restart websec
```

**Pourquoi ?** Les capabilities sont des **attributs étendus (xattr)** qui ne survivent pas au remplacement du fichier binaire.

---

## 📞 Support

Pour tout problème avec le script d'installation :

1. **Vérifier les logs** du script (stdout/stderr)
2. **Consulter** `docs/troubleshooting-guide.md`
3. **Créer une issue GitHub** : https://github.com/yrbane/websec/issues

Inclure dans l'issue :
- Sortie complète du script (avec erreurs)
- Distribution Linux (`cat /etc/os-release`)
- Versions Rust/Cargo (`rustc --version && cargo --version`)
- Contenu de `/opt/websec` (`ls -la /opt/websec`)
