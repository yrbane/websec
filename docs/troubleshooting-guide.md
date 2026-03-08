# Guide de Dépannage WebSec

Guide complet de résolution des problèmes courants rencontrés lors du déploiement de WebSec.

---

## 📋 Table des matières

1. [Problèmes de Permissions](#problèmes-de-permissions)
2. [Problèmes de Configuration](#problèmes-de-configuration)
3. [Problèmes Réseau](#problèmes-réseau)
4. [Problèmes Backend](#problèmes-backend)
5. [Problèmes SSL/TLS](#problèmes-ssltls)
6. [Problèmes de Logs](#problèmes-de-logs)
7. [Problèmes de Performance](#problèmes-de-performance)

---

## 🔒 Problèmes de Permissions

### Erreur : "Permission denied" lors de la lecture de la config

**Symptôme** :
```
Error: Config("Failed to read config file: Permission denied (os error 13)")
```

**Cause** : L'utilisateur `websec` ne peut pas lire `/etc/websec/websec.toml`.

**Solution** :
```bash
# Vérifier les permissions actuelles
ls -la /etc/websec/

# Corriger les permissions
sudo chown -R root:websec /etc/websec
sudo chmod 750 /etc/websec
sudo chmod 640 /etc/websec/*.toml

# Vérifier que websec peut lire
sudo -u websec cat /etc/websec/websec.toml > /dev/null && echo "OK" || echo "ERREUR"
```

**Explication** :
- Répertoire `/etc/websec` : `750` (owner=root read/write/execute, group=websec read/execute)
- Fichiers `*.toml` : `640` (owner=root read/write, group=websec read)

---

### Erreur : "Permission denied" lors de la compilation

**Symptôme** :
```
sudo -u websec cargo build --release
sudo: unable to execute /usr/local/bin/cargo: Permission denied
```

**Cause** : L'utilisateur `websec` n'a pas accès à l'installation Rust.

**Solution** : **Ne PAS compiler en tant qu'utilisateur websec !**

```bash
# ✅ CORRECT : Compiler avec votre utilisateur courant
cargo build --release --features tls

# PUIS changer le propriétaire
sudo chown -R websec:websec /opt/websec

# PUIS appliquer la capability
sudo setcap 'cap_net_bind_service=+ep' /opt/websec/target/release/websec
```

**Explication** : L'utilisateur `websec` est créé uniquement pour **exécuter** le binaire, pas pour compiler.

---

### Erreur : Certificats SSL non accessibles

**Symptôme** :
```
Failed to load TLS config: failed to read from file `/etc/letsencrypt/live/example.com/fullchain.pem`: Permission denied (os error 13)
```

**Cause** : Les symlinks dans `/etc/letsencrypt/live/` nécessitent que tous les répertoires parents soient **traversables**.

**Solution complète** :
```bash
# 1. Rendre les répertoires parents traversables (755 = lisible + exécutable pour tous)
sudo chmod 755 /etc/letsencrypt
sudo chmod 755 /etc/letsencrypt/live
sudo chmod 755 /etc/letsencrypt/archive

# 2. Donner accès au groupe websec pour le domaine spécifique
sudo chown root:websec /etc/letsencrypt/live/example.com
sudo chmod 750 /etc/letsencrypt/live/example.com

sudo chown root:websec /etc/letsencrypt/archive/example.com
sudo chmod 750 /etc/letsencrypt/archive/example.com

# 3. Permissions sur les fichiers .pem
sudo chown root:websec /etc/letsencrypt/archive/example.com/*.pem
sudo chmod 640 /etc/letsencrypt/archive/example.com/*.pem

# 4. Vérifier
sudo -u websec cat /etc/letsencrypt/live/example.com/fullchain.pem | head -5
# Doit afficher: -----BEGIN CERTIFICATE-----
```

**Explication** :
```
/etc/letsencrypt/           ← 755 (traversable par tous)
├── live/                   ← 755 (traversable par tous)
│   └── example.com/ → ../../archive/example.com/  (symlink)
└── archive/                ← 755 (traversable par tous)
    └── example.com/        ← 750 (group websec)
        └── *.pem           ← 640 (group websec)
```

---

### Erreur : Capability manquante après recompilation

**Symptôme** :
```
WebSec démarre mais ne peut pas bind sur port 80/443
Error: Permission denied (os error 13)
```

**Cause** : Les capabilities sont des **attributs de fichier étendus (xattr)** qui ne survivent pas au remplacement du binaire.

**Solution recommandée** (systemd `AmbientCapabilities`) :

Si le service systemd utilise `NoNewPrivileges=yes`, `setcap` ne fonctionne **pas**. Utilisez plutôt un drop-in systemd :

```bash
sudo mkdir -p /etc/systemd/system/websec.service.d
sudo tee /etc/systemd/system/websec.service.d/capabilities.conf > /dev/null << 'EOF'
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOF
sudo systemctl daemon-reload
sudo systemctl restart websec
```

**Solution alternative** (setcap — uniquement si `NoNewPrivileges=no`) :
```bash
# Après CHAQUE recompilation
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/websec

# Vérifier
getcap /usr/local/bin/websec
```

**Script de déploiement** :
```bash
#!/bin/bash
cargo build --release --features tls
sudo systemctl stop websec
sudo cp target/release/websec /usr/local/bin/websec
sudo systemctl start websec
```

---

## ⚙️ Problèmes de Configuration

### Erreur : "missing field `listen`"

**Symptôme** :
```
Error: Config("Failed to parse TOML: missing field `listen`")
```

**Cause** : Configuration incomplète. Les champs `listen` et `backend` sont obligatoires dans `[server]` pour la rétrocompatibilité.

**Solution** : Vérifier que votre `websec.toml` contient :

```toml
[server]
listen = "[::]:80"      # ← Obligatoire (legacy)
backend = "http://127.0.0.1:8081"  # ← Obligatoire (legacy)
workers = 4
trusted_proxies = []
max_body_size = 209715200

# Listeners modernes (multi-listeners)
[[server.listeners]]
listen = "[::]:80"
backend = "http://127.0.0.1:8081"

[[server.listeners]]
listen = "[::]:443"
backend = "https://127.0.0.1:8443"

[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"
```

**Explication** : WebSec garde la compatibilité avec l'ancien format (single listener) et le nouveau format (multi-listeners). Les deux doivent être présents.

---

### Erreur : Redis connection refused

**Symptôme** :
```
Failed to connect to Redis: Connection refused
```

**Solution** :
```bash
# Vérifier que Redis tourne
sudo systemctl status redis-server

# Si non démarré
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Tester la connexion
redis-cli ping
# Doit retourner: PONG

# Vérifier l'URL dans websec.toml
[storage]
redis_url = "redis://127.0.0.1:6379"
```

---

### Erreur : GeoIP database not found

**Symptôme** :
```
WARN: GeoIP database not found at /usr/share/GeoIP/GeoLite2-Country.mmdb
```

**Solution** :
```bash
# Installer la base GeoIP
sudo apt install -y geoip-database-extra

# Ou télécharger manuellement
sudo mkdir -p /usr/share/GeoIP
cd /usr/share/GeoIP
sudo wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb

# Vérifier
ls -lh /usr/share/GeoIP/GeoLite2-Country.mmdb
```

**Alternative** : Désactiver la géolocalisation dans `websec.toml` :
```toml
[geolocation]
enabled = false
```

---

## 🌐 Problèmes Réseau

### Erreur : "Address already in use"

**Symptôme** :
```
Error: Address already in use (os error 98)
```

**Cause** : Un autre processus écoute déjà sur le port 80 ou 443.

**Solution** :
```bash
# Trouver quel processus utilise le port
sudo lsof -i :80
sudo lsof -i :443

# Exemples de coupables courants :
# - Apache écoute encore sur 80/443 (au lieu de 8081/8443)
# - Nginx tourne en parallèle
# - WebSec déjà lancé dans un autre terminal

# Arrêter Apache temporairement
sudo systemctl stop apache2

# Ou vérifier qu'Apache écoute bien sur 8081/8443
sudo ss -tlnp | grep apache
# Attendu: 127.0.0.1:8081  LISTEN  apache2
#          127.0.0.1:8443  LISTEN  apache2
```

---

### Erreur : Apache ne reçoit pas les requêtes

**Symptôme** : WebSec démarre mais les requêtes ne passent pas au backend.

**Solution** :
```bash
# 1. Vérifier qu'Apache écoute sur 8081/8443
sudo ss -tlnp | grep -E ':8081|:8443'
# Attendu: 127.0.0.1:8081  LISTEN  apache2
#          127.0.0.1:8443  LISTEN  apache2

# 2. Tester directement Apache
curl http://127.0.0.1:8081
# Doit retourner votre site

# 3. Vérifier la config WebSec
grep backend /etc/websec/websec.toml
# Doit contenir: backend = "http://127.0.0.1:8081" et backend = "https://127.0.0.1:8443"

# 4. Vérifier les logs WebSec
sudo journalctl -u websec -f
```

---

### Erreur : Firewall bloque le trafic

**Symptôme** : WebSec démarre mais site inaccessible depuis l'extérieur.

**Solution** :
```bash
# Vérifier le firewall
sudo ufw status

# Doit montrer :
# 80/tcp                     ALLOW       Anywhere
# 443/tcp                    ALLOW       Anywhere

# Si manquant, ajouter les règles
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

---

## 🔌 Problèmes Backend

### Erreur : HTTP version mismatch (HTTP/2 sur backend HTTP/1)

**Symptôme** :
```
WARN hyper_util::client::legacy::client: Connection is HTTP/1, but request requires HTTP/2
ERROR websec::proxy::middleware: Backend forwarding failed: client error (UserUnsupportedVersion)
```

**Cause** : WebSec essaie de communiquer en HTTP/2 avec un backend qui n'accepte que HTTP/1.1 (Apache par défaut).

**Solution** : **Déjà corrigé dans la version actuelle** (commit 9052516)

Si vous avez une ancienne version :
```rust
// Dans src/proxy/backend.rs
let client = Client::builder(TokioExecutor::new())
    .http2_only(false)  // Force HTTP/1
    .build_http();
```

**Explication** :
- WebSec gère HTTP/2 sur le **frontend** (ports 80/443 publics)
- Backend (Apache en localhost:8081/8443) reste en HTTP/1.1
- Pas besoin de HTTP/2 pour communication localhost

---

### Erreur : HTTP/2 requests get 301 redirect loop

**Symptôme** : HTTP/1.1 via HTTPS fonctionne (200 OK) mais HTTP/2 via HTTPS renvoie une 301 en boucle.

**Cause** : HTTP/2 utilise le pseudo-header `:authority` au lieu de `Host`. Si WebSec ne synthétise pas le `Host` depuis `:authority`, Apache ne peut pas matcher le VHost et utilise un VHost par défaut qui redirige.

**Solution** : **Corrigé dans v0.2.0** (commit c6aae58)

WebSec synthétise automatiquement le header `Host` depuis `:authority` pour les requêtes HTTP/2 avant de forwarder en HTTP/1.1 au backend.

Si vous avez une ancienne version, mettez à jour :
```bash
cd /opt/websec
cargo build --release --features tls
sudo systemctl stop websec
sudo cp target/release/websec /usr/local/bin/websec
sudo systemctl start websec
```

---

### Erreur : X-Forwarded-Proto redirect loop

**Symptôme** : Apache redirige en boucle HTTP → HTTPS même quand la requête arrive en HTTPS via WebSec.

**Cause** : WebSec ne définissait pas le header `X-Forwarded-Proto`, donc Apache ne savait pas que la requête originale était en HTTPS.

**Solution** : **Corrigé dans v0.2.0**. WebSec ajoute automatiquement `X-Forwarded-Proto: https` ou `http` selon le listener TLS.

Vérifiez que votre VHost Apache utilise :
```apache
RewriteEngine On
RewriteCond %{HTTP:X-Forwarded-Proto} !https
RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
```

---

### Erreur : Backend timeout

**Symptôme** :
```
ERROR websec::proxy::middleware: Backend forwarding failed: timeout
```

**Solution** :
```bash
# 1. Vérifier que le backend répond
curl -I http://127.0.0.1:8081

# 2. Augmenter le timeout dans le code (si nécessaire)
# Par défaut : 30 secondes

# 3. Vérifier les logs Apache
sudo tail -f /var/log/apache2/error.log
```

---

## 🔐 Problèmes SSL/TLS

### Erreur : Certificate expired

**Symptôme** :
```
TLS handshake failed: certificate has expired
```

**Solution** :
```bash
# Vérifier l'expiration du certificat
sudo certbot certificates

# Renouveler si nécessaire
sudo certbot renew

# Recharger WebSec
sudo systemctl reload websec
```

---

### Erreur : Certificate mismatch

**Symptôme** :
```
TLS handshake failed: certificate is not valid for domain
```

**Cause** : Le certificat ne correspond pas au domaine demandé.

**Solution** :
```bash
# Vérifier le certificat
openssl x509 -in /etc/letsencrypt/live/example.com/fullchain.pem -text -noout | grep DNS

# Doit montrer :
# DNS:example.com, DNS:www.example.com

# Si mauvais certificat, obtenir le bon
sudo certbot certonly --standalone -d example.com -d www.example.com
```

---

## 📋 Problèmes de Logs

### Logs multi-lignes non désirés

**Symptôme** : Les logs affichent des retours à la ligne avec `at src/file.rs:line`.

**Solution** : Utiliser le format `compact` au lieu de `pretty` :

```toml
[logging]
level = "info"
format = "compact"  # Options: "json", "compact", "pretty"
```

**Formats disponibles** :

**JSON** (machine-parsable) :
```json
{"timestamp":"2025-11-21T12:00:00Z","level":"INFO","target":"websec","message":"Listener ready"}
```

**Compact** (humain, une ligne) :
```
2025-11-21T12:00:00Z  INFO websec: Listener ready
```

**Pretty** (développement, multi-lignes) :
```
2025-11-21T12:00:00Z  INFO websec: Listener ready
    at src/proxy/server.rs:384
```

---

### Logs trop verbeux

**Solution** : Réduire le niveau de log :

```toml
[logging]
level = "warn"  # Au lieu de "info" ou "debug"
```

**Niveaux disponibles** (du plus verbeux au moins) :
- `trace` : Extrêmement détaillé (debug profond)
- `debug` : Informations de débogage
- `info` : Messages informatifs (recommandé production)
- `warn` : Avertissements uniquement
- `error` : Erreurs uniquement

---

## 🚀 Problèmes de Performance

### WebSec consomme trop de CPU

**Solutions** :

1. **Réduire les workers** :
```toml
[server]
workers = 2  # Au lieu de 4
```

2. **Désactiver les détecteurs coûteux** (si pas nécessaires)

3. **Vérifier que ModSecurity est désactivé** (double WAF = double overhead) :
```bash
apache2ctl -M | grep security
sudo a2dismod security2
sudo systemctl restart apache2
```

---

### WebSec consomme trop de mémoire

**Solutions** :

1. **Réduire le cache Redis** :
```toml
[storage]
cache_size = 5000  # Au lieu de 10000
```

2. **Limiter la taille des requêtes** :
```toml
[server]
max_body_size = 10485760  # 10 MB au lieu de 200 MB
```

---

### Rate limiting trop agressif

**Symptôme** : Utilisateurs légitimes bloqués.

**Solution** : Ajuster les seuils :

```toml
[ratelimit]
normal_rpm = 2000      # Au lieu de 1000
normal_burst = 200     # Au lieu de 100
```

Ou ajouter des IPs à la whitelist :
```toml
[lists]
whitelist = [
    "127.0.0.1",
    "::1",
    "203.0.113.50",  # IP de confiance
]
```

---

## 🔧 Diagnostic Général

### Checklist de vérification

```bash
# 1. Utilisateur websec existe
id websec

# 2. Capability appliquée
getcap /usr/local/bin/websec

# 3. Config lisible
sudo -u websec cat /etc/websec/websec.toml | head -5

# 4. Certificats lisibles
sudo -u websec cat /etc/letsencrypt/live/example.com/fullchain.pem | head -5

# 5. Redis accessible
redis-cli ping

# 6. Ports corrects
sudo ss -tlnp | grep -E ':80|:443|:8081|:8443|:9090'
# Attendu :
# *:80      LISTEN  websec
# *:443     LISTEN  websec
# 127.0.0.1:8081  LISTEN  apache2
# 127.0.0.1:8443  LISTEN  apache2
# *:9090    LISTEN  websec

# 7. Test dry-run
sudo -u websec /usr/local/bin/websec --config /etc/websec/websec.toml run --dry-run

# 8. Logs WebSec
sudo journalctl -u websec -n 50

# 9. Logs Apache
sudo tail -f /var/log/apache2/error.log

# 10. Test HTTP/HTTPS
curl -I http://example.com
curl -I https://example.com
```

---

## 📞 Support

Si le problème persiste après avoir suivi ce guide :

1. **Vérifier les logs** :
   ```bash
   sudo journalctl -u websec -n 100 --no-pager
   ```

2. **Activer le mode debug** (temporairement) :
   ```toml
   [logging]
   level = "debug"
   ```

3. **Créer une issue GitHub** avec :
   - Version de WebSec (`websec --version`)
   - Système d'exploitation
   - Logs complets
   - Configuration (anonymisée)

Repository : https://github.com/yrbane/websec/issues
