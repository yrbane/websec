# Checklist de Déploiement WebSec sur Apache

## 📦 Préparation du Serveur

### 1. Prérequis Système

```bash
# Vérifier la version Ubuntu/Debian
lsb_release -a

# Installer les dépendances
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev redis-server apache2

# Installer Rust (si pas déjà installé)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. Installation Redis

```bash
# Redis doit être actif pour le storage distribué
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Vérifier Redis
redis-cli ping  # Doit retourner "PONG"
```

### 3. Créer un utilisateur dédié

```bash
# Créer un utilisateur système pour WebSec (sans login)
sudo useradd -r -s /bin/false -d /opt/websec websec

# Créer le groupe websec (si pas déjà fait)
sudo groupadd websec 2>/dev/null || true
```

### 4. Cloner et Compiler WebSec

```bash
# Cloner le repo
cd /opt
sudo git clone https://github.com/yrbane/websec.git

# Compiler avec TLS (IMPORTANT pour HTTPS)
cd /opt/websec
cargo build --release --features tls

# APRÈS compilation : changer le propriétaire et ajouter la capability
sudo chown -R websec:websec /opt/websec
sudo setcap 'cap_net_bind_service=+ep' /opt/websec/target/release/websec

# Vérifier le binaire
./target/release/websec --version

# Vérifier les capabilities
getcap /opt/websec/target/release/websec
# Attendu: /opt/websec/target/release/websec cap_net_bind_service=ep
```

**Note importante** : On compile d'abord avec l'utilisateur courant (qui a Rust installé), puis on change le propriétaire des fichiers. L'utilisateur `websec` n'a pas besoin d'avoir Rust installé puisqu'il exécutera seulement le binaire compilé.

---

## 🔐 Configuration SSL/TLS

### 1. Certificats Let's Encrypt

```bash
# Installer Certbot
sudo apt install -y certbot python3-certbot-apache

# Obtenir les certificats (Apache doit écouter sur 80/443 temporairement)
sudo certbot certonly --standalone -d votre-domaine.com -d www.votre-domaine.com

# Certificats générés dans :
# /etc/letsencrypt/live/votre-domaine.com/fullchain.pem
# /etc/letsencrypt/live/votre-domaine.com/privkey.pem
```

### 2. Permissions Certificats

```bash
# L'utilisateur websec doit pouvoir lire les certificats
sudo chown -R root:websec /etc/letsencrypt/archive/votre-domaine.com/
sudo chown -R root:websec /etc/letsencrypt/live/votre-domaine.com/
sudo chmod 750 /etc/letsencrypt/archive/votre-domaine.com/
sudo chmod 750 /etc/letsencrypt/live/votre-domaine.com/
sudo chmod 640 /etc/letsencrypt/archive/votre-domaine.com/*.pem
```

---

## ⚙️ Configuration WebSec

### 1. Créer websec.toml

```bash
sudo mkdir -p /etc/websec
sudo nano /etc/websec/websec.toml
```

**Après création du fichier, configurer les permissions** :
```bash
# Permettre à l'utilisateur websec de lire la config
sudo chown -R root:websec /etc/websec
sudo chmod 750 /etc/websec
sudo chmod 640 /etc/websec/*.toml
```

**Contenu (adaptez votre-domaine.com)** :

```toml
[server]
workers = 4
trusted_proxies = []
max_body_size = 209715200  # 200 MB pour uploads

# HTTP listener (port 80)
[[server.listeners]]
listen = "0.0.0.0:80"
backend = "http://127.0.0.1:8080"

# HTTPS listener (port 443) - TLS terminé par WebSec
[[server.listeners]]
listen = "0.0.0.0:443"
backend = "http://127.0.0.1:8080"

[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/votre-domaine.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/votre-domaine.com/privkey.pem"

[reputation]
base_score = 100
threshold_allow = 70
threshold_ratelimit = 40
threshold_challenge = 20
threshold_block = 0
decay_half_life_hours = 24.0
correlation_penalty_bonus = 10

[reputation.signal_weights]
VulnerabilityScan = 25
SuspiciousUserAgent = 10
BotBehaviorPattern = 15
AbusiveClient = 15
FailedLogin = 20
LoginAttemptPattern = 20
CredentialStuffing = 25
RequestFlood = 20
ConnectionFlood = 20
DistributedAttack = 10
SqlInjectionAttempt = 30
XssAttempt = 30
PathTraversalAttempt = 30
RceAttempt = 50
HighRiskCountry = 15
ImpossibleTravel = 20
HeaderInjection = 20
HostHeaderAttack = 20
RefererSpoofing = 10

[lists]
blacklist = []
whitelist = [
    "127.0.0.1",
    "::1",
]

[storage]
type = "redis"
redis_url = "redis://127.0.0.1:6379"
cache_size = 10000

[geolocation]
enabled = true
database = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
risk_countries = ["CN", "RU", "KP", "IR", "SY"]
impossible_travel_window = 3600

[ratelimit]
normal_rpm = 1000
normal_burst = 100
suspicious_rpm = 200
suspicious_burst = 20
aggressive_rpm = 50
aggressive_burst = 5
window_duration_secs = 60

[logging]
level = "info"
format = "json"

[metrics]
enabled = true
port = 9090
```

### 2. Installer GeoIP Database (optionnel)

```bash
# Télécharger GeoLite2
sudo apt install -y geoip-database-extra

# Ou télécharger manuellement
sudo mkdir -p /usr/share/GeoIP
cd /usr/share/GeoIP
sudo wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb
```

---

## 🌐 Configuration Apache

### 1. Sauvegarder la config actuelle

```bash
sudo cp -r /etc/apache2 /etc/apache2.backup.$(date +%Y%m%d-%H%M%S)
```

### 2. Modifier les ports Apache

```bash
sudo nano /etc/apache2/ports.conf
```

**Remplacer** :
```apache
Listen 80
<IfModule ssl_module>
    Listen 443
</IfModule>
```

**Par (IPv4 + IPv6)** :
```apache
# Apache écoute UNIQUEMENT en local (WebSec forward sur ce port)
# IPv4
Listen 127.0.0.1:8080
# IPv6
Listen [::1]:8080
```

**Ou si vous voulez IPv4 uniquement** :
```apache
Listen 127.0.0.1:8080
```

### 3. Mettre à jour les VirtualHosts

```bash
# Pour chaque VirtualHost dans /etc/apache2/sites-enabled/

sudo nano /etc/apache2/sites-enabled/000-default.conf
```

**Avant** :
```apache
<VirtualHost *:80>
    ServerName votre-domaine.com
    DocumentRoot /var/www/html
    # ...
</VirtualHost>
```

**Après (IPv4 + IPv6)** :
```apache
# VirtualHost IPv4
<VirtualHost 127.0.0.1:8080>
    ServerName votre-domaine.com

    # Récupérer la vraie IP depuis WebSec
    RemoteIPHeader X-Real-IP
    RemoteIPTrustedProxy 127.0.0.1
    RemoteIPTrustedProxy ::1

    # Détecter si requête originale était HTTPS
    SetEnvIf X-Forwarded-Proto "https" HTTPS=on

    # Logs avec vraie IP
    LogFormat "%a %l %u %t \"%r\" %>s %b" combined_real_ip
    CustomLog /var/log/apache2/access.log combined_real_ip
    ErrorLog /var/log/apache2/error.log

    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>

# VirtualHost IPv6 (même configuration)
<VirtualHost [::1]:8080>
    ServerName votre-domaine.com

    RemoteIPHeader X-Real-IP
    RemoteIPTrustedProxy 127.0.0.1
    RemoteIPTrustedProxy ::1

    SetEnvIf X-Forwarded-Proto "https" HTTPS=on

    LogFormat "%a %l %u %t \"%r\" %>s %b" combined_real_ip
    CustomLog /var/log/apache2/access.log combined_real_ip
    ErrorLog /var/log/apache2/error.log

    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

**Note** : Si vous n'utilisez qu'IPv4, le premier VirtualHost suffit.

### 4. Activer les modules Apache

```bash
sudo a2enmod remoteip
sudo a2enmod headers
sudo apachectl configtest
sudo systemctl restart apache2
```

### 5. ModSecurity (si installé)

Si Apache a **mod_security2** installé, vous avez deux WAF. Recommandation :

**Désactiver ModSecurity** (WebSec fait déjà le travail en frontal) :
```bash
# Vérifier si ModSecurity est actif
apache2ctl -M | grep security

# Désactiver mod_security2
sudo a2dismod security2
sudo systemctl restart apache2
```

**Pourquoi ?**
- ✅ WebSec analyse **tout** le trafic avant Apache (HTTP + HTTPS déchiffré)
- ✅ Apache est en localhost uniquement (pas d'accès direct)
- ✅ Pas de double overhead (performance)
- ✅ Un seul WAF = plus simple à maintenir

**Si vous voulez garder ModSecurity** (défense en profondeur) :
```bash
# Activer le moteur
sudo nano /etc/modsecurity/modsecurity.conf
# Changer: SecRuleEngine On
sudo systemctl restart apache2
```

---

## 🔥 Configuration Firewall

```bash
# Autoriser WebSec (80, 443)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# BLOQUER accès direct à Apache (empêche bypass de WebSec)
sudo ufw deny 8080/tcp

# Autoriser SSH (NE PAS OUBLIER !)
sudo ufw allow 22/tcp

# Activer le firewall
sudo ufw enable
sudo ufw status
```

---

## 🚀 Démarrage WebSec

### 1. Test manuel

```bash
cd /opt/websec

# Test dry-run (en tant qu'utilisateur websec)
sudo -u websec ./target/release/websec --config /etc/websec/websec.toml run --dry-run

# Lancer WebSec manuellement (pour tester)
sudo -u websec ./target/release/websec --config /etc/websec/websec.toml run
```

### 2. Service systemd (production)

```bash
sudo nano /etc/systemd/system/websec.service
```

**Contenu** :
```ini
[Unit]
Description=WebSec Security Reverse Proxy
After=network.target redis-server.service
Wants=redis-server.service

[Service]
Type=simple
User=websec
Group=websec
WorkingDirectory=/opt/websec

# Capability pour écouter sur ports 80/443 sans root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

ExecStart=/opt/websec/target/release/websec --config /etc/websec/websec.toml run
Restart=on-failure
RestartSec=5s

# Sécurité renforcée
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log

# Logs
StandardOutput=journal
StandardError=journal
SyslogIdentifier=websec

[Install]
WantedBy=multi-user.target
```

**Activer le service** :
```bash
sudo systemctl daemon-reload
sudo systemctl enable websec
sudo systemctl start websec
sudo systemctl status websec
```

### 3. Vérifier les ports

```bash
sudo ss -tlnp | grep -E ':80|:443|:8080|:9090'
```

**Attendu** :
```
*:80      LISTEN  websec
*:443     LISTEN  websec
127.0.0.1:8080  LISTEN  apache2
*:9090    LISTEN  websec (metrics)
```

---

## ✅ Vérifications

### 1. Tests de base

```bash
# HTTP
curl -I http://votre-domaine.com

# HTTPS
curl -I https://votre-domaine.com

# Vérifier headers WebSec
curl -I https://votre-domaine.com | grep -i x-websec
```

### 2. Logs

```bash
# WebSec
sudo journalctl -u websec -f

# Apache (doit voir les vraies IPs)
sudo tail -f /var/log/apache2/access.log

# Redis
redis-cli info stats
```

### 3. Métriques

```bash
# Depuis le serveur
curl http://localhost:9090/metrics

# Statistiques WebSec
curl http://localhost:9090/metrics | grep websec_requests_total
```

---

## 🔄 Renouvellement SSL Automatique

### Hook Certbot pour recharger WebSec

```bash
sudo mkdir -p /etc/letsencrypt/renewal-hooks/post
sudo nano /etc/letsencrypt/renewal-hooks/post/reload-websec.sh
```

**Contenu** :
```bash
#!/bin/bash
systemctl reload websec
```

**Rendre exécutable** :
```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/post/reload-websec.sh
```

**Tester le renouvellement** :
```bash
sudo certbot renew --dry-run
```

---

## 🛡️ Checklist Finale

- [ ] Utilisateur système `websec` créé
- [ ] Redis actif (`redis-cli ping`)
- [ ] WebSec compilé avec `--features tls`
- [ ] Capability `CAP_NET_BIND_SERVICE` attribuée (`getcap websec`)
- [ ] Certificats SSL valides et lisibles par groupe `websec`
- [ ] `websec.toml` créé avec bon domaine et chemins certificats
- [ ] `/etc/websec` permissions configurées (750, fichiers 640, group websec)
- [ ] Apache écoute sur `127.0.0.1:8080` uniquement
- [ ] VirtualHosts mis à jour (RemoteIPHeader, SetEnvIf)
- [ ] Modules Apache activés (remoteip, headers)
- [ ] Firewall configuré (80/443 open, 8080 closed)
- [ ] Service systemd créé avec `User=websec` et capabilities
- [ ] WebSec démarre sans erreur (`systemctl status websec`)
- [ ] Ports corrects (`ss -tlnp`)
- [ ] Tests HTTP/HTTPS fonctionnent
- [ ] Headers `X-WebSec-*` présents
- [ ] Logs montrent vraies IPs clients
- [ ] Métriques accessibles sur `:9090`
- [ ] Hook renouvellement SSL configuré

---

## 🐛 Troubleshooting

### WebSec ne démarre pas

```bash
# Vérifier la config
sudo -u websec /opt/websec/target/release/websec --config /etc/websec/websec.toml run --dry-run

# Vérifier les logs
sudo journalctl -u websec -n 50

# Vérifier les capabilities
getcap /opt/websec/target/release/websec

# Si capability manquante, la réappliquer
sudo setcap 'cap_net_bind_service=+ep' /opt/websec/target/release/websec
```

### "Permission denied" lors de la lecture de la config

**Erreur** :
```
Error: Config("Failed to read config file: Permission denied (os error 13)")
```

**Solution** : Vérifier les permissions de `/etc/websec` :
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

### "Address already in use"

```bash
# Trouver quel processus utilise le port
sudo lsof -i :80
sudo lsof -i :443

# Arrêter Apache si nécessaire
sudo systemctl stop apache2
```

### Apache ne reçoit pas les requêtes

```bash
# Vérifier qu'Apache écoute bien sur 8080
sudo ss -tlnp | grep :8080

# Tester directement Apache
curl http://127.0.0.1:8080
```

### Certificats SSL non accessibles

```bash
# Vérifier les permissions
ls -la /etc/letsencrypt/live/votre-domaine.com/
ls -la /etc/letsencrypt/archive/votre-domaine.com/

# Vérifier que l'utilisateur websec peut lire
sudo -u websec cat /etc/letsencrypt/live/votre-domaine.com/fullchain.pem > /dev/null

# Ajuster les permissions si nécessaire
sudo chown -R root:websec /etc/letsencrypt/archive/votre-domaine.com/
sudo chown -R root:websec /etc/letsencrypt/live/votre-domaine.com/
sudo chmod 750 /etc/letsencrypt/archive/votre-domaine.com/
sudo chmod 750 /etc/letsencrypt/live/votre-domaine.com/
sudo chmod 640 /etc/letsencrypt/archive/votre-domaine.com/*.pem
```

---

## 📊 Monitoring Post-Déploiement

### Dashboard Grafana (optionnel)

```bash
# Installer Prometheus
sudo apt install -y prometheus

# Configurer scraping WebSec
sudo nano /etc/prometheus/prometheus.yml
```

**Ajouter** :
```yaml
scrape_configs:
  - job_name: 'websec'
    static_configs:
      - targets: ['localhost:9090']
```

```bash
sudo systemctl restart prometheus
```

### Alerting Simple

```bash
# Script de monitoring simple
nano /opt/websec-monitor.sh
```

**Contenu** :
```bash
#!/bin/bash
if ! systemctl is-active --quiet websec; then
    echo "WebSec est DOWN !" | mail -s "ALERTE WebSec" admin@example.com
    systemctl restart websec
fi
```

**Cron toutes les 5 minutes** :
```bash
*/5 * * * * /opt/websec-monitor.sh
```

---

**Déploiement terminé ! WebSec protège maintenant votre serveur Apache.** 🛡️
