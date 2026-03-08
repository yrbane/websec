# Guide de Déploiement Production

Ce guide couvre l'installation et le déploiement de WebSec en environnement de production.

## Table des matières

- [Prérequis](#prérequis)
- [Option 1 : Déploiement Docker](#option-1--déploiement-docker-recommandé)
- [Option 2 : Déploiement Natif](#option-2--déploiement-natif)
- [Configuration du Backend](#configuration-du-backend)
- [Tests en Conditions Réelles](#tests-en-conditions-réelles)
- [Monitoring](#monitoring)
- [Optimisations Production](#optimisations-production)
- [Dépannage](#dépannage)

## Prérequis

### Matériel Recommandé

**Minimum** :
- CPU : 2 cores
- RAM : 1 GB
- Disque : 10 GB
- Débit : 100 Mbps

**Production moyenne** :
- CPU : 4 cores
- RAM : 4 GB
- Disque : 50 GB
- Débit : 1 Gbps

**Production haute charge** :
- CPU : 8+ cores
- RAM : 8+ GB
- Disque : 100+ GB
- Débit : 10 Gbps

### Logiciels Requis

- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, ou équivalent)
- Redis 6.0+ (pour storage distribué)
- Docker 20.10+ (pour déploiement Docker)
- Serveur web backend (Nginx, Apache, Caddy, etc.)

## Option 1 : Déploiement Docker (Recommandé)

### Avantages

- ✅ Installation simple et rapide
- ✅ Isolation complète
- ✅ Mises à jour faciles
- ✅ Rollback instantané
- ✅ Image optimisée (13.2 MB)

### Installation

```bash
# Se connecter au serveur
ssh user@votre-serveur.com

# Installer Docker (si nécessaire)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Cloner le repository
git clone https://github.com/votre-username/websec.git
cd websec

# Créer la configuration de production
cp config/websec.toml config/websec-prod.toml
```

### Configuration Production

Éditez `config/websec-prod.toml` :

```toml
[server]
listen = "[::]:8081"
backend = "http://host.docker.internal:3000"  # Pour Docker
# backend = "http://172.17.0.1:3000"          # Alternative
workers = 4  # Nombre de CPU cores

[reputation]
base_score = 100
threshold_allow = 70
threshold_ratelimit = 40
threshold_challenge = 20
threshold_block = 0
decay_half_life_hours = 24.0
correlation_penalty_bonus = 10

[storage]
type = "redis"  # Alternatives : "memory" (in-process), "sled" (embedded DB)
redis_url = "redis://host.docker.internal:6379"  # Pour Docker (uniquement si type = "redis")
cache_size = 10000

[geolocation]
enabled = true
# database = "/app/GeoLite2-Country.mmdb"  # Si vous avez MaxMind
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

[lists]
# Note : les listes (whitelist/blacklist) sont gérées via la commande CLI
# `websec lists` et le stockage fichier (voir WEBSEC_LISTS_DIR).
# Les entrées ci-dessous dans le TOML sont ignorées par le code actuel.
whitelist = [
    "127.0.0.1",
    "::1",
    # "203.0.113.50",  # Votre IP d'administration
]

blacklist = [
    # IPs malveillantes connues
]
```

### Démarrage des Services

```bash
# 1. Démarrer Redis
docker run -d \
  --name websec-redis \
  --restart unless-stopped \
  -p 6379:6379 \
  -v websec-redis-data:/data \
  redis:7-alpine redis-server --appendonly yes

# Vérifier Redis
docker exec websec-redis redis-cli ping
# Doit retourner: PONG

# 2. Construire l'image WebSec
websec docker build

# 3. Démarrer WebSec
docker run -d \
  --name websec-proxy \
  --restart unless-stopped \
  -p 80:8081 \
  -p 9090:9090 \
  -v $(pwd)/config/websec-prod.toml:/app/config/websec.toml:ro \
  --add-host=host.docker.internal:host-gateway \
  websec:latest

# Vérifier les logs
docker logs -f websec-proxy
```

### Commandes Utiles

```bash
# Voir les logs en temps réel
docker logs -f websec-proxy

# Redémarrer après modification config
docker restart websec-proxy

# Voir les stats du conteneur
docker stats websec-proxy

# Accéder au shell du conteneur
docker exec -it websec-proxy /bin/sh

# Arrêter et supprimer
docker stop websec-proxy
docker rm websec-proxy

# Mise à jour
git pull
websec docker build
docker stop websec-proxy
docker rm websec-proxy
# Relancer avec la nouvelle image
```

## Option 2 : Déploiement Natif

### Avantages

- ✅ Performance maximale (pas d'overhead Docker)
- ✅ Intégration système native
- ✅ Contrôle total

### Intégrer WebSec devant Apache (HTTP + HTTPS)

1. **Préparez Apache** : assurez-vous que les VirtualHosts ":80"/":443" sont opérationnels.
2. **Lancez l’assistant** :

   ```bash
   sudo websec setup --config /opt/websec/config/websec.toml
   ```

   L’outil détecte les VirtualHosts, propose ceux à migrer, met à jour `ports.conf` (ex. 80→8081, 443→8443) et ajoute les entrées `server.listeners` correspondantes.

3. **Configurez TLS** : pour chaque listener HTTPS, renseignez les chemins `cert_file`/`key_file` dans `websec.toml` (Let’s Encrypt ou certificat interne).

4. **Redémarrez Apache** puis lancez WebSec (binaire compilé avec `--features tls` pour capturer 443).

### Exemple de configuration multi-listeners

```toml
[server]
listen = "[::]:80"                # valeur de repli
backend = "http://127.0.0.1:8081"
workers = 4

[[server.listeners]]                 # Listener HTTP public
listen = "[::]:80"
backend = "http://127.0.0.1:8081"

[[server.listeners]]                 # Listener HTTPS public
listen = "[::]:443"
backend = "http://127.0.0.1:8443"
[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_file  = "/etc/letsencrypt/live/example.com/privkey.pem"
```

Compilez ensuite :

```bash
cargo build --release --features tls
sudo ./target/release/websec run --config /opt/websec/config/websec.toml
```

### Installation

```bash
# 1. Installer Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 2. Cloner et compiler
git clone https://github.com/votre-username/websec.git
cd websec
cargo build --release --locked

# 3. Installer le binaire
sudo cp target/release/websec /usr/local/bin/
sudo chmod +x /usr/local/bin/websec

# Vérifier l'installation
websec --version
```

### Configuration Système

```bash
# Créer un utilisateur système
sudo useradd -r -s /bin/false -d /var/lib/websec websec

# Créer les répertoires
sudo mkdir -p /etc/websec /var/log/websec /var/lib/websec
sudo chown websec:websec /var/log/websec /var/lib/websec

# Copier la configuration
sudo cp config/websec.toml /etc/websec/websec.toml
sudo chown root:websec /etc/websec/websec.toml
sudo chmod 640 /etc/websec/websec.toml

# Éditer la configuration
sudo nano /etc/websec/websec.toml
```

### Service Systemd

Créer `/etc/systemd/system/websec.service` :

```ini
[Unit]
Description=WebSec Security Proxy
After=network.target syslog.target

[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
Type=simple
User=websec
Group=websec
# Point to the installed binary location
ExecStart=/usr/local/bin/websec run
# Set default configuration path
Environment=WEBSEC_CONFIG=/etc/websec/websec.toml
Environment=WEBSEC_LISTS_DIR=/etc/websec/lists
# Restart automatically on failure
Restart=always
RestartSec=5

# Security Hardening
# Mount /usr, /boot, and /etc as read-only
ProtectSystem=full
# Make /home, /root, /run/user inaccessible
ProtectHome=yes
# Create private /tmp directory
PrivateTmp=yes
# Make device nodes inaccessible (except /dev/null, /dev/zero, etc)
PrivateDevices=yes

[Install]
WantedBy=multi-user.target
```

**Note sur le port 80** : Si vous voulez écouter sur le port 80 sans être root, deux options :

1. Utiliser `setcap` :
```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/websec
```

2. Ou utiliser un port > 1024 et rediriger avec iptables :
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8081
```

### Démarrage du Service

```bash
# Activer et démarrer
sudo systemctl daemon-reload
sudo systemctl enable websec
sudo systemctl start websec

# Vérifier le statut
sudo systemctl status websec

# Voir les logs
sudo journalctl -u websec -f

# Redémarrer après modification config
sudo systemctl restart websec

# Arrêter
sudo systemctl stop websec
```

### Installation Redis

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install redis-server

# CentOS/RHEL
sudo yum install redis

# Configuration Redis
sudo nano /etc/redis/redis.conf
# Activer persistence: appendonly yes

# Démarrer Redis
sudo systemctl enable redis
sudo systemctl start redis
```

## Configuration du Backend

WebSec doit être placé **devant** votre serveur web existant. Le backend doit écouter sur localhost uniquement.

### Nginx

```nginx
# /etc/nginx/sites-available/default
server {
    # Écouter UNIQUEMENT sur localhost
    listen 127.0.0.1:3000;
    server_name votre-domaine.com;

    root /var/www/html;
    index index.html index.php;

    # Votre configuration existante...
    location / {
        try_files $uri $uri/ =404;
    }

    # PHP (si nécessaire)
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
```

```bash
# Tester la config
sudo nginx -t

# Recharger
sudo systemctl reload nginx
```

### Apache

```apache
# /etc/apache2/ports.conf
Listen 127.0.0.1:3000

# /etc/apache2/sites-available/000-default.conf
<VirtualHost 127.0.0.1:3000>
    ServerName votre-domaine.com
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

```bash
# Tester la config
sudo apache2ctl configtest

# Recharger
sudo systemctl reload apache2
```

### Caddy

```caddyfile
# /etc/caddy/Caddyfile
http://127.0.0.1:3000 {
    root * /var/www/html
    file_server
    php_fastcgi unix//run/php/php8.1-fpm.sock
}
```

```bash
# Recharger
sudo systemctl reload caddy
```

## Tests en Conditions Réelles

### Test 1 : Requêtes Normales

```bash
# Depuis votre machine locale
curl -v http://votre-serveur.com/

# Vérifier les headers WebSec
curl -I http://votre-serveur.com/
# Doit afficher:
# x-websec-decision: ALLOW
# x-websec-score: 100
```

### Test 2 : Bot Suspect

```bash
# Simuler un bot avec User-Agent suspect
curl -A "curl/7.0" http://votre-serveur.com/
# Réponse: HTTP 429 (rate limited) ou 401 (challenge)

# Vérifier le header
curl -I -A "curl/7.0" http://votre-serveur.com/
# x-websec-decision: RATE_LIMIT ou CHALLENGE
# x-websec-score: < 70
```

### Test 3 : Scan de Vulnérabilités

```bash
# Tenter des chemins suspects
curl http://votre-serveur.com/wp-admin/
curl http://votre-serveur.com/.env
curl http://votre-serveur.com/admin.php
curl http://votre-serveur.com/phpmyadmin/

# Chaque requête devrait diminuer le score
# Après plusieurs tentatives : HTTP 403 (blocked)
```

### Test 4 : Injection SQL

```bash
# Tenter une injection SQL
curl "http://votre-serveur.com/search?q=1' OR '1'='1"
curl "http://votre-serveur.com/user?id=1 UNION SELECT * FROM users"

# Devrait être bloqué immédiatement
# HTTP 403 Forbidden
```

### Test 5 : XSS

```bash
# Tenter une injection XSS
curl "http://votre-serveur.com/search?q=<script>alert(1)</script>"
curl "http://votre-serveur.com/comment?text=<img src=x onerror=alert(1)>"

# Devrait être bloqué
# HTTP 403 Forbidden
```

### Test 6 : Flood

```bash
# Envoyer beaucoup de requêtes rapidement
for i in {1..100}; do
  curl -s http://votre-serveur.com/ &
done
wait

# Les dernières requêtes devraient être rate-limitées
# HTTP 429 Too Many Requests
```

### Test 7 : Path Traversal

```bash
# Tenter un path traversal
curl "http://votre-serveur.com/download?file=../../etc/passwd"
curl "http://votre-serveur.com/api/file?path=..%2F..%2Fetc%2Fpasswd"

# Devrait être bloqué
# HTTP 403 Forbidden
```

### Test 8 : Métriques

```bash
# Voir les métriques Prometheus
curl http://votre-serveur.com:9090/metrics

# Compter les détections
curl -s http://votre-serveur.com:9090/metrics | grep detections_total

# Voir les scores de réputation
curl -s http://votre-serveur.com:9090/metrics | grep reputation_score

# Voir les requêtes par décision
curl -s http://votre-serveur.com:9090/metrics | grep requests_total
```

## Monitoring

### Logs Structurés

```bash
# Docker
docker logs -f websec-proxy | jq

# Systemd
sudo journalctl -u websec -f -o json-pretty

# Filtrer par niveau
sudo journalctl -u websec -p warning -f

# Filtrer par IP
sudo journalctl -u websec -f | grep "1.2.3.4"

# Voir les dernières détections
sudo journalctl -u websec -f | grep "Detection triggered"
```

### Prometheus + Grafana

**docker-compose-monitoring.yml** :

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: websec-prometheus
    restart: unless-stopped
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=30d'
      - '--storage.tsdb.path=/prometheus'

  grafana:
    image: grafana/grafana:latest
    container_name: websec-grafana
    restart: unless-stopped
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=changeme
      - GF_INSTALL_PLUGINS=redis-datasource
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - prometheus

volumes:
  prometheus-data:
  grafana-data:
```

**prometheus.yml** :

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'websec'
    static_configs:
      - targets: ['host.docker.internal:9090']
        labels:
          environment: 'production'
```

**Démarrage** :

```bash
docker-compose -f docker-compose-monitoring.yml up -d

# Accéder à Grafana
# http://votre-serveur.com:3001
# Login: admin / changeme

# Ajouter Prometheus comme source de données
# URL: http://prometheus:9090
```

**Dashboard Grafana recommandé** :

1. **Requests Panel** :
   - Métrique : `rate(requests_total[5m])`
   - Type : Time series

2. **Detections Panel** :
   - Métrique : `rate(detections_total[5m])`
   - Type : Time series
   - Group by : signal type

3. **Reputation Score Panel** :
   - Métrique : `reputation_score`
   - Type : Gauge

4. **Top IPs Panel** :
   - Métrique : `topk(10, count by (ip) (requests_total))`
   - Type : Table

### Alerting

**Alertmanager configuration** (prometheus.yml) :

```yaml
rule_files:
  - 'alerts.yml'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

**alerts.yml** :

```yaml
groups:
  - name: websec
    interval: 30s
    rules:
      - alert: HighDetectionRate
        expr: rate(detections_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Taux de détections élevé"
          description: "{{ $value }} détections/sec"

      - alert: TooManyBlocks
        expr: rate(requests_total{decision="BLOCK"}[5m]) > 5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Trop de requêtes bloquées"
          description: "{{ $value }} blocks/sec"

      - alert: WebSecDown
        expr: up{job="websec"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WebSec est down"
```

## Optimisations Production

### Performance

```toml
[server]
workers = 8  # = nombre de CPU cores

[storage]
type = "redis"  # Ou "memory" / "sled" selon vos besoins
cache_size = 50000  # Plus de cache L1

[ratelimit]
window_duration_secs = 60
```

### Tuning Système

```bash
# Augmenter les limites de fichiers ouverts
sudo nano /etc/security/limits.conf
```

```
websec soft nofile 65536
websec hard nofile 65536
```

```bash
# Tuning réseau
sudo nano /etc/sysctl.conf
```

```
# Augmenter les backlog queues
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 5000

# TCP tuning
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Réutilisation des sockets
net.ipv4.tcp_tw_reuse = 1
```

```bash
# Appliquer
sudo sysctl -p
```

### Redis Tuning

```bash
sudo nano /etc/redis/redis.conf
```

```
# Persistence
appendonly yes
appendfsync everysec

# Performance
maxmemory 2gb
maxmemory-policy allkeys-lru

# Réseau
tcp-backlog 511
timeout 0
tcp-keepalive 300
```

### Firewall

```bash
# UFW
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 9090/tcp  # Métriques (restreindre si public)
sudo ufw enable

# iptables
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9090 -s VOTRE_IP_ADMIN -j ACCEPT
```

### Sécurité SSL/TLS

WebSec gère TLS nativement via **rustls** lorsqu'il est compilé avec `--features tls`. Vous pouvez configurer la terminaison TLS directement dans WebSec via les `[[server.listeners]]` avec une section `[server.listeners.tls]` (voir la section "Exemple de configuration multi-listeners" ci-dessus).

Si vous préférez malgré tout placer un reverse proxy TLS devant WebSec (par exemple pour du load-balancing ou du caching), voici un exemple Nginx :

```nginx
# Nginx avec SSL devant WebSec (optionnel)
server {
    listen 443 ssl http2;
    server_name votre-domaine.com;

    ssl_certificate /etc/letsencrypt/live/votre-domaine.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/votre-domaine.com/privkey.pem;

    # SSL hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirection HTTP -> HTTPS
server {
    listen 80;
    server_name votre-domaine.com;
    return 301 https://$server_name$request_uri;
}
```

## Dépannage

### WebSec ne démarre pas

```bash
# Vérifier les logs
sudo journalctl -u websec -n 50

# Vérifier la config
websec run --config /etc/websec/websec.toml --dry-run

# Tester la connexion Redis
redis-cli ping

# Vérifier que le port est libre
sudo netstat -tulpn | grep :8081
```

### Erreur "Cannot connect to backend"

```bash
# Vérifier que le backend écoute
curl http://127.0.0.1:3000/

# Vérifier avec netstat
sudo netstat -tulpn | grep :3000

# Tester depuis le conteneur Docker
docker exec websec-proxy wget -O- http://host.docker.internal:3000/
```

### Trop de faux positifs

Ajustez les seuils dans la configuration :

```toml
[reputation]
threshold_allow = 60        # Plus permissif (était 70)
threshold_ratelimit = 30    # Plus permissif (était 40)
```

Ou ajoutez des IPs à la whitelist via la CLI :

```bash
websec lists whitelist add 1.2.3.4
websec lists whitelist add 10.0.0.0/8
```

### IP légitime bloquée

**Déblocage d'urgence** :

```bash
# Via Redis
redis-cli DEL websec:ip:1.2.3.4

# Ou via whitelist temporaire
sudo nano /etc/websec/websec.toml
# Ajouter à [lists] whitelist
sudo systemctl restart websec
```

### Performance dégradée

```bash
# Vérifier l'utilisation CPU/RAM
docker stats websec-proxy
# ou
top -p $(pgrep websec)

# Vérifier les métriques
curl -s http://localhost:9090/metrics | grep request_duration

# Augmenter les workers
sudo nano /etc/websec/websec.toml
# workers = 8
sudo systemctl restart websec
```

### Logs trop volumineux

```bash
# Changer le niveau de log
sudo nano /etc/websec/websec.toml
```

```toml
[logging]
level = "warn"  # Au lieu de "info"
```

```bash
# Rotation des logs avec logrotate
sudo nano /etc/logrotate.d/websec
```

```
/var/log/websec/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 websec websec
}
```

## Mise à Jour

### Docker

```bash
cd websec
git pull
websec docker build
docker stop websec-proxy
docker rm websec-proxy
# Relancer avec docker run...
```

### Native

```bash
cd websec
git pull
cargo build --release --locked
sudo systemctl stop websec
sudo cp target/release/websec /usr/local/bin/
sudo systemctl start websec
```

## Support

- **Documentation** : [docs/](../docs/)
- **Issues** : https://github.com/votre-username/websec/issues
- **Discussions** : https://github.com/votre-username/websec/discussions

## Checklist Pré-Production

- [ ] Storage configuré (Redis avec persistence, ou "memory"/"sled" si mono-instance)
- [ ] Backend configuré pour écouter sur localhost uniquement
- [ ] WebSec installé et configuré
- [ ] Whitelist configurée avec vos IPs d'administration
- [ ] Firewall configuré
- [ ] SSL/TLS configuré (natif via `--features tls`, ou via Nginx/Caddy devant)
- [ ] Monitoring configuré (Prometheus + Grafana)
- [ ] Alerting configuré
- [ ] Logs rotatés (logrotate)
- [ ] Backups automatiques (Redis + config)
- [ ] Tests fonctionnels passés
- [ ] Plan de rollback préparé
- [ ] Documentation interne à jour
