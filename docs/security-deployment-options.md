# Options de Déploiement Sécurisé WebSec

## ❓ WebSec a-t-il besoin de root ?

**NON !** WebSec peut tourner sans privilèges root en utilisant les capabilities Linux.

---

## 🔐 Option 1 : Capabilities Linux (RECOMMANDÉ)

### Principe

Donner **uniquement** la permission de bind sur ports < 1024, sans accorder tous les privilèges root.

### Avantages

- ✅ **Sécurité maximale** : pas de root complet
- ✅ **Principe du moindre privilège** : uniquement CAP_NET_BIND_SERVICE
- ✅ **Isolation filesystem** : ProtectSystem, ProtectHome
- ✅ **Standard moderne** : Linux kernel 2.2+
- ✅ **Simple à configurer** : une commande setcap
- ✅ **Pas de règles réseau** : pas d'iptables à maintenir

### Setup

```bash
# 1. Créer un utilisateur système dédié
sudo useradd -r -s /bin/false -d /opt/websec websec

# 2. Compiler WebSec
cd /opt/websec
sudo chown -R websec:websec /opt/websec
sudo -u websec cargo build --release --features tls

# 3. Donner la capability CAP_NET_BIND_SERVICE
sudo setcap 'cap_net_bind_service=+ep' /opt/websec/target/release/websec

# 4. Vérifier
getcap /opt/websec/target/release/websec
# Attendu: /opt/websec/target/release/websec cap_net_bind_service=ep

# 5. Permissions certificats SSL
sudo chown -R root:websec /etc/letsencrypt/archive/example.com/
sudo chown -R root:websec /etc/letsencrypt/live/example.com/
sudo chmod 750 /etc/letsencrypt/{archive,live}/example.com/
sudo chmod 640 /etc/letsencrypt/archive/example.com/*.pem
```

### Service systemd

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

[Install]
WantedBy=multi-user.target
```

### Configuration websec.toml

```toml
# HTTP listener (port 80)
[[server.listeners]]
listen = "0.0.0.0:80"
backend = "http://127.0.0.1:8080"

# HTTPS listener (port 443)
[[server.listeners]]
listen = "0.0.0.0:443"
backend = "http://127.0.0.1:8080"

[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"
```

### ⚠️ Attention : Capabilities et Recompilation

**Les capabilities sont liées au binaire, pas au processus !**

Si vous recompilez WebSec, vous **devez réappliquer** la capability :

```bash
# Après chaque cargo build
sudo setcap 'cap_net_bind_service=+ep' /opt/websec/target/release/websec
```

Pourquoi ? Les capabilities sont des **attributs de fichier étendus (xattr)** qui ne survivent pas au remplacement du binaire.

**Solution pour la CI/CD** :
```bash
# Dans votre script de déploiement
cargo build --release --features tls
sudo setcap 'cap_net_bind_service=+ep' ./target/release/websec
sudo systemctl restart websec
```

---

## 🔀 Option 2 : Ports Non-Privilégiés + iptables Redirect

### Principe

WebSec écoute sur ports > 1024 (pas besoin de root), iptables redirige 80→8000 et 443→8443.

### Avantages

- ✅ Pas besoin de capabilities
- ✅ WebSec tourne en utilisateur normal
- ✅ Fonctionne sur vieux kernels

### Inconvénients

- ❌ Règles iptables à maintenir
- ❌ Complexité réseau supplémentaire
- ❌ Peut poser problème avec Docker/Kubernetes

### Setup

```bash
# websec.toml
[[server.listeners]]
listen = "0.0.0.0:8000"  # Au lieu de 80
backend = "http://127.0.0.1:8080"

[[server.listeners]]
listen = "0.0.0.0:8443"  # Au lieu de 443
backend = "http://127.0.0.1:8080"
```

```bash
# Redirection iptables (une seule fois, root requis)
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8000
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443

# OUTPUT chain pour localhost
sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8000
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443

# Sauvegarder les règles (Ubuntu/Debian)
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

**Service systemd** :
```ini
[Service]
User=websec
Group=websec
ExecStart=/opt/websec/target/release/websec --config /etc/websec/websec.toml run
# Pas besoin de capabilities
```

---

## 🚪 Option 3 : Reverse Proxy Devant WebSec

### Principe

Nginx/HAProxy écoute sur 80/443 (root) → forward vers WebSec sur 8000/8443 (non-root).

### Avantages

- ✅ Nginx gère SSL/TLS (mature, optimisé)
- ✅ WebSec en backend simple
- ✅ Load balancing facile

### Inconvénients

- ❌ **Complexité** : un composant supplémentaire
- ❌ **Performance** : un saut réseau de plus
- ❌ **Headers** : attention à la vraie IP client
- ❌ **Overhead** : mémoire + CPU pour Nginx

### Setup

**Nginx** (`/etc/nginx/sites-enabled/websec`) :
```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }
}
```

**WebSec config** :
```toml
[server]
trusted_proxies = ["127.0.0.1"]  # Trust Nginx

[[server.listeners]]
listen = "127.0.0.1:8000"  # Localhost uniquement
backend = "http://127.0.0.1:8080"
```

---

## ⚠️ Option 4 : Root (DÉCONSEILLÉ)

### Principe

WebSec tourne en root complet.

### Avantages

- ✅ Simple (pas de setup)

### Inconvénients

- ❌ **DANGEREUX** : root = accès total système
- ❌ **Mauvaise pratique** : violation principe moindre privilège
- ❌ **Risque de sécurité** : si WebSec est compromis, tout le système l'est
- ❌ **Non recommandé en production**

### Quand utiliser ?

**Uniquement pour tests/développement en local** :
```bash
sudo ./target/release/websec --config websec.toml run
```

**Ne JAMAIS utiliser en production !**

---

## 📊 Comparaison des Options

| Critère | Capabilities (Option 1) | iptables (Option 2) | Nginx Proxy (Option 3) | Root (Option 4) |
|---------|------------------------|---------------------|------------------------|-----------------|
| **Sécurité** | ⭐⭐⭐⭐⭐ Excellent | ⭐⭐⭐⭐ Bon | ⭐⭐⭐ Moyen | ⭐ Très mauvais |
| **Performance** | ⭐⭐⭐⭐⭐ Natif | ⭐⭐⭐⭐⭐ Natif | ⭐⭐⭐ Overhead | ⭐⭐⭐⭐⭐ Natif |
| **Simplicité** | ⭐⭐⭐⭐ Simple | ⭐⭐⭐ Moyen | ⭐⭐ Complexe | ⭐⭐⭐⭐⭐ Trivial |
| **Maintenance** | ⭐⭐⭐⭐ Faible | ⭐⭐⭐ Moyenne | ⭐⭐ Élevée | ⭐⭐⭐⭐⭐ Aucune |
| **Production** | ✅ **RECOMMANDÉ** | ✅ OK | ⚠️ Acceptable | ❌ **JAMAIS** |

---

## 🎯 Recommandation Finale

### Pour la production : **Option 1 (Capabilities)**

**Pourquoi ?**
1. **Sécurité maximale** sans overhead
2. **Standard Linux moderne** (kernel 2.2+, soit depuis 1999)
3. **Simple à maintenir** : pas de règles réseau complexes
4. **Performance native** : pas de proxy intermédiaire
5. **Principe du moindre privilège** : uniquement CAP_NET_BIND_SERVICE

### Configuration minimale

```bash
# 1. Créer l'utilisateur
sudo useradd -r -s /bin/false websec

# 2. Compiler
sudo -u websec cargo build --release --features tls

# 3. Capability
sudo setcap 'cap_net_bind_service=+ep' ./target/release/websec

# 4. Permissions SSL
sudo chown -R root:websec /etc/letsencrypt/archive/example.com/
sudo chmod 640 /etc/letsencrypt/archive/example.com/*.pem

# 5. Lancer
sudo -u websec ./target/release/websec --config websec.toml run
```

**C'est tout !** Pas besoin de root, pas d'iptables, pas de proxy supplémentaire.

---

## 🔍 Vérification

### Vérifier que WebSec ne tourne PAS en root

```bash
# Voir quel utilisateur exécute WebSec
ps aux | grep websec

# Attendu :
# websec   12345  0.5  1.2  123456  ...  /opt/websec/target/release/websec
#  ↑
#  Doit être "websec", PAS "root" !
```

### Vérifier les capabilities

```bash
getcap /opt/websec/target/release/websec

# Attendu :
# /opt/websec/target/release/websec cap_net_bind_service=ep
```

### Vérifier les ports

```bash
sudo ss -tlnp | grep -E ':80|:443'

# Attendu :
# *:80     LISTEN  12345/websec
# *:443    LISTEN  12345/websec
```

### Vérifier les permissions

```bash
# WebSec doit pouvoir lire les certificats
sudo -u websec cat /etc/letsencrypt/live/example.com/fullchain.pem > /dev/null && echo "OK" || echo "ERREUR"

# Attendu : OK
```

---

## 📖 Références

- **Linux Capabilities** : `man capabilities`
- **setcap** : `man setcap`
- **systemd security** : https://www.freedesktop.org/software/systemd/man/systemd.exec.html
- **Guide complet** : [docs/deployment-checklist.md](deployment-checklist.md)
- **Configuration Apache** : [docs/apache-configuration-guide.md](apache-configuration-guide.md)
