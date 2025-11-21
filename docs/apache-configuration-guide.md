# Configuration Apache avec WebSec (HTTP + HTTPS)

## Architecture Recommandée

```
Internet
    ↓
WebSec :80 (HTTP)  ──────────→ Apache :8080 (HTTP)
WebSec :443 (HTTPS) ─(TLS)─→  Apache :8080 (HTTP)
         ↑                           ↑
    🔐 Certificat SSL          Pas de SSL nécessaire
```

**WebSec termine le TLS** et forward en HTTP vers Apache.

## Pourquoi cette architecture ?

### ✅ Avantages

1. **Inspection complète du trafic**
   - WebSec voit le contenu déchiffré
   - Détection SQL injection, XSS, path traversal
   - Analyse des payloads JSON/XML

2. **Gestion SSL simplifiée**
   - Un seul endroit pour les certificats (WebSec)
   - Renouvellement Let's Encrypt centralisé
   - Apache n'a plus besoin de mod_ssl

3. **Performance**
   - Pas de double chiffrement/déchiffrement
   - CPU économisé sur Apache
   - WebSec peut compresser/optimiser

4. **Headers sécurisés**
   - WebSec injecte `X-Real-IP`, `X-Forwarded-For`
   - Apache voit la vraie IP client
   - `X-Forwarded-Proto: https` pour redirections

### ❌ Alternative déconseillée : Pass-through TLS

```
Internet → WebSec :443 (forward TCP) → Apache :8443 (TLS)
                 ❌ Trafic chiffré = WAF aveugle
```

**Problème** : WebSec ne peut pas analyser le trafic → inutile comme WAF !

---

## Configuration WebSec

### 1. Fichier `websec.toml`

```toml
[server]
workers = 4
trusted_proxies = []
max_body_size = 209715200  # 200 MB pour uploads vidéo

# Listener HTTP (port 80)
[[server.listeners]]
listen = "0.0.0.0:80"
backend = "http://127.0.0.1:8080"

# Listener HTTPS (port 443) - TLS terminé par WebSec
[[server.listeners]]
listen = "0.0.0.0:443"
backend = "http://127.0.0.1:8080"  # Apache reçoit HTTP déchiffré

[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"

[metrics]
enabled = true
port = 9090  # Métriques internes uniquement
```

### 2. Certificats SSL

WebSec utilise **les certificats de votre domaine** (identiques à ceux qu'Apache utilisait) :

```bash
# Let's Encrypt (Certbot)
sudo certbot certonly --standalone -d example.com -d www.example.com

# Certificats générés dans :
/etc/letsencrypt/live/example.com/
├── fullchain.pem  → cert_file (certificat + chaîne)
├── privkey.pem    → key_file (clé privée)
```

**Permissions** :
```bash
# WebSec doit pouvoir lire les certificats
sudo chown root:websec /etc/letsencrypt/archive/example.com/*.pem
sudo chmod 640 /etc/letsencrypt/archive/example.com/*.pem
```

### 3. Renouvellement automatique

```bash
# Hook Certbot pour recharger WebSec après renouvellement
sudo nano /etc/letsencrypt/renewal-hooks/post/reload-websec.sh
```

```bash
#!/bin/bash
systemctl reload websec
```

```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/post/reload-websec.sh
```

---

## Configuration Apache

### 1. Désactiver SSL dans Apache

Apache n'a **plus besoin de gérer SSL** (WebSec s'en charge).

#### Avant (Apache gérait SSL) :
```apache
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
    # ...
</VirtualHost>
```

#### Après (Apache reçoit HTTP de WebSec) :
```apache
# Port 8080 pour tout le trafic (HTTP + HTTPS déchiffré)
<VirtualHost *:8080>
    ServerName example.com

    # Pas de SSLEngine - WebSec gère le TLS

    # Récupérer la vraie IP client depuis WebSec
    RemoteIPHeader X-Real-IP
    RemoteIPTrustedProxy 127.0.0.1
    RemoteIPTrustedProxy ::1

    # Détecter si la requête originale était HTTPS
    SetEnvIf X-Forwarded-Proto "https" HTTPS=on

    # Logs avec vraie IP
    LogFormat "%a %l %u %t \"%r\" %>s %b" combined_real_ip
    CustomLog /var/log/apache2/access.log combined_real_ip

    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

### 2. Changer les ports d'écoute Apache

```bash
sudo nano /etc/apache2/ports.conf
```

```apache
# Apache écoute UNIQUEMENT en local sur 8080
Listen 127.0.0.1:8080

# Supprimer :
# Listen 80
# Listen 443
```

### 3. Activer les modules nécessaires

```bash
sudo a2enmod remoteip
sudo a2enmod headers
sudo systemctl restart apache2
```

---

## Vérification

### 1. Tester la configuration

```bash
# WebSec
sudo websec --config /etc/websec/websec.toml --validate

# Apache
sudo apachectl configtest
```

### 2. Démarrage

```bash
# Démarrer dans l'ordre :
sudo systemctl start apache2
sudo systemctl start websec

# Vérifier les ports
sudo ss -tlnp | grep -E ':80|:443|:8080|:9090'
```

Vous devriez voir :
```
*:80    LISTEN  websec
*:443   LISTEN  websec
127.0.0.1:8080  LISTEN  apache2
*:9090  LISTEN  websec (metrics)
```

### 3. Test fonctionnel

```bash
# HTTP
curl -I http://example.com

# HTTPS
curl -I https://example.com

# Vérifier les headers WebSec
curl -I https://example.com | grep -i x-websec
```

### 4. Logs

```bash
# WebSec
sudo journalctl -u websec -f

# Apache (doit voir les vraies IPs clients)
sudo tail -f /var/log/apache2/access.log
```

---

## Sécurité supplémentaire

### 1. Firewall

```bash
# Bloquer l'accès direct à Apache (uniquement depuis localhost)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 8080/tcp  # Empêcher bypass de WebSec
sudo ufw enable
```

### 2. Apache : bind uniquement localhost

Dans `/etc/apache2/ports.conf` :
```apache
# Force Apache à UNIQUEMENT écouter en local
Listen 127.0.0.1:8080
```

Ainsi, même si le firewall est mal configuré, Apache refuse les connexions externes.

### 3. Monitoring

```bash
# Métriques Prometheus
curl http://localhost:9090/metrics

# Statistiques WebSec
curl http://localhost:9090/metrics | grep websec_requests_total
```

---

## Résumé

| Composant | Port  | Fonction |
|-----------|-------|----------|
| WebSec    | :80   | HTTP public |
| WebSec    | :443  | HTTPS public (TLS terminé) |
| WebSec    | :9090 | Métriques Prometheus (interne) |
| Apache    | :8080 | Backend HTTP (local uniquement) |

**Flux de données** :
```
Client HTTPS → WebSec :443 (déchiffre) → Apache :8080 (HTTP)
                  ↑
            🛡️ Analyse WAF
            🔐 Certificat SSL du domaine
```

WebSec utilise **vos certificats Let's Encrypt existants** - ce sont les mêmes que ceux qu'Apache utilisait avant !
