# Configuration SNI Multi-Domaines

Guide complet pour configurer WebSec avec SNI (Server Name Indication) afin de servir plusieurs domaines avec différents certificats SSL sur le même port 443.

---

## 📋 Table des matières

1. [Introduction](#introduction)
2. [Qu'est-ce que SNI ?](#quest-ce-que-sni)
3. [Cas d'usage](#cas-dusage)
4. [Configuration](#configuration)
5. [Exemples pratiques](#exemples-pratiques)
6. [Génération des certificats](#génération-des-certificats)
7. [Tests et vérification](#tests-et-vérification)
8. [Dépannage](#dépannage)

---

## 🎯 Introduction

WebSec supporte SNI (Server Name Indication) permettant de gérer **plusieurs domaines** avec **différents certificats SSL** sur un seul listener HTTPS (port 443).

### Avant (sans SNI) :

```toml
# ❌ Problème : Un seul certificat pour tous les domaines
[[server.listeners]]
listen = "0.0.0.0:443"
[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"  # Seulement example.com
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"
```

→ Les visiteurs de `example.org` reçoivent une erreur SSL car le certificat est pour `example.com`

### Après (avec SNI) :

```toml
# ✅ Solution : Certificat adapté à chaque domaine
[[server.listeners]]
listen = "0.0.0.0:443"
[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"  # Défaut
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"

[[server.listeners.tls.sni_certificates]]
server_name = "example.org"
cert_file = "/etc/letsencrypt/live/example.org/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.org/privkey.pem"
```

→ Chaque domaine reçoit son propre certificat valide

---

## 🔐 Qu'est-ce que SNI ?

**Server Name Indication (SNI)** est une extension TLS qui permet au client d'indiquer quel nom d'hôte il souhaite atteindre **avant** l'établissement de la connexion TLS.

### Fonctionnement :

1. **Client HTTPS** se connecte à `https://example.org`
2. **Handshake TLS** : Client envoie `server_name = "example.org"`
3. **WebSec SNI Resolver** :
   - Reçoit `server_name = "example.org"`
   - Cherche un certificat correspondant
   - Retourne le certificat de `example.org`
4. **TLS établi** avec le bon certificat
5. **Requête HTTP** forward vers Apache/Nginx qui route par `Host:` header

### Types de correspondance :

- **Exact** : `"example.com"` correspond exactement à `example.com`
- **Wildcard** : `"*.example.com"` correspond à `sub.example.com`, `api.example.com`, etc.
- **Fallback** : Si aucune correspondance, utilise le certificat par défaut

---

## 💼 Cas d'usage

### Cas 1 : Plusieurs sites sur le même serveur

```
Serveur avec une IP publique :
- example.com    → Certificat Let's Encrypt example.com
- example.org    → Certificat Let's Encrypt example.org
- example.net    → Certificat Let's Encrypt example.net
```

**Avantages** :
- ✅ Une seule IP publique nécessaire
- ✅ Un seul listener sur port 443
- ✅ Certificats SSL valides pour chaque domaine

### Cas 2 : Domaine principal + sous-domaines

```
Domaine principal : example.com
Sous-domaines :
- *.example.com  → Wildcard pour tous les sous-domaines
- www.example.com → Certificat spécifique (priorité sur wildcard)
```

### Cas 3 : Migration progressive

```
Ancien domaine : oldsite.com (certificat existant)
Nouveau domaine : newsite.com (nouveau certificat)
```

Pendant la migration, les deux domaines sont actifs avec leurs certificats respectifs.

---

## ⚙️ Configuration

### Structure TOML

```toml
[[server.listeners]]
listen = "0.0.0.0:443"
backend = "http://127.0.0.1:8081"

[server.listeners.tls]
# Certificat par défaut/fallback (obligatoire)
cert_file = "/path/to/default/fullchain.pem"
key_file = "/path/to/default/privkey.pem"

# Certificats SNI additionnels (optionnels)
[[server.listeners.tls.sni_certificates]]
server_name = "domain1.com"
cert_file = "/path/to/domain1/fullchain.pem"
key_file = "/path/to/domain1/privkey.pem"

[[server.listeners.tls.sni_certificates]]
server_name = "domain2.com"
cert_file = "/path/to/domain2/fullchain.pem"
key_file = "/path/to/domain2/privkey.pem"
```

### Champs :

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| `server.listeners.tls.cert_file` | String | Oui | Certificat par défaut (fallback) |
| `server.listeners.tls.key_file` | String | Oui | Clé privée par défaut |
| `sni_certificates` | Array | Non | Liste des certificats SNI additionnels |
| `sni_certificates[].server_name` | String | Oui | Nom du serveur (exact ou wildcard) |
| `sni_certificates[].cert_file` | String | Oui | Certificat pour ce domaine |
| `sni_certificates[].key_file` | String | Oui | Clé privée pour ce domaine |

---

## 📚 Exemples pratiques

### Exemple 1 : Configuration minimale (2 domaines)

```toml
[[server.listeners]]
listen = "0.0.0.0:443"
backend = "http://127.0.0.1:8081"

[server.listeners.tls]
# Défaut : example.com
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"

# SNI : example.org
[[server.listeners.tls.sni_certificates]]
server_name = "example.org"
cert_file = "/etc/letsencrypt/live/example.org/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.org/privkey.pem"
```

**Résultat** :
- Requêtes vers `https://example.com` → Certificat `example.com`
- Requêtes vers `https://example.org` → Certificat `example.org`
- Requêtes sans SNI ou domaine inconnu → Certificat `example.com` (fallback)

### Exemple 2 : Wildcards + domaines spécifiques

```toml
[[server.listeners]]
listen = "0.0.0.0:443"
backend = "http://127.0.0.1:8081"

[server.listeners.tls]
# Défaut : example.com
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"

# Wildcard pour tous les sous-domaines
[[server.listeners.tls.sni_certificates]]
server_name = "*.example.com"
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"

# Certificat spécifique pour www (priorité sur wildcard)
[[server.listeners.tls.sni_certificates]]
server_name = "www.example.com"
cert_file = "/etc/letsencrypt/live/www.example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/www.example.com/privkey.pem"
```

**Logique de résolution** :
1. **Exact match** : `www.example.com` → Certificat spécifique `www.example.com`
2. **Wildcard match** : `api.example.com` → Certificat wildcard `*.example.com`
3. **Fallback** : `example.com` → Certificat par défaut

### Exemple 3 : Production avec 5 domaines

```toml
[[server.listeners]]
listen = "0.0.0.0:80"
backend = "http://127.0.0.1:8081"

[[server.listeners]]
listen = "0.0.0.0:443"
backend = "http://127.0.0.1:8081"

[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/mainsite.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/mainsite.com/privkey.pem"

[[server.listeners.tls.sni_certificates]]
server_name = "shop.com"
cert_file = "/etc/letsencrypt/live/shop.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/shop.com/privkey.pem"

[[server.listeners.tls.sni_certificates]]
server_name = "blog.com"
cert_file = "/etc/letsencrypt/live/blog.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/blog.com/privkey.pem"

[[server.listeners.tls.sni_certificates]]
server_name = "api.example.com"
cert_file = "/etc/letsencrypt/live/api.example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/api.example.com/privkey.pem"

[[server.listeners.tls.sni_certificates]]
server_name = "cdn.example.com"
cert_file = "/etc/letsencrypt/live/cdn.example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/cdn.example.com/privkey.pem"
```

---

## 🔑 Génération des certificats

### Option 1 : Certificats séparés (recommandé)

```bash
# Certificat pour example.com
sudo certbot certonly --standalone -d example.com -d www.example.com

# Certificat pour example.org
sudo certbot certonly --standalone -d example.org -d www.example.org

# Certificat pour example.net
sudo certbot certonly --standalone -d example.net
```

**Avantages** :
- Renouvellement indépendant
- Domaines isolés
- Plus facile à gérer

### Option 2 : Certificat SAN multi-domaines

```bash
# Un seul certificat pour tous les domaines
sudo certbot certonly --standalone \
  -d example.com \
  -d www.example.com \
  -d example.org \
  -d www.example.org
```

**Inconvénients** :
- Renouvellement global (si un domaine change, tous les domaines sont impactés)
- Moins flexible

### Configuration des permissions

```bash
# Permissions Let's Encrypt pour websec
sudo chmod 755 /etc/letsencrypt
sudo chmod 755 /etc/letsencrypt/live
sudo chmod 755 /etc/letsencrypt/archive

# Permissions par domaine
for domain in example.com example.org example.net; do
    sudo chown root:websec /etc/letsencrypt/archive/$domain
    sudo chmod 750 /etc/letsencrypt/archive/$domain
    sudo chmod 640 /etc/letsencrypt/archive/$domain/*.pem
done
```

---

## ✅ Tests et vérification

### 1. Vérifier que WebSec charge les certificats

```bash
sudo -u websec /usr/local/bin/websec --config /etc/websec/websec.toml run --dry-run
```

**Output attendu** :
```
🔒 HTTPS listener ready on 0.0.0.0:443 (SNI enabled, 3 certificates)
Loaded SNI certificate for: example.org
Loaded SNI certificate for: example.net
```

### 2. Tester les certificats avec OpenSSL

```bash
# Test example.com (défaut)
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -subject

# Test example.org (SNI)
openssl s_client -connect example.com:443 -servername example.org </dev/null 2>/dev/null | openssl x509 -noout -subject

# Test wildcard
openssl s_client -connect example.com:443 -servername api.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject
```

### 3. Tester avec curl

```bash
# Test avec SNI
curl -v --resolve example.org:443:YOUR_SERVER_IP https://example.org

# Test wildcard
curl -v --resolve api.example.com:443:YOUR_SERVER_IP https://api.example.com
```

### 4. Vérifier les logs WebSec

```bash
sudo journalctl -u websec -f | grep SNI
```

**Logs normaux** :
```
SNI: Exact match found server_name="example.org"
SNI: Wildcard match found server_name="api.example.com"
SNI: No match, using default certificate server_name="unknown.com"
```

---

## 🔧 Dépannage

### Problème 1 : "No SNI match, using default certificate"

**Symptôme** : Tous les domaines reçoivent le certificat par défaut

**Causes possibles** :
1. Client ne supporte pas SNI (très ancien navigateur)
2. `server_name` mal configuré dans TOML
3. Certificats non chargés

**Solutions** :
```bash
# Vérifier la configuration
grep -A 3 "sni_certificates" /etc/websec/websec.toml

# Vérifier les logs de chargement
sudo journalctl -u websec | grep "Loaded SNI certificate"

# Test manuel
openssl s_client -connect localhost:443 -servername example.org
```

### Problème 2 : "Failed to load TLS config"

**Symptôme** : WebSec ne démarre pas

**Causes** :
- Fichiers certificat introuvables
- Permissions incorrectes
- Certificat/clé incompatibles

**Solutions** :
```bash
# Vérifier existence
ls -la /etc/letsencrypt/live/example.org/

# Vérifier permissions
sudo -u websec cat /etc/letsencrypt/live/example.org/fullchain.pem | head -3

# Vérifier validité
openssl x509 -in /etc/letsencrypt/live/example.org/fullchain.pem -noout -text
openssl rsa -in /etc/letsencrypt/live/example.org/privkey.pem -check
```

### Problème 3 : Wildcard ne fonctionne pas

**Symptôme** : `api.example.com` ne correspond pas à `*.example.com`

**Cause** : Wildcard ne couvre qu'un seul niveau de sous-domaine

**Exemples** :
- ✅ `*.example.com` correspond à `api.example.com`
- ✅ `*.example.com` correspond à `www.example.com`
- ❌ `*.example.com` ne correspond PAS à `sub.api.example.com` (2 niveaux)
- ❌ `*.example.com` ne correspond PAS à `example.com` (domaine apex)

**Solution** : Ajouter des entrées exactes ou wildcards supplémentaires

### Problème 4 : Certificat expiré non renouvelé

**Symptôme** : Erreur SSL après renouvellement certbot

**Cause** : WebSec a chargé les anciens certificats au démarrage

**Solution** :
```bash
# Recharger WebSec après renouvellement
sudo systemctl reload websec

# Ou redémarrer
sudo systemctl restart websec
```

**Automatiser** : Ajouter hook certbot
```bash
# /etc/letsencrypt/renewal-hooks/post/websec-reload.sh
#!/bin/bash
systemctl reload websec
```

---

## 🎓 Bonnes pratiques

### 1. Organisation des certificats

```
/etc/letsencrypt/
├── live/
│   ├── example.com/     # Domaine principal
│   ├── example.org/     # Domaine secondaire
│   └── example.net/     # Domaine tertiaire
```

Utilisez certbot avec `--standalone` ou `--webroot` pour chaque domaine séparément.

### 2. Surveillance des expirations

```bash
# Script de monitoring
for domain in example.com example.org example.net; do
    expiry=$(openssl x509 -in /etc/letsencrypt/live/$domain/fullchain.pem -noout -enddate | cut -d= -f2)
    echo "$domain expire le $expiry"
done
```

### 3. Tests réguliers

Testez chaque domaine après déploiement :
```bash
for domain in example.com example.org api.example.com; do
    echo "Testing $domain..."
    curl -I --resolve $domain:443:127.0.0.1 https://$domain
done
```

### 4. Logs et alertes

Configurez des alertes sur les logs :
```bash
# Alerter si certificat par défaut utilisé de manière inattendue
journalctl -u websec -f | grep "SNI: No match" | mail -s "SNI fallback détecté" admin@example.com
```

---

## 📊 Performances

### Impact SNI

L'overhead SNI est **négligeable** :
- **+0.1ms** : Lookup dans HashMap (O(1))
- **0 impact** : Certificats pré-chargés en mémoire
- **Pas de I/O** : Pas de lecture disque pendant handshake

### Limites

- **Nombre de certificats** : Illimité en théorie, mais pour >100 domaines, envisager plusieurs listeners
- **Mémoire** : ~10KB par certificat chargé en mémoire
- **Renouvellement** : Nécessite reload/restart WebSec

---

## 📞 Support

Pour toute question sur la configuration SNI :

1. Vérifier les logs : `sudo journalctl -u websec -f`
2. Tester manuellement : `openssl s_client -servername ...`
3. Consulter : `docs/troubleshooting-guide.md`
4. Créer une issue : https://github.com/yrbane/websec/issues
