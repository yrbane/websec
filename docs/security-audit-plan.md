# Plan d'Audit de Sécurité WebSec

## 🎯 Objectif

Auditer WebSec en conditions réelles pour valider la détection et le blocage de **toutes les familles de menaces** documentées.

---

## 🛠️ Outils d'Audit Recommandés

### 1. Scanners de Vulnérabilités

```bash
# SQLMap (injection SQL)
pip3 install sqlmap

# Nikto (scan web)
sudo apt install nikto

# Gobuster (énumération)
sudo apt install gobuster

# OWASP ZAP (proxy d'interception)
sudo snap install zaproxy --classic

# Burp Suite Community (tests manuels)
# Télécharger depuis https://portswigger.net/burp/communitydownload
```

### 2. Outils de Stress Testing

```bash
# Apache Bench (flood simple)
sudo apt install apache2-utils

# wrk (charge HTTP avancée)
sudo apt install wrk

# Slowloris (slow HTTP attack)
git clone https://github.com/gkbrk/slowloris.git
```

### 3. Outils Custom

```bash
# Scripts de test dans le repo
cd /opt/websec/tests/audit/
```

---

## 📋 Scénarios de Test par Famille

### 🤖 Famille 1 : Bot Detection

#### Test 1.1 : User-Agent Suspect (sqlmap)

```bash
# Attendu : Signal VulnerabilityScan, BLOCK
curl -H "User-Agent: sqlmap/1.7" https://votre-domaine.com/
```

**Vérification** :
```bash
# Logs WebSec
sudo journalctl -u websec | grep -i "sqlmap"

# Métriques
curl http://localhost:9090/metrics | grep 'websec_signals_total{signal="VulnerabilityScan"}'
```

#### Test 1.2 : User-Agent Automatisé (curl, python-requests)

```bash
# Attendu : Signal SuspiciousUserAgent, RATE_LIMIT
curl -H "User-Agent: curl/7.68.0" https://votre-domaine.com/
curl -H "User-Agent: python-requests/2.25.1" https://votre-domaine.com/
```

#### Test 1.3 : Missing User-Agent

```bash
# Attendu : Signal BotBehaviorPattern
curl -H "User-Agent:" https://votre-domaine.com/
```

#### Test 1.4 : Scraping Agressif

```bash
# 100 requêtes sans charger assets CSS/JS
for i in {1..100}; do
    curl -s https://votre-domaine.com/page$i > /dev/null
    sleep 0.1
done
```

**Attendu** : Signal `AbusiveClient` après ~50 requêtes

---

### 🔐 Famille 2 : Brute Force

#### Test 2.1 : Tentatives Login Échouées

**Prérequis** : Créer une page de login sur Apache

```bash
# 10 tentatives échouées rapides
for i in {1..10}; do
    curl -X POST https://votre-domaine.com/login \
         -d "username=admin&password=wrong$i"
    sleep 0.5
done
```

**Attendu** :
- Signal `FailedLogin` après 3-5 tentatives
- `RATE_LIMIT` puis `BLOCK` après 8-10 tentatives

**Vérification** :
```bash
# Voir le score de réputation de votre IP
redis-cli GET "ip:VOTRE_IP:profile"
```

#### Test 2.2 : Password Spraying

```bash
# Tester plusieurs comptes avec le même mot de passe
for user in admin root test user; do
    curl -X POST https://votre-domaine.com/login \
         -d "username=$user&password=Password123"
    sleep 1
done
```

**Attendu** : Signal `LoginAttemptPattern`

---

### 🌊 Famille 3 : Flood/DDoS

#### Test 3.1 : HTTP Flood Simple

```bash
# Apache Bench : 1000 requêtes, 50 concurrentes
ab -n 1000 -c 50 https://votre-domaine.com/
```

**Attendu** : Signal `RequestFlood`, rate limiting activé

#### Test 3.2 : Burst Attack

```bash
# 100 requêtes en 2 secondes
for i in {1..100}; do
    curl -s https://votre-domaine.com/ &
done
wait
```

**Attendu** : Détection burst, `RATE_LIMIT` activé

#### Test 3.3 : Sustained High Rate

```bash
# wrk : charge soutenue pendant 30 secondes
wrk -t4 -c50 -d30s https://votre-domaine.com/
```

**Attendu** : Dégradation progressive du score, `RATE_LIMIT` puis `BLOCK`

#### Test 3.4 : Slowloris (Slow HTTP Attack)

```bash
cd slowloris
python3 slowloris.py votre-domaine.com -p 443 -s 200
```

**Attendu** : Détection connexions lentes anormales

---

### 💉 Famille 4 : Injections

#### Test 4.1 : SQL Injection

```bash
# Union-based SQLi
curl "https://votre-domaine.com/products.php?id=1' UNION SELECT username,password FROM users--"

# Boolean-based SQLi
curl "https://votre-domaine.com/products.php?id=1' AND '1'='1"

# Time-based SQLi
curl "https://votre-domaine.com/products.php?id=1' AND SLEEP(5)--"

# SQLMap automatisé
sqlmap -u "https://votre-domaine.com/products.php?id=1" --batch --banner
```

**Attendu** : Signal `SqlInjectionAttempt` (weight 30), `BLOCK` immédiat

#### Test 4.2 : XSS (Cross-Site Scripting)

```bash
# Reflected XSS
curl "https://votre-domaine.com/search?q=<script>alert(1)</script>"

# Event handler XSS
curl "https://votre-domaine.com/search?q=<img src=x onerror=alert(1)>"

# JavaScript protocol
curl "https://votre-domaine.com/search?q=<a href='javascript:alert(1)'>click</a>"
```

**Attendu** : Signal `XssAttempt` (weight 30), `BLOCK`

#### Test 4.3 : RCE (Remote Code Execution)

```bash
# Command injection
curl "https://votre-domaine.com/ping.php?host=127.0.0.1;cat%20/etc/passwd"

# Shell metacharacters
curl "https://votre-domaine.com/file.php?name=test\$(whoami)"

# Backtick execution
curl "https://votre-domaine.com/log.php?file=\`id\`"
```

**Attendu** : Signal `RceAttempt` (weight 50 - le plus élevé), `BLOCK` immédiat

#### Test 4.4 : Path Traversal

```bash
# Directory traversal classique
curl "https://votre-domaine.com/download.php?file=../../../etc/passwd"

# URL encoded
curl "https://votre-domaine.com/download.php?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Double encoding
curl "https://votre-domaine.com/download.php?file=%252e%252e%252fetc%252fpasswd"
```

**Attendu** : Signal `PathTraversalAttempt` (weight 30), `BLOCK`

---

### 🔍 Famille 5 : Scanning & Reconnaissance

#### Test 5.1 : Scan WordPress

```bash
# Nikto scan complet
nikto -h https://votre-domaine.com

# Scan manuel des chemins WordPress
for path in wp-admin wp-login.php wp-content wp-includes xmlrpc.php; do
    curl -I "https://votre-domaine.com/$path"
    sleep 0.5
done
```

**Attendu** : Signal `VulnerabilityScan` après 3-5 requêtes suspectes

#### Test 5.2 : Énumération de Répertoires

```bash
# Gobuster (wordlist commune)
gobuster dir -u https://votre-domaine.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -t 10

# Scan manuel fichiers sensibles
for file in .env .git/config config.php .htaccess backup.sql; do
    curl -I "https://votre-domaine.com/$file"
done
```

**Attendu** : Accumulation signaux `VulnerabilityScan`, `BLOCK` après seuil

#### Test 5.3 : Burst 404 (Path Enumeration)

```bash
# 50 requêtes 404 rapides
for i in {1..50}; do
    curl -I "https://votre-domaine.com/nonexistent$i"
done
```

**Attendu** : Détection burst 404, signal `VulnerabilityScan`

---

### 🌍 Famille 6 : Géolocalisation

#### Test 6.1 : Pays à Risque

**Limitation** : Nécessite connexion depuis IP chinoise/russe (VPN/proxy)

```bash
# Via VPN Chine/Russie
curl https://votre-domaine.com/
```

**Attendu** : Signal `HighRiskCountry` (weight 15)

#### Test 6.2 : Impossible Travel

**Test complexe** : Nécessite 2 connexions depuis pays différents en <1h

**Simulation manuelle** :
1. Connexion depuis France (IP naturelle)
2. Connexion depuis Chine via VPN <1h après
3. WebSec devrait détecter `ImpossibleTravel`

---

### 🔒 Famille 7 : Manipulation Headers

#### Test 7.1 : CRLF Injection

```bash
# Injection CRLF dans Host
curl -H "Host: example.com%0d%0aX-Injected: evil" https://votre-domaine.com/

# Injection dans User-Agent
curl -H "User-Agent: Mozilla%0d%0aX-Malicious: true" https://votre-domaine.com/
```

**Attendu** : Signal `HeaderInjection` (weight 20), `BLOCK`

#### Test 7.2 : Host Header Attack (Multiple Hosts)

```bash
# Requête HTTP brute avec 2 Host headers
(echo -ne "GET / HTTP/1.1\r\nHost: legitimate.com\r\nHost: evil.com\r\n\r\n") | \
    openssl s_client -connect votre-domaine.com:443 -quiet
```

**Attendu** : Signal `HostHeaderAttack`, `BLOCK`

#### Test 7.3 : Null Byte Injection

```bash
curl -H "X-Custom: value%00malicious" https://votre-domaine.com/
```

**Attendu** : Signal `HeaderInjection`

#### Test 7.4 : Oversized Headers

```bash
# Header de 10 KB
curl -H "X-Large: $(python3 -c 'print("A"*10000)')" https://votre-domaine.com/
```

**Attendu** : Détection header anormalement grand

---

### 🍪 Famille 8 : Session Anomalies

#### Test 8.1 : Session Hijacking Simulation

**Prérequis** : Application avec sessions

```bash
# Obtenir un cookie de session valide
COOKIE=$(curl -c - https://votre-domaine.com/login | grep session | awk '{print $7}')

# Utiliser le même cookie depuis IP différente (via VPN)
curl -b "session=$COOKIE" --interface eth1 https://votre-domaine.com/account
```

**Attendu** : Signal `SessionTokenAnomaly` si changement IP

#### Test 8.2 : Session Anomaly (User-Agent Change)

```bash
# Login avec Firefox
COOKIE=$(curl -A "Mozilla/5.0 Firefox/95.0" -c - https://votre-domaine.com/login | grep session | awk '{print $7}')

# Utiliser session avec Chrome
curl -A "Mozilla/5.0 Chrome/96.0" -b "session=$COOKIE" https://votre-domaine.com/account
```

**Attendu** : Signal `SessionTokenAnomaly`

---

### 🔓 Famille 9 : Protocol Anomalies

#### Test 9.1 : HTTP/1.0 avec Host Header Manquant

```bash
(echo -ne "GET / HTTP/1.0\r\n\r\n") | nc votre-domaine.com 80
```

**Attendu** : Signal `ProtocolViolation`

#### Test 9.2 : Méthode HTTP Invalide

```bash
curl -X INVALID https://votre-domaine.com/
```

**Attendu** : Rejet immédiat

---

### 📤 Famille 10 : Upload Attacks (Future)

#### Test 10.1 : Upload Webshell PHP

```bash
# Créer un webshell basique
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Uploader (si formulaire existe)
curl -F "file=@shell.php" https://votre-domaine.com/upload.php
```

**Attendu** : Signal `ScriptInjection`, `BLOCK` (note : `PotentialWebshellUpload` n'existe pas encore)

---

## 📊 Matrice de Validation

| Famille | Test | Signal Attendu | Weight | Décision | Status |
|---------|------|----------------|--------|----------|--------|
| Bot | sqlmap UA | VulnerabilityScan | 25 | BLOCK | ⏳ |
| Bot | curl UA | SuspiciousUserAgent | 10 | RATE_LIMIT | ⏳ |
| Bot | Missing UA | BotBehaviorPattern | 15 | RATE_LIMIT | ⏳ |
| Bot | Scraping | AbusiveClient | 15 | BLOCK | ⏳ |
| BruteForce | Failed Login | FailedLogin | 20 | BLOCK | ⏳ |
| BruteForce | Password Spray | LoginAttemptPattern | 20 | BLOCK | ⏳ |
| Flood | HTTP Flood | RequestFlood | 20 | RATE_LIMIT | ⏳ |
| Flood | Burst | RequestFlood | 20 | RATE_LIMIT | ⏳ |
| Injection | SQLi | SqlInjectionAttempt | 30 | BLOCK | ⏳ |
| Injection | XSS | XssAttempt | 30 | BLOCK | ⏳ |
| Injection | RCE | RceAttempt | 50 | BLOCK | ⏳ |
| Injection | Path Traversal | PathTraversalAttempt | 30 | BLOCK | ⏳ |
| Scan | Nikto | VulnerabilityScan | 25 | BLOCK | ⏳ |
| Scan | Gobuster | VulnerabilityScan | 25 | BLOCK | ⏳ |
| Scan | 404 Burst | VulnerabilityScan | 25 | BLOCK | ⏳ |
| Geo | High Risk Country | HighRiskCountry | 15 | RATE_LIMIT | ⏳ |
| Geo | Impossible Travel | ImpossibleTravel | 20 | BLOCK | ⏳ |
| Header | CRLF Injection | HeaderInjection | 20 | BLOCK | ⏳ |
| Header | Multiple Host | HostHeaderAttack | 20 | BLOCK | ⏳ |
| Session | Hijacking | SessionTokenAnomaly | 15 | BLOCK | ⏳ |
| Session | UA Change | SessionTokenAnomaly / SessionFixationAttempt | 15 | RATE_LIMIT | ⏳ |
| Protocol | Invalid HTTP | ProtocolViolation | 10 | BLOCK | ⏳ |

**Légende** :
- ⏳ À tester
- ✅ Validé (détection OK)
- ❌ Échec (non détecté)
- ⚠️ Faux positif

---

## 🔬 Analyse Post-Test

### 1. Métriques Globales

```bash
# Statistiques complètes
curl http://localhost:9090/metrics | grep websec_

# Requêtes par décision
curl http://localhost:9090/metrics | grep websec_requests_total

# Top signaux détectés
curl http://localhost:9090/metrics | grep websec_signals_total | sort -t= -k2 -nr
```

### 2. Logs d'Audit

```bash
# Extraire tous les événements BLOCK
sudo journalctl -u websec --since "1 hour ago" | grep -i "block" > audit-blocks.log

# Analyser les signaux générés
sudo journalctl -u websec --since "1 hour ago" | grep -i "signal" > audit-signals.log

# IPs bloquées
redis-cli KEYS "ip:*:profile" | while read key; do
    redis-cli GET "$key" | jq -r '. | select(.score < 20) | .ip'
done
```

### 3. Taux de Faux Positifs

```bash
# Tester requêtes légitimes depuis navigateur réel
# Vérifier qu'aucune n'est bloquée

# Simuler utilisateur légitime
for i in {1..50}; do
    curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0" \
         -H "Accept: text/html,application/xhtml+xml" \
         -H "Accept-Language: en-US,en;q=0.9" \
         https://votre-domaine.com/page$i
    sleep 2
done
```

**Attendu** : Score reste >70, décision `ALLOW`

---

## 📈 Rapport d'Audit

### Template de Rapport

```markdown
# Rapport d'Audit WebSec - [Date]

## Environnement
- **Serveur** : [OS, version]
- **WebSec Version** : v0.2.0+
- **Backend** : Apache 2.4.x
- **Domaine** : votre-domaine.com
- **Configuration** : /etc/websec/websec.toml

## Résultats par Famille

### 🤖 Bot Detection : [X/4 tests passés]
- [✅/❌] sqlmap UA detection
- [✅/❌] curl UA detection
- [✅/❌] Missing UA detection
- [✅/❌] Scraping detection

### 🔐 Brute Force : [X/2 tests passés]
...

## Faux Positifs Détectés
- [Aucun / Liste des FP]

## Faux Négatifs Détectés
- [Aucun / Liste des FN]

## Recommandations
1. Ajuster seuil X
2. Améliorer détection Y
3. ...

## Conclusion
[WebSec est production-ready / Nécessite ajustements]
```

---

## 🚨 Tests de Sécurité Avancés (Optionnel)

### OWASP ZAP Automated Scan

```bash
# Scan passif
zap-cli quick-scan https://votre-domaine.com

# Scan actif (attention, très agressif)
zap-cli active-scan https://votre-domaine.com
```

### Burp Suite Intruder

1. Capturer requête dans Burp
2. Envoyer à Intruder
3. Payload : liste SQLi/XSS
4. Vérifier que toutes sont bloquées

---

**Bon audit ! N'oubliez pas de whitelister votre IP de test si nécessaire.** 🛡️

```bash
# Whitelister votre IP pendant les tests
websec lists whitelist add VOTRE_IP
```
