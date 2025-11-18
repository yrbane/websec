# Menaces détectées par websec

Ce document décrit les différentes **familles de menaces** que `websec` vise à détecter au niveau du proxy HTTP(S), ainsi que des **exemples concrets** de requêtes et de signaux associés.

L’objectif est de servir de base :
- à la conception des **détecteurs**,
- à la configuration du **moteur de réputation**,
- et à la documentation fonctionnelle du projet.

---

## Sommaire

1. [Bots, scrapers & clients non humains](#1-bots-scrapers--clients-non-humains)  
2. [Brute force & credential stuffing](#2-brute-force--credential-stuffing)  
3. [Flood / DDoS applicatif](#3-flood--ddos-applicatif)  
4. [Anomalies de protocole HTTP](#4-anomalies-de-protocole-http)  
5. [Path traversal & accès à des fichiers sensibles](#5-path-traversal--accès-à-des-fichiers-sensibles)  
6. [Uploads de fichiers dangereux](#6-uploads-de-fichiers-dangereux)  
7. [Injections (SQLi, XSS, RCE, LFI/RFI…)](#7-injections-sqli-xss-rce-lfirfi)  
8. [Scans de vulnérabilités & reconnaissance](#8-scans-de-vulnérabilités--reconnaissance)  
9. [Host header abuse & attaques liées au virtual host](#9-host-header-abuse--attaques-liées-au-virtual-host)  
10. [SSRF (Server-Side Request Forgery)](#10-ssrf-server-side-request-forgery)  
11. [Anomalies de sessions & cookies](#11-anomalies-de-sessions--cookies)  
12. [TLS & fingerprinting client](#12-tls--fingerprinting-client)  

---

## 1. Bots, scrapers & clients non humains

### Objectif

Identifier les clients qui ne se comportent pas comme de vrais navigateurs humains :
- bots agressifs,
- scrapers,
- outils automatisés,
- scanners basiques.

### Signaux typiques

- `SuspiciousUserAgent`
- `SuspiciousClientProfile`
- `AbusiveClient`
- `VulnerabilityScan` (si les patterns correspondent à des scanners)

### Indicateurs possibles

- `User-Agent` vide, minimaliste, ou connu comme malveillant (sqlmap, nikto, wpscan…).
- Headers HTTP inconsistants avec un vrai navigateur :
  - absence de `Accept`, `Accept-Language`, `Accept-Encoding` sur un trafic censé être “web”.
  - ordre ou combinaison de headers atypiques.
- Navigation **non humaine** :
  - grand nombre d’URLs uniques sur un temps très court,
  - quasi-absence de hits sur les assets statiques (`.css`, `.js`, images),
  - strictement des requêtes sur `/api/...`.

### Exemples

#### 1.1. User-Agent inexistant ou suspect

```http
GET / HTTP/1.1
Host: example.com
User-Agent: curl/7.79.1
Accept: */*
````

Pour un site grand public, des accès répétés avec ce type de UA peuvent générer des signaux `SuspiciousUserAgent`.

Exemple de UA clairement malveillant :

```http
User-Agent: sqlmap/1.7 (https://sqlmap.org)
```

→ signal `VulnerabilityScan` + pondération élevée.

#### 1.2. Profil de headers non humain

```http
GET /produits HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: */*
```

Si pendant des milliers de requêtes :

* pas de `Accept-Language`,
* pas de `Accept-Encoding`,
* pas de `Referer`,
* aucun chargement d’assets statiques,

on peut émettre des signaux `SuspiciousClientProfile` et `AbusiveClient`.

---

## 2. Brute force & credential stuffing

### Objectif

Détecter les attaques contre les mécanismes d’authentification :

* brute force (mot de passe deviné par essais successifs),
* credential stuffing (utilisation de combos login/mot de passe fuités),
* password spraying.

### Signaux typiques

* `FailedAuthAttempt`
* `CredentialStuffing`
* `PasswordSprayingSuspected`

### Indicateurs possibles

* Séries de réponses `401` ou `403` sur la route de login.
* Tentatives nombreuses sur le même login depuis une même IP.
* Le même mot de passe utilisé avec beaucoup de logins différents (spraying).
* Plusieurs IP différentes testant les mêmes identifiants.

### Exemples

#### 2.1. Brute force simple sur `/login`

```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=123456
```

Si on observe :

* 50 tentatives en 1 minute depuis `203.0.113.10`,
* toutes avec des mots de passe différents,

→ plusieurs `FailedAuthAttempt` + montée du score jusqu’à blocage.

#### 2.2. Credential stuffing

Plusieurs IP qui testent en rafale la combinaison `user@example.com / Password123!` sur le même site.

`websec` peut détecter :

* même login,
* même mot de passe,
* IP différentes,
* sur une fenêtre courte,

→ signal `CredentialStuffing`.

---

## 3. Flood / DDoS applicatif

### Objectif

Détecter les abus de volumétrie au niveau HTTP :

* flood de requêtes,
* bursts ciblés,
* consommation excessive de ressources applicatives.

### Signaux typiques

* `Flooding`
* `AbusiveClient`

### Indicateurs possibles

* Nombre de requêtes par IP au-dessus d’un seuil sur une fenêtre glissante.
* Taux anormalement élevé de requêtes sur un endpoint spécifique (ex: `/search`).
* Comportement de type “burst” :

  * 100 requêtes en 2 secondes sur la même route ou un pattern proche.

### Exemple

```http
GET /search?q=test&page=1 HTTP/1.1
Host: example.com
User-Agent: LegitBrowser/1.0
```

Si une IP envoie :

* 1000 requêtes `/search?q=...` en 10 secondes,
* sans aucune autre navigation,

→ multiples signaux `Flooding` → réputation dégradée → blocage.

---

## 4. Anomalies de protocole HTTP

### Objectif

Détecter les comportements suspects ou invalides au niveau pur HTTP :

* méthodes non attendues,
* headers invalides,
* format de requête douteux.

### Signaux typiques

* `ProtocolAnomaly`

### Indicateurs possibles

* Usage de méthodes comme `TRACE`, `TRACK`, `CONNECT` là où elles ne devraient pas exister.
* Requêtes mal formées, headers dupliqués, version HTTP exotique ou incorrecte.
* Incohérences entre `Content-Length` et taille réelle du body.

### Exemples

#### 4.1. Méthode `TRACE`

```http
TRACE /login HTTP/1.1
Host: example.com
User-Agent: MaliciousScanner/1.0
```

→ `ProtocolAnomaly` (et possiblement `VulnerabilityScan`).

#### 4.2. Headers invalides

```http
GET / HTTP/1.1
Host: example.com
X-Invalid-Header: value\r\nFake-Header: test
```

→ tentative de `CRLF injection` côté proxy / logs → `ProtocolAnomaly`.

---

## 5. Path traversal & accès à des fichiers sensibles

### Objectif

Détecter les tentatives d’accès à des chemins ou fichiers critiques :

* `../` et variantes encodées,
* fichiers de config,
* répertoires internes.

### Signaux typiques

* `SuspiciousPayload`
* `VulnerabilityScan`

### Indicateurs possibles

* `../`, `..\\`, `%2e%2e%2f`, `..%5c` dans les chemins ou paramètres.
* Accès à des chemins comme :

  * `/../../etc/passwd`
  * `/.git/config`
  * `/config.php`
  * `/wp-config.php`
  * `/.env`

### Exemples

```http
GET /../../etc/passwd HTTP/1.1
Host: example.com
```

```http
GET /download?file=../../../../etc/passwd HTTP/1.1
Host: example.com
```

→ `SuspiciousPayload` très fort + potentiellement `VulnerabilityScan`.

---

## 6. Uploads de fichiers dangereux

### Objectif

Surveiller les uploads de fichiers pour détecter :

* webshells,
* malware,
* payloads exécutables.

### Signaux typiques

* `SuspiciousPayload`
* `PotentialWebshellUpload`

### Indicateurs possibles

* Extensions dangereuses :

  * `.php`, `.phtml`, `.phar`, `.jsp`, `.aspx`, `.asp`, `.sh`, `.exe`…
* Incohérence entre `Content-Type` et extension du fichier.
* Uploads fréquents de fichiers sur des endpoints suspects.

### Exemple

```http
POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----XYZ

------XYZ
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png

<?php system($_GET['cmd']); ?>
------XYZ--
```

→ `PotentialWebshellUpload` + forte pénalité de réputation.

---

## 7. Injections (SQLi, XSS, RCE, LFI/RFI)

### Objectif

Détecter les patterns classiques d’injection dans :

* l’URL,
* les paramètres,
* parfois le body.

### Signaux typiques

* `SuspiciousPayload`
* `SqlInjectionAttempt`
* `XssAttempt`
* `RceAttempt`
* `FileInclusionAttempt`

### Indicateurs possibles

#### SQL injection

* `UNION SELECT`, `information_schema`, `' OR 1=1 --`, `sleep(...)`.

#### XSS

* `<script>`, `</script>`, `javascript:`, `onerror=`, `onload=`, `onmouseover=`, etc.

#### RCE / Command injection

* `;cat /etc/passwd`, `;rm -rf /`, `| bash`, `&& curl http://... | sh`.

#### LFI/RFI

* `php://input`, `file://`, `http://` dans des paramètres de type `template` ou `include`.

### Exemples

#### 7.1. SQLi

```http
GET /product?id=1 UNION SELECT username,password FROM users HTTP/1.1
Host: example.com
```

→ `SqlInjectionAttempt` + `SuspiciousPayload`.

#### 7.2. XSS

```http
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: example.com
```

→ `XssAttempt`.

---

## 8. Scans de vulnérabilités & reconnaissance

### Objectif

Identifier la phase de **reconnaissance** :

* scanners automatiques,
* bruteforce de chemins,
* balayage d’admin panels.

### Signaux typiques

* `VulnerabilityScan`
* `BackendErrorAbuse`

### Indicateurs possibles

* Beaucoup de 404/403 sur des chemins variés et “typiques CMS” :

  * `/wp-admin/`, `/wp-login.php`, `/phpmyadmin/`, `/manager/html`, etc.
* UA correspondant à des scanners :

  * `sqlmap`, `nikto`, `acunetix`, `wpscan`, etc.

### Exemple

```http
GET /wp-login.php HTTP/1.1
Host: example.com

GET /phpmyadmin/ HTTP/1.1
Host: example.com

GET /manager/html HTTP/1.1
Host: example.com
```

En rafale depuis la même IP → `VulnerabilityScan`.

---

## 9. Host header abuse & attaques liées au virtual host

### Objectif

Détecter l’utilisation malveillante du header `Host` (ou similaires) :

* tentative d’attaque sur un autre vhost,
* accès à des ressources internes,
* host header injection.

### Signaux typiques

* `ProtocolAnomaly`
* `HostHeaderAbuse`

### Indicateurs possibles

* `Host` inconnu (non configuré dans websec comme backend valide).
* `Host` vers une adresse interne :

  * `localhost`, `127.0.0.1`, `admin.internal`, etc.
* `X-Forwarded-Host` ou `X-Original-Host` manipulés.

### Exemple

```http
GET /admin HTTP/1.1
Host: admin.internal
X-Forwarded-Host: example.com
```

Si `admin.internal` n’est pas un host légitime, on lève `HostHeaderAbuse`.

---

## 10. SSRF (Server-Side Request Forgery)

### Objectif

À partir de certains endpoints connus (ex : `/fetch?url=...`), détecter des tentatives d’accès à des ressources internes via le backend.

### Signaux typiques

* `SuspiciousPayload`
* `SsrSuspected`

### Indicateurs possibles

* Paramètre `url` ou équivalent pointant vers :

  * IP privées (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`).
  * 127.0.0.1 / localhost.
  * endpoints metadata cloud (`169.254.169.254`).

### Exemples

```http
GET /fetch?url=http://127.0.0.1:8080/admin HTTP/1.1
Host: example.com
```

```http
GET /proxy?target=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: example.com
```

→ `SsrSuspected` + pénalité.

---

## 11. Anomalies de sessions & cookies

### Objectif

Détecter les signaux indiquant un **hijacking de session** ou un partage de session suspect.

### Signaux typiques

* `SessionHijackingSuspected`
* `SessionAnomaly`

### Indicateurs possibles

* Même cookie de session utilisé depuis :

  * trop d’IPs différentes sur une fenêtre courte,
  * des pays très différents en très peu de temps.
* IP qui “vole” une session d’une autre IP (pattern de “switch” brutal).

### Exemples

#### 11.1. Même session depuis 2 pays éloignés

* 10h00 : `session_id=abc` depuis France.
* 10h05 : `session_id=abc` depuis Russie.
* 10h07 : retour en France.

→ `SessionHijackingSuspected`.

#### 11.2. Session partagée par des dizaines d’IPs

Trafic massif avec le même `session_id` depuis plein d’IPs → suspect (partage, botnet…).

---

## 12. TLS & fingerprinting client

*(Applicable si `websec` termine TLS.)*

### Objectif

Profiter de la négociation TLS pour :

* détecter des clients obsolètes ou vulnérables,
* reconnaître des empreintes (JA3/JA3S) associées à des botnets / malwares.

### Signaux typiques

* `WeakTlsClient`
* `KnownBadFingerprint`

### Indicateurs possibles

* Version TLS < 1.2 (configurable).
* Suites cryptographiques faibles / obsolètes.
* Empreinte (fingerprint TLS) correspondant à :

  * un outil de scan,
  * un malware connu,
  * un framework d’attaque.

### Exemples

* Client qui force **TLS 1.0** avec des suites connues faibles → `WeakTlsClient`.
* JA3 correspondant à un kit de botnet connu → `KnownBadFingerprint`.

---

## Conclusion

Ces 12 familles constituent la **cartographie de menaces** de `websec`.
Chaque détecteur implémenté dans le proxy pourra :

* produire un ou plusieurs **signaux** (par ex. `SqlInjectionAttempt`, `Flooding`, `SessionHijackingSuspected`, etc.),
* rattacher ces signaux à une **famille de menace**,
* et contribuer au **score de réputation** de l’IP.

Ce document doit évoluer au fil :

* des nouveaux types d’attaques rencontrés en production,
* des besoins métier (par exemple durcir certaines familles comme la brute force),
* et des capacités techniques ajoutées (nouveaux détecteurs, nouveaux signaux, intégration à des feeds de threat intel).