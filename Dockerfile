# Image WebSec — construite pour la cible réelle : Debian 13 (trixie).
#
# Pourquoi Debian et non Alpine : le serveur de production tourne sous Debian
# 13 / glibc 2.41. Compiler ici contre la MÊME bibliothèque garantit que le
# binaire produit y démarre. Un binaire compilé sur une machine de
# développement plus récente (Arch, glibc 2.44) fonctionne tant qu'aucune
# dépendance ne réclame un symbole postérieur, puis refuse brutalement de
# démarrer le jour où l'une le fait — panne du proxy, donc de tous les sites.
#
# Accessoirement, musl imposait de recompiler aws-lc-sys depuis les sources
# (cmake, g++, perl) : des minutes de compilation pour une cible qui n'est pas
# la nôtre.

# ---------- Étape 1 : compilation ----------
# Version ÉPINGLÉE : le code emploie des API stabilisées récemment
# (Duration::from_mins) qu'une image plus ancienne ne sait pas compiler.
FROM rust:1.98-slim-trixie AS builder

# pkg-config et les en-têtes OpenSSL pour les dépendances natives ;
# cmake et perl pour aws-lc-sys, tiré par rustls.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev cmake perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/websec

# Les manifestes d'abord : cette couche ne change que si les dépendances
# bougent, et le cache évite de tout recompiler à chaque modification du code.
# benches/ vient avec eux : Cargo.toml déclare quatre cibles [[bench]] et cargo
# refuse de lire le manifeste si leurs fichiers manquent — il ne les compile
# pas pour autant, `cargo build` ne touchant ni aux bancs d'essai ni aux tests.
COPY Cargo.toml Cargo.lock ./
COPY benches ./benches

# Squelette minimal : on ne compile ici que les dépendances.
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --features tls \
    && rm -rf src

COPY src ./src
COPY config ./config

# Les artefacts du squelette portent le même nom que le vrai crate : sans les
# effacer, cargo les croit à jour et livre un binaire vide.
RUN rm -rf target/release/.fingerprint/websec-* \
           target/release/deps/websec* \
           target/release/deps/libwebsec*

# TLS est indispensable à un proxy qui termine le HTTPS : il n'est PAS dans les
# features par défaut, et l'oublier produit un binaire incapable d'écouter
# en 443 — la panne de dix-huit heures du 21 août.
RUN cargo build --release --features tls \
    && strip target/release/websec

# ---------- Étape 2 : exécution ----------
# Même version que l'étape de compilation ET que le serveur.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 wget \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 websec && \
    useradd -u 1000 -g websec -M -s /usr/sbin/nologin websec

WORKDIR /app

COPY --from=builder /usr/src/websec/target/release/websec /app/websec
COPY --from=builder /usr/src/websec/config /app/config

RUN mkdir -p /app/data && chown -R websec:websec /app

USER websec

# La configuration DÉDIÉE au conteneur : la générique écoute sur [::]:80 et
# vise un backend en 127.0.0.1, ce qui n'a pas de sens dans une image.
ENV WEBSEC_CONFIG=/app/config/websec-docker.toml

# Port du proxy et port des métriques, tels que déclarés par websec-docker.toml
EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/metrics || exit 1

CMD ["/app/websec", "run"]
