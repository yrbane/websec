#!/usr/bin/env bash
#
# Produit le binaire de production à partir de l'étape « builder » de l'image
# Docker, c'est-à-dire dans un Debian 13 identique au serveur.
#
# Pourquoi passer par l'image plutôt que compiler sur sa machine : un binaire
# lié à une glibc plus récente que celle du serveur démarre tant qu'aucune
# dépendance ne réclame un symbole postérieur, puis refuse net le jour où l'une
# le fait. Ici, la bibliothèque de compilation est celle de la cible, donc la
# compatibilité est acquise par construction et non par chance.
#
# Usage :
#   scripts/construire-binaire.sh                 # produit dist/websec
#   scripts/construire-binaire.sh --installer nethttp
#
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SORTIE="$RACINE/dist/websec"
HOTE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --installer) HOTE="${2:?--installer attend un hôte SSH}"; shift 2 ;;
        -h|--help)   sed -n '2,16p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)           echo "option inconnue : $1" >&2; exit 2 ;;
    esac
done

echo "── Compilation dans l'image (Debian 13, comme le serveur)…"
docker build --target builder -t websec:builder "$RACINE"

echo "── Extraction du binaire…"
mkdir -p "$(dirname "$SORTIE")"
CONTENEUR="$(docker create websec:builder)"
trap 'docker rm -f "$CONTENEUR" >/dev/null 2>&1 || true' EXIT
docker cp "$CONTENEUR:/usr/src/websec/target/release/websec" "$SORTIE"
chmod +x "$SORTIE"

echo
echo "── Contrôles"
VERSION="$("$SORTIE" --version 2>/dev/null || echo "ILLISIBLE")"
echo "   version      : $VERSION"

# TLS n'est pas dans les features par défaut : un binaire sans rustls est
# incapable d'écouter en 443, et la panne ne se voit qu'au redémarrage.
#
# On COMPTE au lieu d'interrompre : sous `pipefail`, un `grep -q` sort dès la
# première correspondance, ferme le tube, et `strings` meurt d'un SIGPIPE dont
# l'échec remonterait alors même que la recherche a réussi.
NB_RUSTLS="$(strings "$SORTIE" | grep -ci rustls || true)"
if [[ "${NB_RUSTLS:-0}" -gt 0 ]]; then
    echo "   TLS          : rustls présent ($NB_RUSTLS occurrences)"
else
    echo "   TLS          : ABSENT — binaire inutilisable en 443" >&2
    exit 1
fi

GLIBC="$(objdump -T "$SORTIE" 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -1 | cut -d_ -f2)"
echo "   glibc exigée : ${GLIBC:-inconnue}"

if [[ -z "$HOTE" ]]; then
    echo
    echo "Binaire prêt : $SORTIE"
    echo "Pour l'installer : scripts/construire-binaire.sh --installer <hôte>"
    exit 0
fi

echo
echo "── Vérification de compatibilité avec $HOTE"
GLIBC_CIBLE="$(ssh "$HOTE" 'ldd --version | head -1 | grep -oE "[0-9]+\.[0-9]+$"')"
echo "   glibc du serveur : $GLIBC_CIBLE"
if [[ -n "$GLIBC" ]] && [[ "$(printf '%s\n%s\n' "$GLIBC" "$GLIBC_CIBLE" | sort -V | tail -1)" != "$GLIBC_CIBLE" ]]; then
    echo "   REFUS : le binaire exige glibc $GLIBC, le serveur n'a que $GLIBC_CIBLE." >&2
    exit 1
fi
echo "   compatible."

echo
echo "── Installation sur $HOTE (sauvegarde, bascule, vérification)"
# Le proxy sert TOUS les sites : on garde de quoi revenir en arrière.
cat "$SORTIE" | ssh "$HOTE" 'cat > ~/websec-nouveau && chmod +x ~/websec-nouveau'
ssh "$HOTE" '
    set -e
    sudo -n cp -a /usr/local/bin/websec /usr/local/bin/websec-precedent.bak
    sudo -n install -m 0755 ~/websec-nouveau /usr/local/bin/websec
    sudo -n systemctl restart websec
    sleep 6
    if sudo -n systemctl is-active --quiet websec; then
        echo "   service actif — $(/usr/local/bin/websec --version)"
    else
        echo "   SERVICE MORT → retour arrière" >&2
        sudo -n install -m 0755 /usr/local/bin/websec-precedent.bak /usr/local/bin/websec
        sudo -n systemctl restart websec
        exit 1
    fi
    rm -f ~/websec-nouveau
'
echo "Terminé."
