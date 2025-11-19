#!/bin/bash
# Script de test E2E pour WebSec
# Lance le backend, WebSec, et effectue des tests réels

set -e

BACKEND_PORT=3000
PROXY_PORT=8080
BACKEND_PID=""
PROXY_PID=""

# Couleurs
GREEN='\033[0.32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction de nettoyage
cleanup() {
    echo -e "\n${YELLOW}🧹 Nettoyage...${NC}"
    if [ -n "$PROXY_PID" ]; then
        kill $PROXY_PID 2>/dev/null || true
        echo "  ✓ WebSec arrêté"
    fi
    if [ -n "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
        echo "  ✓ Backend arrêté"
    fi
}

trap cleanup EXIT

echo -e "${GREEN}🚀 Démarrage des tests E2E WebSec${NC}\n"

# 1. Compiler WebSec
echo -e "${YELLOW}📦 Compilation de WebSec...${NC}"
cargo build --release --quiet
echo -e "  ${GREEN}✓${NC} WebSec compilé\n"

# 2. Démarrer le backend
echo -e "${YELLOW}🔧 Démarrage du backend de test (port $BACKEND_PORT)...${NC}"
python3 scripts/test-backend.py $BACKEND_PORT > /tmp/backend.log 2>&1 &
BACKEND_PID=$!
sleep 1

# Vérifier que le backend est démarré
if ! curl -s http://localhost:$BACKEND_PORT/api/health > /dev/null; then
    echo -e "${RED}❌ Échec du démarrage du backend${NC}"
    cat /tmp/backend.log
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Backend démarré (PID: $BACKEND_PID)\n"

# 3. Démarrer WebSec
echo -e "${YELLOW}🛡️  Démarrage de WebSec (port $PROXY_PORT)...${NC}"
./target/release/websec --config config/websec.toml > /tmp/websec.log 2>&1 &
PROXY_PID=$!
sleep 2

# Vérifier que WebSec est démarré
if ! ps -p $PROXY_PID > /dev/null; then
    echo -e "${RED}❌ Échec du démarrage de WebSec${NC}"
    cat /tmp/websec.log
    exit 1
fi
echo -e "  ${GREEN}✓${NC} WebSec démarré (PID: $PROXY_PID)\n"

# 4. Tests fonctionnels
echo -e "${GREEN}🧪 Tests fonctionnels${NC}\n"

# Test 1: Requête GET simple
echo -n "  Test 1: GET / ... "
RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null http://localhost:$PROXY_PORT/)
if [ "$RESPONSE" = "200" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌ (HTTP $RESPONSE)${NC}"
    exit 1
fi

# Test 2: Endpoint /metrics
echo -n "  Test 2: GET /metrics ... "
METRICS=$(curl -s http://localhost:$PROXY_PORT/metrics)
if echo "$METRICS" | grep -q "requests_total"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌ (pas de métriques)${NC}"
    exit 1
fi

# Test 3: API JSON
echo -n "  Test 3: GET /api/users ... "
RESPONSE=$(curl -s http://localhost:$PROXY_PORT/api/users)
if echo "$RESPONSE" | grep -q "Alice"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌ (réponse incorrecte)${NC}"
    exit 1
fi

# Test 4: POST avec body
echo -n "  Test 4: POST /api/echo ... "
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"test":"data"}' http://localhost:$PROXY_PORT/api/echo)
if echo "$RESPONSE" | grep -q "test"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌ (echo échoué)${NC}"
    exit 1
fi

# Test 5: Headers WebSec
echo -n "  Test 5: Headers WebSec ... "
HEADERS=$(curl -s -I http://localhost:$PROXY_PORT/ | grep -i "x-websec")
if echo "$HEADERS" | grep -q "X-WebSec-Decision"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌ (headers manquants)${NC}"
    exit 1
fi

echo ""

# 5. Test de charge léger (optionnel)
if command -v ab &> /dev/null; then
    echo -e "${GREEN}⚡ Test de charge (Apache Bench)${NC}\n"
    echo "  100 requêtes, 10 concurrentes..."
    ab -n 100 -c 10 -q http://localhost:$PROXY_PORT/ > /tmp/ab.log 2>&1

    # Extraire les stats
    REQUESTS_PER_SEC=$(grep "Requests per second" /tmp/ab.log | awk '{print $4}')
    MEAN_TIME=$(grep "Time per request.*mean" /tmp/ab.log | head -1 | awk '{print $4}')

    echo -e "  ${GREEN}✓${NC} Requêtes/sec: $REQUESTS_PER_SEC"
    echo -e "  ${GREEN}✓${NC} Temps moyen: ${MEAN_TIME}ms"
    echo ""
fi

# 6. Vérifier les métriques finales
echo -e "${GREEN}📊 Métriques finales${NC}\n"
FINAL_METRICS=$(curl -s http://localhost:$PROXY_PORT/metrics)

REQUESTS_TOTAL=$(echo "$FINAL_METRICS" | grep "^requests_total" | awk '{print $2}')
echo -e "  Requêtes totales: ${GREEN}$REQUESTS_TOTAL${NC}"

DECISIONS=$(echo "$FINAL_METRICS" | grep 'decisions{decision="allow"}' | awk '{print $2}')
echo -e "  Décisions ALLOW: ${GREEN}$DECISIONS${NC}"

echo ""

echo -e "${GREEN}✅ Tous les tests E2E ont réussi!${NC}\n"
echo "📝 Logs disponibles:"
echo "   - Backend: /tmp/backend.log"
echo "   - WebSec: /tmp/websec.log"
if [ -f /tmp/ab.log ]; then
    echo "   - ApacheBench: /tmp/ab.log"
fi

exit 0
