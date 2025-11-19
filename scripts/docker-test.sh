#!/bin/bash
# Script de test Docker pour WebSec
# Lance docker-compose et teste le stack complet

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🐳 Testing WebSec Docker stack${NC}\n"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up Docker containers...${NC}"
    docker-compose down -v
}

trap cleanup EXIT

# 1. Start the stack
echo -e "${YELLOW}🚀 Starting Docker Compose stack...${NC}"
docker-compose up -d

# 2. Wait for services to be healthy
echo -e "${YELLOW}⏳ Waiting for services to be healthy...${NC}"
sleep 10

# Check backend health
echo -n "  Checking backend... "
if curl -sf http://localhost:3000/api/health > /dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌${NC}"
    docker-compose logs backend
    exit 1
fi

# Check WebSec health
echo -n "  Checking WebSec proxy... "
if curl -sf http://localhost:8080/metrics > /dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌${NC}"
    docker-compose logs websec
    exit 1
fi

# Check Redis
echo -n "  Checking Redis... "
if docker-compose exec -T redis redis-cli ping | grep -q PONG; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌${NC}"
    docker-compose logs redis
    exit 1
fi

echo ""

# 3. Run functional tests
echo -e "${GREEN}🧪 Running functional tests${NC}\n"

# Test 1: Proxy forwards to backend
echo -n "  Test 1: GET / via proxy... "
RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null http://localhost:8080/)
if [ "$RESPONSE" = "200" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌ (HTTP $RESPONSE)${NC}"
    exit 1
fi

# Test 2: Metrics endpoint
echo -n "  Test 2: GET /metrics... "
METRICS=$(curl -s http://localhost:8080/metrics)
if echo "$METRICS" | grep -q "requests_total"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌${NC}"
    exit 1
fi

# Test 3: WebSec headers
echo -n "  Test 3: WebSec headers... "
HEADERS=$(curl -s -I http://localhost:8080/ | grep -i "x-websec")
if echo "$HEADERS" | grep -q "X-WebSec-Decision"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌${NC}"
    exit 1
fi

# Test 4: Backend API via proxy
echo -n "  Test 4: GET /api/users... "
USERS=$(curl -s http://localhost:8080/api/users)
if echo "$USERS" | grep -q "Alice"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌${NC}"
    exit 1
fi

# Test 5: POST via proxy
echo -n "  Test 5: POST /api/echo... "
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"test":"docker"}' http://localhost:8080/api/echo)
if echo "$RESPONSE" | grep -q "docker"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}❌${NC}"
    exit 1
fi

echo ""

# 4. Display container stats
echo -e "${GREEN}📊 Container statistics${NC}\n"
docker-compose ps

echo ""

# 5. Display metrics
echo -e "${GREEN}📈 WebSec metrics${NC}\n"
FINAL_METRICS=$(curl -s http://localhost:8080/metrics)
REQUESTS_TOTAL=$(echo "$FINAL_METRICS" | grep "^requests_total" | awk '{print $2}')
echo -e "  Total requests: ${GREEN}$REQUESTS_TOTAL${NC}"

echo ""
echo -e "${GREEN}✅ All Docker tests passed!${NC}\n"
echo -e "${YELLOW}💡 Stack is running:${NC}"
echo "   - Backend:    http://localhost:3000"
echo "   - WebSec:     http://localhost:8080"
echo "   - Metrics:    http://localhost:8080/metrics"
echo "   - Prometheus: http://localhost:9091"
echo ""
echo -e "${YELLOW}🛑 To stop the stack:${NC}"
echo "   docker-compose down"

# Don't cleanup on success - let user explore
trap - EXIT
