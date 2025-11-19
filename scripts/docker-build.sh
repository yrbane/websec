#!/bin/bash
# Script de build Docker pour WebSec
# Construit l'image Docker avec optimisations

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🐳 Building WebSec Docker image${NC}\n"

# Build avec ou sans BuildKit
echo -e "${YELLOW}📦 Building multi-stage image...${NC}"

# Essayer avec BuildKit si disponible, sinon build classique
if docker buildx version &>/dev/null; then
    echo "  Using BuildKit..."
    DOCKER_BUILDKIT=1 docker build \
        --tag websec:latest \
        --tag websec:$(git rev-parse --short HEAD) \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        .
else
    echo "  Using classic build (BuildKit not available)..."
    docker build \
        --tag websec:latest \
        --tag websec:$(git rev-parse --short HEAD) \
        .
fi

echo -e "\n${GREEN}✅ Docker image built successfully!${NC}\n"

# Afficher les informations de l'image
docker images | grep websec | head -1

echo -e "\n${YELLOW}💡 Usage:${NC}"
echo "  docker run -p 8080:8080 websec:latest"
echo "  docker-compose up -d"
