#!/bin/bash
# Quick-start script for all eRačun mock services

set -e

echo "🚀 Starting eRačun Mock Services..."
echo ""

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found. Please install Docker Compose."
    exit 1
fi

# Build all services
echo "📦 Building all services..."
docker-compose build

# Start all services
echo "🎯 Starting all services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 5

# Check health of all services
echo ""
echo "✅ Service Status:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

services=(
    "http://localhost:8449/health:FINA Mock"
    "http://localhost:8450/health:Porezna Mock"
    "http://localhost:8025/health:Email Mock"
    "http://localhost:8451/health:KLASUS Mock"
    "http://localhost:8452/health:Bank Mock"
    "http://localhost:8453/health:Cert Mock"
    "http://localhost:8080/health:Admin UI"
)

for service in "${services[@]}"; do
    IFS=':' read -r url name <<< "$service"
    if curl -sf "$url" > /dev/null 2>&1; then
        echo "✓ $name - UP ($url)"
    else
        echo "✗ $name - DOWN ($url)"
    fi
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🎮 Admin UI: http://localhost:8080"
echo "📧 Email UI: http://localhost:8025"
echo ""
echo "📝 View logs: docker-compose logs -f"
echo "🛑 Stop all:  docker-compose down"
echo ""
echo "✨ All services started successfully!"
