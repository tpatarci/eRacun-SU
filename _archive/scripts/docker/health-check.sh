#!/bin/bash
# Check health of all services

set -e

echo "🏥 eRačun Services Health Check"
echo "================================"
echo ""

# Check infrastructure
echo "📦 Infrastructure Services:"
echo ""

check_service() {
    local name=$1
    local url=$2

    if curl -sf "$url" > /dev/null 2>&1; then
        echo "  ✅ $name"
    else
        echo "  ❌ $name (not responding)"
    fi
}

check_service "PostgreSQL" "http://localhost:5432" 2>/dev/null || echo "  ⚠️  PostgreSQL (check with: docker-compose exec postgres pg_isready)"
check_service "RabbitMQ Management" "http://localhost:15672"
check_service "Redis" "http://localhost:6379" 2>/dev/null || echo "  ⚠️  Redis (check with: docker-compose exec redis redis-cli ping)"
check_service "Prometheus" "http://localhost:9090/-/healthy"
check_service "Grafana" "http://localhost:3000/api/health"
check_service "Jaeger" "http://localhost:16686"

echo ""
echo "🔧 Team 3 Services:"
echo ""

check_service "cert-lifecycle-manager" "http://localhost:3001/health"
check_service "fina-connector" "http://localhost:3002/health"
check_service "porezna-connector" "http://localhost:3003/health"
check_service "digital-signature-service" "http://localhost:3004/health"
check_service "archive-service" "http://localhost:3005/health"
check_service "reporting-service" "http://localhost:3006/health"
check_service "dead-letter-handler" "http://localhost:3007/health"

echo ""
echo "📊 Container Status:"
echo ""
docker-compose ps

echo ""
echo "💡 View logs: docker-compose logs -f <service-name>"
