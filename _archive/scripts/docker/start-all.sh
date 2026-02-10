#!/bin/bash
# Start all services (infrastructure + Team 3 services)

set -e

echo "🚀 Starting all eRačun services..."

# Build services first
echo "🔨 Building services..."
docker-compose build --parallel

# Start all services
echo "▶️  Starting containers..."
docker-compose up -d

echo ""
echo "✅ All services started!"
echo ""
echo "📊 Access points:"
echo ""
echo "Infrastructure:"
echo "  - PostgreSQL:          localhost:5432"
echo "  - RabbitMQ AMQP:       localhost:5672"
echo "  - RabbitMQ Management:  http://localhost:15672 (eracun/dev_password_change_in_production)"
echo "  - Redis:               localhost:6379"
echo "  - Prometheus:          http://localhost:9090"
echo "  - Grafana:             http://localhost:3000 (admin/admin)"
echo "  - Jaeger UI:           http://localhost:16686"
echo ""
echo "Team 3 Services:"
echo "  - cert-lifecycle-manager:    http://localhost:3001/health"
echo "  - fina-connector:            http://localhost:3002/health"
echo "  - porezna-connector:         http://localhost:3003/health"
echo "  - digital-signature-service: http://localhost:3004/health"
echo "  - archive-service:           http://localhost:3005/health"
echo "  - reporting-service:         http://localhost:3006/health"
echo "  - dead-letter-handler:       http://localhost:3007/health"
echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 5
docker-compose ps

echo ""
echo "📝 View logs:"
echo "   docker-compose logs -f"
echo ""
echo "🛑 Stop all services:"
echo "   docker-compose down"
