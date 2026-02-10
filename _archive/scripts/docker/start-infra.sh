#!/bin/bash
# Start infrastructure services only (for local development)

set -e

echo "🚀 Starting eRačun infrastructure services..."

docker-compose up -d postgres rabbitmq redis prometheus grafana jaeger

echo ""
echo "✅ Infrastructure services started!"
echo ""
echo "📊 Access points:"
echo "  - PostgreSQL:         localhost:5432"
echo "  - RabbitMQ AMQP:      localhost:5672"
echo "  - RabbitMQ Management: http://localhost:15672 (eracun/dev_password_change_in_production)"
echo "  - Redis:              localhost:6379"
echo "  - Prometheus:         http://localhost:9090"
echo "  - Grafana:            http://localhost:3000 (admin/admin)"
echo "  - Jaeger UI:          http://localhost:16686"
echo ""
echo "⏳ Waiting for services to be healthy..."
docker-compose ps

echo ""
echo "💡 Run services locally with:"
echo "   cd services/<service-name> && npm run dev"
echo ""
echo "🛑 Stop infrastructure with:"
echo "   docker-compose stop"
