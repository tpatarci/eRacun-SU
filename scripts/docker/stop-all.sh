#!/bin/bash
# Stop all services

set -e

echo "🛑 Stopping all eRačun services..."

docker-compose stop

echo "✅ All services stopped!"
echo ""
echo "💡 To remove containers:"
echo "   docker-compose down"
echo ""
echo "💡 To remove containers and volumes (clean slate):"
echo "   docker-compose down -v"
echo ""
echo "💡 To start again:"
echo "   ./scripts/docker/start-all.sh"
