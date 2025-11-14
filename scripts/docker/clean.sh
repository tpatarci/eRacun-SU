#!/bin/bash
# Clean up Docker resources

set -e

echo "🧹 Cleaning up eRačun Docker resources..."
echo ""

read -p "⚠️  This will remove containers, volumes, and images. Continue? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cancelled"
    exit 1
fi

echo "🛑 Stopping services..."
docker-compose down

echo "🗑️  Removing volumes..."
docker-compose down -v

echo "🗑️  Removing images..."
docker-compose down -v --rmi all

echo "🗑️  Pruning Docker system..."
docker system prune -f

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "💡 To rebuild and start:"
echo "   ./scripts/docker/start-all.sh"
