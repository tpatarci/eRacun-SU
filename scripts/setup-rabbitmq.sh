#!/bin/bash
# RabbitMQ Exchange and Queue Setup
# Initializes all exchanges and queues for eRačun Team 3 services

set -e

# Configuration
RABBITMQ_HOST="${RABBITMQ_HOST:-localhost}"
RABBITMQ_PORT="${RABBITMQ_PORT:-15672}"
RABBITMQ_USER="${RABBITMQ_USER:-eracun_user}"
RABBITMQ_PASS="${RABBITMQ_PASS:-eracun_password}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "========================================"
echo "RabbitMQ Setup for eRačun Team 3"
echo "========================================"
echo ""
echo "Host: $RABBITMQ_HOST:$RABBITMQ_PORT"
echo "User: $RABBITMQ_USER"
echo ""

# Check if RabbitMQ is accessible
if ! curl -s -u $RABBITMQ_USER:$RABBITMQ_PASS http://$RABBITMQ_HOST:$RABBITMQ_PORT/api/overview > /dev/null 2>&1; then
    echo -e "${RED}❌ Cannot connect to RabbitMQ${NC}"
    echo "Please check:"
    echo "  - RabbitMQ is running"
    echo "  - Management plugin is enabled: rabbitmq-plugins enable rabbitmq_management"
    echo "  - Credentials are correct"
    exit 1
fi

echo -e "${GREEN}✓ Connected to RabbitMQ${NC}"
echo ""

# Function to create exchange
create_exchange() {
    local name=$1
    local type=$2
    local durable=$3

    echo "Creating exchange: $name (type: $type, durable: $durable)"

    if curl -s -u $RABBITMQ_USER:$RABBITMQ_PASS -X PUT \
        http://$RABBITMQ_HOST:$RABBITMQ_PORT/api/exchanges/%2F/$name \
        -H "content-type:application/json" \
        -d "{\"type\":\"$type\",\"durable\":$durable}" > /dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Exchange '$name' created${NC}"
    else
        echo -e "${YELLOW}  ⚠ Exchange '$name' might already exist${NC}"
    fi
}

# Function to create queue
create_queue() {
    local name=$1
    local durable=$2
    local dlx=$3
    local dlx_routing_key=$4
    local ttl=$5

    echo "Creating queue: $name"

    local args="\"durable\":$durable"

    if [ ! -z "$dlx" ]; then
        args="$args,\"arguments\":{\"x-dead-letter-exchange\":\"$dlx\""
        if [ ! -z "$dlx_routing_key" ]; then
            args="$args,\"x-dead-letter-routing-key\":\"$dlx_routing_key\""
        fi
        if [ ! -z "$ttl" ]; then
            args="$args,\"x-message-ttl\":$ttl"
        fi
        args="$args}"
    fi

    if curl -s -u $RABBITMQ_USER:$RABBITMQ_PASS -X PUT \
        http://$RABBITMQ_HOST:$RABBITMQ_PORT/api/queues/%2F/$name \
        -H "content-type:application/json" \
        -d "{$args}" > /dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Queue '$name' created${NC}"
    else
        echo -e "${YELLOW}  ⚠ Queue '$name' might already exist${NC}"
    fi
}

# Function to bind queue to exchange
bind_queue() {
    local queue=$1
    local exchange=$2
    local routing_key=$3

    echo "Binding queue '$queue' to exchange '$exchange' with routing key '$routing_key'"

    if curl -s -u $RABBITMQ_USER:$RABBITMQ_PASS -X POST \
        http://$RABBITMQ_HOST:$RABBITMQ_PORT/api/bindings/%2F/e/$exchange/q/$queue \
        -H "content-type:application/json" \
        -d "{\"routing_key\":\"$routing_key\"}" > /dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Binding created${NC}"
    else
        echo -e "${YELLOW}  ⚠ Binding might already exist${NC}"
    fi
}

echo "Step 1: Creating Exchanges"
echo "========================================"
echo ""

# Main exchange (topic exchange for event routing)
create_exchange "eracun" "topic" "true"

# Dead-letter exchange
create_exchange "dead-letter" "topic" "true"

echo ""
echo "Step 2: Creating Queues"
echo "========================================"
echo ""

# Service queues with dead-letter exchange
SERVICES=(
    "fina-connector"
    "porezna-connector"
    "digital-signature-service"
    "archive-service"
    "cert-lifecycle-manager"
    "reporting-service"
    "dead-letter-handler"
)

for service in "${SERVICES[@]}"; do
    create_queue "$service" "true" "dead-letter" "${service}.failed" ""
done

# Dead-letter queue (72-hour TTL)
create_queue "dead-letter" "true" "" "" "259200000"

echo ""
echo "Step 3: Creating Bindings"
echo "========================================"
echo ""

# Bind service queues to eracun exchange
bind_queue "fina-connector" "eracun" "fina.#"
bind_queue "porezna-connector" "eracun" "porezna.#"
bind_queue "digital-signature-service" "eracun" "signature.#"
bind_queue "archive-service" "eracun" "archive.#"
bind_queue "cert-lifecycle-manager" "eracun" "certificate.#"
bind_queue "reporting-service" "eracun" "report.#"
bind_queue "dead-letter-handler" "eracun" "deadletter.#"

# Bind dead-letter queue to dead-letter exchange
bind_queue "dead-letter" "dead-letter" "#"

echo ""
echo "========================================"
echo -e "${GREEN}✅ RabbitMQ setup complete!${NC}"
echo "========================================"
echo ""
echo "Summary:"
echo "  - 2 exchanges created (eracun, dead-letter)"
echo "  - 8 queues created (7 services + dead-letter)"
echo "  - 8 bindings created"
echo ""
echo "Next steps:"
echo "  1. Verify in RabbitMQ Management UI: http://$RABBITMQ_HOST:$RABBITMQ_PORT"
echo "  2. Update service configurations to use RabbitMQ"
echo "  3. Start services and verify connectivity"
echo ""
