# RabbitMQ Migration Guide

**Migration from In-Memory Message Bus to RabbitMQ**

## Overview

This guide documents the migration from the development in-memory message bus (`@eracun/messaging`) to production RabbitMQ infrastructure. The migration is designed to be seamless with minimal code changes thanks to the adapter pattern implemented in the messaging library.

### Why Migrate?

**In-Memory Bus (Development):**
- ✅ Zero infrastructure setup
- ✅ Fast for local development
- ✅ Simple debugging
- ❌ No persistence (data loss on restart)
- ❌ No distributed messaging
- ❌ No scalability

**RabbitMQ (Production):**
- ✅ Persistent queues (survives restarts)
- ✅ Distributed messaging (multiple consumers)
- ✅ Horizontal scalability
- ✅ Dead-letter exchange for failed messages
- ✅ Message acknowledgments
- ✅ Battle-tested reliability

---

## Prerequisites

### 1. RabbitMQ Installation

**Docker (Recommended for Testing):**
```bash
docker run -d --name rabbitmq \
  -p 5672:5672 \
  -p 15672:15672 \
  -e RABBITMQ_DEFAULT_USER=eracun_user \
  -e RABBITMQ_DEFAULT_PASS=eracun_password \
  rabbitmq:3.12-management-alpine
```

**Production (systemd):**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install rabbitmq-server

# Enable management plugin
sudo rabbitmq-plugins enable rabbitmq_management

# Create application user
sudo rabbitmqctl add_user eracun_user eracun_password
sudo rabbitmqctl set_permissions -p / eracun_user ".*" ".*" ".*"
sudo rabbitmqctl set_user_tags eracun_user administrator
```

**Verify Installation:**
```bash
# Check RabbitMQ status
sudo systemctl status rabbitmq-server

# Access management UI
# http://localhost:15672 (guest/guest or eracun_user/eracun_password)
```

### 2. Install RabbitMQ Client Library

The `@eracun/messaging` library already includes the RabbitMQ adapter. Install amqplib if not already present:

```bash
# In shared/messaging/
npm install amqplib @types/amqplib
```

---

## Migration Steps

### Step 1: Create RabbitMQ Adapter Implementation

The RabbitMQ adapter is already implemented in `shared/messaging/src/adapters/rabbitmq-adapter.ts`. Review the implementation to understand how it works.

**Key Features:**
- Connection pooling
- Automatic reconnection
- Message persistence
- Dead-letter exchange configuration
- Acknowledgment-based delivery

### Step 2: Update Service Configuration

Update each service's environment configuration to use RabbitMQ.

**Before (In-Memory):**
```typescript
// services/fina-connector/src/config.ts
export const config = {
  messageBus: {
    type: 'memory' as const,
  },
};
```

**After (RabbitMQ):**
```typescript
// services/fina-connector/src/config.ts
export const config = {
  messageBus: {
    type: 'rabbitmq' as const,
    url: process.env.RABBITMQ_URL || 'amqp://eracun_user:eracun_password@localhost:5672',
    exchange: process.env.RABBITMQ_EXCHANGE || 'eracun',
    prefetchCount: parseInt(process.env.RABBITMQ_PREFETCH || '10', 10),
  },
};
```

**Environment Variables (.env):**
```bash
# RabbitMQ Configuration
RABBITMQ_URL=amqp://eracun_user:eracun_password@rabbitmq:5672
RABBITMQ_EXCHANGE=eracun
RABBITMQ_PREFETCH=10
```

### Step 3: Update Message Bus Initialization

Update the service initialization to use the RabbitMQ adapter.

**Before:**
```typescript
// services/fina-connector/src/index.ts
import { createInMemoryBus } from '@eracun/messaging';

const messageBus = createInMemoryBus();
await messageBus.connect();
```

**After:**
```typescript
// services/fina-connector/src/index.ts
import { createRabbitMQBus } from '@eracun/messaging';

const messageBus = createRabbitMQBus({
  url: config.messageBus.url,
  exchange: config.messageBus.exchange,
  prefetchCount: config.messageBus.prefetchCount,
});

await messageBus.connect();

// Graceful shutdown
process.on('SIGTERM', async () => {
  await messageBus.disconnect();
  process.exit(0);
});
```

### Step 4: Configure Exchanges and Queues

Create a RabbitMQ setup script to initialize exchanges and queues.

**Script: `scripts/setup-rabbitmq.sh`**
```bash
#!/bin/bash
# RabbitMQ Exchange and Queue Setup

set -e

RABBITMQ_HOST="${RABBITMQ_HOST:-localhost}"
RABBITMQ_PORT="${RABBITMQ_PORT:-15672}"
RABBITMQ_USER="${RABBITMQ_USER:-eracun_user}"
RABBITMQ_PASS="${RABBITMQ_PASS:-eracun_password}"

echo "Setting up RabbitMQ exchanges and queues..."

# Declare main exchange (topic exchange for routing)
curl -u $RABBITMQ_USER:$RABBITMQ_PASS -X PUT \
  http://$RABBITMQ_HOST:$RABBITMQ_PORT/api/exchanges/%2F/eracun \
  -H "content-type:application/json" \
  -d '{"type":"topic","durable":true}'

# Declare dead-letter exchange
curl -u $RABBITMQ_USER:$RABBITMQ_PASS -X PUT \
  http://$RABBITMQ_HOST:$RABBITMQ_PORT/api/exchanges/%2F/dead-letter \
  -H "content-type:application/json" \
  -d '{"type":"topic","durable":true}'

# Declare queues for each service
for service in fina-connector porezna-connector digital-signature-service archive-service cert-lifecycle-manager reporting-service dead-letter-handler; do
  echo "Creating queue: $service"

  curl -u $RABBITMQ_USER:$RABBITMQ_PASS -X PUT \
    http://$RABBITMQ_HOST:$RABBITMQ_PORT/api/queues/%2F/$service \
    -H "content-type:application/json" \
    -d '{
      "durable":true,
      "arguments":{
        "x-dead-letter-exchange":"dead-letter",
        "x-dead-letter-routing-key":"'$service'.failed"
      }
    }'
done

# Create dead-letter queue
curl -u $RABBITMQ_USER:$RABBITMQ_PASS -X PUT \
  http://$RABBITMQ_HOST:$RABBITMQ_PORT/api/queues/%2F/dead-letter \
  -H "content-type:application/json" \
  -d '{"durable":true,"arguments":{"x-message-ttl":259200000}}'

echo "✅ RabbitMQ setup complete!"
```

**Run Setup:**
```bash
chmod +x scripts/setup-rabbitmq.sh
./scripts/setup-rabbitmq.sh
```

### Step 5: Update Docker Compose

Ensure RabbitMQ is included in `docker-compose.team3.yml` (already done in previous commits).

**Verify RabbitMQ service:**
```yaml
services:
  rabbitmq:
    image: rabbitmq:3.12-management-alpine
    environment:
      RABBITMQ_DEFAULT_USER: eracun_user
      RABBITMQ_DEFAULT_PASS: eracun_password
    ports:
      - "5672:5672"   # AMQP
      - "15672:15672" # Management UI
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
```

### Step 6: Update Service Dockerfile (if needed)

Ensure services wait for RabbitMQ to be ready before starting.

**Add wait-for-it script:**
```dockerfile
# Dockerfile
FROM node:20-alpine as builder
# ... build steps ...

FROM node:20-alpine
# ... production setup ...

# Add wait-for-it script
ADD https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

CMD ["/wait-for-it.sh", "rabbitmq:5672", "--", "node", "dist/index.js"]
```

---

## Testing the Migration

### 1. Local Testing

**Start RabbitMQ and Services:**
```bash
# Start infrastructure
docker-compose -f docker-compose.team3.yml up -d rabbitmq postgres

# Wait for RabbitMQ to be ready
./scripts/wait-for-rabbitmq.sh

# Setup exchanges and queues
./scripts/setup-rabbitmq.sh

# Start services
docker-compose -f docker-compose.team3.yml up -d
```

**Verify Connectivity:**
```bash
# Check service logs
docker-compose -f docker-compose.team3.yml logs -f fina-connector

# Should see: "Connected to RabbitMQ at amqp://rabbitmq:5672"
```

### 2. Message Flow Testing

**Publish Test Message:**
```typescript
// test-publish.ts
import { createRabbitMQBus } from '@eracun/messaging';

const bus = createRabbitMQBus({
  url: 'amqp://eracun_user:eracun_password@localhost:5672',
  exchange: 'eracun',
});

await bus.connect();

await bus.publish('invoice.validated', {
  invoiceId: 'TEST-001',
  status: 'validated',
  timestamp: new Date().toISOString(),
});

console.log('✅ Message published');
await bus.disconnect();
```

**Verify Message Delivery:**
```bash
# Check RabbitMQ management UI
# http://localhost:15672 → Queues → Select queue → Get messages

# Or via CLI
sudo rabbitmqctl list_queues name messages_ready messages_unacknowledged
```

### 3. Dead-Letter Exchange Testing

**Simulate Failure:**
```typescript
// Throw error in consumer to trigger DLX
messageBus.subscribe('test.topic', async (message) => {
  throw new Error('Simulated failure');
});
```

**Verify DLX:**
```bash
# Check dead-letter queue
curl -u eracun_user:eracun_password \
  http://localhost:15672/api/queues/%2F/dead-letter
```

---

## Performance Tuning

### 1. Prefetch Count

Controls how many unacknowledged messages a consumer can have.

```typescript
const bus = createRabbitMQBus({
  url: config.rabbitmq.url,
  prefetchCount: 10, // Tune based on processing time
});
```

**Guidelines:**
- **Fast consumers** (< 50ms per message): prefetchCount = 50-100
- **Medium consumers** (50-500ms per message): prefetchCount = 10-20
- **Slow consumers** (> 500ms per message): prefetchCount = 1-5

### 2. Connection Pooling

For high-throughput services, use multiple connections.

```typescript
const connectionPool = await Promise.all(
  Array.from({ length: 5 }, () => createRabbitMQBus(config).connect())
);
```

### 3. Message Persistence

All messages are persistent by default. For high-throughput, non-critical messages:

```typescript
await bus.publish('metrics.collected', data, { persistent: false });
```

---

## Monitoring

### 1. RabbitMQ Management UI

**Access:** http://localhost:15672

**Key Metrics:**
- Queue depths (should be close to 0 under normal load)
- Message rates (in/out)
- Connection count
- Consumer count

### 2. Prometheus Metrics

RabbitMQ Prometheus exporter is already configured in `docker-compose.team3.yml`.

**Metrics Endpoint:** http://localhost:9419/metrics

**Key Metrics:**
- `rabbitmq_queue_messages` - Messages in queue
- `rabbitmq_queue_messages_ready` - Messages ready for delivery
- `rabbitmq_queue_consumers` - Active consumers
- `rabbitmq_channel_consumers` - Total consumers

### 3. Alerting Rules

Add to `deployment/prometheus/alerts.yml`:

```yaml
groups:
  - name: rabbitmq_alerts
    rules:
      - alert: RabbitMQQueueDepthHigh
        expr: rabbitmq_queue_messages > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "RabbitMQ queue {{ $labels.queue }} has high depth"
          description: "Queue depth: {{ $value }} messages"

      - alert: RabbitMQNoConsumers
        expr: rabbitmq_queue_consumers == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "RabbitMQ queue {{ $labels.queue }} has no consumers"
```

---

## Rollback Procedures

### Quick Rollback to In-Memory Bus

If issues are encountered, rollback to in-memory bus:

1. **Update Configuration:**
```bash
# Set environment variable
export MESSAGE_BUS_TYPE=memory

# Or update .env
echo "MESSAGE_BUS_TYPE=memory" >> .env
```

2. **Restart Services:**
```bash
docker-compose -f docker-compose.team3.yml restart
```

3. **Verify:**
```bash
# Check logs for "Using in-memory message bus"
docker-compose logs fina-connector | grep "in-memory"
```

### Data Recovery from RabbitMQ

If messages are stuck in queues during rollback:

```bash
# Export messages to file
sudo rabbitmqctl export_definitions /tmp/rabbitmq-backup.json

# Purge queues (CAREFUL!)
sudo rabbitmqctl purge_queue fina-connector
```

---

## Production Deployment Checklist

- [ ] RabbitMQ installed and running
- [ ] Exchanges and queues created
- [ ] User permissions configured
- [ ] Monitoring and alerting configured
- [ ] Services updated with RabbitMQ configuration
- [ ] Load testing completed
- [ ] Disaster recovery procedures tested
- [ ] Team trained on RabbitMQ operations
- [ ] Rollback procedure documented and tested
- [ ] Message persistence verified
- [ ] Dead-letter exchange tested
- [ ] Performance tuning completed

---

## Troubleshooting

### Connection Refused

**Symptom:** `Error: connect ECONNREFUSED 127.0.0.1:5672`

**Solution:**
```bash
# Check RabbitMQ status
sudo systemctl status rabbitmq-server

# Check if port is listening
sudo netstat -tlnp | grep 5672

# Check firewall
sudo ufw status
sudo ufw allow 5672/tcp
```

### Authentication Failed

**Symptom:** `Error: ACCESS_REFUSED - Login was refused`

**Solution:**
```bash
# Verify user exists
sudo rabbitmqctl list_users

# Reset password
sudo rabbitmqctl change_password eracun_user new_password

# Check permissions
sudo rabbitmqctl list_user_permissions eracun_user
```

### Messages Not Being Consumed

**Symptom:** Messages accumulate in queues

**Solution:**
```bash
# Check consumer count
sudo rabbitmqctl list_queues name consumers

# Check service logs
docker-compose logs fina-connector

# Verify prefetch settings
# Increase prefetchCount in configuration
```

### Memory Issues

**Symptom:** RabbitMQ consuming excessive memory

**Solution:**
```bash
# Configure memory limits in rabbitmq.conf
vm_memory_high_watermark.relative = 0.6

# Or absolute limit
vm_memory_high_watermark.absolute = 2GB

# Restart RabbitMQ
sudo systemctl restart rabbitmq-server
```

---

## Related Documentation

- **Architecture:** @docs/ARCHITECTURE.md (Message Bus section)
- **Deployment:** @docs/DEPLOYMENT_GUIDE.md
- **Monitoring:** @docs/OPERATIONS.md
- **Docker Compose:** @deployment/DOCKER_COMPOSE_README.md
- **RabbitMQ Official Docs:** https://www.rabbitmq.com/documentation.html

---

**Last Updated:** 2025-11-14
**Migration Status:** Ready for production deployment
**Tested With:** RabbitMQ 3.12+, Node.js 20+
