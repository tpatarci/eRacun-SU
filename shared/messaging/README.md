# @eracun/messaging

Shared messaging abstractions for eRačun microservices platform.

## Purpose

Provides unified message bus interface for inter-service communication with support for:
- Topic-based pub/sub
- Request-response (RPC) pattern
- Multiple transports (in-memory, RabbitMQ, Kafka)

## PENDING-006 Resolution

This library addresses **PENDING-006: Architecture Compliance Remediation** by providing a temporary in-memory message bus adapter. Services can use this immediately without waiting for RabbitMQ/Kafka infrastructure. When the real bus topology is ready, we only swap the transport layer - service contracts remain unchanged.

## Usage

### Basic Pub/Sub

```typescript
import { getMessageBus } from '@eracun/messaging';

const bus = getMessageBus();

// Subscribe to topic
await bus.subscribe('invoice.created', async (message) => {
  console.log('Received:', message.payload);
});

// Publish message
await bus.publish('invoice.created', {
  invoiceId: '12345',
  amount: 1000,
});
```

### Request-Response (RPC)

```typescript
// Service A: Handle requests
await bus.subscribe('validate.invoice', async (message) => {
  const result = validateInvoice(message.payload);
  await bus.reply(message, result);
});

// Service B: Make request
const result = await bus.request('validate.invoice', {
  invoiceId: '12345',
}, 5000); // 5 second timeout
```

### Configuration

```typescript
import { createMessageBus } from '@eracun/messaging';

// In-memory (development/testing)
const bus = createMessageBus({ type: 'memory' });

// RabbitMQ (production) - coming soon
const bus = createMessageBus({
  type: 'rabbitmq',
  url: 'amqp://localhost:5672',
});

// Kafka (production) - coming soon
const bus = createMessageBus({
  type: 'kafka',
  url: 'kafka://localhost:9092',
});
```

## Message Format

All messages follow this envelope structure:

```typescript
interface Message<T> {
  id: string;              // UUID
  type: string;            // Topic name
  payload: T;              // Message data
  timestamp: string;       // ISO 8601
  correlationId?: string;  // For request-response
  replyTo?: string;        // Reply topic
  metadata?: Record<string, unknown>;
}
```

## Features

### In-Memory Transport
- ✅ Zero dependencies (EventEmitter-based)
- ✅ Async message handling
- ✅ Error handling and logging
- ✅ Request-response with timeout
- ✅ Perfect for development and testing

### RabbitMQ Transport (Planned)
- ⏳ Persistent queues
- ⏳ Dead letter queues
- ⏳ Acknowledgment-based delivery
- ⏳ Connection pooling

### Kafka Transport (Planned)
- ⏳ Event sourcing support
- ⏳ Long-term retention
- ⏳ Consumer groups
- ⏳ Offset management

## Architecture Compliance

This library enables architecture-compliant service communication:

```typescript
// ❌ Before (direct HTTP calls - violates architecture)
const response = await axios.post('http://validator/validate', data);

// ✅ After (message bus - architecture compliant)
const result = await bus.request('validator.validate', data);
```

## Migration Path

1. **Phase 1 (Current):** Use in-memory bus for all services
2. **Phase 2:** Deploy RabbitMQ, switch command messages
3. **Phase 3:** Deploy Kafka, switch event messages
4. **Phase 4:** Remove in-memory transport

Service code remains **unchanged** during migration.

## Related Documentation

- **Architecture:** @docs/ARCHITECTURE.md (Section 1: Service Communication)
- **PENDING-006:** @docs/pending/006-architecture-compliance-remediation.md
- **Message Patterns:** @docs/guides/message-patterns.md

---

**Package Owner:** Team 3 (External Integration & Compliance)
**Status:** Production Ready (in-memory), Planned (RabbitMQ/Kafka)
**Version:** 1.0.0
