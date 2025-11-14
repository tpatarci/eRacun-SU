# ADR-006: Message Bus Architecture (RabbitMQ + Kafka)

**Status:** ✅ Accepted

**Date:** 2025-11-14

**Context:** Team 1 - Core Processing Pipeline

---

## Context and Problem Statement

The eRačun platform requires inter-service communication to coordinate invoice processing workflows. We need to support both:

1. **Synchronous commands** - Request-response patterns where services need immediate feedback (e.g., "validate this invoice and tell me if it's valid")
2. **Asynchronous events** - Fire-and-forget notifications where services broadcast state changes (e.g., "an invoice was validated")

We evaluated several message bus options for our microservices architecture:
- Single message broker (RabbitMQ only OR Kafka only)
- Dual message brokers (RabbitMQ for commands + Kafka for events)
- HTTP/REST for all inter-service communication
- gRPC for all inter-service communication

## Decision

**We will use RabbitMQ for commands (RPC) and Kafka for events (pub-sub).**

### RabbitMQ for Commands

**Use Case:** Synchronous request-response patterns

**Example:** invoice-gateway-api → validation-coordinator
```json
Command: {
  "type": "ValidateInvoice",
  "payload": { "invoiceId": "...", "xml": "..." }
}

Response: {
  "success": true,
  "data": { "valid": true, "confidence": 0.95 }
}
```

**Features Used:**
- **RPC pattern** with correlation IDs
- **Exclusive reply queues** for responses
- **Persistent messages** for durability
- **Dead letter queues** for failed messages
- **30-second timeout** per command

### Kafka for Events

**Use Case:** Asynchronous event broadcasting

**Example:** invoice-orchestrator → all subscribers
```json
Event: {
  "type": "InvoiceValidated",
  "source": "invoice-orchestrator",
  "data": { "invoiceId": "...", "status": "VALID" }
}
```

**Features Used:**
- **Topic-based pub-sub** for event distribution
- **Consumer groups** for parallel processing
- **7-day retention** for event replay
- **Compression (Snappy)** for efficiency
- **CloudEvents 1.0** format compatibility

## Rationale

### Why Two Message Brokers?

**Separation of Concerns:**
- Commands are **imperative** (do this) → need response → RabbitMQ RPC
- Events are **declarative** (this happened) → fire-and-forget → Kafka pub-sub

**Different Guarantees:**
- Commands need **exactly-once delivery** → RabbitMQ acknowledgments
- Events need **at-least-once delivery** → Kafka offset management

**Different Performance Characteristics:**
- RabbitMQ optimized for **low-latency request-response** (~10-50ms)
- Kafka optimized for **high-throughput event streaming** (10,000+ msg/sec)

**Operational Complexity:**
- RabbitMQ is simpler to operate for RPC patterns
- Kafka provides better event replay capabilities

### Why NOT Single Broker?

**RabbitMQ-only would struggle with:**
- Event replay (no built-in retention policies)
- High-throughput event streams
- Long-term event storage

**Kafka-only would struggle with:**
- Low-latency request-response patterns
- Simple RPC workflows
- Operational overhead for small use cases

**HTTP/REST-only would have:**
- No built-in retry/durability
- No decoupling (direct service-to-service calls)
- Requires circuit breakers everywhere

**gRPC-only would have:**
- No async event broadcasting
- Direct service-to-service coupling
- No message persistence

## Implementation Details

### RabbitMQ Configuration

**Connection:**
```typescript
const connection = await amqp.connect(process.env.RABBITMQ_URL);
const channel = await connection.createChannel();
```

**Sending Commands:**
```typescript
await rabbitmqClient.sendCommand('validation-queue', {
  type: 'ValidateInvoice',
  payload: { invoiceId, xml }
});
// Response received via exclusive reply queue
```

**Consuming Commands:**
```typescript
await rabbitmqClient.consumeCommands('validation-queue', async (command) => {
  const result = await handleValidation(command.payload);
  return { success: true, data: result };
});
```

### Kafka Configuration

**Connection:**
```typescript
const kafka = new Kafka({
  clientId: 'invoice-orchestrator',
  brokers: [process.env.KAFKA_BROKER]
});
```

**Publishing Events:**
```typescript
await kafkaClient.publishEvent('invoice-events', {
  type: 'InvoiceValidated',
  data: { invoiceId, status: 'VALID' }
});
```

**Subscribing to Events:**
```typescript
await kafkaClient.subscribeToEvents('invoice-events', 'audit-group', async (event) => {
  await handleInvoiceEvent(event);
});
```

## Consequences

### Positive

✅ **Clear Separation:** Commands and events have distinct semantics
✅ **Performance Optimized:** Each broker optimized for its use case
✅ **Event Replay:** Kafka provides 7-day event history
✅ **Reliability:** Both brokers have proven durability guarantees
✅ **Scalability:** Kafka handles high-throughput event streams
✅ **Low Latency:** RabbitMQ provides fast request-response

### Negative

❌ **Operational Complexity:** Two message brokers to manage
❌ **Increased Infrastructure Cost:** Need to run both RabbitMQ and Kafka
❌ **Learning Curve:** Team must learn both systems
❌ **Debugging Complexity:** Need to trace messages across two systems

### Mitigation Strategies

**Complexity:**
- Use managed services (DigitalOcean Managed Kafka/RabbitMQ) in production
- Document clear patterns for when to use each broker
- Provide client libraries that abstract broker details

**Cost:**
- Start with single-node Kafka cluster (sufficient for 10,000 invoices/hour)
- Use RabbitMQ community edition (free)
- Scale horizontally only when needed

**Debugging:**
- OpenTelemetry traces span both RabbitMQ and Kafka
- Correlation IDs propagate across broker boundaries
- Grafana dashboards show unified view of message flow

## Alternatives Considered

### Alternative 1: RabbitMQ Only

**Pros:**
- Single broker to manage
- Simpler operations
- Lower cost

**Cons:**
- No event replay capability
- Struggles with high-throughput event streams
- Not optimized for pub-sub patterns

**Decision:** Rejected - event replay is critical for audit trail

### Alternative 2: Kafka Only

**Pros:**
- Single broker to manage
- Excellent event replay
- High throughput

**Cons:**
- Overkill for simple RPC patterns
- Higher operational overhead
- More complex for low-latency request-response

**Decision:** Rejected - RPC patterns would be unnecessarily complex

### Alternative 3: HTTP/REST

**Pros:**
- No message broker infrastructure
- Simplest to understand
- Standard web protocols

**Cons:**
- No durability guarantees
- Requires circuit breakers everywhere
- Direct service coupling
- No async event broadcasting

**Decision:** Rejected - lacks durability and decoupling

## Related Decisions

- **ADR-003:** System Decomposition (defines service boundaries)
- **ADR-005:** Bounded Context Isolation (defines communication patterns)

## References

- [RabbitMQ RPC Tutorial](https://www.rabbitmq.com/tutorials/tutorial-six-python.html)
- [Kafka Documentation](https://kafka.apache.org/documentation/)
- [CloudEvents Specification](https://cloudevents.io/)
- [Enterprise Integration Patterns](https://www.enterpriseintegrationpatterns.com/)

---

**Author:** Team 1 Lead
**Reviewers:** System Architect, Platform Team
**Implementation:** services/invoice-gateway-api/src/messaging/
