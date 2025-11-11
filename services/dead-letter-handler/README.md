# Dead Letter Handler Service - Specification

**Service Name:** `dead-letter-handler`
**Layer:** Infrastructure (Layer 9)
**Complexity:** Medium (~1,800 LOC)
**Status:** 🔴 Specification Only (Ready for Implementation)

---

## 1. Purpose and Scope

### 1.1 Single Responsibility

**Monitor dead letter queues, classify errors, route failed messages to manual review or automated retry.**

This service is the **centralized error recovery mechanism** for the eRacun platform. When any service fails to process a message (validation errors, network failures, business rule violations), the message goes to a Dead Letter Queue (DLQ). This service:
- Monitors all DLQs across all services
- Classifies errors (transient vs. permanent)
- Routes transient errors to retry-scheduler
- Routes permanent errors (business validation) to manual review queue
- Publishes error notifications

### 1.2 What This Service Does

✅ **Monitors all DLQs in RabbitMQ** (40 services = 40 DLQs)
✅ **Classifies error types** (transient, business, technical, unknown)
✅ **Routes transient errors** to retry-scheduler for automated retry
✅ **Routes business errors** to manual review queue (admin-portal)
✅ **Publishes notifications** for critical errors (via notification-service)
✅ **Tracks error statistics** (Prometheus metrics, error rate trends)
✅ **Provides error resolution API** (mark as resolved, resubmit)

### 1.3 What This Service Does NOT Do

❌ Does NOT perform actual retries (retry-scheduler does this)
❌ Does NOT send emails/SMS directly (notification-service does this)
❌ Does NOT process business logic (only routes messages)
❌ Does NOT modify messages (passes through unchanged)

---

## 2. Integration Architecture

### 2.1 Upstream Dependencies

**RabbitMQ Dead Letter Queues (Consumers):**
- `*.dlq` pattern (all service DLQs)
  - `validation.xsd.validate.dlq`
  - `validation.schematron.validate.dlq`
  - `transformation.ubl.transform.dlq`
  - ... (40 DLQs total)
- Binding: Subscribe to `dlx` (Dead Letter Exchange)

**No Direct Service Dependencies** (monitors queues autonomously)

### 2.2 Downstream Consumers

**RabbitMQ Queues (Producers):**
- `retry.scheduled` - Transient errors for retry
- `manual-review.pending` - Business errors requiring human intervention

**Kafka Topics (Producers):**
- `error-events` - Error classification events (for analytics)

**HTTP REST API (Producers):**
- `notification-service` - POST `/notifications` (critical error alerts)

### 2.3 Message Contracts

**Consumed DLQ Message Format** (standard RabbitMQ DLQ):

```typescript
interface DLQMessage {
  original_message: Buffer;      // Original message payload
  original_routing_key: string;  // Where it was going
  original_queue: string;        // Queue it failed from
  error: {
    reason: string;              // Error message
    exception: string;           // Stack trace
    timestamp: number;           // When it failed
  };
  headers: {
    'x-death': [{                // RabbitMQ death header
      count: number;             // Retry attempts
      reason: string;            // rejection/expired/maxlen
      queue: string;
      time: Date;
    }];
    'x-first-death-reason': string;
    'x-first-death-queue': string;
    'x-first-death-exchange': string;
  };
}
```

**Published Message Schema** (`retry.proto`):

```protobuf
message RetryMessage {
  string message_id = 1;            // UUID
  bytes original_payload = 2;       // Original message
  string original_queue = 3;        // Destination queue
  string error_reason = 4;          // Why it failed
  int32 retry_count = 5;            // Current attempt
  int32 max_retries = 6;            // Max allowed (default 3)
  int64 next_retry_at_ms = 7;       // Scheduled retry time
  ErrorClassification classification = 8;
}

enum ErrorClassification {
  TRANSIENT = 0;       // Network, timeout, resource exhaustion
  BUSINESS = 1;        // Validation failure, business rule violation
  TECHNICAL = 2;       // Programming error, null pointer, type mismatch
  UNKNOWN = 3;         // Cannot classify
}
```

**Published Event Schema** (`error-events.proto`):

```protobuf
message ErrorEvent {
  string error_id = 1;
  string invoice_id = 2;
  string service_name = 3;
  ErrorClassification classification = 4;
  string error_message = 5;
  int64 timestamp_ms = 6;
  bool retry_scheduled = 7;
  bool manual_review_required = 8;
}
```

### 2.4 HTTP API (for Admin Portal)

**REST Endpoints:**

```
GET    /api/v1/errors                    # List all errors in manual review
GET    /api/v1/errors/:id                # Get error details
POST   /api/v1/errors/:id/resolve        # Mark error as resolved
POST   /api/v1/errors/:id/resubmit       # Resubmit to original queue
GET    /api/v1/errors/stats              # Error statistics (by service, type)
```

---

## 3. Technology Stack

### 3.1 Required Dependencies

**Core:**
- `Node.js 20+` - Runtime
- `TypeScript 5.3+` - Type safety
- `amqplib` - RabbitMQ client
- `kafkajs` - Kafka producer
- `express` - HTTP API server
- `axios` - HTTP client (notification-service)

**Observability (TODO-008 Compliance):**
- `prom-client` - Prometheus metrics
- `pino` - Structured logging
- `opentelemetry` - Distributed tracing

**Utilities:**
- `uuid` - Message ID generation

### 3.2 External Systems

**RabbitMQ:**
- Connection: via `RABBITMQ_URL` environment variable
- Consumes from: `dlx` exchange (dead letter exchange)
- Produces to: `retry` and `manual-review` queues

**Kafka:**
- Connection: via `KAFKA_BROKERS` environment variable
- Produces to: `error-events` topic (5 partitions)

**PostgreSQL** (for tracking manual review queue):
- Table: `manual_review_errors`
- Schema:
  ```sql
  CREATE TABLE manual_review_errors (
    id BIGSERIAL PRIMARY KEY,
    error_id UUID NOT NULL UNIQUE,
    invoice_id UUID NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    error_classification VARCHAR(50) NOT NULL,
    original_message BYTEA NOT NULL,
    original_queue VARCHAR(255) NOT NULL,
    error_reason TEXT NOT NULL,
    error_stack TEXT,
    retry_count INT NOT NULL DEFAULT 0,
    status VARCHAR(50) DEFAULT 'pending', -- pending, in_review, resolved
    created_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(100)
  );

  CREATE INDEX idx_manual_review_status ON manual_review_errors(status);
  CREATE INDEX idx_manual_review_invoice ON manual_review_errors(invoice_id);
  ```

---

## 4. Error Classification Logic

### 4.1 Classification Rules

**Transient Errors** (retry automatically):
- Network timeouts (`ETIMEDOUT`, `ECONNREFUSED`)
- Database connection failures (`Connection terminated`)
- Rate limit exceeded (`429 Too Many Requests`)
- Resource exhaustion (`ENOMEM`, `EMFILE`)
- Temporary external API errors (`503 Service Unavailable`)

**Business Errors** (manual review required):
- XSD validation failures (`Invalid XML structure`)
- Schematron rule violations (`BR-CO-04: Missing required field`)
- KPD code not found (`KPD code 123456 not in KLASUS registry`)
- OIB validation failures (`Invalid OIB checksum`)
- Duplicate invoice detection (`Invoice INV-001 already submitted`)

**Technical Errors** (manual review + engineering investigation):
- Null pointer exceptions (`Cannot read property 'x' of undefined`)
- Type mismatches (`Expected number, got string`)
- Unhandled exceptions (`ReferenceError`)
- Memory leaks (OOM killer)

**Unknown Errors** (manual review + investigation):
- Generic error messages without stack trace
- Missing error context
- Malformed error objects

### 4.2 Classification Algorithm

```typescript
function classifyError(dlqMessage: DLQMessage): ErrorClassification {
  const errorReason = dlqMessage.error.reason.toLowerCase();
  const errorStack = dlqMessage.error.exception.toLowerCase();

  // Transient errors (network, resource, rate limit)
  if (errorReason.includes('timeout') ||
      errorReason.includes('econnrefused') ||
      errorReason.includes('503') ||
      errorReason.includes('rate limit')) {
    return ErrorClassification.TRANSIENT;
  }

  // Business errors (validation, business rules)
  if (errorReason.includes('validation') ||
      errorReason.includes('br-') ||        // Schematron rule IDs
      errorReason.includes('invalid oib') ||
      errorReason.includes('duplicate')) {
    return ErrorClassification.BUSINESS;
  }

  // Technical errors (programming errors)
  if (errorStack.includes('typeerror') ||
      errorStack.includes('referenceerror') ||
      errorStack.includes('null') ||
      errorStack.includes('undefined')) {
    return ErrorClassification.TECHNICAL;
  }

  // Unknown (cannot classify)
  return ErrorClassification.UNKNOWN;
}
```

---

## 5. Performance Requirements

### 5.1 Throughput

**Target:** 100 DLQ messages/second sustained
**Peak:** 500 DLQ messages/second burst (during incidents)
**Why:** During a widespread validation failure (e.g., bad CIUS rule), many messages could fail simultaneously

### 5.2 Latency

**DLQ consumption to classification:** <100ms p95
**Retry scheduling:** <200ms p95 (publish to retry-scheduler)
**Manual review routing:** <500ms p95 (write to PostgreSQL + notify)
**HTTP API response:** <200ms p95 (100 errors)

### 5.3 Reliability

**Data Loss Tolerance:** ZERO (failed messages must be tracked)
**Availability Target:** 99.9% (errors must be handled even when other services fail)
**Recovery Time Objective (RTO):** 5 minutes
**Recovery Point Objective (RPO):** 0 (no lost errors)

---

## 6. Implementation Guidance

### 6.1 Recommended File Structure

```
services/dead-letter-handler/
├── src/
│   ├── index.ts              # Main entry point (RabbitMQ consumer + HTTP API)
│   ├── consumer.ts           # DLQ consumer logic
│   ├── classifier.ts         # Error classification algorithm
│   ├── router.ts             # Route to retry/manual-review/notification
│   ├── api.ts                # HTTP REST API for admin portal
│   ├── repository.ts         # PostgreSQL persistence (manual review)
│   └── observability.ts      # Metrics, logging, tracing (TODO-008)
├── tests/
│   ├── setup.ts
│   ├── unit/
│   │   ├── classifier.test.ts
│   │   ├── router.test.ts
│   │   └── observability.test.ts
│   └── integration/
│       ├── dlq-consumer.test.ts
│       ├── retry-routing.test.ts
│       └── api.test.ts
├── package.json
├── tsconfig.json
├── jest.config.js
├── Dockerfile
├── dead-letter-handler.service  # systemd unit file
├── .env.example
├── README.md                    # This file
└── RUNBOOK.md                   # Operations guide (create after implementation)
```

### 6.2 Core Implementation Logic

**DLQ Consumer** (`src/consumer.ts`):

```typescript
import amqp from 'amqplib';
import { classifyError } from './classifier';
import { routeError } from './router';

export async function startDLQConsumer() {
  const connection = await amqp.connect(process.env.RABBITMQ_URL!);
  const channel = await connection.createChannel();

  // Bind to dead letter exchange
  await channel.assertExchange('dlx', 'topic', { durable: true });
  await channel.assertQueue('dlq-handler-consumer', { durable: true });
  await channel.bindQueue('dlq-handler-consumer', 'dlx', '*.dlq');

  await channel.consume('dlq-handler-consumer', async (msg) => {
    if (!msg) return;

    const dlqMessage = parseDLQMessage(msg);
    const classification = classifyError(dlqMessage);

    // Route based on classification
    await routeError(dlqMessage, classification);

    // Metrics
    dlqMessagesProcessed.inc({ classification });

    channel.ack(msg);
  });
}
```

**Error Router** (`src/router.ts`):

```typescript
export async function routeError(
  dlqMessage: DLQMessage,
  classification: ErrorClassification
): Promise<void> {
  switch (classification) {
    case ErrorClassification.TRANSIENT:
      // Send to retry-scheduler
      await publishToRetryQueue(dlqMessage);
      break;

    case ErrorClassification.BUSINESS:
    case ErrorClassification.TECHNICAL:
    case ErrorClassification.UNKNOWN:
      // Send to manual review
      await saveToManualReview(dlqMessage, classification);
      await notifyCriticalError(dlqMessage);
      break;
  }

  // Publish error event to Kafka
  await publishErrorEvent(dlqMessage, classification);
}
```

### 6.3 Observability (TODO-008 Compliance)

**Required Prometheus Metrics:**

```typescript
// DLQ message processing
const dlqMessagesProcessed = new Counter({
  name: 'dlq_messages_processed_total',
  help: 'Total DLQ messages processed',
  labelNames: ['classification', 'service']
});

// Error classification distribution
const dlqClassificationDistribution = new Counter({
  name: 'dlq_classification_total',
  help: 'Errors by classification type',
  labelNames: ['classification']
});

// Retry routing rate
const dlqRetriesScheduled = new Counter({
  name: 'dlq_retries_scheduled_total',
  help: 'Messages sent to retry-scheduler',
  labelNames: ['service']
});

// Manual review queue size
const dlqManualReviewPending = new Gauge({
  name: 'dlq_manual_review_pending',
  help: 'Number of errors awaiting manual review'
});

// Processing latency
const dlqProcessingDuration = new Histogram({
  name: 'dlq_processing_duration_seconds',
  help: 'Time to classify and route DLQ message',
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5]
});

// Critical error notifications
const dlqNotificationsSent = new Counter({
  name: 'dlq_notifications_sent_total',
  help: 'Critical error notifications sent',
  labelNames: ['severity']
});
```

---

## 7. Failure Modes and Recovery

### 7.1 Critical Failure Scenarios

**Scenario 1: RabbitMQ Connection Lost**
- **Impact:** DLQ messages accumulate, no error handling
- **Detection:** Health check fails, metrics stop updating
- **Recovery:**
  1. Reconnect to RabbitMQ with exponential backoff
  2. Resume consuming from DLQ (messages not lost)
  3. Verify no messages missed (check queue depth)

**Scenario 2: Retry-Scheduler Queue Full**
- **Impact:** Cannot route transient errors for retry
- **Detection:** RabbitMQ publish fails with queue full error
- **Recovery:**
  1. Alert on-call (P1 incident)
  2. Increase retry-scheduler consumers
  3. Temporarily route to manual review if queue remains full

**Scenario 3: Notification Service Down**
- **Impact:** Critical errors not alerted (human intervention delayed)
- **Detection:** HTTP POST to notification-service fails
- **Recovery:**
  1. Store notifications in local queue
  2. Retry notification delivery (exponential backoff)
  3. Fall back to direct logging (alerts via log monitoring)

**Scenario 4: Manual Review Queue Overflow**
- **Impact:** Many business errors, human review backlog
- **Detection:** `dlq_manual_review_pending` > 1000
- **Recovery:**
  1. Alert operations team (scale human review capacity)
  2. Identify common error patterns (fix root cause)
  3. Bulk resolution tools (admin portal bulk actions)

### 7.2 Error Classification Misclassification

**Transient Error Classified as Business:**
- **Impact:** Manual review for retryable error (wastes human time)
- **Mitigation:** Admin can manually resubmit to retry queue

**Business Error Classified as Transient:**
- **Impact:** Infinite retry loop (never succeeds)
- **Mitigation:** Max retry limit (3 attempts) → then route to manual review

---

## 8. Security Considerations

### 8.1 Data Protection

**Sensitive Data in Error Messages:**
- DLQ messages may contain original invoice payloads (PII)
- Store encrypted in PostgreSQL `manual_review_errors` table
- Access control: Only admins can view manual review queue

### 8.2 Access Control

**HTTP API Authentication:**
- JWT authentication required for all endpoints
- Role-based access: `admin` role required for resolve/resubmit

---

## 9. Deployment Configuration

### 9.1 Environment Variables (`.env.example`)

```bash
# Service Configuration
SERVICE_NAME=dead-letter-handler
NODE_ENV=production
HTTP_PORT=8081
PROMETHEUS_PORT=9091

# RabbitMQ Configuration
RABBITMQ_URL=amqp://user:password@localhost:5672
DLQ_EXCHANGE=dlx
DLQ_QUEUE=dlq-handler-consumer

# Kafka Configuration
KAFKA_BROKERS=localhost:9092
ERROR_EVENTS_TOPIC=error-events

# PostgreSQL Configuration
DATABASE_URL=postgresql://dlh_user:password@localhost:5432/eracun

# Notification Service
NOTIFICATION_SERVICE_URL=http://notification-service:8080

# Retry Configuration
MAX_RETRIES=3
TRANSIENT_RETRY_DELAY_MS=5000

# Observability
LOG_LEVEL=info
JAEGER_AGENT_HOST=localhost
JAEGER_AGENT_PORT=6831
```

---

## 10. Testing Requirements

### 10.1 Unit Tests (70% of test suite)

**Test Coverage:**
- Error classification logic (100% - critical)
- Routing logic (all 4 classifications)
- Metrics increment (all counters)

**Key Test Cases:**
- Classify network timeout → TRANSIENT
- Classify validation error → BUSINESS
- Classify null pointer → TECHNICAL
- Classify unknown error → UNKNOWN

### 10.2 Integration Tests (25% of test suite)

**Test Scenarios:**
1. DLQ message → classify → route to retry queue
2. DLQ message → classify → save to manual review
3. Critical error → notification sent
4. HTTP API → list/resolve/resubmit errors

---

## 11. Acceptance Criteria

### 11.1 Functional Requirements

- [ ] Consumes from all DLQs (via `dlx` exchange)
- [ ] Classifies errors (4 types: transient, business, technical, unknown)
- [ ] Routes transient → retry-scheduler
- [ ] Routes business/technical/unknown → manual review
- [ ] Publishes error events to Kafka
- [ ] Sends notifications for critical errors
- [ ] HTTP API (4 endpoints)

### 11.2 Non-Functional Requirements

- [ ] Throughput: 100 messages/second sustained
- [ ] Latency: <100ms p95 for classification
- [ ] Test coverage: 85%+
- [ ] Observability: 6+ Prometheus metrics
- [ ] Documentation: README.md + RUNBOOK.md

---

**Status:** 🔴 Specification Complete, Ready for Implementation
**Implementation Estimate:** 3-4 days
**Complexity:** Medium (~1,800 LOC)
**Dependencies:** None (can start immediately)

---

**Last Updated:** 2025-11-11
**Specification Author:** System Architect
**Assigned Implementer:** [AI Instance TBD]
