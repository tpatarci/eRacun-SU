# Retry Scheduler Service - Specification

**Service Name:** `retry-scheduler`
**Layer:** Infrastructure (Layer 9)
**Complexity:** Medium (~1,200 LOC)
**Status:** 🔴 Specification Only (Ready for Implementation)

---

## 1. Purpose and Single Responsibility

**Schedule retries for transient failures with exponential backoff and republish to original queues.**

This service receives failed messages classified as "transient" by dead-letter-handler and:
- Schedules retries with exponential backoff (2s, 4s, 8s, 16s...)
- Tracks retry attempts (max 3 by default)
- Republishes to original queues after delay
- Moves to manual review after max retries exhausted

---

## 2. Integration Architecture

### 2.1 Dependencies

**Consumes:**
- RabbitMQ queue: `retry.scheduled` (from dead-letter-handler)

**Produces:**
- Original service queues (republish after delay)
- `manual-review.pending` (if max retries exceeded)

### 2.2 Message Contract

```protobuf
message RetryMessage {
  string message_id = 1;
  bytes original_payload = 2;       // Original message to retry
  string original_queue = 3;        // Where to republish
  string error_reason = 4;
  int32 retry_count = 5;            // Current attempt (0, 1, 2...)
  int32 max_retries = 6;            // Default 3
  int64 next_retry_at_ms = 7;       // When to retry (Unix timestamp)
}
```

---

## 3. Retry Strategy

### 3.1 Exponential Backoff

```typescript
function calculateNextRetryDelay(retryCount: number): number {
  const baseDelay = 2000; // 2 seconds
  const maxDelay = 60000; // 60 seconds (cap)
  const jitter = Math.random() * 1000; // 0-1s jitter

  const delay = Math.min(baseDelay * Math.pow(2, retryCount), maxDelay);
  return delay + jitter; // Add jitter to prevent thundering herd
}

// Retry schedule:
// Attempt 1: ~2s
// Attempt 2: ~4s
// Attempt 3: ~8s
// After 3 attempts → manual review
```

### 3.2 Scheduling Implementation

**Option A: In-Memory Priority Queue**
- Store retry tasks in memory (sorted by `next_retry_at_ms`)
- Poll every second for due retries
- Pros: Fast, simple
- Cons: Lost retries if service restarts (use Option B for production)

**Option B: PostgreSQL Persistent Queue (RECOMMENDED)**
- Store retry tasks in database table
- Poll for due retries every 10 seconds
- Pros: No data loss on restart
- Cons: Slight latency (acceptable for retry use case)

**Schema:**
```sql
CREATE TABLE retry_queue (
  id BIGSERIAL PRIMARY KEY,
  message_id UUID UNIQUE NOT NULL,
  original_payload BYTEA NOT NULL,
  original_queue VARCHAR(255) NOT NULL,
  error_reason TEXT,
  retry_count INT NOT NULL DEFAULT 0,
  max_retries INT NOT NULL DEFAULT 3,
  next_retry_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  status VARCHAR(50) DEFAULT 'pending' -- pending, retried, failed
);

CREATE INDEX idx_retry_next_retry ON retry_queue(next_retry_at, status);
```

---

## 4. Technology Stack

**Core:**
- Node.js 20+ / TypeScript 5.3+
- `pg` - PostgreSQL client (persistent queue)
- `amqplib` - RabbitMQ client

**Observability:**
- `prom-client`, `pino`, `opentelemetry`

---

## 5. Performance Requirements

**Throughput:**
- 50 retries/second sustained
- 200 retries/second burst

**Latency:**
- Retry execution within 5 seconds of scheduled time (acceptable drift)

**Reliability:**
- No lost retry tasks (persistent in PostgreSQL)

---

## 6. Implementation Guidance

### 6.1 Core Logic

```typescript
// Consume from retry.scheduled queue
async function consumeRetryMessages() {
  await channel.consume('retry.scheduled', async (msg) => {
    const retryMsg = parseRetryMessage(msg);

    // Calculate next retry time
    const delay = calculateNextRetryDelay(retryMsg.retry_count);
    const nextRetryAt = Date.now() + delay;

    // Store in PostgreSQL
    await saveRetryTask({
      ...retryMsg,
      next_retry_at: new Date(nextRetryAt)
    });

    channel.ack(msg);
  });
}

// Scheduled retry execution (poll every 10 seconds)
setInterval(async () => {
  const dueTasks = await getDueRetryTasks();

  for (const task of dueTasks) {
    if (task.retry_count >= task.max_retries) {
      // Max retries exceeded → manual review
      await moveToManualReview(task);
    } else {
      // Republish to original queue
      await republishMessage(task);
      task.retry_count++;
      await updateRetryTask(task);
    }
  }
}, 10000);
```

---

## 7. Observability (TODO-008)

**Metrics:**
```typescript
const retriesScheduled = new Counter({
  name: 'retries_scheduled_total',
  labelNames: ['queue']
});

const retriesExecuted = new Counter({
  name: 'retries_executed_total',
  labelNames: ['queue', 'status']  // status: success/failed
});

const retriesExhausted = new Counter({
  name: 'retries_exhausted_total',
  help: 'Messages moved to manual review after max retries',
  labelNames: ['queue']
});

const retryQueueDepth = new Gauge({
  name: 'retry_queue_depth',
  help: 'Pending retry tasks'
});
```

---

## 8. Configuration

```bash
# .env.example
SERVICE_NAME=retry-scheduler
HTTP_PORT=8086

# RabbitMQ
RABBITMQ_URL=amqp://localhost:5672
RETRY_QUEUE=retry.scheduled
MANUAL_REVIEW_QUEUE=manual-review.pending

# Retry Configuration
DEFAULT_MAX_RETRIES=3
BASE_DELAY_MS=2000
MAX_DELAY_MS=60000
RETRY_POLL_INTERVAL_MS=10000

# PostgreSQL
DATABASE_URL=postgresql://retry_user:password@localhost:5432/eracun
```

---

## 9. Acceptance Criteria

- [ ] Consume retry messages from RabbitMQ
- [ ] Store retry tasks in PostgreSQL (persistent)
- [ ] Execute retries with exponential backoff + jitter
- [ ] Republish to original queues after delay
- [ ] Move to manual review after max retries
- [ ] Test coverage 85%+
- [ ] 4+ Prometheus metrics

---

**Status:** 🔴 Ready for Implementation
**Estimate:** 3 days | **Complexity:** Medium (~1,200 LOC)
**Dependencies:** None

---

**Last Updated:** 2025-11-11
