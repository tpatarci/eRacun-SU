# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Service Overview

**Service:** `retry-scheduler`
**Layer:** Infrastructure (Layer 9)
**Status:** ✅ Fully Implemented (Code + Tests + Documentation)
**Purpose:** Automated retry scheduler with exponential backoff for transient failures

This service consumes retry requests from the `retry.scheduled` RabbitMQ queue, persists them in PostgreSQL with calculated retry times, and republishes messages to their original queues after the appropriate delay. If max retries are exceeded, messages are moved to manual review.

### Implementation Completeness

- ✅ **Production Code**: All 7 modules implemented (~1,200 LOC)
- ✅ **Unit Tests**: 59 tests, 93.82% statement coverage, 100% function coverage
- ✅ **Integration Tests**: 27 tests (run with `RUN_INTEGRATION_TESTS=true`)
- ✅ **Operational Documentation**: Complete RUNBOOK.md with 8+ scenarios
- ✅ **Deployment**: Dockerfile + systemd unit with security hardening

---

## Commands

### Build & Development

```bash
# Install dependencies
npm install

# Build TypeScript to JavaScript
npm run build

# Development mode (with ts-node)
npm run dev

# Production mode (requires build first)
npm run build && npm start
```

### Testing

```bash
# Run unit tests (fast, no infrastructure required)
npm test

# Run with coverage report
npm run test:coverage

# Run ALL tests including integration tests (requires PostgreSQL + RabbitMQ)
RUN_INTEGRATION_TESTS=true npm run test:coverage

# Watch mode for development
npm run test:watch
```

**Coverage achieved:**
- **Unit tests:** 93.82% statements, 68.75% branches, 100% functions
- **Integration tests:** Repository, retry flow end-to-end (27 tests)
- **Total:** 86 tests (59 unit + 27 integration)

**Note:** Integration tests are skipped by default (require PostgreSQL/RabbitMQ). Core business logic (backoff, observability) has 100% coverage.

---

## Architecture

### Core Components

1. **Consumer (`src/consumer.ts`)**: RabbitMQ consumer that receives retry requests from `retry.scheduled` queue
2. **Repository (`src/repository.ts`)**: PostgreSQL operations for the `retry_queue` table (persistent storage)
3. **Scheduler (`src/scheduler.ts`)**: Polling mechanism that executes due retries every 10 seconds
4. **Backoff (`src/backoff.ts`)**: Exponential backoff calculator with jitter (2s → 4s → 8s → 16s...)
5. **Publisher (`src/publisher.ts`)**: Republishes messages to original queues or moves to manual review
6. **Observability (`src/observability.ts`)**: Prometheus metrics, structured logging (Pino), distributed tracing (OpenTelemetry)

### Data Flow

```
RabbitMQ (retry.scheduled)
  → Consumer receives retry request
    → Calculate next retry time (exponential backoff + jitter)
      → Store in PostgreSQL retry_queue table
        → Scheduler polls for due retries (every 10s)
          → If retry_count < max_retries: Republish to original queue
          → If retry_count >= max_retries: Move to manual-review.pending
```

### PostgreSQL Schema

The service uses the `retry_queue` table with the following structure:

- **message_id** (UUID): Unique identifier, used for upserts
- **original_payload** (BYTEA): The original message to retry
- **original_queue** (VARCHAR): Where to republish the message
- **error_reason** (TEXT): Why the retry was needed
- **retry_count** (INT): Current attempt number (0-based)
- **max_retries** (INT): Maximum attempts before moving to manual review (default: 3)
- **next_retry_at** (TIMESTAMP): When to execute the retry
- **status** (VARCHAR): 'pending', 'retried', or 'failed'

**Critical Index:** `idx_retry_next_retry ON retry_queue(next_retry_at, status)` for efficient polling.

### Exponential Backoff Strategy

- **Base delay:** 2000ms (2 seconds)
- **Max delay:** 60000ms (60 seconds)
- **Jitter:** 0-1000ms random to prevent thundering herd
- **Formula:** `min(BASE_DELAY * 2^retryCount, MAX_DELAY) + jitter`

Example schedule for default settings:
- Attempt 0: ~2s
- Attempt 1: ~4s
- Attempt 2: ~8s
- After 3 attempts: moved to manual review

### Message Contracts

**Consumed from `retry.scheduled`:**
```typescript
{
  message_id: string;           // UUID
  original_payload: Buffer;     // Original message bytes
  original_queue: string;       // Queue name to republish to
  error_reason?: string;
  retry_count: number;          // 0-based
  max_retries: number;          // Default 3
  next_retry_at_ms: number;     // Unix timestamp
}
```

**Republished messages include headers:**
- `x-retry-count`: Current retry attempt
- `x-original-error`: Why the retry was needed

### Idempotency

The service uses **upsert logic** (ON CONFLICT DO UPDATE) for the `retry_queue` table, keyed on `message_id`. This means:
- Duplicate retry requests overwrite existing pending retries
- Safe to republish retry requests without creating duplicates
- Restarts don't lose retry tasks (persistent in PostgreSQL)

---

## Configuration

All configuration via environment variables (see `.env.example`):

**Service:**
- `SERVICE_NAME`: Service identifier (default: `retry-scheduler`)
- `HTTP_PORT`: Health/metrics endpoint port (default: `8086`)

**RabbitMQ:**
- `RABBITMQ_URL`: Connection string (e.g., `amqp://localhost:5672`)
- `RETRY_QUEUE`: Input queue name (default: `retry.scheduled`)
- `MANUAL_REVIEW_QUEUE`: Dead-end queue (default: `manual-review.pending`)

**PostgreSQL:**
- `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`
- `POSTGRES_POOL_MIN`: Min connections (default: 10)
- `POSTGRES_POOL_MAX`: Max connections (default: 50)

**Retry Behavior:**
- `DEFAULT_MAX_RETRIES`: Attempts before manual review (default: 3)
- `BASE_DELAY_MS`: Initial retry delay (default: 2000)
- `MAX_DELAY_MS`: Maximum retry delay cap (default: 60000)
- `RETRY_POLL_INTERVAL_MS`: How often to poll for due retries (default: 10000)

---

## Observability

### Prometheus Metrics (port 9094)

Exposed via `GET /metrics`:

- `retries_scheduled_total{queue}`: Counter of retry tasks created
- `retries_executed_total{queue, status}`: Counter of retries executed (status: success/failed)
- `retries_exhausted_total{queue}`: Counter of messages moved to manual review
- `retry_queue_depth`: Gauge of pending retry tasks

### Health Endpoints

- `GET /health`: Returns 200 if database and RabbitMQ are connected
- `GET /ready`: Returns 200 if service is ready to process retries

### Logging

Structured JSON logs via Pino:
- **Level:** DEBUG in development, INFO in production
- **Fields:** timestamp, service_name, message_id, retry_count, original_queue
- **No PII:** Retry messages should already be sanitized by upstream services

### Distributed Tracing

OpenTelemetry instrumentation with 100% sampling. Key spans:
- `rabbitmq.consume`: Receiving retry request
- `postgres.write`: Persisting retry task
- `retry.schedule`: Calculating next retry time
- `retry.execute`: Republishing or moving to manual review

---

## Testing Strategy

**Test Structure:**
- `tests/setup.ts`: Jest configuration, global mocks
- `tests/unit/`: Unit tests for backoff calculation, observability
- `tests/integration/`: Tests with real PostgreSQL (Testcontainers)

**Coverage Requirements:**
- 85% minimum (enforced in `jest.config.js`)
- Focus on: backoff calculation, retry logic, max retries handling

**Key Test Scenarios:**
- Exponential backoff calculation correctness
- Jitter prevents thundering herd
- Max retries triggers manual review routing
- Idempotency (duplicate message_id upserts)
- Graceful shutdown doesn't lose pending retries

---

## Deployment

### Docker

Multi-stage Dockerfile:
1. **Builder stage:** Compile TypeScript, prune dev dependencies
2. **Runtime stage:** Minimal Alpine image, non-root user (`eracun:1001`)

```bash
docker build -t eracun/retry-scheduler:latest .
docker run -p 8086:8086 -p 9094:9094 --env-file .env eracun/retry-scheduler
```

### systemd

Service unit: `deployment/eracun-retry-scheduler.service`

**Security hardening:**
- `ProtectSystem=strict`: Read-only filesystem
- `ProtectHome=true`: No access to user directories
- `NoNewPrivileges=true`: Prevent privilege escalation
- `PrivateTmp=true`: Isolated /tmp

**Install:**
```bash
sudo cp deployment/eracun-retry-scheduler.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable eracun-retry-scheduler
sudo systemctl start eracun-retry-scheduler
sudo systemctl status eracun-retry-scheduler
```

### Graceful Shutdown

The service handles `SIGTERM` and `SIGINT`:
1. Stop accepting new retry requests (close RabbitMQ consumer)
2. Stop polling for due retries (clear interval)
3. Close HTTP server
4. Close database pool
5. Shutdown tracing

**No data loss:** Pending retries remain in PostgreSQL and are processed on restart.

---

## Common Development Tasks

### Adding a New Metric

1. Define metric in `src/observability.ts` (Counter, Gauge, Histogram)
2. Export the metric
3. Instrument the relevant code path
4. Add tests to verify metric increments
5. Update this documentation

### Changing Backoff Strategy

1. Modify `calculateNextRetryDelay()` in `src/backoff.ts`
2. Update tests in `tests/unit/backoff.test.ts`
3. Update environment variable defaults in `.env.example`
4. Document behavior in README.md

### Debugging Retry Issues

1. Check Prometheus metrics (`GET /metrics`):
   - Is `retry_queue_depth` growing unbounded? (Scheduler not keeping up)
   - Are `retries_exhausted_total` increasing? (Max retries being hit)
2. Check structured logs for specific `message_id`
3. Query PostgreSQL directly:
   ```sql
   SELECT * FROM retry_queue WHERE status = 'pending' ORDER BY next_retry_at;
   ```
4. Verify RabbitMQ connection (check `GET /health` and `GET /ready`)

### Running Without Tests

If you need to skip tests during local development (NOT recommended for CI):
```bash
npm run build && npm start
```

Tests are intentionally required for the `npm test` command to enforce quality standards.

---

## Integration Points

**Upstream Services:**
- `dead-letter-handler`: Classifies errors and publishes to `retry.scheduled`

**Downstream Services:**
- **Any service queue**: Retries are republished to their original queues
- `manual-review-handler`: Receives messages that exceeded max retries

**Infrastructure:**
- **RabbitMQ**: Message bus (requires `retry.scheduled` and `manual-review.pending` queues)
- **PostgreSQL**: Persistent storage (requires `retry_queue` table)
- **Prometheus**: Metrics collection (scrapes `GET /metrics` on port 9094)
- **Jaeger**: Distributed tracing backend

---

## Performance Characteristics

**Throughput:**
- Target: 50 retries/second sustained
- Burst: 200 retries/second

**Latency:**
- Retry execution within 5 seconds of scheduled time (acceptable drift due to polling interval)

**Reliability:**
- No lost retry tasks (persistent in PostgreSQL)
- Survives service restarts (retries resume from database)

**Resource Usage:**
- Memory: ~512MB typical (burst to 1GB)
- CPU: ~0.5 cores sustained (burst to 2 cores)

---

## Failure Modes & Recovery

### RabbitMQ Connection Lost

**Symptom:** Consumer stops receiving messages, `GET /health` returns 503
**Recovery:** Automatic reconnection with exponential backoff (implemented in `src/consumer.ts`)

### PostgreSQL Connection Lost

**Symptom:** Cannot save retry tasks, `GET /health` returns 503
**Recovery:** Connection pool automatically retries failed queries

### Scheduler Overload

**Symptom:** `retry_queue_depth` metric grows unbounded
**Cause:** Retry poll interval (10s) is too slow for incoming rate
**Recovery:**
1. Decrease `RETRY_POLL_INTERVAL_MS` (e.g., to 5000)
2. Increase database pool size (`POSTGRES_POOL_MAX`)
3. Horizontally scale service instances (each polls independently)

### Max Retries Exhausted

**Symptom:** `retries_exhausted_total` metric increasing
**Cause:** Downstream service persistently failing (not transient)
**Recovery:**
1. Check `manual-review.pending` queue for failed messages
2. Investigate downstream service health
3. Consider increasing `DEFAULT_MAX_RETRIES` if appropriate

---

## Code Quality Standards

- **TypeScript strict mode** (no `any` types without explicit justification)
- **85%+ test coverage** (enforced by Jest)
- **All errors explicitly handled** (no swallowed exceptions)
- **Structured logging** (use `logger`, never `console.log`)
- **Prometheus metrics** for all critical operations
- **Prepared statements** for PostgreSQL (prevent SQL injection)

---

## Related Documentation

- **README.md**: Service specification and technical details
- **RUNBOOK.md**: Comprehensive operational guide (monitoring, troubleshooting, disaster recovery)
- **Parent CLAUDE.md**: Repository-wide architecture (e-invoice platform standards)
- **deployment/**: systemd unit files and deployment procedures
- **tests/**: Unit and integration tests demonstrating all functionality

---

**Last Updated:** 2025-11-12
**Service Version:** 1.0.0
