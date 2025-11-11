# CLAUDE.md - Retry Scheduler Service

**Service:** `retry-scheduler`
**Layer:** Infrastructure (Layer 9)
**Implementation Status:** 🔴 Not Started
**Your Mission:** Implement this service from specification to production-ready

---

## 1. YOUR MISSION

You are implementing the **retry-scheduler** service for the eRacun e-invoice processing platform. This service handles **automated retry of transient failures** with exponential backoff and jitter.

**What you're building:**
- RabbitMQ consumer (receives retry requests from dead-letter-handler)
- PostgreSQL persistent queue (schedules retries, survives restarts)
- Retry scheduler (polls for due retries, executes with exponential backoff)
- Message republisher (sends back to original queues after delay)

**Estimated effort:** 3 days
**Complexity:** Medium (~1,200 LOC)

---

## 2. REQUIRED READING (Read in Order)

**Before writing any code, read these documents:**

1. **`README.md`** (in this directory) - Complete service specification
2. **`/CLAUDE.md`** (repository root) - System architecture and standards
3. **`/docs/TODO-008-cross-cutting-concerns.md`** - Observability requirements (MANDATORY)
4. **`/services/xsd-validator/`** - Reference implementation pattern
5. **`/services/schematron-validator/`** - Reference observability module
6. **`/services/dead-letter-handler/README.md`** - Upstream service (sends retry requests)

**Time investment:** 30-40 minutes reading
**Why mandatory:** Prevents rework, ensures compliance, establishes patterns

---

## 3. ARCHITECTURAL CONTEXT

### 3.1 Where This Service Fits

```
            ┌────────────────────┐
            │  dead-letter-      │
            │  handler           │
            │  (classifies       │
            │   transient errors)│
            └────────┬───────────┘
                     │
                     │ Send retry request
                     ▼
            ┌────────────────────┐
            │  RabbitMQ Queue    │
            │  'retry.scheduled' │
            └────────┬───────────┘
                     │
                     │ Consume
                     ▼
            ┌────────────────────┐
            │  THIS SERVICE      │
            │  retry-scheduler   │
            └────────┬───────────┘
                     │
                     │ Store with delay
                     ▼
            ┌────────────────────┐
            │  PostgreSQL        │
            │  retry_queue       │
            │  (persistent)      │
            └────────┬───────────┘
                     │
                     │ Poll for due retries
                     │ (every 10 seconds)
                     ▼
            ┌────────────────────┐
            │  Retry Executor    │
            │  (exponential      │
            │   backoff + jitter)│
            └────────┬───────────┘
                     │
        ┌────────────┼────────────┐
        │                         │
        ▼                         ▼
  Retry < max           Retry >= max
  attempts              attempts
        │                         │
        │ Republish               │ Move to manual
        ▼                         ▼ review
  Original queue         manual-review.pending
  (e.g., validation.
   xsd.validate)
```

### 3.2 Critical Dependencies

**Upstream (Consumes From):**
- RabbitMQ queue: `retry.scheduled` (from dead-letter-handler)

**Downstream (Produces To):**
- Original service queues (republish after delay)
  - Examples: `validation.xsd.validate`, `transformation.ubl.transform`
- RabbitMQ queue: `manual-review.pending` (if max retries exceeded)

**PostgreSQL Table:**
- `retry_queue` (persistent retry task storage)

### 3.3 Message Contract

**Consumed Retry Request:**

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

**PostgreSQL Schema:**

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

## 4. IMPLEMENTATION WORKFLOW

**Follow this sequence strictly:**

### Phase 1: Setup (Day 1, Morning)

1. **Create package.json**
   ```bash
   npm init -y
   npm install --save pg amqplib prom-client pino opentelemetry uuid
   npm install --save-dev typescript @types/node @types/pg jest @types/jest ts-jest
   ```

2. **Create tsconfig.json** (strict mode)
   ```json
   {
     "compilerOptions": {
       "target": "ES2022",
       "module": "commonjs",
       "strict": true,
       "esModuleInterop": true,
       "outDir": "./dist"
     }
   }
   ```

3. **Create directory structure**
   ```
   src/
   ├── index.ts              # Main entry (RabbitMQ consumer + retry scheduler)
   ├── consumer.ts           # RabbitMQ consumer (retry.scheduled)
   ├── repository.ts         # PostgreSQL retry queue operations
   ├── scheduler.ts          # Retry scheduler (poll for due retries)
   ├── backoff.ts            # Exponential backoff + jitter calculation
   ├── publisher.ts          # Republish to original queues
   └── observability.ts      # Metrics, logs, traces (TODO-008)
   tests/
   ├── setup.ts
   ├── unit/
   │   ├── backoff.test.ts
   │   ├── scheduler.test.ts
   │   └── observability.test.ts
   └── integration/
       ├── retry-flow.test.ts
       └── repository.test.ts
   ```

### Phase 2: Core Implementation (Day 1 Afternoon - Day 2)

1. **Implement observability.ts FIRST** (TODO-008 compliance)
   - Copy pattern from `/services/xsd-validator/src/observability.ts`
   - Define 4+ Prometheus metrics (see README.md Section 7)
   - Structured logging (Pino)
   - Distributed tracing (OpenTelemetry)
   - No PII in retry messages (already sanitized)

2. **Implement backoff.ts** (Exponential backoff calculation)
   - `calculateNextRetryDelay(retryCount: number): number`
   - Algorithm:
     ```typescript
     const baseDelay = 2000; // 2 seconds
     const maxDelay = 60000; // 60 seconds (cap)
     const jitter = Math.random() * 1000; // 0-1s jitter

     const delay = Math.min(baseDelay * Math.pow(2, retryCount), maxDelay);
     return delay + jitter; // Prevent thundering herd
     ```
   - Retry schedule:
     - Attempt 1: ~2s
     - Attempt 2: ~4s
     - Attempt 3: ~8s
     - After 3 attempts → manual review

3. **Implement repository.ts** (PostgreSQL operations)
   - Connection pool (min: 10, max: 50)
   - `saveRetryTask(task: RetryTask): Promise<void>`
   - `getDueRetryTasks(): Promise<RetryTask[]>`
     - Query: `WHERE next_retry_at <= NOW() AND status = 'pending'`
   - `updateRetryTask(task: RetryTask): Promise<void>`
   - `markRetrySuccess(messageId: string): Promise<void>`
   - `markRetryFailed(messageId: string): Promise<void>`

4. **Implement publisher.ts** (RabbitMQ republisher)
   - `republishMessage(task: RetryTask): Promise<void>`
   - Publish to `task.original_queue`
   - Add retry headers: `x-retry-count`, `x-original-error`
   - `moveToManualReview(task: RetryTask): Promise<void>`
     - Publish to `manual-review.pending` queue

5. **Implement consumer.ts** (RabbitMQ consumer)
   - Connect to RabbitMQ
   - Consume from `retry.scheduled` queue
   - On message:
     ```typescript
     const retryMsg = parseRetryMessage(msg);
     const delay = calculateNextRetryDelay(retryMsg.retry_count);
     const nextRetryAt = new Date(Date.now() + delay);

     await saveRetryTask({
       ...retryMsg,
       next_retry_at: nextRetryAt
     });

     channel.ack(msg);
     ```

6. **Implement scheduler.ts** (Retry scheduler)
   - Poll for due retries every 10 seconds:
     ```typescript
     setInterval(async () => {
       const dueTasks = await getDueRetryTasks();

       for (const task of dueTasks) {
         if (task.retry_count >= task.max_retries) {
           // Max retries exceeded → manual review
           await moveToManualReview(task);
           await markRetryFailed(task.message_id);
         } else {
           // Republish to original queue
           await republishMessage(task);
           task.retry_count++;
           await updateRetryTask(task);
         }
       }
     }, 10000);
     ```

7. **Implement index.ts** (Main entry point)
   - Start RabbitMQ consumer
   - Start retry scheduler (polling loop)
   - Start Prometheus metrics endpoint (port 9094)
   - Health check endpoint (GET /health, GET /ready)
   - Graceful shutdown (SIGTERM, SIGINT)

### Phase 3: Testing (Day 2-3)

1. **Create test fixtures**
   - `tests/fixtures/retry-messages.json` (10 sample retry requests)
   - Testcontainers for PostgreSQL
   - Mock RabbitMQ (in-memory or Testcontainers)

2. **Write unit tests** (70% of suite)
   - `backoff.test.ts`: Exponential backoff + jitter (verify delays)
   - `scheduler.test.ts`: Retry execution logic (max retries, manual review)
   - `observability.test.ts`: Metrics, logging
   - Target: 90%+ coverage for critical paths

3. **Write integration tests** (25% of suite)
   - `retry-flow.test.ts`: End-to-end (consume → store → retry → republish)
   - `repository.test.ts`: PostgreSQL operations (concurrent writes)

4. **Run tests**
   ```bash
   npm test -- --coverage
   ```
   - **MUST achieve 85%+ coverage** (enforced in jest.config.js)

### Phase 4: Documentation (Day 3)

1. **Create RUNBOOK.md** (operations guide)
   - Copy structure from `/services/schematron-validator/RUNBOOK.md`
   - Sections: Deployment, Monitoring, Common Issues, Troubleshooting, Disaster Recovery
   - Scenarios:
     - Retry queue backlog
     - RabbitMQ connection lost
     - PostgreSQL connection lost
     - Max retries exceeded (manual review overflow)
   - Minimum 8 operational scenarios documented

2. **Create .env.example**
   - All environment variables documented
   - Include: DATABASE_URL, RABBITMQ_URL, DEFAULT_MAX_RETRIES, BASE_DELAY_MS

3. **Create Dockerfile**
   - Multi-stage build (build → production)
   - Security: Run as non-root user, minimal base image

4. **Create systemd unit file** (`retry-scheduler.service`)
   - Security hardening: ProtectSystem=strict, NoNewPrivileges=true
   - Restart policy: always, RestartSec=10
   - Copy from `/services/xsd-validator/*.service`

5. **Create completion report**
   - File: `/docs/reports/{date}-retry-scheduler-completion.md`
   - Template: `/docs/reports/2025-11-11-schematron-validator-completion.md`
   - Sections: Executive Summary, Deliverables, Git Status, Traceability, Next Steps

### Phase 5: Commit & Push (Day 3)

1. **Commit all work**
   ```bash
   git add services/retry-scheduler/
   git commit -m "feat(retry-scheduler): implement automated retry with exponential backoff"
   ```

2. **Push to branch**
   ```bash
   git push -u origin claude/retry-scheduler-{your-session-id}
   ```

---

## 5. QUALITY STANDARDS (Non-Negotiable)

### 5.1 Code Quality

- ✅ **TypeScript strict mode** (no `any` types)
- ✅ **ESLint + Prettier** compliant
- ✅ **85%+ test coverage** (enforced in jest.config.js)
- ✅ **All errors explicitly handled** (no swallowed exceptions)

### 5.2 Security

- ✅ **No secrets in code** (use environment variables)
- ✅ **PostgreSQL prepared statements** (prevent SQL injection)
- ✅ **RabbitMQ TLS enabled** (in production)
- ✅ **systemd security hardening** (ProtectSystem=strict, etc.)

### 5.3 Observability (TODO-008 Compliance)

**MANDATORY - Your service MUST include:**

- ✅ **4+ Prometheus metrics**:
  - `retries_scheduled_total` (Counter, labels: queue)
  - `retries_executed_total` (Counter, labels: queue, status)
  - `retries_exhausted_total` (Counter, labels: queue)
  - `retry_queue_depth` (Gauge)

- ✅ **Structured JSON logging** (Pino):
  - Log level: DEBUG (development), INFO (production)
  - Fields: timestamp, service_name, request_id, message
  - No PII in retry messages

- ✅ **Distributed tracing** (OpenTelemetry):
  - 100% sampling
  - Spans: rabbitmq.consume, postgres.write, retry.schedule, rabbitmq.publish
  - Trace ID propagated from retry request

- ✅ **Health endpoints**:
  - GET /health → { status: "healthy", uptime_seconds: 86400 }
  - GET /ready → { status: "ready", dependencies: {...} }
  - GET /metrics → Prometheus text format

### 5.4 Performance

- ✅ **Throughput:** 50 retries/second sustained
- ✅ **Latency:** Retry execution within 5 seconds of scheduled time
- ✅ **Reliability:** No lost retry tasks (persistent in PostgreSQL)

### 5.5 Testing

- ✅ **85%+ coverage** (jest.config.js threshold)
- ✅ **Unit tests:** 70% of suite
- ✅ **Integration tests:** 25% of suite
- ✅ **E2E tests:** 5% of suite (critical paths)
- ✅ **All tests pass** before committing

---

## 6. COMMON PITFALLS (Avoid These)

❌ **DON'T:**
- Use `.clear()` on Prometheus registry (use `.resetMetrics()` in tests)
- Skip exponential backoff (causes thundering herd)
- Skip jitter (all retries at same time)
- Allow infinite retries (max 3 attempts enforced)
- Lose retry tasks on restart (use PostgreSQL persistence)
- Ignore max retries exceeded (must move to manual review)

✅ **DO:**
- Follow patterns from xsd-validator and schematron-validator
- Implement TODO-008 observability compliance
- Test backoff calculation (verify delays are correct)
- Test max retries logic (ensure manual review routing)
- Document all operational scenarios in RUNBOOK
- Create comprehensive completion report

---

## 7. ACCEPTANCE CRITERIA

**Your service is COMPLETE when:**

### 7.1 Functional Requirements
- [ ] Consume retry messages from RabbitMQ
- [ ] Store retry tasks in PostgreSQL (persistent)
- [ ] Execute retries with exponential backoff + jitter
- [ ] Republish to original queues after delay
- [ ] Move to manual review after max retries
- [ ] Poll for due retries every 10 seconds
- [ ] Track retry counts and max retries

### 7.2 Non-Functional Requirements
- [ ] Throughput: 50 retries/second sustained (load tested)
- [ ] Latency: <5s drift from scheduled time (benchmarked)
- [ ] Test coverage: 85%+ (jest report confirms)
- [ ] Observability: 4+ Prometheus metrics implemented
- [ ] Security: systemd hardening applied
- [ ] Documentation: README.md + RUNBOOK.md complete

### 7.3 Deliverables
- [ ] All code in `src/` directory
- [ ] All tests in `tests/` directory (passing)
- [ ] `.env.example` (all variables documented)
- [ ] `Dockerfile` (multi-stage, secure)
- [ ] `retry-scheduler.service` (systemd unit with hardening)
- [ ] `RUNBOOK.md` (comprehensive operations guide)
- [ ] Completion report in `/docs/reports/`
- [ ] Committed and pushed to `claude/retry-scheduler-{session-id}` branch

---

## 8. HELP & REFERENCES

**If you get stuck:**

1. **Reference implementations:**
   - `/services/xsd-validator/` - First service (validation pattern)
   - `/services/schematron-validator/` - Second service (observability pattern)
   - `/services/audit-logger/` - PostgreSQL persistence pattern

2. **Specifications:**
   - `README.md` (this directory) - Your primary spec
   - `/services/dead-letter-handler/README.md` - Upstream service

3. **Standards:**
   - `/CLAUDE.md` - System architecture
   - `/docs/TODO-008-cross-cutting-concerns.md` - Observability requirements

4. **Dependencies:**
   - This service has ZERO service dependencies (can implement immediately)
   - Only depends on RabbitMQ and PostgreSQL (infrastructure)

---

## 9. SUCCESS METRICS

**You've succeeded when:**

✅ All tests pass (`npm test`)
✅ Coverage ≥85% (`npm run test:coverage`)
✅ Service starts without errors (`npm run dev`)
✅ Health endpoints respond correctly
✅ RabbitMQ consumer processes retry requests
✅ PostgreSQL retry queue stores tasks
✅ Retry scheduler polls and executes retries
✅ Exponential backoff + jitter works correctly
✅ Max retries → manual review routing works
✅ RUNBOOK.md covers all operational scenarios
✅ Completion report written
✅ Code pushed to branch

---

## 10. TIMELINE CHECKPOINT

**Day 1 End:** Core implementation complete (consumer, repository, backoff, observability)
**Day 2 End:** Scheduler + publisher complete
**Day 3 End:** All tests written and passing (85%+ coverage), documentation complete, code committed & pushed

**If you're behind schedule:**
- Prioritize functional requirements over nice-to-haves
- Ensure observability compliance (non-negotiable)
- Ask for help if blocked >2 hours

---

**Status:** 🔴 Ready for Implementation
**Last Updated:** 2025-11-11
**Assigned To:** [Your AI Instance]
**Session ID:** [Your Session ID]

---

## FINAL REMINDER

**Read the specification (`README.md`) thoroughly before writing code.**

This CLAUDE.md provides workflow and context. The README.md provides technical details. Together, they contain everything you need to implement this service to production standards.

**Good luck!**
