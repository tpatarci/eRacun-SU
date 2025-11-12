# CLAUDE.md - Dead Letter Handler Service

**Service:** `dead-letter-handler`
**Layer:** Infrastructure (Layer 9)
**Implementation Status:** 🔴 Not Started
**Your Mission:** Implement this service from specification to production-ready

---

## 1. YOUR MISSION

You are implementing the **dead-letter-handler** service for the eRacun e-invoice processing platform. This service is the **centralized error recovery mechanism** for all 40 bounded contexts.

**What you're building:**
- DLQ monitor (consumes from all service dead letter queues)
- Error classifier (transient vs. business vs. technical vs. unknown)
- Routing engine (retry-scheduler, manual-review, notifications)
- HTTP API for manual error resolution (admin portal integration)

**Estimated effort:** 3-4 days
**Complexity:** Medium (~1,800 LOC)

---

## 2. REQUIRED READING (Read in Order)

**Before writing any code, read these documents:**

1. **`README.md`** (in this directory) - Complete service specification
2. **`/CLAUDE.md`** (repository root) - System architecture and standards
3. **`/docs/TODO-008-cross-cutting-concerns.md`** - Observability requirements (MANDATORY)
4. **`/services/xsd-validator/`** - Reference implementation pattern
5. **`/services/schematron-validator/`** - Reference observability module
6. **`/services/audit-logger/`** - Message consumer pattern (Kafka)

**Time investment:** 30-45 minutes reading
**Why mandatory:** Prevents rework, ensures compliance, establishes patterns

---

## 3. ARCHITECTURAL CONTEXT

### 3.1 Where This Service Fits

```
┌─────────────────────────────────────────────────────────────┐
│ ALL 40 SERVICES                                             │
│ (xsd-validator, schematron-validator, fina-connector, ...) │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ Messages fail processing
                     ▼
            ┌────────────────────┐
            │  RabbitMQ DLX      │
            │  'dlx' exchange    │
            │  (40 DLQs total)   │
            └────────┬───────────┘
                     │
                     │ Consume
                     ▼
            ┌────────────────────┐
            │  THIS SERVICE      │
            │  dead-letter-      │
            │  handler           │
            └────────┬───────────┘
                     │
                     │ Classify error
            ┌────────┼────────┬──────────┐
            │        │        │          │
            ▼        ▼        ▼          ▼
      Transient  Business Technical Unknown
            │        │        │          │
            ▼        └────────┴──────────┘
     retry-scheduler    manual-review
                            +
                    notification-service
```

### 3.2 Critical Dependencies

**Upstream (Consumes From):**
- RabbitMQ DLX (Dead Letter Exchange): `dlx`
- Pattern: `*.dlq` (all service DLQs)
- Examples:
  - `validation.xsd.validate.dlq`
  - `validation.schematron.validate.dlq`
  - `transformation.ubl.transform.dlq`

**Downstream (Produces To):**
- RabbitMQ queues:
  - `retry.scheduled` (transient errors)
  - `manual-review.pending` (business/technical/unknown errors)
- Kafka topics:
  - `error-events` (error classification analytics)
- HTTP APIs:
  - `notification-service` - POST `/notifications` (critical alerts)

**PostgreSQL Tables:**
- `manual_review_errors` (tracking manual review queue)

### 3.3 Message Contract

**Consumed DLQ Message Format** (RabbitMQ standard):

```typescript
interface DLQMessage {
  original_message: Buffer;      // Original payload
  original_routing_key: string;  // Destination routing key
  original_queue: string;        // Source queue
  error: {
    reason: string;              // Error message
    exception: string;           // Stack trace
    timestamp: number;           // Failure time
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
  };
}
```

**Published Message Schemas:**

```protobuf
// To retry-scheduler
message RetryMessage {
  string message_id = 1;
  bytes original_payload = 2;
  string original_queue = 3;
  string error_reason = 4;
  int32 retry_count = 5;
  int32 max_retries = 6;
  int64 next_retry_at_ms = 7;
  ErrorClassification classification = 8;
}

// To Kafka error-events
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

enum ErrorClassification {
  TRANSIENT = 0;    // Network, timeout, resource exhaustion
  BUSINESS = 1;     // Validation failure, business rule violation
  TECHNICAL = 2;    // Programming error, null pointer
  UNKNOWN = 3;      // Cannot classify
}
```

---

## 4. IMPLEMENTATION WORKFLOW

**Follow this sequence strictly:**

### Phase 1: Setup (Day 1, Morning)

1. **Create package.json**
   ```bash
   npm init -y
   npm install --save amqplib kafkajs pg axios prom-client pino opentelemetry uuid
   npm install --save-dev typescript @types/node @types/amqplib jest @types/jest ts-jest
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
   ├── index.ts              # Main entry (RabbitMQ consumer + HTTP API)
   ├── consumer.ts           # DLQ consumer
   ├── classifier.ts         # Error classification algorithm
   ├── router.ts             # Route to retry/manual-review/notification
   ├── api.ts                # HTTP REST API for admin portal
   ├── repository.ts         # PostgreSQL persistence (manual review)
   └── observability.ts      # Metrics, logs, traces (TODO-008)
   tests/
   ├── setup.ts
   ├── unit/
   │   ├── classifier.test.ts
   │   ├── router.test.ts
   │   └── observability.test.ts
   └── integration/
       ├── dlq-consumer.test.ts
       ├── retry-routing.test.ts
       └── api.test.ts
   ```

### Phase 2: Core Implementation (Day 1 Afternoon - Day 2)

1. **Implement observability.ts FIRST** (TODO-008 compliance)
   - Copy pattern from `/services/xsd-validator/src/observability.ts`
   - Define 6+ Prometheus metrics (see README.md Section 6.3)
   - Structured logging (Pino)
   - Distributed tracing (OpenTelemetry, 100% sampling)
   - PII masking (OIB, IBAN in error messages)

2. **Implement classifier.ts** (Error classification logic)
   - `classifyError(dlqMessage: DLQMessage): ErrorClassification`
   - Transient detection: timeouts, network errors, rate limits
   - Business detection: validation failures, Schematron violations
   - Technical detection: null pointers, type errors
   - Unknown fallback (cannot classify)
   - See README.md Section 4 for classification rules

3. **Implement repository.ts** (PostgreSQL for manual review)
   - Connection pool (min: 10, max: 50)
   - `saveToManualReview(dlqMessage, classification)`
   - `getManualReviewErrors(filters)`
   - `resolveError(errorId, resolvedBy)`
   - `resubmitError(errorId)`
   - Schema: See README.md Section 3.2

4. **Implement router.ts** (Routing logic)
   - `routeError(dlqMessage, classification)`
   - Transient → `publishToRetryQueue()`
   - Business/Technical/Unknown → `saveToManualReview()` + `notifyCriticalError()`
   - `publishErrorEvent()` to Kafka
   - Metrics: Track routing decisions

5. **Implement consumer.ts** (RabbitMQ DLQ consumer)
   - Connect to RabbitMQ
   - Bind to `dlx` exchange (pattern: `*.dlq`)
   - On message: Parse → Classify → Route → Ack
   - Error handling: Nack on routing failure (retry)

6. **Implement api.ts** (HTTP REST API)
   - Express server (port 8081)
   - Authentication: JWT validation (middleware)
   - Endpoints:
     - GET `/api/v1/errors` - List manual review errors
     - GET `/api/v1/errors/:id` - Get error details
     - POST `/api/v1/errors/:id/resolve` - Mark resolved
     - POST `/api/v1/errors/:id/resubmit` - Resubmit to original queue
     - GET `/api/v1/errors/stats` - Error statistics

7. **Implement index.ts** (Main entry point)
   - Start RabbitMQ consumer
   - Start HTTP API server
   - Start Prometheus metrics endpoint (port 9091)
   - Health check endpoint (GET /health, GET /ready)
   - Graceful shutdown (SIGTERM, SIGINT)

### Phase 3: Testing (Day 3)

1. **Create test fixtures**
   - `tests/fixtures/dlq-messages.json` (10 sample DLQ messages)
   - Mock RabbitMQ producer (Testcontainers or in-memory)
   - Testcontainers for PostgreSQL

2. **Write unit tests** (70% of suite)
   - `classifier.test.ts`: All 4 classification types (100+ test cases)
   - `router.test.ts`: Routing logic for each classification
   - `observability.test.ts`: Metrics, logging (PII masking)
   - Target: 90%+ coverage for critical paths

3. **Write integration tests** (25% of suite)
   - `dlq-consumer.test.ts`: End-to-end (RabbitMQ DLQ → classification → routing)
   - `retry-routing.test.ts`: Verify transient errors go to retry-scheduler
   - `api.test.ts`: All HTTP endpoints (resolve, resubmit)

4. **Run tests**
   ```bash
   npm test -- --coverage
   ```
   - **MUST achieve 85%+ coverage** (enforced in jest.config.js)

### Phase 4: Documentation (Day 3-4)

1. **Create RUNBOOK.md** (operations guide)
   - Copy structure from `/services/schematron-validator/RUNBOOK.md`
   - Sections: Deployment, Monitoring, Common Issues, Troubleshooting, Disaster Recovery
   - Scenarios:
     - RabbitMQ connection lost
     - Retry-scheduler queue full
     - Notification service down
     - Manual review queue overflow
   - Minimum 8 operational scenarios documented

2. **Create .env.example**
   - All environment variables documented
   - No default secrets (use placeholders)
   - Include: RABBITMQ_URL, KAFKA_BROKERS, DATABASE_URL, NOTIFICATION_SERVICE_URL

3. **Create Dockerfile**
   - Multi-stage build (build → production)
   - Security: Run as non-root user, minimal base image (alpine)

4. **Create systemd unit file** (`dead-letter-handler.service`)
   - Security hardening: ProtectSystem=strict, NoNewPrivileges=true
   - Restart policy: always, RestartSec=10
   - Copy from `/services/xsd-validator/*.service`

5. **Create completion report**
   - File: `/docs/reports/{date}-dead-letter-handler-completion.md`
   - Template: `/docs/reports/2025-11-11-schematron-validator-completion.md`
   - Sections: Executive Summary, Deliverables, Git Status, Traceability, Next Steps

### Phase 5: Commit & Push (Day 4)

1. **Commit all work**
   ```bash
   git add services/dead-letter-handler/
   git commit -m "feat(dead-letter-handler): implement centralized error recovery service"
   ```

2. **Push to branch**
   ```bash
   git push -u origin claude/dead-letter-handler-{your-session-id}
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
- ✅ **JWT validation** for HTTP API (admin portal integration)
- ✅ **systemd security hardening** (ProtectSystem=strict, etc.)

### 5.3 Observability (TODO-008 Compliance)

**MANDATORY - Your service MUST include:**

- ✅ **6+ Prometheus metrics**:
  - `dlq_messages_processed_total` (Counter, labels: classification, service)
  - `dlq_classification_total` (Counter, labels: classification)
  - `dlq_retries_scheduled_total` (Counter, labels: service)
  - `dlq_manual_review_pending` (Gauge)
  - `dlq_processing_duration_seconds` (Histogram)
  - `dlq_notifications_sent_total` (Counter, labels: severity)

- ✅ **Structured JSON logging** (Pino):
  - Log level: DEBUG (development), INFO (production)
  - Fields: timestamp, service_name, request_id, message
  - PII handling: Mask OIB, IBAN in error messages

- ✅ **Distributed tracing** (OpenTelemetry):
  - 100% sampling (regulatory compliance)
  - Spans: rabbitmq.consume, classify, route, postgres.write
  - Trace ID propagated from RabbitMQ message headers

- ✅ **Health endpoints**:
  - GET /health → { status: "healthy", uptime_seconds: 86400 }
  - GET /ready → { status: "ready", dependencies: {...} }
  - GET /metrics → Prometheus text format

### 5.4 Performance

- ✅ **Throughput:** 100 DLQ messages/second sustained
- ✅ **Latency:** <100ms p95 for classification
- ✅ **No data loss:** Every DLQ message tracked in PostgreSQL or routed

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
- Skip error classification (always classify, use UNKNOWN if uncertain)
- Hardcode secrets or credentials
- Ignore DLQ messages (every message must be processed)
- Allow infinite retries (max 3 attempts, then manual review)
- Classify incorrectly (test classification logic thoroughly)

✅ **DO:**
- Follow patterns from xsd-validator and schematron-validator
- Implement TODO-008 observability compliance
- Test all 4 classification types (transient, business, technical, unknown)
- Document classification rules in RUNBOOK
- Create comprehensive completion report
- Handle RabbitMQ connection failures gracefully

---

## 7. ACCEPTANCE CRITERIA

**Your service is COMPLETE when:**

### 7.1 Functional Requirements
- [ ] Consumes from all DLQs (via `dlx` exchange)
- [ ] Classifies errors (4 types: transient, business, technical, unknown)
- [ ] Routes transient errors to retry-scheduler
- [ ] Routes business/technical/unknown errors to manual review
- [ ] Publishes error events to Kafka
- [ ] Sends notifications for critical errors
- [ ] HTTP API (4 endpoints: list, get, resolve, resubmit)

### 7.2 Non-Functional Requirements
- [ ] Throughput: 100 messages/second sustained (load tested)
- [ ] Latency: <100ms p95 for classification (benchmarked)
- [ ] Test coverage: 85%+ (jest report confirms)
- [ ] Observability: 6+ Prometheus metrics implemented
- [ ] Security: JWT validation, systemd hardening applied
- [ ] Documentation: README.md + RUNBOOK.md complete

### 7.3 Deliverables
- [ ] All code in `src/` directory
- [ ] All tests in `tests/` directory (passing)
- [ ] `.env.example` (all variables documented)
- [ ] `Dockerfile` (multi-stage, secure)
- [ ] `dead-letter-handler.service` (systemd unit with hardening)
- [ ] `RUNBOOK.md` (comprehensive operations guide)
- [ ] Completion report in `/docs/reports/`
- [ ] Committed and pushed to `claude/dead-letter-handler-{session-id}` branch

---

## 8. HELP & REFERENCES

**If you get stuck:**

1. **Reference implementations:**
   - `/services/xsd-validator/` - First service (validation pattern)
   - `/services/schematron-validator/` - Second service (observability pattern)
   - `/services/audit-logger/` - Kafka consumer pattern

2. **Specifications:**
   - `README.md` (this directory) - Your primary spec
   - `/docs/adr/003-system-decomposition-integration-architecture.md` - Service catalog

3. **Standards:**
   - `/CLAUDE.md` - System architecture
   - `/docs/TODO-008-cross-cutting-concerns.md` - Observability requirements

4. **Dependencies:**
   - This service has ZERO service dependencies (can implement immediately)
   - Only depends on RabbitMQ, Kafka, PostgreSQL (infrastructure)

---

## 9. SUCCESS METRICS

**You've succeeded when:**

✅ All tests pass (`npm test`)
✅ Coverage ≥85% (`npm run test:coverage`)
✅ Service starts without errors (`npm run dev`)
✅ Health endpoints respond correctly
✅ RabbitMQ DLQ consumer processes messages
✅ Error classification works for all 4 types
✅ Routing logic sends to correct destinations
✅ HTTP API endpoints work (list/resolve/resubmit)
✅ RUNBOOK.md covers all operational scenarios
✅ Completion report written
✅ Code pushed to branch

---

## 10. TIMELINE CHECKPOINT

**Day 1 End:** Core implementation complete (consumer, classifier, router, observability)
**Day 2 End:** PostgreSQL repository + HTTP API complete
**Day 3 End:** All tests written and passing (85%+ coverage)
**Day 4 End:** Documentation complete, code committed & pushed

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
