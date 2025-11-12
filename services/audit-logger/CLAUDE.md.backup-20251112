# CLAUDE.md - Audit Logger Service

**Service:** `audit-logger`
**Layer:** Infrastructure (Layer 9)
**Implementation Status:** 🔴 Not Started
**Your Mission:** Implement this service from specification to production-ready

---

## 1. YOUR MISSION

You are implementing the **audit-logger** service for the eRacun e-invoice processing platform. This service is **mission-critical** for Croatian regulatory compliance (11-year audit retention requirement).

**What you're building:**
- Immutable audit trail consumer (Kafka → PostgreSQL)
- Hash chain integrity verification (cryptographic linking)
- gRPC query API for audit trail retrieval
- Zero data loss tolerance (regulatory requirement)

**Estimated effort:** 3-4 days
**Complexity:** Medium (~1,500 LOC)

---

## 2. REQUIRED READING (Read in Order)

**Before writing any code, read these documents:**

1. **`README.md`** (in this directory) - Complete service specification
2. **`/CLAUDE.md`** (repository root) - System architecture and standards
3. **`/docs/TODO-008-cross-cutting-concerns.md`** - Observability requirements (MANDATORY)
4. **`/CROATIAN_COMPLIANCE.md`** - Regulatory requirements (audit retention: 11 years)
5. **`/services/xsd-validator/`** - Reference implementation pattern
6. **`/services/schematron-validator/`** - Reference observability module

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
                     │ Publish audit events
                     ▼
            ┌────────────────────┐
            │  Kafka Topic       │
            │  'audit-log'       │
            │  (5 partitions)    │
            └────────┬───────────┘
                     │
                     │ Consume
                     ▼
            ┌────────────────────┐
            │  THIS SERVICE      │
            │  audit-logger      │
            └────────┬───────────┘
                     │
                     │ Write (append-only)
                     ▼
            ┌────────────────────┐
            │  PostgreSQL        │
            │  audit_events      │
            │  (immutable)       │
            └────────────────────┘
                     │
                     │ Query via gRPC
                     ▼
            ┌────────────────────┐
            │  admin-portal-api  │
            │  (audit retrieval) │
            └────────────────────┘
```

### 3.2 Critical Dependencies

**Upstream (Consumes From):**
- Kafka topic: `audit-log` (ALL 40 services publish here)
- Consumer group: `audit-logger-group`

**Downstream (Produces To):**
- PostgreSQL table: `audit_events` (append-only, WORM)
- gRPC API: Query endpoints for audit trail retrieval

**External Systems:**
- Kafka brokers (3+ for HA)
- PostgreSQL database (managed or self-hosted)

### 3.3 Message Contract

**Consumed from Kafka:**
```protobuf
message AuditEvent {
  string event_id = 1;              // UUID v4
  string invoice_id = 2;            // Invoice being processed
  string service_name = 3;          // Producer (e.g., "xsd-validator")
  string event_type = 4;            // Event category (e.g., "VALIDATION_PASSED")
  int64 timestamp_ms = 5;           // Unix timestamp
  string request_id = 7;            // Trace ID
  map<string, string> metadata = 8; // Event-specific data
  string previous_hash = 9;         // Hash chain linking
  string event_hash = 10;           // SHA-256 of this event
}
```

**Provided via gRPC:**
- `GetAuditTrail(invoice_id)` → All events for invoice
- `QueryAuditEvents(filters)` → Filtered audit log
- `VerifyIntegrity(date_range)` → Hash chain verification

---

## 4. IMPLEMENTATION WORKFLOW

**Follow this sequence strictly:**

### Phase 1: Setup (Day 1, Morning)

1. **Create package.json**
   ```bash
   npm init -y
   npm install --save kafkajs pg prom-client pino opentelemetry crypto
   npm install --save-dev typescript @types/node jest @types/jest ts-jest
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
   ├── index.ts              # Main entry
   ├── consumer.ts           # Kafka consumer
   ├── writer.ts             # PostgreSQL writer
   ├── grpc-server.ts        # gRPC API
   ├── integrity.ts          # Hash verification
   └── observability.ts      # Metrics, logs, traces
   tests/
   ├── setup.ts
   ├── unit/
   └── integration/
   proto/
   └── audit.proto           # gRPC service definition
   ```

### Phase 2: Core Implementation (Day 1 Afternoon - Day 2)

1. **Implement observability.ts FIRST** (TODO-008 compliance)
   - Copy pattern from `/services/xsd-validator/src/observability.ts`
   - Define 6+ Prometheus metrics (see README.md Section 5.3)
   - Implement PII masking (OIB, IBAN - though audit logs store unmasked)
   - Structured logging (Pino)
   - Distributed tracing (OpenTelemetry, 100% sampling)

2. **Implement writer.ts** (PostgreSQL append-only)
   - Connection pool (min: 10, max: 50)
   - `writeAuditEvent()` - INSERT only (never UPDATE/DELETE)
   - `calculateEventHash()` - SHA-256 hash for integrity
   - `getLastEventHash()` - Retrieve previous hash for chaining
   - Metrics: Increment counters, record latency

3. **Implement consumer.ts** (Kafka consumer)
   - Connect to Kafka brokers
   - Subscribe to `audit-log` topic
   - Consumer group: `audit-logger-group`
   - Auto-offset-reset: `earliest` (never lose events)
   - On message: Parse → Write to PostgreSQL → Ack
   - Error handling: DO NOT commit offset if write fails

4. **Implement integrity.ts** (Hash chain verification)
   - `verifyIntegrity(start_time, end_time)`
   - Query events in time range
   - Verify each event's `previous_hash` matches previous event's `event_hash`
   - Return list of broken chains (if any)

5. **Implement grpc-server.ts** (Query API)
   - Define `.proto` file (see README.md Section 2.4)
   - Implement 3 RPC methods: GetAuditTrail, QueryAuditEvents, VerifyIntegrity
   - Authentication: JWT validation (optional for MVP)

6. **Implement index.ts** (Main entry point)
   - Start Kafka consumer
   - Start gRPC server
   - Start Prometheus metrics endpoint (port 9090)
   - Health check endpoint (HTTP, port 8080)
   - Graceful shutdown (SIGTERM, SIGINT)

### Phase 3: Testing (Day 3)

1. **Create test fixtures**
   - `tests/fixtures/sample-audit-events.json` (10 events)
   - Mock Kafka producer
   - Testcontainers for PostgreSQL

2. **Write unit tests** (70% of suite)
   - `writer.test.ts`: Hash calculation, event writing, metrics
   - `integrity.test.ts`: Hash chain verification (1000 events)
   - `observability.test.ts`: Metrics, logging (PII handling)
   - Target: 90%+ coverage for critical paths

3. **Write integration tests** (25% of suite)
   - `kafka-consumer.test.ts`: End-to-end (Kafka → PostgreSQL)
   - `grpc-api.test.ts`: All 3 RPC methods
   - `postgres-write.test.ts`: Concurrent writes, error handling

4. **Run tests**
   ```bash
   npm test -- --coverage
   ```
   - **MUST achieve 85%+ coverage** (enforced in jest.config.js)

### Phase 4: Documentation (Day 3-4)

1. **Create RUNBOOK.md** (operations guide)
   - Copy structure from `/services/schematron-validator/RUNBOOK.md`
   - Sections: Deployment, Monitoring, Common Issues, Troubleshooting, Disaster Recovery
   - Minimum 8 operational scenarios documented

2. **Create .env.example**
   - All environment variables documented
   - No default secrets (use placeholders)

3. **Create Dockerfile**
   - Multi-stage build (build → production)
   - Security: Run as non-root user, minimal base image

4. **Create systemd unit file** (`audit-logger.service`)
   - Security hardening: ProtectSystem=strict, NoNewPrivileges=true
   - Restart policy: always, RestartSec=10
   - Copy from `/services/xsd-validator/*.service`

5. **Create completion report**
   - File: `/docs/reports/{date}-audit-logger-completion.md`
   - Template: `/docs/reports/2025-11-11-schematron-validator-completion.md`
   - Sections: Executive Summary, Deliverables, Git Status, Traceability, Next Steps

### Phase 5: Commit & Push (Day 4)

1. **Commit all work**
   ```bash
   git add services/audit-logger/
   git commit -m "feat(audit-logger): implement immutable audit trail service"
   ```

2. **Push to branch**
   ```bash
   git push -u origin claude/audit-logger-{your-session-id}
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
- ✅ **Kafka TLS enabled** (in production)
- ✅ **systemd security hardening** (ProtectSystem=strict, etc.)

### 5.3 Observability (TODO-008 Compliance)

**MANDATORY - Your service MUST include:**

- ✅ **6+ Prometheus metrics**:
  - `audit_events_written_total` (Counter)
  - `audit_write_duration_seconds` (Histogram)
  - `audit_consumer_lag` (Gauge)
  - `audit_integrity_checks_total` (Counter)
  - `audit_db_connections` (Gauge)
  - `audit_grpc_requests_total` (Counter)

- ✅ **Structured JSON logging** (Pino):
  - Log level: DEBUG (development), INFO (production)
  - Fields: timestamp, service_name, request_id, message
  - PII handling: Audit logs DO NOT mask PII (regulatory requirement)

- ✅ **Distributed tracing** (OpenTelemetry):
  - 100% sampling (regulatory compliance)
  - Spans: kafka.consume, postgres.write, grpc.query
  - Trace ID propagated from Kafka message

- ✅ **Health endpoints**:
  - GET /health → { status: "healthy", uptime_seconds: 86400 }
  - GET /ready → { status: "ready", dependencies: {...} }
  - GET /metrics → Prometheus text format

### 5.4 Performance

- ✅ **Throughput:** 1,000 events/second sustained
- ✅ **Latency:** <50ms p95 for write
- ✅ **No data loss:** Every Kafka message written to PostgreSQL

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
- Skip test execution (must verify all tests pass)
- Hardcode secrets or credentials
- Allow UPDATE/DELETE on audit_events table (append-only only)
- Commit Kafka offset before PostgreSQL write (data loss risk)
- Mask PII in audit logs (defeats forensic purpose, regulatory violation)

✅ **DO:**
- Follow patterns from xsd-validator and schematron-validator
- Implement TODO-008 observability compliance
- Test PII handling thoroughly (even though audit logs don't mask)
- Document all operational scenarios in RUNBOOK
- Create comprehensive completion report

---

## 7. ACCEPTANCE CRITERIA

**Your service is COMPLETE when:**

### 7.1 Functional Requirements
- [ ] Consumes events from Kafka `audit-log` topic
- [ ] Writes to PostgreSQL `audit_events` table (INSERT-only)
- [ ] Enforces immutability (no UPDATE/DELETE possible)
- [ ] Implements hash chain integrity (previous_hash linking)
- [ ] Provides gRPC query API (3 methods working)
- [ ] Verifies hash chain integrity on demand
- [ ] Handles consumer lag gracefully (no data loss)

### 7.2 Non-Functional Requirements
- [ ] Throughput: 1,000 events/second sustained (load tested)
- [ ] Latency: <50ms p95 for write (benchmarked)
- [ ] Test coverage: 85%+ (jest report confirms)
- [ ] Observability: 6+ Prometheus metrics implemented
- [ ] Security: TLS/mTLS configured, systemd hardening applied
- [ ] Documentation: README.md + RUNBOOK.md complete

### 7.3 Deliverables
- [ ] All code in `src/` directory
- [ ] All tests in `tests/` directory (passing)
- [ ] `.env.example` (all variables documented)
- [ ] `Dockerfile` (multi-stage, secure)
- [ ] `audit-logger.service` (systemd unit with hardening)
- [ ] `RUNBOOK.md` (comprehensive operations guide)
- [ ] Completion report in `/docs/reports/`
- [ ] Committed and pushed to `claude/audit-logger-{session-id}` branch

---

## 8. HELP & REFERENCES

**If you get stuck:**

1. **Reference implementations:**
   - `/services/xsd-validator/` - First service (validation pattern)
   - `/services/schematron-validator/` - Second service (observability pattern)

2. **Specifications:**
   - `README.md` (this directory) - Your primary spec
   - `/docs/adr/003-system-decomposition-integration-architecture.md` - Service catalog

3. **Standards:**
   - `/CLAUDE.md` - System architecture
   - `/docs/TODO-008-cross-cutting-concerns.md` - Observability requirements
   - `/CROATIAN_COMPLIANCE.md` - Regulatory requirements

4. **Dependencies:**
   - This service has ZERO service dependencies (can implement immediately)
   - Only depends on Kafka and PostgreSQL (infrastructure)

---

## 9. SUCCESS METRICS

**You've succeeded when:**

✅ All tests pass (`npm test`)
✅ Coverage ≥85% (`npm run test:coverage`)
✅ Service starts without errors (`npm run dev`)
✅ Health endpoints respond correctly
✅ Kafka consumer processes events
✅ PostgreSQL audit trail written correctly
✅ gRPC API queries work
✅ Hash chain integrity verification passes
✅ RUNBOOK.md covers all operational scenarios
✅ Completion report written
✅ Code pushed to branch

---

## 10. TIMELINE CHECKPOINT

**Day 1 End:** Core implementation complete (consumer, writer, observability)
**Day 2 End:** gRPC API + integrity verification complete
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

**Good luck! 🚀**
