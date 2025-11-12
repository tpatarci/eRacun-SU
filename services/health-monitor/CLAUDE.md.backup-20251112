# CLAUDE.md - Health Monitor Service

**Service:** `health-monitor`
**Layer:** Infrastructure (Layer 9)
**Implementation Status:** 🔴 Not Started
**Your Mission:** Implement this service from specification to production-ready

---

## 1. YOUR MISSION

You are implementing the **health-monitor** service for the eRacun e-invoice processing platform. This service provides **system-wide health visibility** across all 40 bounded contexts and external dependencies.

**What you're building:**
- Active health checker (polls all service `/health` endpoints)
- External dependency monitor (RabbitMQ, PostgreSQL, Kafka, FINA API)
- Circuit breaker state tracker (monitors all circuit breakers)
- Health dashboard API (provides data for admin portal)

**Estimated effort:** 3-4 days
**Complexity:** Medium (~1,400 LOC)

---

## 2. REQUIRED READING (Read in Order)

**Before writing any code, read these documents:**

1. **`README.md`** (in this directory) - Complete service specification
2. **`/CLAUDE.md`** (repository root) - System architecture and standards
3. **`/docs/TODO-008-cross-cutting-concerns.md`** - Observability requirements (MANDATORY)
4. **`/services/xsd-validator/`** - Reference implementation pattern
5. **`/services/schematron-validator/`** - Reference observability module
6. **`/docs/adr/003-system-decomposition-integration-architecture.md`** - All 40 services catalog

**Time investment:** 30-45 minutes reading
**Why mandatory:** Prevents rework, ensures compliance, establishes patterns

---

## 3. ARCHITECTURAL CONTEXT

### 3.1 Where This Service Fits

```
                     ┌────────────────────┐
                     │  THIS SERVICE      │
                     │  health-monitor    │
                     └────────┬───────────┘
                              │
                              │ Poll health endpoints (HTTP GET)
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Layer 1-8     │    │ External Deps │    │ Circuit       │
│ 40 Services   │    │ (RabbitMQ,    │    │ Breakers      │
│ /health       │    │  PostgreSQL,  │    │ (all services)│
│ /ready        │    │  Kafka, FINA) │    └───────────────┘
└───────┬───────┘    └───────┬───────┘
        │                     │
        └─────────┬───────────┘
                  │
                  │ Health status changes
                  ▼
        ┌────────────────────┐
        │  Kafka Topic       │
        │  'system-health'   │
        └────────┬───────────┘
                  │
                  │ Consume
                  ▼
        ┌────────────────────┐
        │  notification-     │
        │  service           │
        │  (critical alerts) │
        └────────────────────┘
                  │
                  │ Query health data
                  ▼
        ┌────────────────────┐
        │  admin-portal-api  │
        │  (dashboard)       │
        └────────────────────┘
```

### 3.2 Critical Dependencies

**Upstream (Polls):**
- ALL 40 services: GET `http://{service}:port/health`
- ALL 40 services: GET `http://{service}:port/ready`
- RabbitMQ: GET `http://rabbitmq:15672/api/healthchecks/node`
- PostgreSQL: `SELECT 1` query
- Kafka: Broker metadata request
- FINA API: `https://cistest.apis-it.hr:8449/health` (if available)

**Downstream (Produces To):**
- Kafka topic: `system-health` (health status change events)
- HTTP API: Health dashboard data (for admin-portal-api)
- notification-service: POST `/notifications` (critical alerts)

**No RabbitMQ queues** (pull-based HTTP polling, not message-driven)

### 3.3 Health Check Response Schema

**Expected from each service:**

```json
{
  "status": "healthy" | "degraded" | "unhealthy",
  "checks": {
    "database": { "status": "healthy", "latency_ms": 5 },
    "message_queue": { "status": "healthy", "latency_ms": 3 },
    "circuit_breaker": { "status": "closed", "failure_rate": 0.01 }
  },
  "uptime_seconds": 86400,
  "version": "1.0.0"
}
```

**Published Health Event Schema:**

```protobuf
message HealthStatusEvent {
  string service_name = 1;
  HealthStatus status = 2;           // healthy, degraded, unhealthy
  int64 timestamp_ms = 3;
  string reason = 4;                 // Why status changed
  map<string, string> metadata = 5;  // Additional context
}

enum HealthStatus {
  HEALTHY = 0;
  DEGRADED = 1;
  UNHEALTHY = 2;
}
```

---

## 4. IMPLEMENTATION WORKFLOW

**Follow this sequence strictly:**

### Phase 1: Setup (Day 1, Morning)

1. **Create package.json**
   ```bash
   npm init -y
   npm install --save axios pg kafkajs amqplib prom-client pino opentelemetry express
   npm install --save-dev typescript @types/node @types/express jest @types/jest ts-jest
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
   ├── index.ts              # Main entry (health checker + HTTP API)
   ├── health-checker.ts     # Core health checking logic
   ├── service-registry.ts   # Load service list (from config or discovery)
   ├── external-deps.ts      # External dependency checks (RabbitMQ, PostgreSQL, Kafka)
   ├── circuit-breaker.ts    # Circuit breaker state monitoring
   ├── api.ts                # HTTP REST API (dashboard endpoints)
   ├── alerting.ts           # Notification logic (critical alerts)
   └── observability.ts      # Metrics, logs, traces (TODO-008)
   tests/
   ├── setup.ts
   ├── unit/
   │   ├── health-checker.test.ts
   │   ├── circuit-breaker.test.ts
   │   └── observability.test.ts
   └── integration/
       ├── service-polling.test.ts
       ├── external-deps.test.ts
       └── api.test.ts
   config/
   └── services.json         # Service registry (all 40 services)
   ```

### Phase 2: Core Implementation (Day 1 Afternoon - Day 2)

1. **Implement observability.ts FIRST** (TODO-008 compliance)
   - Copy pattern from `/services/xsd-validator/src/observability.ts`
   - Define 5+ Prometheus metrics (see README.md Section 7)
   - Structured logging (Pino)
   - Distributed tracing (OpenTelemetry)
   - No PII in this service (health data only)

2. **Implement service-registry.ts** (Service discovery)
   - Load service list from `config/services.json` or Consul
   - Service definition:
     ```typescript
     interface Service {
       name: string;
       health_url: string;      // e.g., "http://xsd-validator:8088/health"
       ready_url: string;       // e.g., "http://xsd-validator:8088/ready"
       critical: boolean;       // If true, P0 alert on failure
       poll_interval_ms: number; // 15000 (critical), 30000 (standard)
     }
     ```
   - `getAllServices(): Service[]`
   - `getCriticalServices(): Service[]`

3. **Implement health-checker.ts** (Core health checking)
   - `checkServiceHealth(service: Service): HealthCheckResult`
   - HTTP GET with 5-second timeout
   - Parse response, extract status
   - Retry logic: 3 consecutive failures → mark UNHEALTHY
   - 2 consecutive successes → mark HEALTHY
   - `calculateServiceHealth(checks): HealthStatus` (see README.md Section 3.2)

4. **Implement external-deps.ts** (External dependency checks)
   - `checkRabbitMQ(): HealthCheckResult`
     - HTTP GET to RabbitMQ management API
     - Check: node status, queue depths, connection counts
   - `checkPostgreSQL(): HealthCheckResult`
     - `SELECT 1` query with 2-second timeout
   - `checkKafka(): HealthCheckResult`
     - Broker metadata request
   - `checkFinaAPI(): HealthCheckResult` (optional)
     - Ping FINA test endpoint (if available)

5. **Implement circuit-breaker.ts** (Circuit breaker monitoring)
   - Parse circuit breaker state from service health responses
   - Track state changes (CLOSED → OPEN → HALF_OPEN)
   - Alert when circuit opens (P1 alert)
   - Alert when circuit stays open >5 minutes (P0 alert)

6. **Implement alerting.ts** (Notification logic)
   - `sendCriticalAlert(service, status, reason)`
   - POST to notification-service
   - Alert levels:
     - UNHEALTHY critical service → P0 (page immediately)
     - DEGRADED critical service → P1 (page in 15min)
     - Circuit breaker open >5min → P0
   - Publish health events to Kafka `system-health` topic

7. **Implement api.ts** (HTTP REST API)
   - Express server (port 8084)
   - Endpoints:
     - GET `/health/dashboard` - All services health status
     - GET `/health/services/:name` - Specific service details
     - GET `/health/external` - External dependency health
     - GET `/health/circuit-breakers` - All circuit breaker states
     - GET `/health/history/:service` - Historical health (last 24h)
   - CORS: Allow admin-portal frontend

8. **Implement index.ts** (Main entry point)
   - Start health checker (scheduled polling)
   - Start HTTP API server
   - Start Prometheus metrics endpoint (port 9092)
   - Health check endpoint (GET /health, GET /ready)
   - Graceful shutdown (SIGTERM, SIGINT)

### Phase 3: Testing (Day 3)

1. **Create test fixtures**
   - `tests/fixtures/service-health-responses.json` (mock responses)
   - Mock HTTP server (nock or similar)
   - Mock Kafka producer

2. **Write unit tests** (70% of suite)
   - `health-checker.test.ts`: Status calculation, retry logic
   - `circuit-breaker.test.ts`: State tracking, alert triggers
   - `observability.test.ts`: Metrics, logging
   - Target: 90%+ coverage for critical paths

3. **Write integration tests** (25% of suite)
   - `service-polling.test.ts`: Poll all services, aggregate status
   - `external-deps.test.ts`: Check RabbitMQ, PostgreSQL, Kafka
   - `api.test.ts`: All 5 HTTP endpoints

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
     - Health monitor service down (external monitoring required)
     - Many services unhealthy (system-wide outage)
     - False positive health check failures
     - RabbitMQ/PostgreSQL/Kafka unavailable
   - Minimum 8 operational scenarios documented

2. **Create config/services.json** (Service registry)
   - List all 40 services with health endpoints
   - Example:
     ```json
     {
       "services": [
         {
           "name": "xsd-validator",
           "health_url": "http://xsd-validator:8088/health",
           "ready_url": "http://xsd-validator:8088/ready",
           "critical": true,
           "poll_interval_ms": 15000
         },
         ...
       ]
     }
     ```

3. **Create .env.example**
   - All environment variables documented
   - Include: SERVICE_REGISTRY_URL, KAFKA_BROKERS, NOTIFICATION_SERVICE_URL

4. **Create Dockerfile**
   - Multi-stage build (build → production)
   - Security: Run as non-root user, minimal base image

5. **Create systemd unit file** (`health-monitor.service`)
   - Security hardening: ProtectSystem=strict, NoNewPrivileges=true
   - Restart policy: always, RestartSec=10
   - Copy from `/services/xsd-validator/*.service`

6. **Create completion report**
   - File: `/docs/reports/{date}-health-monitor-completion.md`
   - Template: `/docs/reports/2025-11-11-schematron-validator-completion.md`
   - Sections: Executive Summary, Deliverables, Git Status, Traceability, Next Steps

### Phase 5: Commit & Push (Day 4)

1. **Commit all work**
   ```bash
   git add services/health-monitor/
   git commit -m "feat(health-monitor): implement system-wide health monitoring service"
   ```

2. **Push to branch**
   ```bash
   git push -u origin claude/health-monitor-{your-session-id}
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
- ✅ **HTTP timeouts enforced** (prevent hanging requests)
- ✅ **TLS verification** (don't disable SSL checks)
- ✅ **systemd security hardening** (ProtectSystem=strict, etc.)

### 5.3 Observability (TODO-008 Compliance)

**MANDATORY - Your service MUST include:**

- ✅ **5+ Prometheus metrics**:
  - `service_health_status` (Gauge, labels: service) - 1=healthy, 0.5=degraded, 0=unhealthy
  - `health_check_success_total` (Counter, labels: service)
  - `health_check_failures_total` (Counter, labels: service, reason)
  - `circuit_breaker_state` (Gauge, labels: service, breaker) - 0=closed, 1=open, 0.5=half-open
  - `health_check_duration_seconds` (Histogram, labels: service)

- ✅ **Structured JSON logging** (Pino):
  - Log level: DEBUG (development), INFO (production)
  - Fields: timestamp, service_name, request_id, message
  - No PII in this service (health data only)

- ✅ **Distributed tracing** (OpenTelemetry):
  - 100% sampling
  - Spans: health_check, external_dep_check, circuit_breaker_check
  - Trace ID for each polling cycle

- ✅ **Health endpoints**:
  - GET /health → { status: "healthy", uptime_seconds: 86400 }
  - GET /ready → { status: "ready", dependencies: {...} }
  - GET /metrics → Prometheus text format

### 5.4 Performance

- ✅ **Polling overhead:** <1.5 requests/second (40 services × 30s intervals)
- ✅ **Health check latency:** <100ms per service
- ✅ **Dashboard response:** <500ms (aggregate all service health)
- ✅ **Alerting latency:** <10 seconds from status change to notification sent

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
- Poll too frequently (respect service capacity)
- Disable TLS verification (security risk)
- Ignore health check timeouts (causes hanging threads)
- Treat all services equally (mark critical services explicitly)
- Skip external dependency checks (RabbitMQ/PostgreSQL/Kafka critical)

✅ **DO:**
- Follow patterns from xsd-validator and schematron-validator
- Implement TODO-008 observability compliance
- Test false positive scenarios (3 failures required before UNHEALTHY)
- Document all operational scenarios in RUNBOOK
- Create comprehensive completion report
- Handle network failures gracefully (retry with backoff)

---

## 7. ACCEPTANCE CRITERIA

**Your service is COMPLETE when:**

### 7.1 Functional Requirements
- [ ] Polls all 40 service health endpoints
- [ ] Checks external dependency health (RabbitMQ, PostgreSQL, Kafka)
- [ ] Monitors circuit breaker states
- [ ] Publishes health events to Kafka
- [ ] Sends notifications for critical health changes
- [ ] HTTP API for dashboard data (5 endpoints)
- [ ] Retry logic (3 consecutive failures → UNHEALTHY)
- [ ] Health status calculation (healthy/degraded/unhealthy)

### 7.2 Non-Functional Requirements
- [ ] Polling overhead: <1.5 requests/second (verified)
- [ ] Health check latency: <100ms per service (benchmarked)
- [ ] Dashboard response: <500ms (load tested)
- [ ] Test coverage: 85%+ (jest report confirms)
- [ ] Observability: 5+ Prometheus metrics implemented
- [ ] Security: TLS verification, systemd hardening applied
- [ ] Documentation: README.md + RUNBOOK.md complete

### 7.3 Deliverables
- [ ] All code in `src/` directory
- [ ] All tests in `tests/` directory (passing)
- [ ] `config/services.json` (all 40 services listed)
- [ ] `.env.example` (all variables documented)
- [ ] `Dockerfile` (multi-stage, secure)
- [ ] `health-monitor.service` (systemd unit with hardening)
- [ ] `RUNBOOK.md` (comprehensive operations guide)
- [ ] Completion report in `/docs/reports/`
- [ ] Committed and pushed to `claude/health-monitor-{session-id}` branch

---

## 8. HELP & REFERENCES

**If you get stuck:**

1. **Reference implementations:**
   - `/services/xsd-validator/` - First service (validation pattern)
   - `/services/schematron-validator/` - Second service (observability pattern)

2. **Specifications:**
   - `README.md` (this directory) - Your primary spec
   - `/docs/adr/003-system-decomposition-integration-architecture.md` - All 40 services

3. **Standards:**
   - `/CLAUDE.md` - System architecture
   - `/docs/TODO-008-cross-cutting-concerns.md` - Observability requirements

4. **Dependencies:**
   - This service has ZERO service dependencies (can implement immediately)
   - Only polls HTTP endpoints (no message queues required)

---

## 9. SUCCESS METRICS

**You've succeeded when:**

✅ All tests pass (`npm test`)
✅ Coverage ≥85% (`npm run test:coverage`)
✅ Service starts without errors (`npm run dev`)
✅ Health endpoints respond correctly
✅ Service polling works (all 40 services)
✅ External dependency checks work (RabbitMQ, PostgreSQL, Kafka)
✅ Circuit breaker monitoring works
✅ HTTP API endpoints work (all 5)
✅ Notifications sent on critical status changes
✅ RUNBOOK.md covers all operational scenarios
✅ Completion report written
✅ Code pushed to branch

---

## 10. TIMELINE CHECKPOINT

**Day 1 End:** Core implementation complete (health-checker, service-registry, observability)
**Day 2 End:** External deps + circuit breaker + API complete
**Day 3 End:** All tests written and passing (85%+ coverage)
**Day 4 End:** Documentation complete, code committed & pushed

**If you're behind schedule:**
- Prioritize critical service monitoring over non-critical
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
