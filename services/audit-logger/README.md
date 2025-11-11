# Audit Logger Service - Specification

**Service Name:** `audit-logger`
**Layer:** Infrastructure (Layer 9)
**Complexity:** Medium (~1,500 LOC)
**Status:** 🔴 Specification Only (Ready for Implementation)

---

## 1. Purpose and Scope

### 1.1 Single Responsibility

**Write immutable audit trail to append-only log for regulatory compliance and forensic analysis.**

This service is the **single source of truth** for all audit events in the eRacun platform. Every critical operation (invoice processing, validation, submission, archiving, retrieval) must be logged immutably for:
- Croatian Tax Authority audits (11-year retention requirement)
- Forensic analysis (incident investigation)
- Regulatory compliance (GDPR, Fiskalizacija 2.0)
- Non-repudiation (legal disputes)

### 1.2 What This Service Does

✅ **Consumes audit events from Kafka** (`audit-log` topic)
✅ **Writes to PostgreSQL append-only table** (never UPDATE or DELETE)
✅ **Enforces immutability** (cryptographic hash chaining)
✅ **Provides read-only query API** (gRPC) for audit retrieval
✅ **Monitors log integrity** (periodic hash verification)
✅ **Publishes audit metrics** (events written, integrity checks)

### 1.3 What This Service Does NOT Do

❌ Does NOT process business logic (only writes logs)
❌ Does NOT modify existing audit entries (append-only)
❌ Does NOT delete audit logs (retention handled by separate cold-storage service)
❌ Does NOT perform real-time alerting (notification-service does this)

---

## 2. Integration Architecture

### 2.1 Upstream Dependencies

**Kafka Topics (Consumers):**
- `audit-log` (5 partitions, 11-year retention)
  - Consumes from: **ALL SERVICES** (40 producers)
  - Consumer group: `audit-logger-group`
  - Offset management: Auto-commit after successful write

**No Direct Service Dependencies** (pure event consumer)

### 2.2 Downstream Consumers

**PostgreSQL Database:**
- Table: `audit_events` (append-only, WORM characteristics)
- Indexes: `invoice_id`, `timestamp`, `service_name`, `event_type`

**gRPC API (Read-Only):**
- `GetAuditTrail(invoice_id)` → Returns all events for invoice
- `QueryAuditEvents(filters)` → Filtered audit log retrieval
- `VerifyIntegrity(start_date, end_date)` → Hash chain verification

**No Message Publishing** (terminal consumer, does not produce events)

### 2.3 Message Contracts

**Consumed Event Schema** (`common.proto`):

```protobuf
message AuditEvent {
  string event_id = 1;              // UUID v4
  string invoice_id = 2;            // Invoice being processed
  string service_name = 3;          // Producer service (e.g., "xsd-validator")
  string event_type = 4;            // Event category (e.g., "VALIDATION_STARTED")
  int64 timestamp_ms = 5;           // Unix timestamp in milliseconds
  string user_id = 6;               // Authenticated user (if applicable)
  string request_id = 7;            // Trace ID for correlation
  map<string, string> metadata = 8; // Event-specific data (JSON)
  string previous_hash = 9;         // Hash of previous event (chain integrity)
  string event_hash = 10;           // SHA-256 hash of this event
}
```

**Event Types** (standardized across all services):
- `INVOICE_INGESTED` - Invoice received
- `VALIDATION_STARTED` - Validation layer initiated
- `VALIDATION_PASSED` - Validation successful
- `VALIDATION_FAILED` - Validation failed
- `TRANSFORMATION_STARTED` - Transformation initiated
- `SIGNATURE_APPLIED` - Digital signature added
- `SUBMISSION_STARTED` - Submission to FINA/AS4
- `SUBMISSION_SUCCESS` - Submission confirmed
- `SUBMISSION_FAILED` - Submission rejected
- `ARCHIVE_WRITTEN` - Invoice archived
- `ARCHIVE_RETRIEVED` - Invoice retrieved (PII access audit)

### 2.4 gRPC API Contract

```protobuf
service AuditLogService {
  // Get complete audit trail for invoice
  rpc GetAuditTrail(GetAuditTrailRequest) returns (GetAuditTrailResponse);

  // Query audit events with filters
  rpc QueryAuditEvents(QueryAuditEventsRequest) returns (QueryAuditEventsResponse);

  // Verify hash chain integrity
  rpc VerifyIntegrity(VerifyIntegrityRequest) returns (VerifyIntegrityResponse);
}

message GetAuditTrailRequest {
  string invoice_id = 1;
}

message GetAuditTrailResponse {
  repeated AuditEvent events = 1;
  int32 total_events = 2;
}

message QueryAuditEventsRequest {
  string service_name = 1;          // Optional filter
  string event_type = 2;            // Optional filter
  int64 start_timestamp_ms = 3;     // Time range start
  int64 end_timestamp_ms = 4;       // Time range end
  int32 limit = 5;                  // Max results (default 100)
  int32 offset = 6;                 // Pagination offset
}

message QueryAuditEventsResponse {
  repeated AuditEvent events = 1;
  int32 total_count = 2;
}

message VerifyIntegrityRequest {
  int64 start_timestamp_ms = 1;
  int64 end_timestamp_ms = 2;
}

message VerifyIntegrityResponse {
  bool integrity_valid = 1;
  repeated string broken_chains = 2; // Event IDs with hash mismatches
}
```

---

## 3. Technology Stack

### 3.1 Required Dependencies

**Core:**
- `Node.js 20+` - Runtime
- `TypeScript 5.3+` - Type safety
- `kafkajs` - Kafka consumer
- `pg` - PostgreSQL client
- `@grpc/grpc-js` - gRPC server
- `@grpc/proto-loader` - Protocol Buffers

**Observability (TODO-008 Compliance):**
- `prom-client` - Prometheus metrics
- `pino` - Structured logging
- `opentelemetry` - Distributed tracing

**Security:**
- `crypto` (Node.js built-in) - SHA-256 hashing for chain integrity

### 3.2 External Systems

**PostgreSQL Database:**
- Table: `audit_events`
- Connection: via environment variable `DATABASE_URL`
- Schema:
  ```sql
  CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    invoice_id UUID NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    user_id VARCHAR(100),
    request_id UUID NOT NULL,
    metadata JSONB,
    previous_hash VARCHAR(64),
    event_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  );

  CREATE INDEX idx_audit_invoice ON audit_events(invoice_id);
  CREATE INDEX idx_audit_timestamp ON audit_events(timestamp_ms);
  CREATE INDEX idx_audit_service ON audit_events(service_name);
  CREATE INDEX idx_audit_type ON audit_events(event_type);
  ```

**Kafka:**
- Bootstrap servers: via `KAFKA_BROKERS` environment variable
- Consumer group: `audit-logger-group`
- Auto-offset-reset: `earliest` (never lose events)

---

## 4. Performance Requirements

### 4.1 Throughput

**Target:** 1,000 events/second sustained
**Peak:** 5,000 events/second burst (10 seconds)
**Why:** 40 services × 25 events per invoice × 10 invoices/second = 10,000 events/second theoretical maximum

### 4.2 Latency

**Event consumption to PostgreSQL write:** <50ms p95
**gRPC query response:** <200ms p95 (100 events)
**Hash verification:** <5s for 1 million events

### 4.3 Reliability

**Data Loss Tolerance:** ZERO (regulatory requirement)
**Availability Target:** 99.9% (audit logs must be always available)
**Recovery Time Objective (RTO):** 5 minutes
**Recovery Point Objective (RPO):** 0 (no data loss acceptable)

---

## 5. Implementation Guidance

### 5.1 Recommended File Structure

```
services/audit-logger/
├── src/
│   ├── index.ts              # Main entry point (Kafka consumer + gRPC server)
│   ├── consumer.ts           # Kafka consumer logic
│   ├── writer.ts             # PostgreSQL append-only writer
│   ├── grpc-server.ts        # gRPC API server
│   ├── integrity.ts          # Hash chain verification
│   └── observability.ts      # Metrics, logging, tracing (TODO-008)
├── tests/
│   ├── setup.ts
│   ├── unit/
│   │   ├── writer.test.ts
│   │   ├── integrity.test.ts
│   │   └── observability.test.ts
│   └── integration/
│       ├── kafka-consumer.test.ts
│       ├── grpc-api.test.ts
│       └── postgres-write.test.ts
├── proto/
│   └── audit.proto           # gRPC service definition
├── package.json
├── tsconfig.json
├── jest.config.js
├── Dockerfile
├── audit-logger.service       # systemd unit file
├── .env.example
├── README.md                  # This file
└── RUNBOOK.md                 # Operations guide (create after implementation)
```

### 5.2 Core Implementation Logic

**Kafka Consumer** (`src/consumer.ts`):

```typescript
import { Kafka } from 'kafkajs';
import { writeAuditEvent } from './writer';

export async function startConsumer() {
  const kafka = new Kafka({
    clientId: 'audit-logger',
    brokers: process.env.KAFKA_BROKERS!.split(',')
  });

  const consumer = kafka.consumer({ groupId: 'audit-logger-group' });
  await consumer.connect();
  await consumer.subscribe({ topic: 'audit-log', fromBeginning: true });

  await consumer.run({
    eachMessage: async ({ topic, partition, message }) => {
      const event = JSON.parse(message.value!.toString());

      // Write to PostgreSQL (append-only)
      await writeAuditEvent(event);

      // Metrics
      auditEventsWritten.inc({ service: event.service_name, event_type: event.event_type });
    }
  });
}
```

**Append-Only Writer** (`src/writer.ts`):

```typescript
import { Pool } from 'pg';
import crypto from 'crypto';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function writeAuditEvent(event: AuditEvent): Promise<void> {
  // Calculate hash for integrity chain
  const eventHash = calculateEventHash(event);

  // Get previous hash (last event in chain)
  const previousHash = await getLastEventHash();

  // Insert (never UPDATE or DELETE)
  await pool.query(
    `INSERT INTO audit_events
     (event_id, invoice_id, service_name, event_type, timestamp_ms,
      user_id, request_id, metadata, previous_hash, event_hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      event.event_id,
      event.invoice_id,
      event.service_name,
      event.event_type,
      event.timestamp_ms,
      event.user_id,
      event.request_id,
      JSON.stringify(event.metadata),
      previousHash,
      eventHash
    ]
  );
}

function calculateEventHash(event: AuditEvent): string {
  const data = `${event.event_id}|${event.invoice_id}|${event.timestamp_ms}|${event.metadata}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}
```

**Hash Chain Verification** (`src/integrity.ts`):

```typescript
export async function verifyIntegrity(startTime: number, endTime: number): Promise<VerificationResult> {
  const events = await pool.query(
    `SELECT event_id, event_hash, previous_hash
     FROM audit_events
     WHERE timestamp_ms BETWEEN $1 AND $2
     ORDER BY timestamp_ms ASC`,
    [startTime, endTime]
  );

  const brokenChains: string[] = [];
  let previousHash: string | null = null;

  for (const event of events.rows) {
    if (previousHash && event.previous_hash !== previousHash) {
      brokenChains.push(event.event_id);
    }
    previousHash = event.event_hash;
  }

  return {
    integrity_valid: brokenChains.length === 0,
    broken_chains: brokenChains
  };
}
```

### 5.3 Observability (TODO-008 Compliance)

**Required Prometheus Metrics:**

```typescript
// Event throughput
const auditEventsWritten = new Counter({
  name: 'audit_events_written_total',
  help: 'Total number of audit events written to database',
  labelNames: ['service', 'event_type']
});

// Write latency
const auditWriteDuration = new Histogram({
  name: 'audit_write_duration_seconds',
  help: 'Time to write audit event to PostgreSQL',
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1]
});

// Kafka consumer lag
const auditConsumerLag = new Gauge({
  name: 'audit_consumer_lag',
  help: 'Kafka consumer lag (messages behind)',
  labelNames: ['partition']
});

// Integrity check results
const auditIntegrityChecks = new Counter({
  name: 'audit_integrity_checks_total',
  help: 'Total number of integrity verifications performed',
  labelNames: ['status'] // valid or broken
});

// Database connection pool
const auditDbConnections = new Gauge({
  name: 'audit_db_connections',
  help: 'Active PostgreSQL connections'
});

// gRPC request rate
const auditGrpcRequests = new Counter({
  name: 'audit_grpc_requests_total',
  help: 'Total gRPC API requests',
  labelNames: ['method', 'status']
});
```

**Structured Logging:**
- Log every event write (DEBUG level)
- Log integrity check results (INFO level)
- Log any hash chain breaks (ERROR level, alert immediately)
- Log gRPC queries (INFO level with query filters)

**Distributed Tracing:**
- Trace ID propagated from Kafka message metadata
- Spans: `kafka.consume`, `postgres.write`, `grpc.query`

### 5.4 Error Handling

**Kafka Consumer Failures:**
- Network errors: Retry with exponential backoff (max 5 retries)
- Deserialization errors: Log error + skip message (malformed event)
- Write failures: DO NOT commit offset (retry on restart)

**PostgreSQL Write Failures:**
- Connection errors: Retry with circuit breaker
- Constraint violations: Log error (should never happen with UUID)
- Disk full: Alert immediately (critical failure)

**gRPC Query Failures:**
- Invalid invoice_id: Return empty result (not an error)
- Database timeout: Return error with retry suggestion
- Large result sets: Enforce pagination (max 1000 events per query)

---

## 6. Failure Modes and Recovery

### 6.1 Critical Failure Scenarios

**Scenario 1: PostgreSQL Database Down**
- **Impact:** Audit events accumulate in Kafka (not lost due to retention)
- **Detection:** Health check fails, metrics stop updating
- **Recovery:**
  1. Restart PostgreSQL
  2. Restart audit-logger (consumer resumes from last committed offset)
  3. Verify no events lost (check Kafka consumer lag)

**Scenario 2: Kafka Consumer Lag Exceeds Threshold**
- **Impact:** Audit events delayed (not lost)
- **Detection:** `audit_consumer_lag` metric > 10,000 messages
- **Recovery:**
  1. Scale horizontally (add more consumer instances)
  2. Investigate slow writes (check PostgreSQL performance)
  3. Verify database indexes exist

**Scenario 3: Hash Chain Integrity Break**
- **Impact:** Audit trail compromised (regulatory violation)
- **Detection:** `VerifyIntegrity()` returns `integrity_valid: false`
- **Recovery:**
  1. Alert on-call immediately (P0 incident)
  2. Identify broken chain event IDs
  3. Forensic analysis (check for data tampering)
  4. Report to Croatian Tax Authority if required

**Scenario 4: Disk Space Exhausted**
- **Impact:** Cannot write new audit events (data loss risk)
- **Detection:** PostgreSQL write fails with disk full error
- **Recovery:**
  1. Provision more disk space immediately
  2. Migrate old events to cold storage (>1 year)
  3. Implement automatic archival policy

### 6.2 Non-Critical Failures

**gRPC Query Timeout:**
- Retry with smaller time range
- Add pagination to reduce result set size

**Deserialization Error:**
- Log malformed message
- Skip and continue (do not block consumer)

---

## 7. Security Considerations

### 7.1 Data Protection

**Encryption:**
- At rest: PostgreSQL encryption via `pgcrypto` extension
- In transit: TLS for Kafka and PostgreSQL connections
- gRPC: mTLS in production

**Access Control:**
- Kafka: SASL/SCRAM authentication
- PostgreSQL: Role-based access (audit-logger user has INSERT-only on `audit_events`)
- gRPC: JWT authentication for query API

### 7.2 PII Handling

**Audit events may contain PII (OIB, IBAN, user IDs):**
- ✅ Store PII in `metadata` JSONB field (required for compliance)
- ✅ Encrypt `metadata` field if regulations require
- ✅ Implement access logging (who queried which audit trail)
- ❌ DO NOT mask PII in audit logs (defeats forensic purpose)

### 7.3 Immutability Enforcement

**Database-Level Protection:**
- PostgreSQL triggers to prevent UPDATE/DELETE on `audit_events`
- Row-level security to enforce INSERT-only
- Periodic hash chain verification (daily scheduled job)

---

## 8. Deployment Configuration

### 8.1 Environment Variables (`.env.example`)

```bash
# Service Configuration
SERVICE_NAME=audit-logger
NODE_ENV=production
PORT=8080
GRPC_PORT=50051

# Kafka Configuration
KAFKA_BROKERS=localhost:9092,localhost:9093,localhost:9094
KAFKA_TOPIC=audit-log
KAFKA_GROUP_ID=audit-logger-group

# PostgreSQL Configuration
DATABASE_URL=postgresql://audit_user:password@localhost:5432/eracun_audit
DATABASE_POOL_MIN=10
DATABASE_POOL_MAX=50

# Observability
PROMETHEUS_PORT=9090
JAEGER_AGENT_HOST=localhost
JAEGER_AGENT_PORT=6831
LOG_LEVEL=info

# Security
TLS_ENABLED=true
TLS_CERT_PATH=/etc/eracun/certs/audit-logger.crt
TLS_KEY_PATH=/etc/eracun/certs/audit-logger.key
```

### 8.2 systemd Unit File

```ini
[Unit]
Description=eRacun Audit Logger Service
After=network.target postgresql.service kafka.service
Requires=postgresql.service kafka.service

[Service]
Type=simple
User=eracun
Group=eracun
WorkingDirectory=/opt/eracun/services/audit-logger
EnvironmentFile=/etc/eracun/services/audit-logger.conf
ExecStart=/usr/bin/node /opt/eracun/services/audit-logger/dist/index.js
Restart=always
RestartSec=10

# Security Hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadOnlyPaths=/opt/eracun
ReadWritePaths=/var/log/eracun

[Install]
WantedBy=multi-user.target
```

### 8.3 Docker Compose (Local Development)

```yaml
services:
  audit-logger:
    build: .
    ports:
      - "8080:8080"    # Health checks
      - "50051:50051"  # gRPC API
      - "9090:9090"    # Prometheus metrics
    environment:
      KAFKA_BROKERS: kafka:9092
      DATABASE_URL: postgresql://eracun:password@postgres:5432/eracun
      LOG_LEVEL: debug
    depends_on:
      - kafka
      - postgres
    volumes:
      - ./src:/app/src
    command: npm run dev
```

---

## 9. Testing Requirements

### 9.1 Unit Tests (70% of test suite)

**Test Coverage Targets:**
- `writer.ts`: 90% (critical path)
- `integrity.ts`: 95% (security-critical)
- `observability.ts`: 85% (TODO-008 compliance)

**Key Test Scenarios:**
- Event hash calculation (deterministic)
- Previous hash retrieval (chain linking)
- Hash chain verification (detect breaks)
- PII handling (no masking in audit logs)
- Metrics increment (all counters/histograms)

### 9.2 Integration Tests (25% of test suite)

**Test Scenarios:**
1. Kafka consumer → PostgreSQL write (end-to-end)
2. gRPC query API (all methods)
3. Hash chain verification (1000 events)
4. Consumer lag recovery (simulated backlog)

**Test Environment:**
- Testcontainers for Kafka and PostgreSQL
- Mock Kafka producer (publish test events)
- gRPC client (query API)

### 9.3 Performance Tests (5% of test suite)

**Load Test Scenarios:**
- 1,000 events/second sustained (10 minutes)
- 5,000 events/second burst (10 seconds)
- Query 10,000 events (pagination)
- Verify 1 million event hash chain (< 5 seconds)

---

## 10. Acceptance Criteria

### 10.1 Functional Requirements

- [ ] Consumes events from Kafka `audit-log` topic
- [ ] Writes to PostgreSQL `audit_events` table (INSERT-only)
- [ ] Enforces immutability (no UPDATE/DELETE)
- [ ] Implements hash chain integrity (previous_hash linking)
- [ ] Provides gRPC query API (3 methods)
- [ ] Verifies hash chain integrity on demand
- [ ] Handles consumer lag gracefully (no data loss)

### 10.2 Non-Functional Requirements

- [ ] Throughput: 1,000 events/second sustained
- [ ] Latency: <50ms p95 for write
- [ ] Test coverage: 85%+
- [ ] Observability: 6+ Prometheus metrics
- [ ] Security: TLS/mTLS enabled
- [ ] Documentation: README.md + RUNBOOK.md complete

### 10.3 TODO-008 Compliance

- [ ] Prometheus metrics (all required metrics implemented)
- [ ] Structured JSON logging (Pino)
- [ ] Distributed tracing (OpenTelemetry, 100% sampling)
- [ ] Health endpoints (`/health`, `/ready`, `/metrics`)
- [ ] PII handling (stored unmasked, access logged)

---

## 11. References

**Related Documents:**
- `CLAUDE.md` - System architecture
- `docs/adr/003-system-decomposition-integration-architecture.md` - Service catalog (Layer 9, audit-logger)
- `docs/TODO-005-service-dependency-matrix.md` - Dependency analysis (zero dependencies)
- `docs/TODO-008-cross-cutting-concerns.md` - Observability requirements
- `CROATIAN_COMPLIANCE.md` - Audit retention requirements (11 years)

**Existing Service Templates:**
- `services/xsd-validator/` - Reference implementation pattern
- `services/schematron-validator/` - Reference observability module

---

**Status:** 🔴 Specification Complete, Ready for Implementation
**Implementation Estimate:** 3-4 days
**Complexity:** Medium (~1,500 LOC)
**Dependencies:** None (can start immediately)

---

**Last Updated:** 2025-11-11
**Specification Author:** System Architect
**Assigned Implementer:** [AI Instance TBD]
