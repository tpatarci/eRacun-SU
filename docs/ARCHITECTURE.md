# System Architecture

## Core Architectural Pattern

**Event-Driven Microservices with CQRS**

- **Command Query Responsibility Segregation (CQRS):** Separate read and write models
- **Event Sourcing:** All state changes captured as immutable events
- **Domain-Driven Design:** Each service owns one bounded context
- **Fire-and-Forget Reliability:** Clients submit and trust the system

---

## 1. Service Communication

### 1.1 Message Bus Architecture

**Primary Message Broker:** RabbitMQ
- Reliability and mature tooling
- Persistent queues for durability
- Dead letter queues for failed messages
- Acknowledgment-based delivery

**Event Store:** Apache Kafka
- Event sourcing and replay capability
- Long-term event retention
- High throughput for event streaming
- Topic-based pub/sub model

### 1.2 Message Patterns

**Commands (RabbitMQ RPC):**
- Direct service-to-service communication
- Request-response pattern
- Exactly-once delivery semantics
- Example: `ValidateInvoiceCommand`

**Events (Kafka Topics):**
- Broadcast state changes to interested services
- At-least-once delivery
- Consumers maintain their own offsets
- Example: `InvoiceValidatedEvent`

**Queries (HTTP/gRPC):**
- Synchronous queries for immediate results
- Limited use (prefer async patterns)
- REST for external APIs
- gRPC for internal APIs

### 1.3 Message Schema

**Protocol Buffers (`.proto`):**
```protobuf
syntax = "proto3";

message InvoiceValidatedEvent {
  string invoice_id = 1;
  string oib = 2;
  int64 timestamp = 3;
  ValidationResult result = 4;
}
```

**Schema Requirements:**
- All messages defined in Protocol Buffers
- Versioned schemas (backward compatibility required)
- Schema registry enforced (no runtime mismatches)
- Breaking changes require major version bump

---

## 2. API Contracts

### External APIs
- **Format:** REST + OpenAPI 3.1 specifications
- **Authentication:** JWT tokens
- **Rate Limiting:** 100 req/min per client
- **Versioning:** URL-based (`/api/v1/`)

### Internal APIs
- **Format:** gRPC with Protocol Buffers
- **Authentication:** mTLS (mutual TLS)
- **Service Discovery:** Static configuration
- **Load Balancing:** Client-side (gRPC channels)

### Webhooks
- **Standard:** CloudEvents 1.0
- **Delivery:** At-least-once with retries
- **Security:** HMAC signature verification
- **Timeout:** 5 seconds per webhook

### Contract Testing
- Producer provides contract tests (Pact)
- Consumers verify against contracts
- Breaking changes require major version bump
- CI fails on contract violations

---

## 3. Service Boundaries

### Bounded Contexts

Each service represents one bounded context from Domain-Driven Design:

| Service | Bounded Context | Responsibilities |
|---------|----------------|------------------|
| **invoice-gateway-api** | Invoice Ingestion | Upload, basic validation, routing |
| **email-ingestion-worker** | Email Processing | Parse emails, extract attachments |
| **ocr-processing-service** | Document OCR | Extract text from scanned invoices |
| **schema-validator** | Schema Validation | XSD/Schematron validation |
| **ai-validation-service** | AI Verification | Anomaly detection, cross-checks |
| **ubl-transformer** | Format Transformation | Convert to UBL 2.1 format |
| **fina-connector** | FINA Integration | Submit to Tax Authority |
| **porezna-connector** | Porezna Integration | Tax reporting integration |

### Service Size Limit
- **Maximum:** 2,500 LOC per service (excluding tests)
- **Reason:** AI context window optimization
- **Enforcement:** CI fails on violation

### Service Isolation
- Each service has own database schema
- No direct database access between services
- All communication via messages or APIs
- Independent deployment and scaling

---

## 4. Shared Libraries

### Philosophy
**Share code carefully.** Premature abstraction creates coupling.

### Guidelines
- **Only extract to `shared/` after pattern appears in 3+ services**
- **Measure impact:** Every shared library addition requires performance justification
- **Version independently:** Shared libs use semantic versioning (semver)
- **Tree-shaking compatible:** All shared code must support dead code elimination
- **Zero-dependency preferred:** Minimize transitive dependencies

### Performance Checklist for Shared Code
- [ ] Does not introduce runtime overhead >1ms
- [ ] Bundle size impact <10KB
- [ ] No synchronous I/O in critical paths
- [ ] Benchmark results documented in `shared/*/PERFORMANCE.md`

### Existing Shared Libraries
- `@eracun/common-types` - TypeScript interfaces, domain models
- `@eracun/validation-core` - Reusable validation primitives
- `@eracun/messaging` - Message bus abstractions (RabbitMQ/Kafka)
- `@eracun/observability` - Logging, tracing, metrics

---

## 5. Performance Budgets

### API Response Time SLAs

| Endpoint | p50 | p95 | p99 | Notes |
|----------|-----|-----|-----|-------|
| **Document Upload** | 50ms | 200ms | 500ms | Gateway only, async processing |
| **Validation Pipeline** | 1s | 3s | 5s | Full 6-layer validation |
| **XML Generation** | 200ms | 1s | 2s | UBL 2.1 transformation |
| **FINA Submission** | 1s | 3s | 5s | External API dependency |

### Resource Limits (Per Service)

**Memory:**
- Baseline: 512MB
- Burst: 1GB maximum
- OOM Kill if exceeded

**CPU:**
- Baseline: 0.5 cores
- Burst: 2 cores maximum
- Throttled if sustained >2 cores

**Disk I/O:**
- 100 IOPS sustained
- 500 IOPS burst (short duration)

### Scalability Targets

**Current (Year 1):**
- 10,000 invoices/hour
- 5 service replicas per service
- Single DigitalOcean droplet

**Target (Year 2):**
- 100,000 invoices/hour
- 50+ service replicas
- Multi-region deployment

**Future (Year 3+):**
- 1,000,000 invoices/hour
- Kubernetes migration
- Auto-scaling based on load

---

## 6. Data Flow Diagram

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTPS POST /api/v1/invoices
       ▼
┌─────────────────────┐
│ invoice-gateway-api │ (REST API)
└──────┬──────────────┘
       │ PublishEvent: InvoiceReceived
       ▼
┌─────────────────────┐
│   RabbitMQ Queue    │
└──────┬──────────────┘
       │
       ├───► schema-validator
       │     └─► ai-validation-service
       │         └─► ubl-transformer
       │             └─► fina-connector
       │                 └─► FINA Tax Authority
       │
       └───► Kafka: InvoiceValidatedEvent
             └─► audit-logger
             └─► reporting-service
             └─► notification-service
```

---

## 7. Database Architecture

### PostgreSQL Schema Design

**One Schema Per Service:**
```sql
-- invoice_gateway schema
CREATE SCHEMA invoice_gateway;
CREATE TABLE invoice_gateway.invoices (...);

-- validation schema
CREATE SCHEMA validation;
CREATE TABLE validation.validation_results (...);
```

**Benefits:**
- Logical isolation
- Independent migrations
- Clear ownership
- Simpler backup/restore

### Connection Pooling
- PgBouncer for connection management
- Pool size: 20 connections per service
- Max lifetime: 30 minutes

### Backup Strategy
- Continuous WAL archiving
- Daily full backups
- Point-in-time recovery (PITR) enabled
- Retention: 30 days

---

## 8. Observability Architecture

### The Three Pillars

**Metrics (Prometheus + Grafana):**
- Request latency (p50, p95, p99)
- Error rates by service
- Queue depths (RabbitMQ/Kafka)
- Database connection pool utilization

**Logs (Pino + Loki):**
- Structured JSON logs
- Request ID correlation
- Error context preservation
- Log aggregation in Loki

**Traces (OpenTelemetry + Jaeger):**
- End-to-end request flow
- Performance bottleneck identification
- Cross-service dependency visualization
- Distributed context propagation

---

## 9. Failure Modes and Recovery

### Circuit Breaker Pattern
```typescript
const breaker = new CircuitBreaker(finaSubmit, {
  timeout: 5000,
  errorThresholdPercentage: 50,
  resetTimeout: 30000
});
```

### Retry with Exponential Backoff
```typescript
const retry = async (fn, maxRetries = 3) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (e) {
      if (i === maxRetries - 1) throw e;
      await sleep(2 ** i * 1000 + Math.random() * 1000);
    }
  }
};
```

### Dead Letter Queues
- Failed messages moved to DLQ after 3 retries
- Manual inspection and reprocessing
- Alert on DLQ depth >10 messages

---

## Related Documentation

- **Development Standards:** @docs/DEVELOPMENT_STANDARDS.md
- **Security Standards:** @docs/SECURITY.md
- **Deployment Guide:** @docs/DEPLOYMENT_GUIDE.md
- **Service Catalog:** @docs/api-contracts/ (OpenAPI specs)
- **ADRs:** @docs/adr/ (Architecture decisions)

---

**Last Updated:** 2025-11-12
**Document Owner:** System Architect
**Review Cadence:** Monthly
