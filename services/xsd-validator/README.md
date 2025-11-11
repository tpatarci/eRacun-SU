# XSD Validator Service

**Bounded Context:** Validation Layer
**Single Responsibility:** Validate XML documents against UBL 2.1 XSD schemas
**Complexity:** Medium (target: 1,200 LOC)
**Status:** 🚧 In Development

---

## Purpose

The XSD Validator ensures syntactic correctness of invoice XML documents by validating them against official UBL 2.1 (OASIS Universal Business Language) schemas. This is the **first validation layer** in the invoice processing pipeline.

**Scope:**
- ✅ Validate XML structure against UBL 2.1 XSD schemas
- ✅ Support Invoice, CreditNote, and other UBL document types
- ✅ Return detailed validation errors with line numbers
- ❌ Does NOT validate business rules (see schematron-validator)
- ❌ Does NOT validate KPD codes (see kpd-validator)

---

## API Contract

### Input (Protocol Buffer)

```protobuf
message ValidateXSDCommand {
  eracun.v1.common.RequestContext context = 1;
  eracun.v1.common.InvoiceId invoice_id = 2;
  bytes xml_content = 3;
  SchemaType schema_type = 4; // UBL_INVOICE_2_1, UBL_CREDIT_NOTE_2_1
}
```

### Output (Protocol Buffer)

```protobuf
message ValidateXSDResponse {
  eracun.v1.common.InvoiceId invoice_id = 1;
  ValidationStatus status = 2; // VALID, INVALID, ERROR
  repeated eracun.v1.common.Error errors = 3;
  int32 validation_time_ms = 4;
}
```

**RabbitMQ Queue:** `eracun.xsd-validator.xml`
**Routing Key:** `validation.xsd`

---

## Dependencies

### External Libraries
- **libxmljs2** - Fast XML parsing and XSD validation (C++ libxml2 bindings)
- **prom-client** - Prometheus metrics (TODO-008 compliance)
- **@opentelemetry/api** - Distributed tracing (TODO-008 compliance)
- **pino** - Structured JSON logging (TODO-008 compliance)
- **amqplib** - RabbitMQ client

### UBL 2.1 Schemas
- Downloaded from OASIS UBL TC website
- Stored in `/services/xsd-validator/schemas/ubl-2.1/`
- Version: 2.1 (official release)

### Upstream Services
- None (entry point for validation pipeline)

### Downstream Services
- **schematron-validator** (receives validated XML)
- **invoice-state-manager** (receives validation results)

---

## Performance Requirements

**Target SLA (from ADR-003 Section 3):**
- **Latency:** <100ms p50, <200ms p95
- **Throughput:** 100 validations/second sustained
- **Memory:** 256MB max (128MB typical)
- **CPU:** 0.2 cores sustained, 1 core burst

**Validation Complexity:**
- Small invoice (<10KB): <50ms
- Medium invoice (10-100KB): <100ms
- Large invoice (100KB-1MB): <500ms

---

## Error Handling

**Error Scenarios:**
1. **Invalid XML Structure:** Return detailed libxml2 errors with line/column numbers
2. **Missing Required Elements:** XSD validation failure with element path
3. **Invalid Data Types:** Type mismatch errors (e.g., date format)
4. **Schema Not Found:** Internal error (critical - alert)
5. **Malformed XML:** Parse error before validation

**Dead Letter Queue:**
- **Queue:** `eracun.dlq.xsd-validator`
- **Retry Policy:** 3 attempts with exponential backoff (2s, 4s, 8s)
- **TTL:** 5 minutes (then manual review)

---

## Observability (TODO-008 Compliance)

### Prometheus Metrics

**Required Metrics:**
```javascript
// Request counter
xsd_validation_total{status="valid|invalid|error"}

// Latency histogram
xsd_validation_duration_seconds{schema_type="invoice|credit_note"}

// Error counter
xsd_validation_errors_total{error_type="parse|schema|internal"}

// Queue depth
xsd_validation_queue_depth
```

**Health Endpoints:**
- `GET /health` - Always returns 200 (liveness)
- `GET /ready` - Returns 200 if schemas loaded and RabbitMQ connected (readiness)
- `GET /metrics` - Prometheus metrics endpoint

### Jaeger Tracing

**Trace Spans:**
- `xsd_validation` (parent span)
  - `parse_xml` (child span)
  - `load_schema` (child span)
  - `validate_against_schema` (child span)

**Trace Attributes:**
- `invoice.id` - UUID
- `validation.schema_type` - UBL_INVOICE_2_1
- `validation.result` - valid|invalid|error
- `validation.error_count` - Number of errors
- `xml.size_bytes` - Document size

**Sampling:** 100% (per TODO-008 decision)

### Structured Logging

**Mandatory Log Fields (TODO-008):**
```json
{
  "timestamp": "2025-11-10T14:32:18.123Z",
  "level": "info",
  "service": "xsd-validator",
  "request_id": "7f3a2b8c-...",
  "invoice_id": "550e8400-...",
  "message": "XSD validation completed",
  "duration_ms": 85,
  "result": "valid",
  "schema_type": "UBL_INVOICE_2_1"
}
```

**Log Retention:** 90 days (per TODO-008)

---

## Security (TODO-008 Compliance)

### Input Validation
- **XXE Protection:** Disable external entity resolution
- **Billion Laughs Protection:** Limit entity expansion depth
- **Size Limits:** Max 10MB per XML document
- **Resource Limits:** Max 100 concurrent validations

### Secrets
- No secrets required (uses public UBL schemas)

### Network Security
- **Production:** mTLS for RabbitMQ connection
- **Development:** Simple authentication

---

## Testing

### Unit Tests (Target: 85% coverage)
- XSD validation logic
- Error handling
- Schema loading
- Message parsing/serialization

### Integration Tests
- RabbitMQ message flow
- Prometheus metrics collection
- Jaeger trace propagation
- Health endpoint responses

### Test Cases
1. Valid UBL 2.1 invoice → VALID status
2. Missing required element → INVALID with error details
3. Invalid date format → INVALID with type error
4. Malformed XML → ERROR with parse error
5. Large invoice (1MB) → Performance within SLA
6. Concurrent validations → No resource exhaustion

---

## Deployment

### systemd Service
- **Unit File:** `/etc/systemd/system/eracun-xsd-validator.service`
- **User:** `eracun`
- **Working Directory:** `/opt/eracun/services/xsd-validator/`
- **Restart Policy:** `on-failure`
- **Resource Limits:** 256MB RAM, 1 CPU core

### Environment Variables
```bash
NODE_ENV=production
LOG_LEVEL=info
RABBITMQ_URL=amqp://localhost:5672
RABBITMQ_QUEUE=eracun.xsd-validator.xml
SCHEMA_PATH=/opt/eracun/services/xsd-validator/schemas/ubl-2.1/
PROMETHEUS_PORT=9100
JAEGER_ENDPOINT=http://localhost:14268/api/traces
```

### Docker Image
- **Base:** `node:20-alpine`
- **Size Target:** <100MB
- **Registry:** `registry.digitalocean.com/eracun/xsd-validator:latest`

---

## Development

### Setup

```bash
cd services/xsd-validator
npm install
npm run build
npm test
```

### Run Locally

```bash
npm run dev
```

### Debug

```bash
DEBUG=* npm run dev
```

---

## Architecture Decisions

**Why libxmljs2?**
- Fast (C++ bindings to libxml2)
- Native XSD validation support
- Battle-tested (used in production systems)
- Alternative considered: xmllint CLI (rejected - subprocess overhead)

**Why RabbitMQ over Kafka?**
- Sequential processing required (preserve order within invoice)
- Request/response pattern fits RabbitMQ better
- Dead letter queue support built-in

**Why Not gRPC?**
- Async processing via message queue preferred
- gRPC reserved for synchronous queries only (per ADR-003)

---

## Known Limitations

1. **Single UBL Version:** Only UBL 2.1 supported (UBL 2.2+ not needed for Croatian compliance)
2. **No Parallel Validation:** Single-threaded per message (intentional - CPU bound)
3. **Schema Caching:** Schemas loaded at startup, no hot reload (restart required for schema updates)

---

## Future Enhancements (Post-MVP)

- [ ] Support UN/CEFACT CII format (alternative to UBL)
- [ ] Schema version detection (auto-detect UBL version)
- [ ] Validation cache (cache results for identical documents)
- [ ] Batch validation API (validate multiple documents in one call)

---

## References

- **ADR-003 Section 1:** Service catalog entry
- **ADR-003 Section 3:** Integration topology
- **ADR-003 Section 4:** Processing pipeline
- **TODO-008:** Cross-cutting concerns (security, observability, compliance)
- **EXTERNAL_INTEGRATIONS.md:** No external systems (uses local schemas)

---

**Created:** 2025-11-10
**Owner:** Development Team
**Status:** 🚧 Implementation in progress
