# Cross-Cutting Concerns Standard

**Document Classification:** Technical Standard (Mandatory)
**Applies To:** All bounded contexts in eRacun platform
**Version:** 1.0
**Last Updated:** 2025-11-10
**Owner:** System Architect

---

## Purpose

This document defines **mandatory standards** for security, observability, and compliance that **every service must implement**. These cross-cutting concerns ensure:

- **Security:** Consistent authentication, encryption, and secrets management
- **Observability:** Complete visibility into system behavior (metrics, logs, traces)
- **Compliance:** Croatian Tax Authority regulatory requirements and audit trails

**Guiding Principle:** *"Robust over fancy"* - prefer proven, open-source solutions that work reliably on vanilla Linux.

---

## 1. Security Standards

### 1.1 Service-to-Service Authentication

#### Production Environment

**Mechanism:** mTLS (Mutual TLS with Client Certificates)

**Why:** Most robust authentication, zero external dependencies, works natively on Linux with OpenSSL.

**Implementation:**

```yaml
# systemd service unit with mTLS
[Service]
Environment="NODE_TLS_CLIENT_CERT=/etc/eracun/certs/service-cert.pem"
Environment="NODE_TLS_CLIENT_KEY=/etc/eracun/certs/service-key.pem"
Environment="NODE_TLS_CA_CERT=/etc/eracun/certs/ca-cert.pem"
Environment="NODE_TLS_VERIFY=true"
```

**Certificate Management:**
- **Issuer:** Internal CA (OpenSSL-based) or external CA (FINA for production)
- **Validity:** 90 days (short-lived, rotate frequently)
- **Storage:** `/etc/eracun/certs/` with 600 permissions (read by `eracun` user only)
- **Rotation:** Automated via `certificate-lifecycle-manager` service (30 days before expiration)

**TypeScript Example:**

```typescript
import https from 'https';
import fs from 'fs';

const httpsAgent = new https.Agent({
  cert: fs.readFileSync(process.env.NODE_TLS_CLIENT_CERT),
  key: fs.readFileSync(process.env.NODE_TLS_CLIENT_KEY),
  ca: fs.readFileSync(process.env.NODE_TLS_CA_CERT),
  rejectUnauthorized: true // MUST be true in production
});

// All service-to-service calls use this agent
const response = await fetch('https://xsd-validator:8443/validate', {
  agent: httpsAgent,
  method: 'POST',
  body: JSON.stringify(request)
});
```

---

#### Development/Staging Environments

**Mechanism:** Simple bearer token (optional) or no authentication

**Why:** mTLS adds complexity that slows development iteration. Dev/staging are isolated environments.

**Implementation:**

```typescript
// Simple token for dev/staging (NOT production)
const token = process.env.SERVICE_TOKEN || 'dev-token';

const response = await fetch('http://xsd-validator:8080/validate', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

---

### 1.2 Authorization Model

**Decision:** **Trust-based authorization** (services authenticate, then fully trust each other)

**Rationale:**
- Bounded contexts own their data (no cross-context access control needed)
- All services run in secure zone (network-level isolation)
- Fine-grained RBAC between services adds complexity without security benefit

**What This Means:**
- Once a service authenticates (via mTLS), it has full access to the receiving service
- No per-request authorization checks between services
- Authorization is enforced at **external boundaries** (API gateway, web portal)

**External API Authorization:**

```typescript
// API Gateway enforces user authentication & authorization
// Internal services trust authenticated requests

// Example: API Gateway (user-facing)
router.post('/invoices', authenticate, authorize('upload:invoices'), async (req, res) => {
  // User authenticated, authorized
  // Forward to internal service (which trusts this request)
  await fileClassifier.classify(req.file);
});
```

---

### 1.3 Encryption

#### In Transit

**Requirement:** TLS 1.2+ for ALL network communication

**Implementation:**
- **Service-to-service:** mTLS (production), TLS (dev/staging)
- **External APIs:** TLS 1.2+ with strong cipher suites
- **Message bus:** TLS for RabbitMQ, SASL_SSL for Kafka

**RabbitMQ TLS Configuration:**

```yaml
# /etc/rabbitmq/rabbitmq.conf
listeners.ssl.default = 5671
ssl_options.cacertfile = /etc/eracun/certs/ca-cert.pem
ssl_options.certfile   = /etc/eracun/certs/rabbitmq-cert.pem
ssl_options.keyfile    = /etc/eracun/certs/rabbitmq-key.pem
ssl_options.verify     = verify_peer
ssl_options.fail_if_no_peer_cert = true
```

---

#### At Rest

**Requirement:** AES-256 encryption for stored data

**Implementation:**
- **Archive storage (S3):** Server-side encryption (SSE-S3 or SSE-KMS)
- **Database:** Disk-level encryption (LUKS on Linux)
- **Secrets:** SOPS + age encryption (see ADR-002)

**DigitalOcean Spaces Encryption:**

```typescript
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

const s3 = new S3Client({
  endpoint: 'https://fra1.digitaloceanspaces.com',
  region: 'fra1'
});

// Server-side encryption enabled
await s3.send(new PutObjectCommand({
  Bucket: 'eracun-archive',
  Key: `invoices/${invoiceId}.xml`,
  Body: xmlContent,
  ServerSideEncryption: 'AES256' // Mandatory
}));
```

---

### 1.4 Secrets Management

**Reference:** See ADR-002 for complete secrets management strategy.

**Quick Summary:**
- **Tool:** SOPS + age encryption (open source, €0 cost)
- **Storage:** Encrypted secrets in git (`*.env.enc`), plaintext NEVER committed
- **Runtime:** systemd `ExecStartPre` decrypts to `/run/eracun/secrets.env` (tmpfs, cleared on reboot)
- **Permissions:** 600 (read-only by `eracun` user)

**Do NOT:**
- ❌ Hardcode secrets in code
- ❌ Commit plaintext secrets to git
- ❌ Store secrets in environment variables visible to `ps` command
- ❌ Log secrets (even in DEBUG mode)

---

### 1.5 Input Validation

**Requirement:** Validate ALL external input (size, format, content)

**XML Security (Critical for Invoice Processing):**

```typescript
import { XMLParser } from 'fast-xml-parser';

// MANDATORY: Disable external entities (XXE protection)
const parser = new XMLParser({
  ignoreAttributes: false,
  parseTagValue: false,
  trimValues: true,
  // XXE Protection
  processEntities: false, // CRITICAL: Prevents XXE attacks
  // Billion Laughs Protection
  stopNodes: ['*'], // Limit nesting depth
  // Size limit
  maxEntityExpansion: 0 // No entity expansion
});

// Size limit (BEFORE parsing)
const MAX_XML_SIZE = 10 * 1024 * 1024; // 10MB
if (xmlContent.length > MAX_XML_SIZE) {
  throw new Error('XML exceeds 10MB size limit');
}

const parsed = parser.parse(xmlContent);
```

**String Sanitization:**

```typescript
// MANDATORY: Sanitize all string inputs
function sanitizeString(input: string, maxLength: number = 1000): string {
  if (!input) return '';

  // Trim whitespace
  let sanitized = input.trim();

  // Length limit
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength);
  }

  // Remove control characters (except newline/tab)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  return sanitized;
}
```

---

### 1.6 Rate Limiting

**Requirement:** Protect all external-facing APIs from abuse

**Per-Service Defaults** (adjust after TODO-006 research):

| Service | Rate Limit | Burst | Window |
|---------|-----------|-------|--------|
| api-gateway | 100 req/sec | 200 | 1 minute |
| web-upload-handler | 10 req/sec | 20 | 1 minute |
| as4-gateway-receiver | 50 req/sec | 100 | 1 minute |
| fina-soap-connector | 10 req/sec | 20 | 1 minute (external API limit) |

**Implementation (Express middleware):**

```typescript
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per window
  message: 'Too many requests, please try again later',
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false
});

app.use('/api/', limiter);
```

---

### 1.7 PII Protection

**PII Data Classification:**

| Data Type | Classification | Protection Required |
|-----------|----------------|---------------------|
| OIB (Croatian tax number) | **High** | Mask in logs, encrypt at rest |
| Company names | Medium | Mask in logs |
| Contact info (email, phone) | Medium | Mask in logs |
| Invoice amounts | Low | No masking (business data) |
| Invoice numbers | Low | No masking (business data) |

**Log Masking (MANDATORY):**

```typescript
// MANDATORY: Mask OIB in all logs
function maskOIB(oib: string): string {
  if (!oib || oib.length !== 11) return 'INVALID_OIB';
  return `***********`; // Full mask
}

// MANDATORY: Mask before logging
logger.info({
  invoice_id: invoiceId,
  issuer_oib: maskOIB(issuerOIB), // MASKED
  recipient_oib: maskOIB(recipientOIB), // MASKED
  amount: amount // NOT masked (business data)
}, 'Invoice validated');
```

**Database Access Auditing:**

```sql
-- MANDATORY: Audit all PII access
-- Trigger on SELECT from invoices table
CREATE OR REPLACE FUNCTION audit_pii_access()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO audit_log (
    timestamp, service, action, invoice_id, user_id, pii_accessed
  ) VALUES (
    NOW(), current_setting('app.service_name'), 'SELECT', NEW.invoice_id,
    current_setting('app.user_id'), true
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_invoice_access
AFTER SELECT ON invoices
FOR EACH ROW
EXECUTE FUNCTION audit_pii_access();
```

---

## 2. Observability Standards

### 2.1 Metrics (Prometheus)

**Requirement:** Every service MUST expose Prometheus metrics on `/metrics` endpoint (port 9090)

#### Mandatory Metrics (ALL Services)

**Health Checks:**

```typescript
// /health endpoint (simple HTTP 200)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// /ready endpoint (checks dependencies)
app.get('/ready', async (req, res) => {
  const dbHealthy = await checkDatabase();
  const mqHealthy = await checkRabbitMQ();

  if (dbHealthy && mqHealthy) {
    res.status(200).json({ status: 'ready' });
  } else {
    res.status(503).json({
      status: 'not ready',
      database: dbHealthy,
      rabbitmq: mqHealthy
    });
  }
});
```

**Request Metrics:**

```typescript
import { register, Counter, Histogram } from 'prom-client';

// MANDATORY: Request counter
const httpRequestsTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'path', 'status_code']
});

// MANDATORY: Request latency histogram
const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request latency in seconds',
  labelNames: ['method', 'path', 'status_code'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10] // 10ms to 10s
});

// MANDATORY: Error counter
const httpErrorsTotal = new Counter({
  name: 'http_errors_total',
  help: 'Total HTTP errors',
  labelNames: ['method', 'path', 'error_type']
});

// Middleware to record metrics
app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;

    httpRequestsTotal.inc({
      method: req.method,
      path: req.route?.path || req.path,
      status_code: res.statusCode
    });

    httpRequestDuration.observe({
      method: req.method,
      path: req.route?.path || req.path,
      status_code: res.statusCode
    }, duration);

    if (res.statusCode >= 400) {
      httpErrorsTotal.inc({
        method: req.method,
        path: req.route?.path || req.path,
        error_type: res.statusCode >= 500 ? 'server_error' : 'client_error'
      });
    }
  });

  next();
});

// /metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

**Business Metrics (Service-Specific):**

```typescript
// Example: XSD Validator metrics
const validationTotal = new Counter({
  name: 'xsd_validations_total',
  help: 'Total XSD validations performed',
  labelNames: ['result'] // 'valid', 'invalid', 'error'
});

const validationDuration = new Histogram({
  name: 'xsd_validation_duration_seconds',
  help: 'XSD validation duration in seconds',
  buckets: [0.01, 0.05, 0.1, 0.2, 0.5, 1]
});

// In validation code
const start = Date.now();
const result = await validateXSD(xmlContent);
const duration = (Date.now() - start) / 1000;

validationTotal.inc({ result: result.isValid ? 'valid' : 'invalid' });
validationDuration.observe(duration);
```

---

### 2.2 Logging (Structured JSON)

**Requirement:** ALL logs MUST be structured JSON written to **stdout** (not files)

**Why stdout:** Works with any log aggregator (journald, Loki, ELK), no file I/O overhead.

#### Mandatory Log Fields

```typescript
{
  "timestamp": "2025-11-10T14:32:18.123Z",  // ISO 8601
  "level": "info",                           // debug, info, warn, error
  "service": "xsd-validator",                // Service name
  "request_id": "7f3a2b8c-...",             // W3C Trace Context trace ID
  "invoice_id": "550e8400-...",             // Business entity ID
  "message": "XSD validation completed",     // Human-readable
  "duration_ms": 85,                         // Operation duration
  "result": "valid",                         // Operation result (if applicable)
  // ... additional context fields
}
```

**Implementation (Pino - fast structured logging):**

```typescript
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level(label) {
      return { level: label };
    }
  },
  base: {
    service: process.env.SERVICE_NAME || 'unknown'
  },
  timestamp: pino.stdTimeFunctions.isoTime
});

// Usage
logger.info({
  request_id: req.headers['traceparent'],
  invoice_id: invoiceId,
  duration_ms: 85,
  result: 'valid'
}, 'XSD validation completed');
```

**Log Levels:**

| Level | When to Use | Examples |
|-------|-------------|----------|
| **DEBUG** | Development only, verbose details | SQL queries, message payloads |
| **INFO** | Normal operations, state transitions | "Invoice validated", "Submitted to FINA" |
| **WARN** | Recoverable errors, degraded performance | "Retry attempt 2/3", "Circuit breaker open" |
| **ERROR** | Unrecoverable errors, requires attention | "Database connection failed", "FINA API timeout" |

**PII Masking (MANDATORY):**

```typescript
// ALWAYS mask PII before logging
logger.info({
  invoice_id: invoiceId,
  issuer_oib: maskOIB(issuerOIB), // MASKED
  amount: amount // NOT masked
}, 'Invoice processed');
```

**Log Retention:**
- **Service logs (stdout):** **90 days** (via journald or log aggregator)
- **Audit logs (Kafka):** **11 years** (regulatory requirement)
- **Debug logs:** **7 days** (high volume, low value)

---

### 2.3 Distributed Tracing (Jaeger)

**Requirement:** ALL services MUST propagate trace context and create spans

**Why:** Complete end-to-end visibility (15+ service hops in B2C pipeline)

**Standard:** W3C Trace Context (`traceparent` header)

**Sampling Rate:**
- **Staging:** **100%** (full visibility, low traffic)
- **Production:** **100%** (ISO 9000 traceability + regulatory compliance)

**Why 100% in production:** Invoice processing is legally binding financial documents requiring complete audit trail.

#### Implementation (OpenTelemetry)

**Setup:**

```typescript
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';

const provider = new NodeTracerProvider({
  resource: new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: process.env.SERVICE_NAME
  })
});

const exporter = new JaegerExporter({
  endpoint: 'http://jaeger:14268/api/traces'
});

provider.addSpanProcessor(
  new BatchSpanProcessor(exporter)
);

provider.register();

const tracer = trace.getTracer('eracun');
```

**Creating Spans:**

```typescript
import { trace, context, propagation } from '@opentelemetry/api';

async function validateXSD(xmlContent: string, requestContext: RequestContext) {
  // Extract parent trace from W3C traceparent header
  const parentContext = propagation.extract(context.active(), {
    traceparent: requestContext.request_id
  });

  const span = tracer.startSpan('xsd_validation', {
    attributes: {
      'invoice.id': requestContext.invoice_id,
      'validation.type': 'xsd',
      'xml.size': xmlContent.length
    }
  }, parentContext);

  try {
    const result = await performValidation(xmlContent);

    span.setAttributes({
      'validation.result': result.isValid ? 'valid' : 'invalid',
      'validation.errors': result.errors.length
    });

    return result;
  } catch (error) {
    span.recordException(error);
    span.setStatus({ code: SpanStatusCode.ERROR });
    throw error;
  } finally {
    span.end();
  }
}
```

**Propagating Trace Context (RabbitMQ):**

```typescript
// Producer: Inject trace context into message
const traceContext = {};
propagation.inject(context.active(), traceContext);

await rabbitMQ.publish('validation-queue', {
  invoice_id: invoiceId,
  xml_content: xmlContent,
  trace_context: traceContext // MANDATORY: Propagate trace
});

// Consumer: Extract trace context from message
const parentContext = propagation.extract(context.active(), message.trace_context);

context.with(parentContext, () => {
  // All spans created here will be children of parent trace
  validateXSD(message.xml_content);
});
```

---

### 2.4 Alerting (Prometheus Alertmanager + Grafana OnCall)

**Requirement:** Define alert rules for critical conditions

**Alerting Stack:**
- **Prometheus Alertmanager** (open source, rule-based)
- **Grafana OnCall** (open source, on-call scheduling, NOT PagerDuty)

**Alert Severity Levels:**

| Level | Response Time | Notification Method | Examples |
|-------|---------------|---------------------|----------|
| **P0 (Critical)** | Immediate (page on-call) | Phone call, SMS, push | FINA submission timeout, archive failure, database down |
| **P1 (High)** | 15 minutes | SMS, push, email | High error rate, circuit breaker open, DLQ backlog |
| **P2 (Medium)** | Next business day | Email, Slack | OCR low confidence, slow queries |

**Example Alert Rules (`/etc/prometheus/alerts.yml`):**

```yaml
groups:
  - name: eracun_alerts
    interval: 30s
    rules:
      # P0: Archive failure (CRITICAL - regulatory risk)
      - alert: ArchiveFailure
        expr: |
          increase(archive_errors_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
          service: archive-service
        annotations:
          summary: "Invoice submitted but not archived (regulatory violation)"
          description: "{{ $value }} invoices failed to archive in last 5 minutes"
          runbook: "https://docs.eracun.hr/runbooks/archive-failure"

      # P0: FINA submission timeout
      - alert: FINASubmissionTimeout
        expr: |
          rate(fina_submission_errors_total{error_type="timeout"}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
          service: fina-soap-connector
        annotations:
          summary: "FINA API timing out consistently"
          description: "{{ $value }} FINA timeouts per second"
          runbook: "https://docs.eracun.hr/runbooks/fina-timeout"

      # P1: High validation error rate
      - alert: HighValidationErrorRate
        expr: |
          rate(validation_errors_total[5m]) / rate(validation_total[5m]) > 0.05
        for: 5m
        labels:
          severity: high
          service: validation-pipeline
        annotations:
          summary: "More than 5% of invoices failing validation"
          description: "{{ $value }} error rate"

      # P1: Circuit breaker open
      - alert: CircuitBreakerOpen
        expr: |
          circuit_breaker_open == 1
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "Circuit breaker open for {{ $labels.service }}"
          description: "External dependency unavailable"

      # P2: OCR low confidence
      - alert: OCRLowConfidence
        expr: |
          histogram_quantile(0.5, rate(ocr_confidence_bucket[10m])) < 0.8
        for: 10m
        labels:
          severity: medium
          service: ocr-service
        annotations:
          summary: "OCR confidence below 80% (median)"
          description: "Poor quality scans or OCR model degradation"
```

---

### 2.5 Health Checks

**Requirement:** ALL services MUST expose `/health` and `/ready` endpoints

**Health Check:**
- **Path:** `/health`
- **Purpose:** Is the service running?
- **Response:** HTTP 200 (always, unless process crashed)

**Readiness Check:**
- **Path:** `/ready`
- **Purpose:** Can the service handle requests?
- **Response:** HTTP 200 (ready) or 503 (not ready)
- **Checks:** Database connection, RabbitMQ connection, critical dependencies

**systemd Integration:**

```ini
[Service]
# Health check before starting dependent services
ExecStartPre=/usr/bin/curl -f http://localhost:8080/health || exit 1

# Restart if health check fails
Restart=on-failure
RestartSec=10s
```

**Kubernetes Probes (Future):**

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5
```

---

## 3. Compliance Standards

### 3.1 Audit Logging

**Requirement:** ALL state changes and PII access MUST be logged to audit trail

**Audit Log Destination:** Kafka topic `eracun.audit-log` (11-year retention)

#### What to Audit

**MANDATORY Audit Events:**
1. **State Changes:** Every invoice state transition (RECEIVED → PARSED → ... → ARCHIVED)
2. **PII Access:** Every SELECT on OIB, company names, contact info
3. **FINA/AS4 Submissions:** Every submission attempt (success or failure)
4. **Manual Corrections:** Every human intervention (admin portal)
5. **Authentication Events:** All login/logout attempts
6. **Configuration Changes:** Any change to service configuration
7. **Certificate Operations:** Certificate issuance, renewal, revocation

**Audit Log Format:**

```typescript
interface AuditLogEntry {
  timestamp: string;          // ISO 8601
  event_type: string;         // "state_change", "pii_access", "submission", etc.
  service: string;            // Service that generated event
  actor: string;              // Service or user ID
  action: string;             // "SELECT", "UPDATE", "SUBMIT", etc.
  resource_type: string;      // "invoice", "certificate", "config"
  resource_id: string;        // Invoice ID, cert serial, etc.
  old_state?: string;         // Before state (if applicable)
  new_state?: string;         // After state (if applicable)
  success: boolean;           // Did action succeed?
  error_message?: string;     // If failed, why?
  ip_address?: string;        // Source IP (if applicable)
  user_agent?: string;        // User agent (if applicable)
  additional_context: Record<string, any>; // Extra fields
}
```

**Example Audit Logs:**

```typescript
// State change
{
  "timestamp": "2025-11-10T14:32:18.123Z",
  "event_type": "state_change",
  "service": "xsd-validator",
  "actor": "xsd-validator",
  "action": "VALIDATE",
  "resource_type": "invoice",
  "resource_id": "550e8400-e29b-41d4-a716-446655440000",
  "old_state": "PARSING",
  "new_state": "VALIDATING",
  "success": true,
  "additional_context": {
    "validation_type": "xsd",
    "schema_version": "UBL-2.1"
  }
}

// PII access
{
  "timestamp": "2025-11-10T14:32:20.456Z",
  "event_type": "pii_access",
  "service": "admin-portal-api",
  "actor": "user-12345",
  "action": "SELECT",
  "resource_type": "invoice",
  "resource_id": "550e8400-e29b-41d4-a716-446655440000",
  "success": true,
  "ip_address": "192.168.1.100",
  "additional_context": {
    "fields_accessed": ["issuer_oib", "recipient_oib", "company_name"]
  }
}

// FINA submission
{
  "timestamp": "2025-11-10T14:32:25.789Z",
  "event_type": "submission",
  "service": "fina-soap-connector",
  "actor": "fina-soap-connector",
  "action": "SUBMIT",
  "resource_type": "invoice",
  "resource_id": "550e8400-e29b-41d4-a716-446655440000",
  "success": true,
  "additional_context": {
    "destination": "FINA_SOAP",
    "jir": "f5e8d9a7-b2c4-4f3e-a1d6-9c7b5e4a3d2c",
    "response_time_ms": 1823
  }
}
```

**Implementation:**

```typescript
import { Kafka } from 'kafkajs';

const kafka = new Kafka({
  clientId: 'audit-logger',
  brokers: ['kafka:9092']
});

const producer = kafka.producer();

async function logAudit(entry: AuditLogEntry) {
  await producer.send({
    topic: 'eracun.audit-log',
    messages: [{
      key: entry.resource_id, // Partition by resource ID
      value: JSON.stringify(entry),
      timestamp: Date.now().toString()
    }]
  });
}

// Usage
await logAudit({
  timestamp: new Date().toISOString(),
  event_type: 'state_change',
  service: 'xsd-validator',
  actor: 'xsd-validator',
  action: 'VALIDATE',
  resource_type: 'invoice',
  resource_id: invoiceId,
  old_state: 'PARSING',
  new_state: 'VALIDATING',
  success: true,
  additional_context: {}
});
```

**Immutability:**
- Audit logs are **append-only** (never UPDATE or DELETE)
- Kafka topic configured with `cleanup.policy=compact` (keeps all records)
- Tampering detection via cryptographic signatures (future enhancement)

---

### 3.2 Data Retention

**Service Logs:** **90 days** (operational debugging)
**Audit Logs:** **11 years** (Croatian Tax Authority requirement)
**Metrics:** **30 days** (Prometheus default)
**Traces:** **7 days** (Jaeger storage)

**Regulatory Archiving (11 Years):**
- Original XML invoices (UBL 2.1)
- Digital signatures (XMLDSig)
- Qualified timestamps (eIDAS)
- Submission confirmations (JIR for B2C, MDN for B2B)
- Audit trail (all state transitions)

**Implementation:**

```typescript
// Archive service: Set 11-year retention
const elevenYearsFromNow = Date.now() + (11 * 365 * 24 * 60 * 60 * 1000);

await s3.send(new PutObjectCommand({
  Bucket: 'eracun-archive',
  Key: `invoices/${invoiceId}.xml`,
  Body: xmlContent,
  Metadata: {
    'retention-expires-at': elevenYearsFromNow.toString(),
    'jir': jir,
    'submission-date': new Date().toISOString()
  },
  ServerSideEncryption: 'AES256'
}));
```

**Deletion Policy:**
- **NEVER delete audit logs** (11-year retention)
- **NEVER delete archived invoices** (11-year retention)
- Service logs auto-expire after 90 days (journald/log aggregator)
- Metrics auto-expire after 30 days (Prometheus)

---

### 3.3 GDPR & Croatian Law

**Key Decision:** Croatian Tax Authority 11-year retention **overrides** GDPR "right to erasure"

**Legal Basis:** Croatian Fiscalization Law (NN 89/25) mandates 11-year invoice retention. Tax law takes precedence over GDPR for financial records.

**What This Means:**
- ✅ We CAN store OIB, company names, invoice data for 11 years
- ✅ We CANNOT delete invoices before 11 years (even if user requests)
- ✅ We MUST inform users of 11-year retention (terms of service)
- ❌ We CANNOT use "GDPR right to erasure" as excuse to delete invoices

**GDPR Compliance Actions:**
1. **Privacy Policy:** Clearly state 11-year retention requirement
2. **User Consent:** Obtain consent for data processing (implicit via invoice submission)
3. **Data Minimization:** Only collect necessary invoice data (no tracking cookies, analytics)
4. **Access Rights:** Users can request their invoice data (retrieval-service)
5. **Breach Notification:** 72-hour notification if data breach occurs

---

### 3.4 Regulatory Mapping (Croatian Fiskalizacija)

**ADR-003 Section 4** (Processing Pipelines) defines complete regulatory mapping. Key points:

| Regulatory Requirement | Technical Implementation | Service Responsible |
|------------------------|-------------------------|---------------------|
| **UBL 2.1 Format** | XML generation with Croatian CIUS extensions | ubl-transformer |
| **Digital Signature** | XMLDSig with FINA X.509 certificate | digital-signature-service |
| **Qualified Timestamp** | eIDAS-compliant timestamp for B2B | timestamp-service |
| **KPD Classification** | 6-digit KLASUS 2025 product codes | kpd-validator |
| **OIB Validation** | Checksum algorithm, issuer + recipient | oib-validator |
| **11-Year Archiving** | S3 storage with AES-256 encryption | archive-service |
| **5-Day Fiscalization** | Invoice state tracking, deadline alerts | State machine + alerting |
| **B2C Submission** | SOAP API to FINA | fina-soap-connector |
| **B2B Submission** | AS4 protocol to recipient Access Point | as4-gateway-sender |

---

## 4. Implementation Checklist

### 4.1 Definition of Done (Per Service)

Before marking a service "complete," verify:

**Security:**
- [ ] mTLS configured (production) or token auth (dev/staging)
- [ ] All external input validated (size limits, sanitization)
- [ ] PII masked in all logs
- [ ] Secrets loaded via SOPS (not hardcoded)
- [ ] TLS 1.2+ for all network communication

**Observability:**
- [ ] `/health` and `/ready` endpoints implemented
- [ ] Prometheus metrics exposed on `/metrics` (port 9090)
- [ ] Structured JSON logs to stdout (with mandatory fields)
- [ ] OpenTelemetry tracing integrated (W3C Trace Context)
- [ ] Alert rules defined for critical conditions

**Compliance:**
- [ ] All state changes logged to audit trail (Kafka)
- [ ] PII access logged to audit trail
- [ ] 11-year retention for archived invoices
- [ ] 90-day retention for service logs
- [ ] GDPR privacy policy updated (if user-facing)

**Testing:**
- [ ] Unit tests (100% coverage per CLAUDE.md)
- [ ] Integration tests (contract tests with upstream/downstream)
- [ ] Load tests (can handle expected throughput)
- [ ] Security tests (input validation, injection attacks)

**Documentation:**
- [ ] Service CLAUDE.md complete (15 sections)
- [ ] API contract defined (Protocol Buffers)
- [ ] Runbook created (failure scenarios, recovery procedures)
- [ ] Metrics dashboard created (Grafana)

---

### 4.2 Code Review Checklist

**Security Review:**
- [ ] No hardcoded secrets (grep for "password", "key", "secret")
- [ ] All database queries parameterized (no SQL injection)
- [ ] XML parsing has XXE protection disabled
- [ ] File size limits enforced (10MB max)
- [ ] Rate limiting on external-facing endpoints

**Observability Review:**
- [ ] All errors logged with context (no silent failures)
- [ ] PII masked before logging (OIB, names)
- [ ] Metrics have meaningful labels (not high-cardinality)
- [ ] Trace context propagated (RabbitMQ messages, gRPC calls)
- [ ] Health checks verify actual dependencies (not just HTTP 200)

**Compliance Review:**
- [ ] Audit logs for all state changes (immutable, Kafka)
- [ ] No DELETE operations on invoices (11-year retention)
- [ ] Archived invoices include JIR/MDN (submission proof)
- [ ] Certificate expiration monitored (30 days before expiry)

---

### 4.3 Pre-Production Readiness

**Before deploying to production:**

1. **Security Scan:**
   - [ ] Run Snyk or Trivy (vulnerability scanning)
   - [ ] Penetration test completed (external-facing APIs)
   - [ ] Certificate expiration monitored (Alertmanager rule)

2. **Load Testing:**
   - [ ] Service can handle expected throughput (100-10,000 invoices/hour)
   - [ ] Circuit breakers tested (simulate FINA/AS4 down)
   - [ ] DLQ processing tested (inject failures, verify recovery)

3. **Observability Validation:**
   - [ ] Metrics dashboard created in Grafana
   - [ ] Alert rules tested (trigger test alerts, verify notifications)
   - [ ] Distributed tracing end-to-end (verify trace propagation through 15+ services)

4. **Compliance Validation:**
   - [ ] Audit log query tested (retrieve all events for invoice ID)
   - [ ] Archive restoration tested (can retrieve + verify signature after 11 years?)
   - [ ] GDPR privacy policy reviewed (11-year retention disclosed)

5. **Disaster Recovery:**
   - [ ] Backup/restore procedures tested (PostgreSQL, Kafka)
   - [ ] Runbooks tested (simulate FINA down, follow runbook, verify recovery)
   - [ ] On-call rotation configured (Grafana OnCall)

---

## 5. Reference Examples

### 5.1 TypeScript Service Template

**File:** `/services/example-service/src/index.ts`

```typescript
import express from 'express';
import pino from 'pino';
import { register, Counter, Histogram } from 'prom-client';
import { trace, context, propagation } from '@opentelemetry/api';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';

// Initialize logger
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  base: { service: process.env.SERVICE_NAME || 'unknown' }
});

// Initialize tracing
const provider = new NodeTracerProvider();
provider.register();
const tracer = trace.getTracer('eracun');

// Initialize metrics
const httpRequestsTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'path', 'status_code']
});

const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request latency',
  labelNames: ['method', 'path', 'status_code']
});

// Express app
const app = express();
app.use(express.json({ limit: '10mb' }));

// Metrics middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    httpRequestsTotal.inc({ method: req.method, path: req.route?.path || req.path, status_code: res.statusCode });
    httpRequestDuration.observe({ method: req.method, path: req.route?.path || req.path, status_code: res.statusCode }, duration);
  });
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Readiness check
app.get('/ready', async (req, res) => {
  const dbHealthy = await checkDatabase();
  if (dbHealthy) {
    res.status(200).json({ status: 'ready' });
  } else {
    res.status(503).json({ status: 'not ready' });
  }
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// Business logic endpoint
app.post('/validate', async (req, res) => {
  const span = tracer.startSpan('validate_request');

  try {
    const { invoice_id, xml_content } = req.body;

    logger.info({ invoice_id }, 'Validation request received');

    const result = await performValidation(xml_content);

    logger.info({ invoice_id, result: result.isValid ? 'valid' : 'invalid' }, 'Validation completed');

    res.status(200).json(result);
  } catch (error) {
    span.recordException(error);
    logger.error({ error: error.message }, 'Validation failed');
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    span.end();
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  logger.info({ port: PORT }, 'Service started');
});
```

---

### 5.2 systemd Unit Template

**File:** `/deployment/systemd/eracun-example-service.service`

```ini
[Unit]
Description=eRacun Example Service
After=network-online.target rabbitmq.service postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=eracun
Group=eracun
WorkingDirectory=/opt/eracun/services/example-service

# Environment files (precedence: later overrides earlier)
EnvironmentFile=/etc/eracun/platform.conf
EnvironmentFile=/etc/eracun/environment.conf
EnvironmentFile=/etc/eracun/services/example-service.conf

# Decrypt secrets before starting (see ADR-002)
ExecStartPre=/usr/local/bin/decrypt-secrets.sh example-service

# Load secrets from tmpfs
EnvironmentFile=/run/eracun/secrets.env

# Start service
ExecStart=/usr/local/bin/node dist/index.js

# Restart policy
Restart=on-failure
RestartSec=10s

# Security hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=
SystemCallFilter=@system-service
InaccessiblePaths=/etc/eracun/.age-key

# Resource limits
MemoryMax=512M
CPUQuota=100%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=eracun-example-service

[Install]
WantedBy=multi-user.target
```

---

## 6. Decision Record

### Why 100% Trace Sampling (Not 10%)?

**Decision:** 100% trace sampling in production

**Rationale:**
- Invoice processing is **legally binding financial documents** (need complete audit trail)
- Throughput is manageable (100-10,000 invoices/hour, not millions/second)
- ISO 9000 quality management requires **full traceability**
- Croatian Tax Authority audits need **complete evidence chain**
- Cost is acceptable (7-day retention, ~100GB storage)

**Alternatives Considered:**
- 10% sampling (rejected: breaks audit trail, missing 90% of invoices)
- Adaptive sampling (rejected: complexity not justified for low throughput)

---

### Why mTLS (Not JWT)?

**Decision:** mTLS for production service-to-service authentication

**Rationale:**
- **Most robust** authentication mechanism (cryptographic proof of identity)
- **Zero external dependencies** (no auth server required)
- **Works natively on Linux** with OpenSSL
- **Mutual authentication** (both client and server verify each other)
- **Certificate rotation** built into `certificate-lifecycle-manager`

**Alternatives Considered:**
- JWT tokens (rejected: requires auth server, adds single point of failure)
- API keys (rejected: less secure, no mutual authentication)

---

### Why Grafana OnCall (Not PagerDuty)?

**Decision:** Grafana OnCall for alerting

**Rationale:**
- **Open source** (free, self-hosted, aligns with "open source preferred")
- **Integrates with Prometheus** Alertmanager (already using Prometheus)
- **Robust on-call scheduling** (rotations, escalations)
- **Terminal-based CLI** (grafana-oncall CLI)

**Alternatives Considered:**
- PagerDuty (rejected: expensive, proprietary, not self-hosted)
- OpsGenie (rejected: proprietary)
- Email-only (rejected: not robust for P0 alerts)

---

## 7. Compliance Matrix

| Regulation | Requirement | Technical Control | Service | Verification |
|-----------|-------------|------------------|---------|--------------|
| **Croatian Fiscalization Law (NN 89/25)** | 11-year invoice retention | S3 storage with metadata | archive-service | Monthly signature verification job |
| **Croatian Fiscalization Law** | Digital signature (XMLDSig) | FINA X.509 certificate | digital-signature-service | Certificate expiration alerts (30 days before) |
| **Croatian Fiscalization Law** | UBL 2.1 format | XML generation with CIUS extensions | ubl-transformer | XSD validation (xsd-validator) |
| **Croatian Fiscalization Law** | KPD classification | KLASUS 2025 product codes | kpd-validator | DZS registry sync (daily) |
| **GDPR** | Data minimization | Only collect invoice data | All services | No tracking cookies, no analytics |
| **GDPR** | Right to access | User can request invoice data | retrieval-service | API endpoint + audit log |
| **GDPR** | Breach notification | 72-hour notification | Incident response plan | Alert rules + on-call |
| **ISO 9000 (Traceability)** | Complete audit trail | 100% trace sampling + audit logs | Jaeger + Kafka | End-to-end trace verification |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-11-10 | Initial standard (security, observability, compliance) |

---

**Last Updated:** 2025-11-10
**Review Cadence:** Quarterly (or after major incidents)
**Owner:** System Architect
