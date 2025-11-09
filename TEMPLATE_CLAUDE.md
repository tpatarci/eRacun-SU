# [SERVICE_NAME] - Service Specification

**Service Category:** [LAYER] (Ingestion / Validation / Transformation / Integration / Storage / Orchestration)
**Service Path:** `services/[layer]/[service-name]/`
**Target LOC:** [TARGET] (excluding tests)
**Last Updated:** [DATE]
**Specification Version:** 1.0.0

---

## CRITICAL CONTEXT

**⚠️ MANDATORY READING BEFORE DEVELOPMENT:**
1. `/CLAUDE.md` - Platform-wide architecture and compliance requirements
2. `/CROATIAN_COMPLIANCE.md` - Complete regulatory specifications
3. `/TBD.md` - Open architectural decisions and research status
4. `/docs/MONOREPO_STRUCTURE.md` - Service decomposition rationale

**This service is part of a mission-critical five-nines availability system handling legally binding financial documents. Zero tolerance for:**
- Data corruption or loss
- Regulatory non-compliance
- Silent failures
- Incomplete error handling

---

## 1. SERVICE MISSION

### 1.1 Primary Responsibility

**Single Sentence Description:**
[One sentence describing what this service does - e.g., "Validates XML documents against UBL 2.1 XSD schema for syntactic correctness"]

**Business Value:**
[Why this service exists - what business/regulatory need it fulfills]

**Bounded Context:**
[What is IN scope for this service - clear boundaries]

**Explicitly OUT of Scope:**
[What this service does NOT do - prevent scope creep]

---

### 1.2 Regulatory Mapping

**Applicable Regulations:**
[Which sections of CROATIAN_COMPLIANCE.md apply to this service]

**Compliance Requirements:**
- [ ] [Specific regulation requirement 1]
- [ ] [Specific regulation requirement 2]
- [ ] [...]

**Non-Compliance Consequences:**
[Financial penalties, legal liability, or technical failures if this service fails]

---

## 2. FUNCTIONAL REQUIREMENTS

### 2.1 Input Specification

**Input Method:** [gRPC / Event Subscription / REST API / File-based]

**Input Contract:**
```protobuf
[Exact Protocol Buffer definition OR OpenAPI spec]

Example:
service XSDValidator {
  rpc Validate(XMLDocument) returns (ValidationResult);
}

message XMLDocument {
  bytes xml_content = 1;
  string schema_version = 2; // "UBL-2.1"
  map<string, string> metadata = 3;
}
```

**Input Validation Rules:**
- [ ] **Size limits:** [e.g., Max 10MB per document]
- [ ] **Required fields:** [List all mandatory fields]
- [ ] **Format constraints:** [e.g., UTF-8 encoding only]
- [ ] **Schema version:** [e.g., Must be "UBL-2.1" or "CII-2.0"]

**Invalid Input Handling:**
```
IF [condition] THEN [action]

Example:
IF xml_content > 10MB THEN return ERROR_TOO_LARGE (413)
IF schema_version unknown THEN return ERROR_UNSUPPORTED_SCHEMA (400)
IF xml_content not UTF-8 THEN return ERROR_INVALID_ENCODING (400)
```

**Idempotency:**
- [ ] **Key generation:** [How to generate idempotency key]
- [ ] **Duplicate detection:** [How to detect duplicate requests]
- [ ] **Idempotent response:** [Return same result for duplicate requests]

---

### 2.2 Processing Logic

**Step-by-Step Algorithm:**

```
1. [STEP NAME]
   Input: [what data is needed]
   Output: [what is produced]
   Error handling: [what errors can occur, how to handle]

   Pseudocode:
   [Precise logic description]

2. [NEXT STEP]
   ...
```

**Business Rules:**
[List all business rules this service must enforce]

**Example:**
```
RULE BR-001: OIB Checksum Validation
- Input: 11-digit OIB string
- Algorithm: ISO 7064, MOD 11-10
- Validation:
  - Sum = Σ(digit[i] * weight[i]) where weight = [10,9,8,7,6,5,4,3,2]
  - Checksum = (10 - (Sum mod 10)) mod 10
  - MUST equal digit[10]
- Error if invalid: ERROR_INVALID_OIB_CHECKSUM
- Reference: Croatian Tax Authority OIB specification
```

**Decision Tables:**
[For complex conditional logic, use decision tables]

| Condition 1 | Condition 2 | Condition 3 | Action | Error Code |
|-------------|-------------|-------------|--------|------------|
| [example]   | [example]   | [example]   | [example] | [example] |

---

### 2.3 Output Specification

**Output Method:** [gRPC Response / Event Publication / REST Response / File write]

**Output Contract:**
```protobuf
[Exact Protocol Buffer definition OR OpenAPI spec]

Example:
message ValidationResult {
  bool is_valid = 1;
  repeated ValidationError errors = 2;
  google.protobuf.Duration processing_time = 3;
  string validation_id = 4; // for audit trail
}

message ValidationError {
  string xpath = 1;           // location in XML
  string error_code = 2;      // machine-readable
  string message = 3;         // human-readable
  Severity severity = 4;      // ERROR, WARNING
}

enum Severity {
  ERROR = 0;    // Blocks fiscalization
  WARNING = 1;  // Proceed with caution
}
```

**Output Guarantees:**
- [ ] **Completeness:** [All required fields always populated]
- [ ] **Determinism:** [Same input = same output]
- [ ] **Ordering:** [If applicable, output order guarantees]
- [ ] **Timing:** [Response time SLA - e.g., <100ms p95]

**Error Response Format:**
```protobuf
message ErrorResponse {
  string error_code = 1;        // e.g., "INVALID_XML_SYNTAX"
  string message = 2;           // Human-readable
  map<string, string> details = 3; // Context (e.g., line number)
  string request_id = 4;        // For debugging
  google.protobuf.Timestamp timestamp = 5;
}
```

---

### 2.4 Error Taxonomy

**All possible error codes this service can return:**

| Error Code | HTTP/gRPC Code | Severity | Description | Retry? | User Action |
|------------|----------------|----------|-------------|--------|-------------|
| [CODE_1] | [e.g., 400] | [ERROR/WARN] | [Description] | [YES/NO] | [What user should do] |
| [CODE_2] | ... | ... | ... | ... | ... |

**Example:**
| ERROR_INVALID_XML_SYNTAX | 400 (INVALID_ARGUMENT) | ERROR | XML is not well-formed | NO | Fix XML syntax and resubmit |
| ERROR_SCHEMA_NOT_FOUND | 500 (INTERNAL) | ERROR | XSD schema file missing | YES (transient) | Contact support if persists |
| WARN_DEPRECATED_FIELD | 200 (OK) | WARNING | Using deprecated field | N/A | Update to new field name |

---

## 3. NON-FUNCTIONAL REQUIREMENTS

### 3.1 Performance

**Response Time SLAs:**
- p50: [e.g., <50ms]
- p95: [e.g., <100ms]
- p99: [e.g., <200ms]
- p99.9: [e.g., <500ms]

**Throughput:**
- Target: [e.g., 1000 requests/second]
- Peak: [e.g., 5000 requests/second]

**Resource Limits:**
- CPU: [e.g., 500m cores sustained, 2 cores burst]
- Memory: [e.g., 256MB sustained, 512MB burst]
- Disk I/O: [e.g., 100 IOPS]
- Network: [e.g., 10 Mbps]

**Scalability:**
- Horizontal scaling: [YES/NO - if yes, how many replicas]
- Scaling trigger: [e.g., CPU > 70% for 5min]
- Stateless: [YES/NO - if stateful, explain state management]

---

### 3.2 Reliability

**Availability Target:** 99.99% (52 minutes downtime/year)

**Failure Modes:**
[All ways this service can fail and mitigation strategies]

| Failure Mode | Probability | Impact | Detection | Mitigation | Recovery Time |
|--------------|-------------|--------|-----------|------------|---------------|
| [example] | [HIGH/MED/LOW] | [severity] | [how to detect] | [what to do] | [RTO] |

**Example:**
| XSD schema file corrupted | LOW | HIGH (all validations fail) | Health check fails on startup | Reload from S3 backup | <1 minute |
| Out of memory | MEDIUM | HIGH (service crash) | Kubernetes OOMKilled | Restart pod, investigate leak | <30 seconds |

**Circuit Breaker:**
- [ ] **Enabled:** [YES/NO]
- [ ] **Threshold:** [e.g., 5 consecutive failures]
- [ ] **Timeout:** [e.g., 30 seconds open, then half-open]
- [ ] **Fallback:** [What happens when circuit is open]

**Retry Policy:**
- [ ] **Transient errors:** [Which errors are retryable]
- [ ] **Max attempts:** [e.g., 3]
- [ ] **Backoff strategy:** [Exponential: 1s, 2s, 4s]
- [ ] **Jitter:** [Add random 0-500ms to prevent thundering herd]

**Health Checks:**
```yaml
Liveness Probe:
  - Check: [e.g., HTTP GET /health/live]
  - Interval: [e.g., 10s]
  - Timeout: [e.g., 1s]
  - Failure threshold: [e.g., 3 consecutive failures = restart]

Readiness Probe:
  - Check: [e.g., HTTP GET /health/ready]
  - Criteria: [e.g., Can load XSD schema, Can connect to dependencies]
  - Interval: [e.g., 5s]
  - Timeout: [e.g., 1s]
  - Failure threshold: [e.g., 1 failure = remove from load balancer]
```

---

### 3.3 Security

**Authentication:**
- [ ] **Method:** [mTLS / OAuth 2.0 JWT / API Key / None (internal only)]
- [ ] **Credentials storage:** [Kubernetes Secret / Vault]
- [ ] **Rotation policy:** [e.g., Every 90 days]

**Authorization:**
- [ ] **RBAC model:** [Describe roles and permissions]
- [ ] **Least privilege:** [Service can only access what it needs]

**Input Sanitization:**
- [ ] **XML External Entity (XXE) attacks:** [DISABLED]
- [ ] **Billion laughs attack:** [Max entity expansion limit]
- [ ] **Size limits enforced:** [Before parsing]
- [ ] **SQL injection:** [N/A if no database / Use parameterized queries]

**Secrets Management:**
- [ ] **No hardcoded secrets:** [All secrets from env vars or Vault]
- [ ] **Audit logging:** [All secret access logged]

**Cryptography:**
[If this service does crypto operations]
- [ ] **Algorithm:** [e.g., SHA-256 with RSA]
- [ ] **Key size:** [e.g., 2048-bit minimum]
- [ ] **Library:** [e.g., OpenSSL 3.0+]
- [ ] **FIPS 140-2 compliance:** [If required]

---

### 3.4 Observability

**Logging:**
```json
Standard Log Format (JSON):
{
  "timestamp": "2026-01-15T10:23:45.123Z",
  "level": "INFO",
  "service": "[service-name]",
  "request_id": "uuid",
  "message": "Validation completed",
  "duration_ms": 45,
  "result": "valid",
  "context": {
    "schema_version": "UBL-2.1",
    "document_size_bytes": 12345
  }
}
```

**Log Levels:**
- **ERROR:** [When to use - e.g., validation failed due to service error]
- **WARN:** [When to use - e.g., deprecated field used]
- **INFO:** [When to use - e.g., successful validation]
- **DEBUG:** [When to use - e.g., detailed validation steps]

**Do NOT log:**
- Personally identifiable information (PII)
- Passwords, API keys, tokens
- Full invoice content (only metadata)

**Metrics (Prometheus format):**
```
# Request counter
[service_name]_requests_total{status="success|error", error_code="..."}

# Response time histogram
[service_name]_request_duration_seconds{quantile="0.5|0.95|0.99"}

# In-flight requests gauge
[service_name]_requests_in_progress

# Error rate
[service_name]_errors_total{error_code="..."}

# Business metrics (service-specific)
[service_name]_validations_total{schema_version="UBL-2.1", result="valid|invalid"}
```

**Distributed Tracing:**
- [ ] **Trace ID propagation:** [From incoming request headers]
- [ ] **Span creation:** [One span per major operation]
- [ ] **Span attributes:** [Include schema_version, document_size, etc.]
- [ ] **Error recording:** [Mark span as error on failure]

**Alerting:**
[When should this service trigger alerts]

| Alert Name | Condition | Severity | Action |
|------------|-----------|----------|--------|
| [example] | [threshold] | [P0/P1/P2] | [what to do] |

**Example:**
| HighErrorRate | error_rate > 5% for 5min | P1 | Check logs, verify XSD schema files |
| ServiceDown | All pods crash | P0 | Page on-call, check resource limits |

---

## 4. DEPENDENCIES

### 4.1 External Dependencies

**Upstream Services:**
[Services this service CALLS]

| Service Name | Protocol | Endpoint | Purpose | Timeout | Retry | Fallback |
|--------------|----------|----------|---------|---------|-------|----------|
| [example] | [gRPC/REST] | [URL] | [why needed] | [ms] | [YES/NO] | [what if down] |

**Example:**
| kpd-validator | gRPC | kpd-validator:50051 | Validate KPD codes | 2s | YES (3x) | Proceed with warning |

**Downstream Services:**
[Services that CALL this service]

| Service Name | Expected Request Rate | Impact if This Service Fails |
|--------------|----------------------|------------------------------|
| [example] | [req/sec] | [description] |

**Example:**
| consensus-orchestrator | 100 req/sec | Validation pipeline blocked |

---

### 4.2 Data Dependencies

**Databases:**
[If this service uses a database]

| Database | Type | Purpose | Tables/Collections | Read/Write |
|----------|------|---------|-------------------|------------|
| [example] | [PostgreSQL/Redis/etc] | [why needed] | [list] | [R/W/Both] |

**Cache:**
[If this service uses caching]
- [ ] **Technology:** [Redis / In-memory]
- [ ] **TTL:** [e.g., 1 hour]
- [ ] **Eviction policy:** [e.g., LRU]
- [ ] **Cache invalidation:** [When/how to invalidate]

**File System:**
[If this service reads/writes files]

| File Type | Location | Purpose | Size | Update Frequency |
|-----------|----------|---------|------|------------------|
| [example] | [path] | [why] | [MB] | [daily/never/etc] |

**Example:**
| UBL-2.1.xsd | /app/schemas/ | XSD schema for validation | 2MB | Never (baked into image) |

---

### 4.3 Shared Libraries

**From `shared/`:**
- [ ] **types:** [Which Protocol Buffer definitions]
- [ ] **messaging:** [If publishes/subscribes to events]
- [ ] **validation-primitives:** [Which reusable validators]
- [ ] **crypto:** [Which crypto functions]
- [ ] **observability:** [Logging, tracing, metrics helpers]

**Third-Party Libraries:**
[External dependencies with versions]

| Library | Version | Purpose | License | Security Notes |
|---------|---------|---------|---------|----------------|
| [example] | [semver] | [why] | [MIT/Apache/etc] | [vulnerabilities?] |

**Example:**
| libxml2 | 2.11.5+ | XML parsing | MIT | CVE-XXXX patched in 2.11.5 |

---

## 5. INTEGRATION CONTRACTS

### 5.1 Synchronous API (gRPC/REST)

**Service Definition:**
```protobuf
[Complete .proto file OR OpenAPI 3.1 spec]

Include:
- Service name
- RPC methods
- All message types
- Comments explaining each field
```

**Example Request/Response:**
```json
Request:
{
  "xml_content": "<Invoice>...</Invoice>",
  "schema_version": "UBL-2.1"
}

Response (Success):
{
  "is_valid": true,
  "errors": [],
  "processing_time": "0.045s",
  "validation_id": "uuid"
}

Response (Failure):
{
  "is_valid": false,
  "errors": [
    {
      "xpath": "/Invoice/ID",
      "error_code": "MISSING_REQUIRED_FIELD",
      "message": "Invoice ID is mandatory",
      "severity": "ERROR"
    }
  ],
  "processing_time": "0.023s",
  "validation_id": "uuid"
}
```

---

### 5.2 Asynchronous Messaging (Events)

**Events This Service PUBLISHES:**

```protobuf
Event: [EventName]
Topic: [topic.name]
Schema:
message [EventName] {
  string event_id = 1;        // UUID
  string request_id = 2;       // Correlation ID
  google.protobuf.Timestamp created_at = 3;

  [... service-specific fields ...]
}

When published: [trigger condition]
Consumers: [list of services that consume this event]
Guarantee: [at-least-once / exactly-once / at-most-once]
Ordering: [ordered / unordered]
```

**Events This Service CONSUMES:**

```protobuf
Event: [EventName]
Topic: [topic.name]
Producer: [which service publishes this]
Processing: [what this service does with the event]
Idempotency: [how to handle duplicates]
Error handling: [what if processing fails]
Dead-letter queue: [after N failures, send to DLQ]
```

---

## 6. DATA MODELS

### 6.1 Internal Data Structures

[Define key data structures used internally]

```typescript
interface [StructureName] {
  field1: type;  // description
  field2: type;  // description
  // ...
}
```

**Validation Rules:**
- [ ] [Field constraints - e.g., `field1` must match regex `^[A-Z]{2}\d{9}$`]
- [ ] [Cross-field validation - e.g., `date_end` must be after `date_start`]

---

### 6.2 Database Schema

[If this service uses a database]

```sql
CREATE TABLE [table_name] (
  id UUID PRIMARY KEY,
  [field_name] [TYPE] [CONSTRAINTS],
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX [index_name] ON [table_name]([field]);
```

**Migrations:**
- [ ] **Strategy:** [e.g., Flyway, Liquibase, Alembic]
- [ ] **Backward compatibility:** [Can rollback without data loss?]

---

## 7. TESTING REQUIREMENTS

### 7.1 Unit Tests

**Target Coverage:** 85% minimum

**Test Categories:**
- [ ] **Happy path:** [All expected inputs produce correct outputs]
- [ ] **Edge cases:** [Empty input, max size, special characters, etc.]
- [ ] **Error cases:** [Invalid input, resource exhaustion, etc.]
- [ ] **Business rules:** [Each business rule has dedicated test]

**Test Structure:**
```typescript
describe('[FunctionName]', () => {
  describe('when [condition]', () => {
    it('should [expected behavior]', () => {
      // Arrange
      const input = ...;

      // Act
      const result = functionUnderTest(input);

      // Assert
      expect(result).toEqual(expected);
    });
  });
});
```

**Example Test Cases:**

```
TEST: validate_ubl_xml_valid
  Input: Valid UBL 2.1 XML (test_data/valid_invoice.xml)
  Expected: is_valid=true, errors=[]

TEST: validate_ubl_xml_missing_id
  Input: UBL XML without <cbc:ID> element
  Expected: is_valid=false, error_code="MISSING_REQUIRED_FIELD", xpath="/Invoice/cbc:ID"

TEST: validate_ubl_xml_too_large
  Input: 15MB XML file (exceeds 10MB limit)
  Expected: error_code="REQUEST_TOO_LARGE" before parsing
```

---

### 7.2 Integration Tests

**Test Scope:**
- [ ] **External API calls:** [Test against mock/test servers]
- [ ] **Database operations:** [Use Testcontainers]
- [ ] **Message bus:** [Test event publishing/consuming]

**Example Integration Tests:**

```
TEST: validate_with_real_xsd_schema
  Setup: Load actual UBL 2.1 XSD files
  Input: Sample invoices (valid and invalid)
  Verify: Correct validation results

TEST: publish_validation_completed_event
  Setup: Start mock message bus (Testcontainers RabbitMQ)
  Action: Complete validation
  Verify: Event published to correct topic with correct schema
```

---

### 7.3 Contract Tests

**Provider Contract Tests:**
[If this service provides an API]
- [ ] **Tool:** [Pact, Pactflow]
- [ ] **Consumers:** [List services that depend on this API]
- [ ] **Contract verification:** [CI pipeline step]

**Consumer Contract Tests:**
[If this service calls other APIs]
- [ ] **Providers:** [List services this depends on]
- [ ] **Mock providers:** [Use Pact mocks in tests]

---

### 7.4 Performance Tests

**Load Testing:**
```
Tool: [k6, Gatling, Locust]

Scenarios:
1. Normal load: [e.g., 100 req/sec for 10 minutes]
2. Peak load: [e.g., 1000 req/sec for 5 minutes]
3. Stress test: [e.g., Ramp up to failure point]

Success criteria:
- p95 latency < [threshold]
- Error rate < 0.1%
- No memory leaks
```

---

### 7.5 Chaos Testing

**Failure Injection:**
- [ ] **Network latency:** [Add 1s delay, service should timeout gracefully]
- [ ] **Dependency failure:** [Upstream service returns 500, should circuit break]
- [ ] **Resource exhaustion:** [Limit memory to 50MB, should handle gracefully]
- [ ] **CPU throttling:** [Limit to 100m cores, should slow but not crash]

---

## 8. DEPLOYMENT SPECIFICATION

### 8.1 Container Image

**Base Image:** [e.g., `node:20-alpine`, `python:3.11-slim`]

**Dockerfile Requirements:**
- [ ] **Multi-stage build:** [Separate build and runtime stages]
- [ ] **Non-root user:** [Run as UID 1000]
- [ ] **Minimal layers:** [Combine RUN commands]
- [ ] **Security scanning:** [Trivy in CI pipeline]

**Image Size Target:** < 200MB

**Example Dockerfile:**
```dockerfile
# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# Runtime stage
FROM node:20-alpine
RUN adduser -D -u 1000 appuser
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
USER appuser
EXPOSE 50051
CMD ["node", "dist/main.js"]
```

---

### 8.2 Kubernetes Deployment

**Manifest Requirements:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: [service-name]
  labels:
    app: [service-name]
    layer: [ingestion/validation/etc]
spec:
  replicas: [number]
  selector:
    matchLabels:
      app: [service-name]
  template:
    metadata:
      labels:
        app: [service-name]
    spec:
      containers:
      - name: [service-name]
        image: [registry]/[service-name]:[version]
        ports:
        - containerPort: [port]
          protocol: TCP
        env:
        - name: LOG_LEVEL
          value: "info"
        resources:
          requests:
            memory: "[e.g., 256Mi]"
            cpu: "[e.g., 500m]"
          limits:
            memory: "[e.g., 512Mi]"
            cpu: "[e.g., 2000m]"
        livenessProbe:
          httpGet:
            path: /health/live
            port: [port]
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: [port]
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: [service-name]
spec:
  selector:
    app: [service-name]
  ports:
  - protocol: TCP
    port: [port]
    targetPort: [port]
  type: ClusterIP
```

---

### 8.3 Configuration Management

**Environment Variables:**

| Variable | Required | Default | Description | Example |
|----------|----------|---------|-------------|---------|
| [VAR_NAME] | [YES/NO] | [value] | [purpose] | [example] |

**Example:**
| LOG_LEVEL | NO | info | Logging verbosity | debug, info, warn, error |
| XSD_SCHEMA_PATH | YES | /app/schemas | Directory containing XSD files | /app/schemas |
| GRPC_PORT | NO | 50051 | Port to listen on | 50051 |

**ConfigMap:**
[For non-sensitive configuration]
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: [service-name]-config
data:
  [key]: [value]
```

**Secrets:**
[For sensitive data]
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: [service-name]-secrets
type: Opaque
data:
  [key]: [base64-encoded-value]
```

---

### 8.4 Monitoring & Alerting

**Prometheus ServiceMonitor:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: [service-name]
spec:
  selector:
    matchLabels:
      app: [service-name]
  endpoints:
  - port: metrics
    interval: 15s
```

**Grafana Dashboard:**
- [ ] **Request rate panel** (requests/second)
- [ ] **Error rate panel** (errors/second, % of total)
- [ ] **Latency panel** (p50, p95, p99)
- [ ] **Resource usage panel** (CPU, memory)
- [ ] **Business metrics panel** [service-specific]

**Alerts:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: [service-name]-alerts
spec:
  groups:
  - name: [service-name]
    rules:
    - alert: HighErrorRate
      expr: rate([service_name]_errors_total[5m]) > 0.05
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High error rate in [service-name]"
        description: "Error rate is {{ $value }} req/sec"
```

---

## 9. RESEARCH REFERENCES

### 9.1 Standards & Specifications

**Primary Standards:**
[List all standards this service must comply with]

| Standard | Version | Section(s) | URL | Local Copy |
|----------|---------|------------|-----|------------|
| [example] | [version] | [relevant sections] | [official URL] | [path in repo] |

**Example:**
| UBL 2.1 | 2.1 | All | https://docs.oasis-open.org/ubl/UBL-2.1.html | docs/standards/UBL-2.1/ |
| EN 16931-1 | 2017 | Sections 3-7 | https://... | docs/standards/EN-16931/ |

---

### 9.2 API Documentation

**External APIs:**
[If this service integrates with external systems]

| API | Provider | Documentation URL | Authentication | Test Environment |
|-----|----------|-------------------|----------------|------------------|
| [example] | [company] | [URL] | [method] | [test endpoint] |

**Example:**
| SOAP Fiscalization | Porezna uprava | https://porezna.gov.hr/... | X.509 cert | https://cistest.apis-it.hr:8449 |

---

### 9.3 Domain Knowledge

**Required Expertise:**
[What domain knowledge is needed to develop this service]

- [ ] [Domain 1 - e.g., XML schema validation]
- [ ] [Domain 2 - e.g., Croatian tax law]
- [ ] [Domain 3 - e.g., Cryptographic signatures]

**Reference Materials:**
[Links to research documents, whitepapers, tutorials]

| Topic | Document | Location |
|-------|----------|----------|
| [example] | [title] | [path or URL] |

---

### 9.4 Test Data

**Sample Data Location:**
`services/[layer]/[service-name]/test-data/`

**Required Test Cases:**
- [ ] `valid_minimal.xml` - Smallest valid document
- [ ] `valid_full.xml` - All optional fields populated
- [ ] `invalid_missing_id.xml` - Missing required field
- [ ] `invalid_wrong_type.xml` - Field has wrong data type
- [ ] `invalid_too_large.xml` - Exceeds size limit
- [ ] `edge_case_special_chars.xml` - Unicode, Croatian characters (čćžšđ)

**Where to obtain samples:**
[Source of realistic test data]

---

## 10. DEVELOPMENT CHECKLIST

**Before writing ANY code, ensure:**

- [ ] This CLAUDE.md is complete (no [PLACEHOLDERS])
- [ ] All research references gathered and reviewed
- [ ] Input/output contracts validated with dependent services
- [ ] Test data prepared
- [ ] Protocol Buffers defined and generated
- [ ] Database schema designed (if applicable)
- [ ] Security review of requirements completed
- [ ] Performance benchmarks defined

**During development:**

- [ ] Write failing test first (TDD)
- [ ] Implement minimal code to pass test
- [ ] Refactor for clarity (no clever code)
- [ ] Run linter and type checker
- [ ] Update tests for edge cases
- [ ] Document public functions with examples
- [ ] No TODOs or FIXMEs in committed code

**Before committing:**

- [ ] All tests pass (unit + integration)
- [ ] Code coverage ≥ 85%
- [ ] No linter errors
- [ ] No security vulnerabilities (Snyk/Trivy)
- [ ] Docker image builds successfully
- [ ] Documentation updated (if API changed)
- [ ] Conventional commit message

**Before deploying:**

- [ ] Performance tests pass
- [ ] Load tests pass
- [ ] Chaos tests pass (if critical service)
- [ ] Monitoring dashboards configured
- [ ] Alerts configured
- [ ] Runbook written
- [ ] Staged rollout plan defined

---

## 11. FAILURE MODES & RUNBOOKS

### 11.1 Failure Scenarios

**Scenario: [Failure Description]**
```
Symptoms:
- [Observable symptom 1]
- [Observable symptom 2]

Root Cause:
[Why this happens]

Detection:
[How to detect - logs, metrics, alerts]

Resolution:
1. [Step 1]
2. [Step 2]
3. [Step 3]

Prevention:
[How to prevent in future]
```

---

### 11.2 Rollback Procedure

**If deployment fails:**
```
1. Check logs: kubectl logs -l app=[service-name] --tail=100
2. Check recent changes: git log --oneline -5
3. Rollback to previous version:
   kubectl rollout undo deployment/[service-name]
4. Verify rollback: kubectl rollout status deployment/[service-name]
5. Investigate root cause offline
```

---

### 11.3 Emergency Contacts

| Role | Name | Contact | Availability |
|------|------|---------|--------------|
| Service Owner | [TBD] | [email/phone] | [hours] |
| On-Call Engineer | [Rotation] | [PagerDuty] | 24/7 |
| Domain Expert | [TBD] | [email] | Business hours |

---

## 12. COMPLIANCE AUDIT TRAIL

**Regulatory Requirements Addressed:**

| Requirement ID | Description | Implementation | Test Coverage | Audit Evidence |
|----------------|-------------|----------------|---------------|----------------|
| [REG-001] | [requirement] | [how implemented] | [test file:line] | [log/metric/document] |

**Example:**
| CIUS-BR-001 | Invoice must have unique ID | Validated in validateInvoiceId() | test/validation.test.ts:45 | Logs show validation failure when ID missing |

---

## 13. OPEN QUESTIONS

**Unresolved Issues:**
[Anything unclear that needs stakeholder input BEFORE development starts]

| Question | Stakeholder | Blocking? | Target Resolution Date |
|----------|-------------|-----------|------------------------|
| [example] | [who to ask] | [YES/NO] | [date] |

---

## 14. VERSION HISTORY

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | [DATE] | [NAME] | Initial specification |

---

## 15. APPROVAL

**This specification must be approved before development begins.**

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Technical Lead | [TBD] | | |
| Product Owner | [TBD] | | |
| Compliance Officer | [TBD] | | |
| Security Engineer | [TBD] | | |

---

**END OF TEMPLATE**

**Instructions for using this template:**
1. Copy to `services/[layer]/[service-name]/CLAUDE.md`
2. Replace ALL `[PLACEHOLDERS]` with actual values
3. Delete sections not applicable (mark N/A if unsure)
4. Ensure NO placeholders remain before starting development
5. Get approvals from stakeholders
6. Keep updated as service evolves
