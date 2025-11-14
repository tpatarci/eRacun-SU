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

**⚠️ ELEVATED STANDARDS: This is a mission-critical five-nines system. Testing requirements are non-negotiable.**

**Target Coverage:** **100% line coverage, 100% branch coverage, 100% function coverage**

**Test Philosophy:**
- Zero untested code paths
- Every error condition explicitly tested
- Real data + mock data + mutated data
- Test with malicious inputs (fuzzing)
- Test under resource constraints
- Test with production-scale data volumes

---

### 7.1 Unit Tests

**Coverage Requirements:**
- [ ] **100% line coverage** - Every line executed in tests
- [ ] **100% branch coverage** - Every if/else, switch case tested
- [ ] **100% function coverage** - Every function called
- [ ] **Mutation testing score ≥95%** - Tests detect code mutations

**Test Categories (ALL MANDATORY):**

#### 7.1.1 Happy Path Tests
- [ ] **Minimal valid input** - Smallest possible valid request
- [ ] **Typical valid input** - Representative real-world data
- [ ] **Maximal valid input** - Largest allowed valid request
- [ ] **All optional fields populated** - Full feature coverage
- [ ] **All optional fields omitted** - Minimal feature coverage

#### 7.1.2 Edge Cases
- [ ] **Empty input** - "", null, undefined, empty arrays/objects
- [ ] **Boundary values** - Min/max integers, string lengths, array sizes
- [ ] **Off-by-one** - Exactly at limit, one below, one above
- [ ] **Special characters** - Unicode, Croatian (čćžšđ), emoji, control chars
- [ ] **Whitespace variations** - Leading/trailing spaces, tabs, newlines
- [ ] **Numeric edge cases** - Zero, negative, infinity, NaN, floating point precision
- [ ] **Date/time edge cases** - Leap years, DST transitions, time zones, Y2K38

#### 7.1.3 Invalid Input Tests
- [ ] **Wrong type** - String instead of number, number instead of object
- [ ] **Missing required fields** - Each mandatory field tested independently
- [ ] **Invalid format** - Bad email, OIB, IBAN, date format
- [ ] **Out of range** - Negative where positive required, future dates where past required
- [ ] **Too large** - Exceeds size limits (test at limit+1)
- [ ] **Too small** - Below minimum (test at limit-1)
- [ ] **Invalid enum values** - Values not in allowed set
- [ ] **Malformed XML/JSON** - Syntax errors, unclosed tags

#### 7.1.4 Malicious Input Tests (Security)
- [ ] **SQL injection attempts** - `' OR 1=1 --`, `'; DROP TABLE;`
- [ ] **XSS attempts** - `<script>alert('XSS')</script>`
- [ ] **XXE attacks** - External entity declarations in XML
- [ ] **Billion laughs** - Exponential entity expansion
- [ ] **Path traversal** - `../../etc/passwd`
- [ ] **Command injection** - `; rm -rf /`
- [ ] **Buffer overflow attempts** - Extremely long strings
- [ ] **Null byte injection** - `\0` in strings
- [ ] **Unicode exploits** - Right-to-left override, zero-width chars

#### 7.1.5 Business Rule Tests
- [ ] **Each business rule has 3+ tests** - Valid case, invalid case, boundary case
- [ ] **Complex conditionals decomposed** - Test each branch independently
- [ ] **Rule interactions** - Test rules that affect each other
- [ ] **Regulatory compliance** - Each regulation mapped to tests

#### 7.1.6 Error Handling Tests
- [ ] **Every error code tested** - All possible error responses
- [ ] **Error message quality** - Helpful, actionable, no sensitive data leaked
- [ ] **Partial failures** - What if step 3 of 5 fails?
- [ ] **Rollback scenarios** - Compensation transactions work correctly
- [ ] **Idempotency under errors** - Retry after failure produces same result

**Test Structure:**
```typescript
describe('[FunctionName]', () => {
  describe('Happy Path', () => {
    it('should handle minimal valid input', () => { /* ... */ });
    it('should handle typical valid input', () => { /* ... */ });
    it('should handle maximal valid input', () => { /* ... */ });
  });

  describe('Edge Cases', () => {
    it('should handle empty input', () => { /* ... */ });
    it('should handle boundary values', () => { /* ... */ });
    // ... all edge cases
  });

  describe('Invalid Input', () => {
    it('should reject wrong type', () => { /* ... */ });
    it('should reject missing required field', () => { /* ... */ });
    // ... all invalid cases
  });

  describe('Security', () => {
    it('should prevent SQL injection', () => { /* ... */ });
    it('should prevent XXE attacks', () => { /* ... */ });
    // ... all malicious inputs
  });

  describe('Business Rules', () => {
    it('should enforce BR-001: OIB checksum', () => { /* ... */ });
    // ... all business rules
  });

  describe('Error Handling', () => {
    it('should return ERROR_CODE_X when condition Y', () => { /* ... */ });
    // ... all error paths
  });
});
```

**Example Test Cases:**

```
TEST SUITE: validateOIB()

Happy Path:
  TEST: valid_oib_11_digits
    Input: "12345678901" (valid checksum)
    Expected: { valid: true }

Edge Cases:
  TEST: oib_exactly_11_digits
    Input: "10000000000" (boundary: min valid)
    Expected: { valid: true }

  TEST: oib_with_leading_zero
    Input: "01234567890"
    Expected: { valid: true }

Invalid Input:
  TEST: oib_10_digits
    Input: "1234567890" (too short)
    Expected: { valid: false, error: "OIB_INVALID_LENGTH" }

  TEST: oib_12_digits
    Input: "123456789012" (too long)
    Expected: { valid: false, error: "OIB_INVALID_LENGTH" }

  TEST: oib_invalid_checksum
    Input: "12345678900" (checksum should be 1, not 0)
    Expected: { valid: false, error: "OIB_INVALID_CHECKSUM" }

  TEST: oib_non_numeric
    Input: "1234567890A"
    Expected: { valid: false, error: "OIB_INVALID_FORMAT" }

Malicious Input:
  TEST: oib_sql_injection
    Input: "' OR 1=1 --"
    Expected: { valid: false, error: "OIB_INVALID_FORMAT" }

  TEST: oib_null_byte
    Input: "12345678\0901"
    Expected: { valid: false, error: "OIB_INVALID_FORMAT" }

Business Rules:
  TEST: oib_checksum_algorithm_iso_7064
    Input: "12345678901"
    Algorithm verification:
      - Sum = 1*10 + 2*9 + 3*8 + 4*7 + 5*6 + 6*5 + 7*4 + 8*3 + 9*2 = 165
      - Checksum = (10 - (165 mod 10)) mod 10 = 1
      - Expected: digit[10] = 1 ✓
```

---

### 7.2 Mock Data Tests

**Purpose:** Test business logic without external dependencies

**Mock Data Requirements:**
- [ ] **Comprehensive fixtures** - Cover all data variations
- [ ] **Realistic data** - Based on real production samples (anonymized)
- [ ] **Edge case fixtures** - Boundary values, special cases
- [ ] **Invalid fixtures** - Known bad data for negative tests

**Mock Data Location:**
`services/[layer]/[service-name]/test-data/mocks/`

**File Structure:**
```
mocks/
├── valid/
│   ├── minimal.json          # Smallest valid input
│   ├── typical.json          # Representative sample
│   ├── maximal.json          # All fields populated
│   └── all_vat_rates.json    # Tests all VAT categories
├── invalid/
│   ├── missing_id.json
│   ├── wrong_type.json
│   ├── out_of_range.json
│   └── invalid_checksum.json
├── edge_cases/
│   ├── empty_fields.json
│   ├── special_chars.json
│   ├── boundary_values.json
│   └── unicode_croatian.json
└── malicious/
    ├── sql_injection.json
    ├── xxe_attack.xml
    └── billion_laughs.xml
```

**Mock Service Responses:**
```typescript
// Mock upstream service responses
const mockValidatorResponse = {
  success: { is_valid: true, errors: [] },
  failure: { is_valid: false, errors: [{ code: 'ERROR_X', message: '...' }] },
  timeout: new Error('ETIMEDOUT'),
  serverError: { status: 500, message: 'Internal Server Error' }
};
```

---

### 7.3 Real Data Tests

**Purpose:** Validate against actual production-like data

**Real Data Sources:**
- [ ] **Anonymized production data** - Real invoices with PII removed
- [ ] **Tax Authority samples** - Official UBL 2.1 examples from Porezna uprava
- [ ] **OASIS UBL samples** - Reference implementations
- [ ] **Partner data** - Sample invoices from integration partners (with permission)

**Real Data Location:**
`services/[layer]/[service-name]/test-data/real/`

**Data Sanitization:**
- [ ] **PII removed** - No real OIBs, names, addresses
- [ ] **Amounts randomized** - Financial data obscured
- [ ] **Dates adjusted** - Relative to test date
- [ ] **Companies anonymized** - Use fictional company names

**Real Data Test Cases:**
```
TEST: validate_real_croatian_invoice
  Input: test-data/real/sample_invoice_hr.xml
  Source: Anonymized from partner XYZ
  Expected: Passes all validation layers

TEST: validate_oasis_ubl_sample
  Input: test-data/real/oasis_ubl_2.1_invoice.xml
  Source: https://docs.oasis-open.org/ubl/os-UBL-2.1/xml/
  Expected: Passes XSD and Schematron validation
```

---

### 7.4 Mutation Testing

**Purpose:** Ensure tests actually detect bugs, not just pass

**Tool:** [Stryker, PITest, Mutmut]

**Mutation Operators:**
- [ ] **Arithmetic:** `+` → `-`, `*` → `/`, `++` → `--`
- [ ] **Relational:** `<` → `<=`, `==` → `!=`, `>` → `>=`
- [ ] **Logical:** `&&` → `||`, `!x` → `x`
- [ ] **Statement deletion:** Remove lines, see if tests fail
- [ ] **Constant mutation:** `0` → `1`, `true` → `false`
- [ ] **Return value mutation:** Change return values

**Mutation Score Target:** ≥95% (mutants killed by tests)

**Example:**
```
Original:  if (age >= 18) return "adult";
Mutant 1:  if (age > 18) return "adult";   // Should be caught by test with age=18
Mutant 2:  if (age >= 18) return "child";  // Should be caught by assertion
```

---

### 7.5 Data Mutation Tests

**Purpose:** Test robustness against data corruption and variations

**Mutation Strategies:**
- [ ] **Field omission** - Remove optional fields one at a time
- [ ] **Field reordering** - Change XML/JSON element order
- [ ] **Type coercion** - "123" → 123, "true" → true
- [ ] **Whitespace variations** - Add/remove spaces, newlines
- [ ] **Encoding changes** - UTF-8 → UTF-16, Windows-1252
- [ ] **Case sensitivity** - Uppercase/lowercase field names
- [ ] **Numeric precision** - 1.0 → 1.00, 10 → 10.0
- [ ] **Date format variations** - ISO 8601 variants

**Example Mutations:**
```
Original:
<Invoice>
  <ID>123</ID>
  <IssueDate>2026-01-15</IssueDate>
</Invoice>

Mutation 1 (reordering):
<Invoice>
  <IssueDate>2026-01-15</IssueDate>
  <ID>123</ID>
</Invoice>
Expected: Still valid (XML order shouldn't matter if schema allows)

Mutation 2 (whitespace):
<Invoice>
  <ID>  123  </ID>
  <IssueDate>2026-01-15</IssueDate>
</Invoice>
Expected: Should trim whitespace, still valid

Mutation 3 (encoding):
<Invoice encoding="UTF-16">
  <ID>123</ID>
  <IssueDate>2026-01-15</IssueDate>
</Invoice>
Expected: Handle UTF-16, still valid
```

---

### 7.6 Integration Tests

**Test Scope:**
- [ ] **External API calls** - Test against mock servers AND test environments
- [ ] **Database operations** - Use Testcontainers for real DB
- [ ] **Message bus** - Test event publishing/consuming with real broker
- [ ] **File I/O** - Test with real file system (temp directories)
- [ ] **Network failures** - Simulate timeouts, connection refused

**Example Integration Tests:**

```
TEST: validate_with_real_xsd_schema
  Setup: Load actual UBL 2.1 XSD files from disk
  Input: 100 sample invoices (valid and invalid mix)
  Verify:
    - All valid invoices pass
    - All invalid invoices fail with correct error codes
    - XPath in error messages is accurate
  Performance: Complete in <10 seconds

TEST: publish_validation_completed_event
  Setup: Start Testcontainers RabbitMQ
  Action: Complete validation, trigger event publication
  Verify:
    - Event published to correct exchange + routing key
    - Event schema matches Protocol Buffer definition
    - Event payload contains all required fields
    - Idempotency key prevents duplicate processing

TEST: call_upstream_validator_with_retry
  Setup: Mock upstream service with failure sequence: [500, 500, 200]
  Action: Call validator
  Verify:
    - Service retries 2x after failures
    - Circuit breaker doesn't open (under threshold)
    - Final response is success (200)
    - Total time includes backoff delays
```

---

### 7.7 Contract Tests

**Provider Contract Tests (if this service provides an API):**
- [ ] **Tool:** Pact, Spring Cloud Contract, or equivalent
- [ ] **Consumers:** [List all services that depend on this API]
- [ ] **Contract verification:** Run in CI on every commit
- [ ] **Breaking change detection:** Alert if contract changes incompatibly

**Consumer Contract Tests (if this service calls other APIs):**
- [ ] **Providers:** [List all services this depends on]
- [ ] **Mock providers:** Use consumer-driven contract mocks
- [ ] **Contract updates:** Verify compatibility when provider changes

**Example Pact Test:**
```typescript
describe('XSD Validator Contract', () => {
  it('should validate UBL XML and return result', async () => {
    // Consumer expectation
    await provider.addInteraction({
      state: 'XSD schema is loaded',
      uponReceiving: 'a validation request',
      withRequest: {
        method: 'POST',
        path: '/validate',
        body: { xml_content: '...', schema_version: 'UBL-2.1' }
      },
      willRespondWith: {
        status: 200,
        body: { is_valid: true, errors: [] }
      }
    });

    // Actual test
    const result = await xsdValidator.validate(sampleXML);
    expect(result.is_valid).toBe(true);
  });
});
```

---

### 7.8 Performance Tests

**Load Testing:**
```
Tool: k6 (preferred), Gatling, Locust

Scenarios:
1. Baseline: 10 req/sec for 1 minute (warm-up)
2. Normal load: [e.g., 100 req/sec for 10 minutes]
3. Peak load: [e.g., 1000 req/sec for 5 minutes]
4. Spike test: [e.g., 0 → 5000 req/sec → 0 in 2 minutes]
5. Soak test: [e.g., 500 req/sec for 1 hour] (detect memory leaks)
6. Stress test: Ramp up until failure (find breaking point)

Success criteria:
- p50 latency < [threshold from section 3.1]
- p95 latency < [threshold]
- p99 latency < [threshold]
- p99.9 latency < [threshold]
- Error rate < 0.01% (1 in 10,000)
- No memory leaks (heap stable during soak test)
- Throughput ≥ [target from section 3.1]
- CPU < 80% sustained
- Memory < 80% of limit
```

**Performance Test Data:**
- [ ] **Varied payload sizes** - Small, medium, large invoices
- [ ] **Realistic distribution** - 70% small, 25% medium, 5% large
- [ ] **Concurrent users** - Simulate N parallel clients

**k6 Script Example:**
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '1m', target: 10 },   // Warm-up
    { duration: '5m', target: 100 },  // Normal load
    { duration: '2m', target: 1000 }, // Peak load
    { duration: '2m', target: 0 },    // Ramp down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<100', 'p(99)<200'],
    'http_req_failed': ['rate<0.01'],
  },
};

export default function() {
  const payload = JSON.stringify({ xml_content: '...' });
  const params = { headers: { 'Content-Type': 'application/json' } };

  let res = http.post('http://xsd-validator:50051/validate', payload, params);

  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 100ms': (r) => r.timings.duration < 100,
  });

  sleep(1);
}
```

---

### 7.9 Stress Testing

**Resource Exhaustion Tests:**
- [ ] **Memory limit:** Run with 50% of normal memory, should degrade gracefully
- [ ] **CPU throttle:** Limit to 50% of normal CPU, should slow but not crash
- [ ] **Disk full:** Fill disk to 99%, should handle write failures
- [ ] **Connection exhaustion:** Max out database connections, should queue
- [ ] **File descriptor limit:** Open max files, should close old ones

**Concurrency Stress:**
- [ ] **Thundering herd:** 10,000 requests simultaneously
- [ ] **Race conditions:** Concurrent updates to same resource
- [ ] **Deadlock detection:** Competing transactions

**Example:**
```bash
# Memory stress test
docker run --memory=128m [service-image]
# Expected: Service starts, handles reduced throughput, logs warnings

# CPU stress test
docker run --cpus=0.5 [service-image]
# Expected: Slower but stable, no crashes

# Connection exhaustion
for i in {1..1000}; do curl http://service:50051/validate & done
# Expected: Queue requests, return 503 when overloaded, recover after spike
```

---

### 7.10 Chaos Testing

**Failure Injection (use Chaos Mesh, Gremlin, or manual):**

#### Network Chaos:
- [ ] **Latency injection:** Add 1-5 second delay
- [ ] **Packet loss:** 10% packet drop rate
- [ ] **Bandwidth limit:** Throttle to 10 Kbps
- [ ] **Network partition:** Isolate service from dependencies
- [ ] **DNS failures:** Resolve to wrong IP

#### Infrastructure Chaos:
- [ ] **Pod kill:** Random pod termination
- [ ] **CPU spike:** Consume 100% CPU for 30 seconds
- [ ] **Memory spike:** Allocate memory until near OOM
- [ ] **Disk I/O saturation:** Flood disk with reads/writes
- [ ] **Clock skew:** Advance system time by 1 hour

#### Dependency Chaos:
- [ ] **Upstream failure:** Mock service returns 500
- [ ] **Upstream timeout:** Mock service never responds
- [ ] **Upstream slow:** Mock service responds after 30s
- [ ] **Database failure:** Kill database pod
- [ ] **Message bus failure:** Stop RabbitMQ/Kafka

**Expected Behaviors:**
- [ ] Circuit breaker opens after N failures
- [ ] Retry with exponential backoff
- [ ] Graceful degradation (skip non-critical features)
- [ ] Health check fails appropriately
- [ ] Service recovers automatically when dependency recovers
- [ ] No cascading failures to other services
- [ ] Logs contain actionable error context

**Example Chaos Test:**
```yaml
# Chaos Mesh experiment
apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: network-delay-test
spec:
  action: delay
  mode: one
  selector:
    namespaces:
      - default
    labelSelectors:
      app: xsd-validator
  delay:
    latency: "1s"
    correlation: "100"
  duration: "5m"
  scheduler:
    cron: "@every 1h"
```

---

### 7.11 Fuzz Testing

**Purpose:** Discover crashes and vulnerabilities with random inputs

**Tools:** [AFL++, libFuzzer, Jazzer, Atheris]

**Fuzz Targets:**
- [ ] **XML parsing** - Random XML documents
- [ ] **JSON parsing** - Random JSON payloads
- [ ] **Protocol Buffer parsing** - Random binary data
- [ ] **String validation** - Random strings for OIB, IBAN, etc.
- [ ] **Arithmetic operations** - Random numbers for calculations

**Fuzz Duration:** 24 hours minimum per target

**Example Fuzz Test:**
```typescript
// Using fast-check for property-based fuzzing
import fc from 'fast-check';

describe('OIB Validation Fuzz Test', () => {
  it('should never crash on any string input', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        // Should not throw exception, should return valid or invalid
        expect(() => {
          const result = validateOIB(input);
          expect(typeof result.valid).toBe('boolean');
        }).not.toThrow();
      }),
      { numRuns: 10000 } // Run 10k random inputs
    );
  });
});
```

---

### 7.12 Regression Testing

**Purpose:** Ensure bug fixes stay fixed

**Process:**
- [ ] **Every bug gets a test** - Before fixing, write failing test
- [ ] **Test captures root cause** - Not just symptom
- [ ] **Regression test suite** - All bug-fix tests in separate suite
- [ ] **Run on every commit** - Prevent re-introduction

**Example:**
```
BUG-123: Validator crashes on XML with BOM (Byte Order Mark)

Regression Test:
TEST: validate_xml_with_bom
  Input: \xEF\xBB\xBF<?xml version="1.0"?><Invoice>...</Invoice>
  Expected: BOM stripped, validation succeeds
  Previously: Crashed with "Unexpected character"
  Fixed in: commit abc123
```

---

### 7.13 Test Data Management

**Generating Test Data:**
- [ ] **Faker libraries** - Realistic fake data (names, addresses, dates)
- [ ] **Data builders** - Fluent APIs for constructing complex objects
- [ ] **Snapshot testing** - Capture known-good outputs

**Test Data Version Control:**
- [ ] **Committed to repo** - Test data in `test-data/` directory
- [ ] **Large files in LFS** - Use Git LFS for files >1MB
- [ ] **Data generation scripts** - Reproducible data generation

**Example Data Builder:**
```typescript
class InvoiceBuilder {
  private data: Partial<Invoice> = {};

  withID(id: string): this {
    this.data.id = id;
    return this;
  }

  withIssueDate(date: string): this {
    this.data.issueDate = date;
    return this;
  }

  withVATRate(rate: number): this {
    this.data.vatRate = rate;
    return this;
  }

  build(): Invoice {
    // Apply defaults for missing fields
    return {
      id: this.data.id ?? 'INV-001',
      issueDate: this.data.issueDate ?? '2026-01-15',
      vatRate: this.data.vatRate ?? 25,
      // ... all required fields with sensible defaults
    };
  }
}

// Usage in tests
const invoice = new InvoiceBuilder()
  .withID('TEST-123')
  .withVATRate(13)
  .build();
```

---

### 7.14 Test Execution Requirements

**CI Pipeline:**
- [ ] **Unit tests:** Run on every commit (<2 minutes)
- [ ] **Integration tests:** Run on every commit (<5 minutes)
- [ ] **Contract tests:** Run on every commit (<3 minutes)
- [ ] **Performance tests:** Run on PRs to main (<10 minutes)
- [ ] **Stress tests:** Run nightly (<30 minutes)
- [ ] **Chaos tests:** Run weekly in staging (manual trigger)
- [ ] **Fuzz tests:** Run continuously (dedicated fuzzing server)

**Pre-Commit Hooks:**
- [ ] **Linter** - No warnings allowed
- [ ] **Type checker** - No type errors
- [ ] **Fast unit tests** - Critical path only (<30 seconds)

**Pre-Merge Requirements:**
- [ ] All tests pass (unit, integration, contract)
- [ ] Coverage ≥ 100%
- [ ] Mutation score ≥ 95%
- [ ] No new security vulnerabilities (Snyk/Trivy)
- [ ] Performance tests pass (if service-specific)

**Pre-Deploy Requirements:**
- [ ] All tests pass in staging environment
- [ ] Smoke tests pass (critical user journeys)
- [ ] Load tests pass (production-scale traffic)
- [ ] Rollback procedure tested

---

## 7.15 Test Quality Standards

**Test Code Quality:**
- [ ] **Tests are readable** - Clear arrange/act/assert structure
- [ ] **Tests are maintainable** - No code duplication, use helpers
- [ ] **Tests are fast** - Unit tests <100ms each
- [ ] **Tests are isolated** - No shared state, can run in parallel
- [ ] **Tests are deterministic** - Same input always produces same result

**Test Anti-Patterns to AVOID:**
- ❌ **Flaky tests** - Tests that randomly fail
- ❌ **Slow tests** - Tests that take >1 second (unless integration/performance)
- ❌ **Unclear assertions** - `expect(result).toBeTruthy()` (be specific!)
- ❌ **Testing implementation details** - Test behavior, not internals
- ❌ **One giant test** - Split into focused tests
- ❌ **No assertions** - Every test must assert something
- ❌ **Brittle tests** - Break when refactoring (test interface, not implementation)

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
