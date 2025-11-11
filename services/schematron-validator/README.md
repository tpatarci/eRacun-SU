# Schematron Validator Service

**Bounded Context:** Validation Layer
**Single Responsibility:** Validate XML documents against Schematron business rules (Croatian CIUS)
**Complexity:** Medium-High (target: 1,500 LOC)
**Status:** 🚧 In Development

---

## Purpose

Validates UBL 2.1 invoices against **Schematron business rules** defined in the **Croatian Core Invoice Usage Specification (CIUS-HR)**. This is the second validation layer after XSD schema validation.

**Validation Hierarchy:**
1. ✅ **XSD Validation** (xsd-validator) - Syntactic correctness
2. ✅ **Schematron Validation** (THIS SERVICE) - Business rules
3. ⏳ **KPD Validation** (kpd-validator) - Product classification codes
4. ⏳ **Semantic Validation** (semantic-validator) - Cross-field business logic
5. ⏳ **AI Validation** (ai-validator) - Anomaly detection

---

## Schematron Overview

**What is Schematron?**
- Rule-based XML validation language (ISO/IEC 19757-3)
- Validates business rules beyond what XSD can express
- Uses XPath expressions to query and validate XML content
- Produces human-readable error messages

**Croatian CIUS Rules Examples:**
- "If VAT category is 'S' (standard rate), VAT rate MUST be 25%"
- "If payment means code is 30 (credit transfer), IBAN MUST be present"
- "Invoice total MUST equal sum of line totals plus VAT"
- "Supplier OIB MUST be 11 digits and pass checksum validation"
- "Invoice currency MUST be EUR or HRK (until EUR transition complete)"

---

## API Contract

### Input Message (RabbitMQ)

**Queue:** `validation.schematron.validate`
**Exchange:** `validation` (topic)
**Routing Key:** `validation.schematron.validate`

**Protocol Buffer Schema:**
```protobuf
message ValidateSchematronCommand {
  RequestContext context = 1;
  InvoiceId invoice_id = 2;
  bytes xml_content = 3;              // UBL 2.1 XML (must be XSD-valid)
  SchematronRuleSet rule_set = 4;     // Which rule set to apply
}

enum SchematronRuleSet {
  CIUS_HR_CORE = 0;          // Croatian CIUS core rules (mandatory)
  CIUS_HR_EXTENDED = 1;      // Extended Croatian rules (optional)
  EN16931_CORE = 2;          // European standard (EN 16931-1)
  UBL_FULL = 3;              // Full UBL 2.1 business rules
}
```

**Temporary (pre-Protobuf):**
```json
{
  "request_id": "uuid-v4",
  "invoice_id": "uuid-v4",
  "xml_content": "base64-encoded-xml",
  "rule_set": "CIUS_HR_CORE"
}
```

### Output Event (RabbitMQ)

**Exchange:** `validation` (topic)
**Routing Key:** `validation.schematron.completed`

**Success:**
```json
{
  "request_id": "uuid-v4",
  "invoice_id": "uuid-v4",
  "status": "VALID",
  "rules_checked": 142,
  "validation_time_ms": 850,
  "warnings": []
}
```

**Failure:**
```json
{
  "request_id": "uuid-v4",
  "invoice_id": "uuid-v4",
  "status": "INVALID",
  "rules_checked": 142,
  "rules_failed": 3,
  "validation_time_ms": 820,
  "errors": [
    {
      "rule_id": "BR-S-01",
      "severity": "error",
      "message": "VAT rate MUST be 25% when category code is 'S'",
      "location": "//cac:TaxCategory[cbc:ID='S']/cbc:Percent",
      "xpath": "/Invoice/cac:TaxTotal/cac:TaxSubtotal[1]/cac:TaxCategory",
      "actual_value": "20",
      "expected_value": "25"
    }
  ],
  "warnings": [
    {
      "rule_id": "BR-W-01",
      "severity": "warning",
      "message": "Payment due date should be within 90 days of issue date",
      "location": "//cbc:PaymentDueDate"
    }
  ]
}
```

### Health Endpoints (HTTP)

**Liveness:** `GET /health` → `200 OK`
**Readiness:** `GET /ready` → `200 OK` (rules loaded) / `503 Service Unavailable`
**Metrics:** `GET /metrics` → Prometheus format

---

## Performance Requirements

**Latency:**
- **p50:** <500ms (schematron processing is slower than XSD)
- **p95:** <1s
- **p99:** <2s

**Throughput:**
- **Target:** 50 validations/second
- **Sustained:** 30 validations/second
- **Scalability:** Horizontal scaling to 20+ replicas

**Resource Limits:**
- **Memory:** 512MB max (larger than XSD due to rule compilation)
- **CPU:** 0.5 cores sustained, 1.5 cores burst
- **Disk I/O:** Minimal (rules cached in memory)

---

## Implementation Technology

**Core Library:** `xslt3` (Saxon-JS Node.js binding)

**Why Saxon-JS?**
- ✅ Pure JavaScript, no native dependencies
- ✅ XSLT 3.0 support (required for Schematron → XSLT transformation)
- ✅ ISO Schematron standard compliant
- ✅ Well-maintained, enterprise-grade
- ❌ Slower than native libxslt, but acceptable for our throughput

**Alternative Considered:** `schematron` npm package
- ⚠️ Abandoned (last update 2017)
- ⚠️ Limited Schematron feature support
- ✅ Faster than Saxon-JS
- **Decision:** Use Saxon-JS for standards compliance

**Schematron Processing Pipeline:**
1. Load Schematron rules (.sch file)
2. Transform Schematron → XSLT (using iso-schematron-xslt3 skeleton)
3. Compile XSLT stylesheet (cached)
4. Apply XSLT to invoice XML
5. Parse SVRL (Schematron Validation Report Language) output
6. Extract errors/warnings

---

## Schematron Rule Sets

**Location:** `services/schematron-validator/rules/`

### Croatian CIUS Core Rules

**File:** `rules/cius-hr-core.sch`
**Source:** Croatian Tax Authority (Porezna Uprava)
**Version:** 1.0 (2025-01-01 - Fiscalization 2.0 launch)
**Rules:** ~150 business rules

**Categories:**
- **BR-CO:** Cardinality rules (required/optional fields)
- **BR-HR:** Croatian-specific rules (OIB, currency, tax rates)
- **BR-S:** VAT rules (rates, categories, exemptions)
- **BR-E:** Accounting rules (totals, rounding, calculations)
- **BR-AE:** Administrative rules (dates, codes, formats)

**Acquisition:**
- ⏳ Download from: https://cis.porezna-uprava.hr/docs/cius-hr-v1.0.sch
- ⏳ Contact: FINA Support (01 4404 707) or Porezna Uprava

### EN 16931 Core Rules

**File:** `rules/en16931-core.sch`
**Source:** CEN (European Committee for Standardization)
**Version:** EN 16931-1:2017
**Rules:** ~120 business rules

**Use Case:** Validate against European standard (superset of Croatian rules)

---

## Error Handling

**Failure Modes:**

1. **Schematron Rules Not Found**
   - **HTTP 503:** `/ready` returns Service Unavailable
   - **Action:** Wait for rules to load, retry
   - **Alert:** P1 (High) - Service degraded

2. **Invalid XML (Not Well-Formed)**
   - **Response:** `INVALID` with parse error
   - **Action:** Client should re-validate with xsd-validator
   - **Alert:** None (expected failure mode)

3. **XSLT Transformation Error**
   - **Response:** `ERROR` with error details
   - **Action:** Log full context, investigate rule bug
   - **Alert:** P1 (High) - Rule engine malfunction

4. **Timeout (Processing >10s)**
   - **Response:** `ERROR` with timeout message
   - **Action:** Reject message to DLQ, investigate XML size/complexity
   - **Alert:** P2 (Medium) - Performance degradation

**Idempotency:**
- ✅ Same XML + same rule set = same validation result (always)
- ✅ Safe to retry on failure
- ✅ No side effects

---

## Observability (TODO-008 Compliance)

### Prometheus Metrics

**Port:** `9101` (validation layer: 9100-9199)

**Metrics:**
```
# Validation outcomes
schematron_validation_total{status, rule_set}                    # Counter
schematron_validation_duration_seconds{rule_set}                 # Histogram

# Rule statistics
schematron_rules_checked_total{rule_set}                         # Histogram
schematron_rules_failed_total{rule_set}                          # Histogram
schematron_rules_loaded{rule_set}                                # Gauge

# Errors and warnings
schematron_errors_by_rule{rule_id, rule_set}                     # Counter
schematron_warnings_by_rule{rule_id, rule_set}                   # Counter

# Resource usage
schematron_rule_cache_size_bytes                                 # Gauge
schematron_xslt_compilation_time_seconds{rule_set}               # Histogram
```

### Structured Logging (Pino)

**Format:** JSON (mandatory)
**Fields:** `request_id`, `invoice_id`, `rule_set`, `duration_ms`, `status`, `error_count`, `warning_count`

**Log Levels:**
- **INFO:** Validation completed
- **WARN:** Validation failed with warnings
- **ERROR:** XSLT transformation error, timeout, rule load failure

**PII Masking:**
- ✅ OIB → `***********`
- ✅ IBAN → `HR** **** **** **** ****`
- ✅ VAT numbers → `HR***********`

**Retention:** 90 days (regulatory compliance)

### Distributed Tracing (Jaeger)

**Spans:**
- `schematron_validation` (top-level)
  - `load_rules` (if not cached)
  - `parse_xml`
  - `apply_xslt`
  - `parse_svrl`
  - `publish_result`

**Trace ID:** Propagated from `request_id` in input message
**Sampling:** 100% (regulatory compliance)

---

## Security

**XML Security:**
- ✅ XXE protection (inherited from xsd-validator)
- ✅ Size limits (10MB max)
- ✅ Timeout protection (10s max processing)

**Schematron Rule Security:**
- ⚠️ XSLT can execute arbitrary code
- ✅ Only load rules from trusted sources (Porezna Uprava)
- ✅ Rules reviewed before deployment
- ✅ Read-only filesystem (`ProtectSystem=strict`)

**systemd Hardening:**
- ✅ `ProtectSystem=strict`
- ✅ `PrivateTmp=true`
- ✅ `NoNewPrivileges=true`
- ✅ `SystemCallFilter=@system-service`
- ✅ `InaccessiblePaths=/etc/eracun/.age-key`

---

## Deployment

**Service Unit:** `deployment/systemd/eracun-schematron-validator.service`

**Configuration:**
- `/etc/eracun/services/schematron-validator.conf`

**Environment Variables:**
```bash
RABBITMQ_URL=amqp://localhost:5672
SCHEMATRON_RULES_PATH=/opt/eracun/services/schematron-validator/rules
PROMETHEUS_PORT=9101
HTTP_PORT=8081
LOG_LEVEL=info
NODE_ENV=production
```

**Health Check:**
```bash
curl http://localhost:8081/health
```

---

## Dependencies

### Service Dependencies (Upstream)

- **xsd-validator** - Must validate XSD before Schematron validation
- **RabbitMQ** - Message broker for commands and events

### Service Dependencies (Downstream)

- **kpd-validator** - Next validation step (KPD product codes)
- **audit-logger** - Immutable audit trail

### External Dependencies

- None (offline validation)

---

## Testing

**Coverage Target:** 85% (branches, functions, lines, statements)

**Test Suite:**
- **Unit Tests:** Rule loading, XSLT compilation, SVRL parsing
- **Integration Tests:** End-to-end validation with real Croatian rules
- **Property Tests:** Idempotency, deterministic results
- **Security Tests:** Rule injection prevention, timeout enforcement
- **Performance Tests:** <500ms p50, 50 validations/sec

**Test Fixtures:**
```
tests/fixtures/
├── schematron-rules/
│   ├── cius-hr-minimal.sch      # Simplified Croatian rules for testing
│   ├── en16931-minimal.sch      # Simplified EU rules
│   └── invalid-rule.sch         # Malformed rule for error testing
└── invoices/
    ├── valid-cius-hr.xml        # Passes all Croatian rules
    ├── invalid-vat-rate.xml     # Fails BR-S-01 (VAT rate)
    ├── invalid-oib.xml          # Fails BR-HR-01 (OIB checksum)
    └── warnings-only.xml        # No errors, but warnings
```

---

## Known Limitations

1. **Schematron Processing is Slow**
   - XSLT transformation overhead
   - Target: <500ms p50 (vs <100ms for XSD)
   - Mitigation: Compiled XSLT caching, horizontal scaling

2. **No Official Croatian CIUS Rules Yet**
   - Fiscalization 2.0 launches 2026-01-01
   - Rules will be published closer to launch
   - Mitigation: Use EN 16931 rules as foundation, adapt for Croatia

3. **XSLT Code Execution Risk**
   - Schematron → XSLT → execution
   - Malicious rules could execute arbitrary code
   - Mitigation: Only load rules from Porezna Uprava, code review all rules

---

## Future Enhancements

**Phase 2 (After Launch):**
- [ ] Custom Croatian rule extensions (beyond official CIUS)
- [ ] Rule versioning support (multiple CIUS versions)
- [ ] Rule override mechanism (per-client customization)
- [ ] Schematron Quick Fix (automatic error correction suggestions)

**Phase 3 (Scale):**
- [ ] Compiled XSLT persistence (across service restarts)
- [ ] Rule compilation service (separate microservice)
- [ ] Schematron rule editor UI (for rule authoring)

---

## References

**Standards:**
- ISO/IEC 19757-3:2016 (Schematron)
- EN 16931-1:2017 (European e-invoicing semantic model)
- Croatian CIUS v1.0 (2025-01-01 - pending publication)

**Implementation Guides:**
- https://www.schematron.com/
- https://www.saxonica.com/saxon-js/documentation/
- https://github.com/Schematron/schematron

**Croatian Resources:**
- https://cis.porezna-uprava.hr/docs/
- FINA Support: 01 4404 707

---

**Last Updated:** 2025-11-11
**Owner:** Validation Layer Team
**Status:** 🚧 In Development
