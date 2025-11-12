# Letter to Codex: Archive & Compliance Layer Design

**Date:** 2025-11-12
**Project:** eRacun Invoice Processing Platform
**Requestor:** System Architect
**Priority:** 🔴 P0 - Blocking Implementation
**Timeline:** Must be production-ready by 2025-12-31

---

## Mission

Design and implement the **Archive & Compliance Layer** - the subsystem responsible for long-term storage, integrity verification, and audit trail management of invoices processed through the eRacun platform.

This is not optional. This is regulatory mandate.

---

## Context & Constraints

### Regulatory Requirements (Non-Negotiable)

**Croatian Fiscalization Law (NN 89/25) - Effective 1 January 2026:**

1. **Retention Period:** 11 YEARS (not 7 years)
   - This is a hard requirement. Non-compliance penalties: **66,360 EUR + loss of VAT deduction rights**

2. **Storage Format:** Original XML with preserved digital signatures and qualified timestamps
   - ❌ PDF conversions are NOT legally compliant
   - ❌ Paper printouts are NOT legally compliant
   - ✅ Must preserve XMLDSig enveloped signatures intact through entire storage lifecycle

3. **Immutability Requirement:** WORM (Write Once Read Many)
   - Once written, cannot be modified or deleted
   - Documents must be cryptographically protected against tampering
   - Deletion must be cryptographically audited (never silently removed)

4. **Geographic Data Residency:** EU region only
   - No data transfer to non-EU jurisdictions
   - Backup location must also be within EU

5. **Monthly Integrity Verification:** Automated signature validation
   - Minimum: Monthly audit that all stored signatures remain valid
   - Failed signatures must trigger P0 alert (potential data corruption)

6. **Audit Trail:** Complete forensic record
   - Every document access logged (who, when, why)
   - Every transformation/repair logged
   - Cross-referenced with FINA submission confirmations (JIR for B2C, UUID for B2B)
   - 11-year retention for audit logs (same as documents)

### System Architecture Context

See `CLAUDE.md` section 6 (Deployment & Orchestration):
- **Target Environment:** DigitalOcean Dedicated Droplets (Linux)
- **Primary Storage:** S3-compatible object storage (DigitalOcean Spaces recommended)
- **Archive Tier:** Cold storage (Glacier-class) after 1 year
- **Database:** PostgreSQL for metadata, signatures, audit index
- **Encryption:** AES-256 minimum (at rest)
- **Message Bus:** RabbitMQ for event propagation
- **Observability:** Prometheus + Pino + OpenTelemetry (Jaeger)

### Timeline Constraints

- **1 January 2026:** MANDATORY compliance deadline (no extensions possible)
- **Current date:** 2025-11-12
- **Development window:** 49 days remaining
- **This service must be:** Designed by 2025-11-15, implemented by 2025-12-20, hardened by 2025-12-31

---

## Deliverables (What We Need from You)

### **Phase 1: Architecture & Design (By 2025-11-15)**

1. **System Architecture Document** (`docs/adr/ADR-00X-archive-compliance-layer.md`)
   - High-level component diagram (storage, metadata DB, retrieval, audit)
   - Data flow diagrams (invoice ingestion → archive, retrieval → compliance reporting)
   - Interface specifications (RabbitMQ events, HTTP API contracts)
   - Failure mode analysis (what breaks, recovery procedures)

2. **Data Model Specification**
   - PostgreSQL schema for:
     - Invoice metadata (invoice_id, original_filename, hash, signature_validity, storage_location)
     - Submission confirmations (FINA JIR for B2C, UUID for B2B, submission_timestamp)
     - Audit trail (access logs, transformations, integrity check results)
     - Signature validation results (signature_valid_at, certificate_chain, expiration_date)
   - S3 object structure (bucket naming, folder hierarchy, retention policies)

3. **Storage Strategy Document**
   - Hot tier (0-30 days): Standard storage, immediate access
   - Warm tier (1-12 months): Archive storage, 24-hour retrieval SLA
   - Cold tier (1-11 years): Glacier-class, 48-hour retrieval SLA, cost-optimized
   - Replication strategy: Primary (DigitalOcean Spaces EU), Backup (cross-region EU)

4. **Signature Preservation & Validation Strategy**
   - How to safely store XMLDSig signatures without modification
   - Automated monthly validation workflow (which certificates to trust, chain verification)
   - Handling for expired certificates (alert, but maintain immutability)
   - Recovery procedures for corrupted signatures

5. **Audit Trail Architecture**
   - What events to log (document received, validated, stored, retrieved, signature checked, exported for compliance)
   - Log format (JSON, structured fields, request ID correlation)
   - Immutable log storage (event sourcing pattern possible)
   - Query capabilities (find all documents accessed by user X on date Y)

6. **Integration Points Specification**
   - **Inbound:** Which services write to archive? (ubl-transformer, fina-connector, as4-gateway-connector)
   - **Outbound:** Which services read from archive? (compliance-reporting-service, audit-service, admin-portal-api)
   - **Message contracts:** Define RabbitMQ events (ArchiveInvoiceCommand, InvoiceArchivedEvent, etc.)
   - **HTTP API:** REST endpoints for retrieve, validate, export

### **Phase 2: Implementation (By 2025-12-20)**

1. **Service Code** (`services/archive-service/`)
   - Express.js REST API with proper error handling
   - Connection pooling to PostgreSQL
   - S3 client with retry/backoff
   - RabbitMQ consumer for ArchiveInvoiceCommand
   - 100% test coverage (CLAUDE.md section 3.3 requirement)

2. **Database Migrations** (`services/archive-service/migrations/`)
   - PostgreSQL schema creation
   - Indexes for common queries (by invoice_id, by submission_date, by signature_validity)
   - Partitioning strategy for 11-year retention (time-series data)

3. **Signature Validation Service** (`services/archive-service/signature-validator.ts`)
   - Integration with digital-signature-service for X.509 chain verification
   - Monthly batch validation cronjob
   - Alert generation for failed signatures

4. **Audit Trail Service** (`services/audit-logger/` enhancements)
   - Structured logging with archive-specific fields
   - Immutable event storage
   - Query API for compliance reports

5. **Data Recovery & Export Tools** (`scripts/archive-recovery/`)
   - Bulk export for compliance audits
   - Selective retrieval by date range, invoice ID, etc.
   - Integrity verification before export

### **Phase 3: Hardening & Testing (By 2025-12-31)**

1. **Chaos Testing** - Simulate failures:
   - S3 unavailable (graceful degradation, queue fallback)
   - Database connection lost (retry logic, timeout handling)
   - Signature validation failure (alert + immutability maintained)
   - Clock skew (time-based assertions work across time zones)

2. **Performance Testing**
   - Archive 100,000 documents in 1 hour (parallel write capacity)
   - Retrieve document in <200ms (p95)
   - Monthly signature validation completes in <1 hour
   - Audit query (1 year of logs) returns in <5 seconds

3. **Compliance Audit Trail** - Verify:
   - All 11-year retention documents are preserved
   - All signatures remain valid (cryptographic integrity)
   - All audit logs are immutable and complete
   - All FINA submission confirmations are cross-referenced

4. **Disaster Recovery Testing**
   - Backup/restore cycle validated
   - Geographic failover tested (EU region → backup EU region)
   - RPO/RTO targets met

---

## Context: Related Services & Contracts

### Upstream Producers (Write to Archive)

1. **ubl-transformer** - Submits validated UBL 2.1 XML
   - Message: `ArchiveInvoiceCommand { invoice_id, ubl_xml, metadata }`

2. **fina-connector** - After successful FINA submission
   - Message: `ArchiveInvoiceCommand { invoice_id, original_xml, jir_confirmation, submission_timestamp }`

3. **as4-gateway-connector** - After B2B AS4 submission
   - Message: `ArchiveInvoiceCommand { invoice_id, original_xml, uuid_confirmation, submission_timestamp }`

### Downstream Consumers (Read from Archive)

1. **compliance-reporting-service** - Monthly eIzvještavanje (e-reporting)
   - Query: `GetArchivedInvoicesByDateRange { start_date, end_date, invoice_type }`
   - Returns: List of invoices with status, amounts, submission confirmations

2. **admin-portal-api** - Customer invoice retrieval
   - Query: `GetInvoiceByID { invoice_id }`
   - Returns: Original XML + metadata + validation status + FINA confirmation

3. **audit-logger** - Cross-reference for compliance verification
   - Query: `GetAuditTrailForInvoice { invoice_id }`
   - Returns: Complete lifecycle events (created, validated, submitted, archived, verified)

---

## Regulatory Context

**Reference Documents Available in Repo:**
- `CLAUDE.md` - System architecture, observability, deployment requirements
- `TODO.md` - Project timeline, dependencies, related services
- `TBD.md` - Pending decisions (data residency region, caching strategy, etc.)

**Croatian Compliance Requirements:**
- 11-year retention (11 YEARS not 7)
- XMLDSig preservation
- FINA submission confirmations (JIR/UUID) must be linked to archived invoices
- Monthly integrity verification
- Audit trail with complete forensics
- EU data residency

---

## Quality Standards (Non-Negotiable)

From CLAUDE.md section 3.3:

1. **100% Test Coverage** - All code paths tested
   - Unit tests: 70% of test suite
   - Integration tests: 25% (archive service boundaries)
   - E2E tests: 5% (full workflow archive → retrieve → verify)

2. **Reliability Patterns** (all mandatory):
   - **Idempotency:** Archiving same invoice twice = same result (no duplication)
   - **Circuit Breakers:** S3 failures don't cascade
   - **Structured Logging:** JSON format, request IDs for tracing
   - **Distributed Tracing:** OpenTelemetry spans across service calls

3. **Security Hardening:**
   - No hardcoded credentials (use SOPS encrypted secrets)
   - XXE protection if parsing XML for validation
   - Input validation on all API endpoints
   - Immutability enforcement (prevent accidental overwrites)

4. **Performance Budgets:**
   - Archive write: <200ms (p95)
   - Archive retrieve: <200ms (p95)
   - Monthly signature validation: <1 hour for 10M documents

---

## Success Criteria

✅ You know the design is correct when:

1. **Regulatory Compliance:** 11-year retention with preserved signatures is architecturally guaranteed
2. **Zero Data Loss:** Immutability prevents accidental or malicious deletion
3. **Forensic Trail:** Complete audit log enables "what happened to invoice X" in under 5 seconds
4. **Integration Ready:** ubl-transformer, fina-connector, as4-gateway-connector can archive without modification
5. **Compliance Ready:** compliance-reporting-service can export documents for tax authority audits
6. **Performance:** Archive/retrieve operations meet budgets without optimization
7. **Tested:** 100% coverage + chaos tests + disaster recovery drills pass
8. **Documented:** ADR explains design rationale, README covers operations, runbooks document failure recovery

---

## Resources Provided

```
/home/user/eRacun-development/
├── CLAUDE.md                          # System architecture & standards
├── TODO.md                            # Project timeline & dependencies
├── TBD.md                             # Pending decisions
├── services/fina-connector/           # Example FINA integration (reference for lifecycle)
├── services/digital-signature-service/ # Signature validation (dependency)
└── docs/adr/                          # Architecture decision record examples
```

---

## What We Trust You To Do

1. **Make architectural decisions** within these constraints
2. **Identify gaps** in requirements and flag them (data residency region, exact cold storage tier, etc.)
3. **Call out risks** if something is architecturally unsound
4. **Propose optimizations** if you see ways to improve performance/cost without compromising compliance
5. **Create production-ready code** - this goes to live within 49 days, no rework possible

---

## Communication

When you're ready to present the design:
1. Create `docs/adr/ADR-00X-archive-compliance-layer.md` (architecture)
2. Update `docs/TODO-007-archive-service-implementation.md` (progress)
3. Create `services/archive-service/README.md` (service documentation)
4. Flag any blockers or open questions in comment blocks marked `// TODO: CODEX-DECISION-REQUIRED`

We believe in your judgment. Build what's right for a production system handling legally binding financial documents.

---

**Deadline:** Phase 1 design by 2025-11-15, full implementation by 2025-12-31

**This is not a prototype. This system will be live on 2026-01-01. Make it bulletproof.**

---

*~ System Architect, eRacun Team*
