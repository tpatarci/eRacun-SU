# CLAUDE.md - eRacun Invoice Processing Platform

## Mission-Critical System Architecture Document

**System Classification:** Five-Nines Availability (99.999% uptime)
**Architecture Pattern:** Event-Driven Microservices with CQRS
**Development Approach:** AI-Assisted, Context-Window Optimized
**Repository Type:** Monorepo

---

## 1. PROJECT MISSION

This platform is the **architectural foundation** for a production-grade B2B electronic invoice processing system serving Croatian legal entities. This is not a prototype. This is not an experiment. This system will handle **legally binding financial documents** with zero tolerance for data corruption, loss, or regulatory non-compliance.

**Core Commitments:**
- **Fire-and-forget reliability** - Clients submit documents and trust the system completely
- **Triple redundancy validation** - AI/heuristic verification with consensus mechanisms
- **Regulatory compliance** - Full adherence to Croatian e-invoice standards (FINA e-Račun, UBL 2.1, EN 16931)
- **Multi-channel ingestion** - Email, web upload, API, manual scanning
- **Zero-error tolerance** - Multiple validation layers prevent bad data reaching authorities

---

## 2. MONOREPO STRUCTURE PRINCIPLES

### 2.1 Repository Organization

```
eRacun-development/
├── services/               # Individual microservices (bounded contexts)
│   ├── invoice-gateway-api/
│   ├── email-ingestion-worker/
│   ├── ocr-processing-service/
│   ├── schema-validator/
│   ├── ai-validation-service/
│   ├── ubl-transformer/
│   ├── fina-connector/
│   └── porezna-connector/
├── shared/                 # Shared libraries (use with performance awareness)
│   ├── common-types/       # TypeScript interfaces, domain models
│   ├── validation-core/    # Reusable validation primitives
│   ├── messaging/          # Message bus abstractions
│   └── observability/      # Logging, tracing, metrics
├── config/                 # Configuration templates (see ADR-001)
│   ├── platform.conf.example        # Global settings
│   ├── environment-*.conf.example   # Environment overrides
│   └── services/                    # Service-specific configs
├── secrets/                # SOPS-encrypted secrets (see ADR-002)
│   ├── .sops.yaml          # age public keys for encryption
│   ├── *.env.enc           # Encrypted secrets (safe in git)
│   └── *.env.example       # Secret templates
├── deployment/             # Deployment automation
│   ├── systemd/            # systemd service units
│   ├── ansible/            # Ansible playbooks (optional)
│   └── terraform/          # DigitalOcean infrastructure (optional)
├── docs/                   # Documentation and decisions
│   ├── adr/                # Architecture Decision Records
│   ├── operations/         # Operational runbooks
│   ├── standards/          # Regulatory standards (UBL, CIUS-HR, etc.)
│   ├── research/           # Implementation guides (OIB, VAT, XMLDSig)
│   ├── api-contracts/      # OpenAPI/gRPC specs
│   └── pending/            # Deferred critical issues (PENDING.md)
└── scripts/                # Build, deployment, orchestration scripts
```

### 2.2 Context-Window Optimization Strategy

**Problem:** Large codebases exhaust AI assistant context windows, reducing code quality.

**Solution:** Aggressive service decomposition with clear boundaries.

**Rules:**
1. **Service Size Limit:** No service exceeds 2,500 LOC (excluding tests)
2. **Single Responsibility:** Each service has ONE clearly defined bounded context
3. **Explicit Contracts:** All inter-service communication through typed schemas
4. **Isolated Development:** Services can be developed/reviewed independently
5. **Documentation Proximity:** Each service contains its own README.md with:
   - Purpose and scope
   - API contract
   - Dependencies
   - Performance characteristics
   - Failure modes

### 2.3 Shared Libraries - Performance Considerations

**Philosophy:** Share code carefully. Premature abstraction creates coupling.

**Guidelines:**
- **Only extract to `shared/` after pattern appears in 3+ services**
- **Measure impact:** Every shared library addition requires performance justification
- **Version independently:** Shared libs use semantic versioning
- **Tree-shaking compatible:** All shared code must support dead code elimination
- **Zero-dependency preferred:** Minimize transitive dependencies

**Performance Checklist for Shared Code:**
- [ ] Does not introduce runtime overhead >1ms
- [ ] Bundle size impact <10KB
- [ ] No synchronous I/O in critical paths
- [ ] Benchmark results documented in `shared/*/PERFORMANCE.md`

---

## 3. CODE QUALITY STANDARDS

### 3.1 Development Principles

**"Created with utmost care, but not abundant"** - Every line serves a purpose.

- **No speculative features** - Build what's needed now
- **No premature optimization** - Optimize after measurement
- **No clever code** - Clarity over brevity
- **No silent failures** - Explicit error handling everywhere
- **No magic numbers** - Constants are named and documented

### 3.2 Reliability Patterns (Mandatory)

Every service MUST implement:

1. **Idempotency**
   - All operations use idempotency keys
   - Duplicate requests produce identical results
   - No partial state mutations

2. **Circuit Breakers**
   - External API calls protected by circuit breakers
   - Graceful degradation on dependency failures
   - Health checks expose circuit states

3. **Retry with Exponential Backoff**
   - Transient failures automatically retried
   - Max retry limits enforced (default: 3)
   - Jitter added to prevent thundering herd

4. **Structured Logging**
   - JSON-formatted logs
   - Request IDs propagated through entire call chain
   - Error context captured (never swallow exceptions)

5. **Distributed Tracing**
   - OpenTelemetry instrumentation
   - Every service operation creates spans
   - Trace IDs link cross-service operations

### 3.3 Testing Requirements

**Minimum Coverage:** 85% (enforced in CI)

**Test Pyramid:**
- **Unit Tests:** 70% of test suite - Fast, isolated, no I/O
- **Integration Tests:** 25% - Test service boundaries, message contracts
- **E2E Tests:** 5% - Critical user journeys only

**Special Requirements:**
- **Chaos Testing:** Inject failures (network, CPU, disk) in staging
- **Property-Based Testing:** For validators and transformers
- **Contract Testing:** Pact/Pactflow for inter-service contracts

### 3.4 Security Hardening

**Zero Trust Architecture:**
- No service trusts incoming data without validation
- All inter-service communication authenticated (mTLS in production)
- Secrets managed via SOPS + age encryption (see ADR-002)
- Input sanitization at every boundary

**Secrets Management (Unix/systemd):**
- **SOPS + age:** Encrypted secrets in git (Mozilla open source, €0 cost)
- **Filesystem-based:** `/etc/eracun/secrets/` with 600 permissions
- **systemd integration:** ExecStartPre decrypts before service start
- **tmpfs storage:** Decrypted secrets in `/run/eracun/` (cleared on reboot)
- **File permissions:** Services run as `eracun` user (not root)
- **Never in git:** `.p12`, `.key`, `.pem`, `.env` (protected by .gitignore)
- **See:** ADR-001 (Configuration), ADR-002 (Secrets), `deployment/systemd/`

**XML Security (Critical for e-invoice processing):**
- XXE (XML External Entity) attacks prevented
- Schema validation before parsing
- Size limits enforced (max 10MB per document)
- Billion laughs attack protection

**systemd Hardening:**
- `ProtectSystem=strict` - Read-only filesystem
- `ProtectHome=true` - No access to user directories
- `PrivateTmp=true` - Isolated /tmp directory
- `NoNewPrivileges=true` - Prevent privilege escalation
- `CapabilityBoundingSet=` - Drop all Linux capabilities
- `SystemCallFilter=@system-service` - Restrict system calls
- `InaccessiblePaths=/etc/eracun/.age-key` - Hide encryption keys

---

## 4. AI-ASSISTED DEVELOPMENT GUIDELINES

### 4.1 Context Window Management

**Problem:** AI assistants lose coherence when context exceeds token limits.

**Solutions:**

1. **Service-Scoped Sessions**
   - Develop one service at a time in isolation
   - Load only relevant service code into context
   - Use `CLAUDE.md` + service `README.md` as foundation

2. **Progressive Disclosure**
   - Start with interfaces/types
   - Then core business logic
   - Finally infrastructure concerns

3. **Checkpoint Documentation**
   - After each significant change, update service README
   - Document decisions in ADRs
   - AI sessions can resume from documented state

### 4.2 Code Review Protocol

**Every AI-generated code block must:**
1. Be read and understood by human developer
2. Pass automated tests
3. Be reviewed for security vulnerabilities
4. Be profiled if performance-critical
5. Include error handling for all failure modes

**Red Flags (Auto-reject):**
- Missing error handling
- Hardcoded credentials
- Synchronous blocking in async contexts
- Unbounded loops/recursion
- Missing input validation

---

## 5. SERVICE COMMUNICATION

### 5.1 Message Bus Architecture

**Primary:** RabbitMQ (reliability, mature tooling)
**Event Store:** Apache Kafka (event sourcing, replay capability)

**Message Patterns:**
- **Commands:** Direct service-to-service (RabbitMQ RPC)
- **Events:** Broadcast state changes (Kafka topics)
- **Queries:** Synchronous HTTP/gRPC (limited use)

**Message Schema:**
- All messages defined in Protocol Buffers (`.proto`)
- Versioned schemas (backward compatibility required)
- Schema registry enforced (no runtime schema mismatches)

### 5.2 API Contracts

**External APIs:** REST + OpenAPI 3.1 specifications
**Internal APIs:** gRPC with Protocol Buffers
**Webhooks:** CloudEvents standard

**Contract Testing:**
- Producer provides contract tests
- Consumers verify against contracts
- Breaking changes require major version bump

---

## 6. DEPLOYMENT & ORCHESTRATION

### 6.1 Target Environment

**Platform:** DigitalOcean Dedicated Droplets (Linux)
**Operating System:** Ubuntu 22.04 LTS or Debian 12+
**Orchestrator:** systemd (native Linux service manager)
**Architecture:** Unix-native, filesystem-based configuration
**Philosophy:** Classic Unix conventions (POSIX standards, FHS compliance)

**Environment Separation:**
- **Development:** `dev.eracun.internal` (local or dedicated droplet)
- **Staging:** `staging.eracun.internal` (FINA test environment: cistest.apis-it.hr)
- **Production:** `production.eracun.hr` (FINA production: cis.porezna-uprava.hr)

**Infrastructure Components:**
- **Message Bus:** RabbitMQ (self-hosted on droplet)
- **Database:** PostgreSQL (DigitalOcean Managed Database recommended)
- **Observability:** Prometheus + Grafana (self-hosted)
- **Workflow Engine:** Temporal (future consideration for complex sagas)

**Future Scaling:** Kubernetes migration possible if horizontal scaling requirements exceed single-server capacity.

### 6.2 Deployment Strategy

**systemd Service Deployment:**
- Services deployed as systemd units to `/etc/systemd/system/`
- Service code deployed to `/opt/eracun/services/{service-name}/`
- Configuration in `/etc/eracun/` (platform/environment/service hierarchy)
- Secrets decrypted via systemd `ExecStartPre` hook

**Rolling Deployment Process:**
1. Build service locally or in CI/CD pipeline
2. rsync built artifacts to droplet `/opt/eracun/services/`
3. Update configuration files in `/etc/eracun/` if needed
4. Reload systemd: `systemctl daemon-reload`
5. Restart service: `systemctl restart eracun-{service-name}`
6. Verify health: `systemctl status eracun-{service-name}`

**Zero-Downtime Strategy:**
- Run multiple service instances behind nginx/HAProxy
- Drain connections before restart (systemd `ExecStop` with graceful shutdown)
- Health checks prevent routing to restarting services
- Rollback: `systemctl stop new-service && systemctl start old-service`

**See:** `deployment/systemd/README.md` for complete deployment procedures

### 6.3 System-Level Services

**Critical Daemons (systemd units):**
- `eracun-healthcheck.service` - System-wide health monitoring
- `eracun-deadletter.service` - Failed message reprocessing
- `eracun-audit.service` - Immutable audit log writer

**Cron-Based Tasks:**
- `eracun-daily-report.timer` - Daily reconciliation reports
- `eracun-cert-renewal.timer` - TLS certificate rotation
- `eracun-backup-verification.timer` - Backup integrity checks

---

## 7. OBSERVABILITY

### 7.1 The Three Pillars

**Metrics (Prometheus + Grafana):**
- Request latency (p50, p95, p99)
- Error rates by service
- Queue depths
- Database connection pool utilization

**Logs (ELK Stack or Loki):**
- Structured JSON logs
- Request ID correlation
- Error context preservation

**Traces (Jaeger):**
- End-to-end request flow
- Performance bottleneck identification
- Cross-service dependency visualization

### 7.2 Alerting

**On-Call Severity Levels:**
- **P0 (Page immediately):** Service down, data loss risk
- **P1 (Page in 15min):** Degraded performance, SLA breach risk
- **P2 (Ticket next day):** Non-critical errors, capacity warnings

**Alert Principles:**
- Every alert must be actionable
- No noisy alerts (max 1 false positive per week)
- Runbooks linked in alert descriptions

---

## 8. REGULATORY COMPLIANCE

**⚠️ CRITICAL: See CROATIAN_COMPLIANCE.md for complete regulatory specifications**

### 8.1 Croatian E-Invoice Standards (Fiskalizacija 2.0)

**Effective Date:** 1 January 2026 (HARD DEADLINE)
**Legal Framework:** Croatian Fiscalization Law (NN 89/25)

**Mandatory Formats:**
- **UBL 2.1** (OASIS Universal Business Language) - PRIMARY
- **EN 16931-1:2017** (European e-invoicing semantic model) - REQUIRED
- **Croatian CIUS** (Core Invoice Usage Specification with extensions) - REQUIRED
- **Alternative:** UN/CEFACT CII v.2.0 (less common)

**Mandatory Data Elements:**
- **OIB Numbers:** Issuer (BT-31), Operator (HR-BT-5), Recipient (BT-48)
- **KPD Classification:** 6-digit KLASUS 2025 codes for EVERY line item
- **VAT Breakdown:** Category codes + rates (25%, 13%, 5%, 0%)
- **Digital Signature:** XMLDSig with FINA X.509 certificate
- **Qualified Timestamp:** eIDAS-compliant for B2B invoices

**Validation Layers:**
1. **Syntactic:** XSD schema validation (UBL 2.1)
2. **Business Rules:** Schematron validator (Croatian CIUS)
3. **KPD Validation:** Against official KLASUS registry
4. **Semantic:** Business rules engine (tax rates, VAT validation)
5. **Cross-Reference:** AI-based anomaly detection
6. **Consensus:** Triple redundancy with majority voting

**Integration Endpoints:**
- **B2C Fiscalization:** SOAP API `https://cis.porezna-uprava.hr:8449/FiskalizacijaService`
- **B2B Exchange:** AS4 protocol via Access Point (four-corner model)
- **Test Environment:** `https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest`

---

### 8.2 Audit & Archiving Requirements

**⚠️ CRITICAL - NON-COMPLIANCE PENALTIES:**
- **Fines:** Up to 66,360 EUR
- **VAT Deduction Loss:** Retroactive tax liability
- **Criminal Liability:** For intentional destruction

**Retention Period:** **11 YEARS** (NOT 7 years)

**Format Requirements:**
- ✅ Original XML with UBL 2.1 structure
- ✅ Preserved digital signatures (must remain valid)
- ✅ Preserved qualified timestamps
- ✅ Submission confirmations (JIR for B2C, UUID for B2B)
- ❌ PDF conversion NOT legally compliant
- ❌ Paper printouts NOT legally compliant

**Storage Characteristics:**
- **Immutability:** WORM (Write Once Read Many) required
- **Encryption:** AES-256 at rest (minimum)
- **Geographic Redundancy:** EU region + backup location
- **Integrity Verification:** Automated signature checks (monthly minimum)
- **Access Control:** Audit trail of all retrievals
- **Archive Tier:** Cold storage after 1 year (cost optimization)

**Audit Trail:**
- Every document transformation logged
- Request IDs propagated through entire processing chain
- Error context captured (never swallow exceptions)
- Cryptographic signatures on audit entries
- Cross-referenced with Tax Authority submission records

---

### 8.3 Compliance Obligations Calendar

**1 September 2025:**
- Testing environment live
- Begin certificate acquisition (5-10 day processing)
- Start KPD product mapping
- Register with FiskAplikacija (ePorezna portal)

**1 September - 31 December 2025 (Transition Period):**
- Confirm information system provider
- Grant fiscalization authorization
- Register endpoints with AMS (Address Metadata Service)
- Complete integration testing
- Obtain production FINA certificates

**1 January 2026 (MANDATORY COMPLIANCE):**
- **VAT Entities:** Issue + receive + fiscalize all B2B/B2G/B2C invoices
- **Non-VAT Entities:** Receive + fiscalize incoming invoices only

**Monthly (by 20th of following month):**
- **eIzvještavanje (e-Reporting):** Payment data + rejection reports

**1 January 2027:**
- **Non-VAT Entities:** Issuing e-invoices becomes mandatory

---

### 8.4 Certificate Management

**FINA Application Certificates (X.509):**
- **Type:** Qualified digital certificates for fiscalization
- **Cost:** ~39.82 EUR + VAT per 5-year certificate
- **Demo Certificates:** FREE for testing (1-year validity)
- **Issuance Time:** 5-10 business days
- **Issuer:** FINA (primary) or AKD (alternative)
- **Format:** .p12 soft certificate (PKCS#12)

**Cryptographic Requirements:**
- **Signature Algorithm:** SHA-256 with RSA
- **Standard:** XMLDSig (enveloped signature)
- **PKI Hierarchy:** Fina Root CA → Fina RDC 2015 CA → Application Certificate
- **ZKI Code:** MD5 hash signed with private key (B2C receipts)

**Lifecycle Management:**
- **Renewal:** 30 days before expiration
- **Revocation:** Immediate notification to FINA required
- **Key Storage:** Hardware Security Module (HSM) preferred for production
- **Access Control:** Minimum privilege, audit logging

**Acquisition Contacts:**
- FINA Support: 01 4404 707
- Portal: cms.fina.hr
- CMS activation: Online via NIAS authentication

---

## 9. DEVELOPMENT WORKFLOW

### 9.1 Git Branching Strategy

**Trunk-Based Development:**
- `main` branch always deployable
- Feature branches max 2 days lifespan
- CI/CD on every commit to `main`

**Branch Naming:**
```
feature/<service-name>/<short-description>
fix/<service-name>/<issue-number>
refactor/<service-name>/<improvement>
```

### 9.2 Commit Standards

**Conventional Commits:**
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `chore`
**Scope:** Service name (e.g., `email-worker`, `schema-validator`)

### 9.3 CI/CD Pipeline

**On Every Commit:**
1. Lint (ESLint, Prettier)
2. Type check (TypeScript strict mode)
3. Unit tests (Jest)
4. Security scan (Snyk, Trivy)
5. Build Docker images
6. Push to registry (only on `main`)

**On Merge to Main:**
7. Integration tests (Testcontainers)
8. Deploy to staging
9. E2E smoke tests
10. Deploy to production (manual approval gate)

### 9.4 Critical Issue Tracking (MANDATORY)

**⚠️ CONSTITUTIONAL MANDATE:** All identified critical gaps MUST be tracked in `PENDING.md`

**Purpose:** Prevent critical work from being forgotten when deferred for higher priorities.

**When to Create PENDING Item:**
- ✅ Critical architectural gap identified (blocks or risks significant work)
- ✅ Scope is clear (known what needs deciding/building)
- ✅ Can't address immediately due to higher priority work
- ❌ Simple bugs (use GitHub issues or fix immediately)
- ❌ Vague concerns without clear scope (discuss first)

**Workflow (NON-NEGOTIABLE):**

1. **Identify Gap**
   - During architecture review, development, or design
   - Recognize it blocks or creates risk for other work

2. **Create Detailed Specification**
   - File: `docs/pending/{number}-{slug}.md`
   - Number sequentially (001, 002, 003...)
   - Must include:
     - Problem statement (what's missing/wrong)
     - Scope (what needs deciding/building)
     - Open questions requiring decisions
     - Deliverables required to close
     - What it blocks
     - Why deferred (what was higher priority)
     - Estimated effort

3. **Track in PENDING.md**
   - Add to appropriate priority section
   - Link to detailed file
   - Note blockers and dependencies

4. **Resolve When Priority Allows**
   - Complete deliverables (ADRs, implementation, docs)
   - Update related documents (CLAUDE.md, TBD.md)
   - Move from "Active Items" to "Completed Items"

**Priority Levels (P0-P3):**
- **🔴 P0 (Critical):** Blocks all work, resolve immediately
- **🟡 P1 (High):** Blocks significant work, resolve this sprint
- **🟢 P2 (Medium):** Important but not blocking, resolve soon
- **⚪ P3 (Low):** Nice to have, address when convenient

**PENDING.md vs TBD.md:**
- **TBD.md** = Questions without answers (architectural exploration)
- **PENDING.md** = Work with known scope (implementation deferred)

**Review Cadence:** Weekly triage required
- Re-prioritize as work evolves
- Promote P1→P0 if blocking increases
- Close P2/P3 if no longer relevant

**Git Integration:**
- Commit messages: `fix(pending-001): implement configuration strategy`
- ADRs reference: `See PENDING-001 for background`

**Violation Consequences:**
- Critical gaps not tracked = forgotten work = system risk
- This is **NON-NEGOTIABLE** project hygiene

---

## 10. PERFORMANCE BUDGETS

**API Response Times:**
- Document upload: <200ms (p95)
- Validation pipeline: <5s (p99)
- XML generation: <1s (p95)
- FINA submission: <3s (p99)

**Resource Limits (per service):**
- Memory: 512MB (burst to 1GB)
- CPU: 0.5 cores (burst to 2 cores)
- Disk I/O: 100 IOPS sustained

**Scalability Targets:**
- 10,000 invoices/hour (initial)
- 100,000 invoices/hour (12-month target)
- Horizontal scaling to 50+ service replicas

---

## 11. DISASTER RECOVERY

### 11.1 Backup Strategy

**RTO (Recovery Time Objective):** 1 hour
**RPO (Recovery Point Objective):** 5 minutes

**Backup Scope:**
- Database: Continuous WAL archiving + daily snapshots
- Object storage: Cross-region replication
- Configuration: Git-versioned IaC

### 11.2 Incident Response

**Runbook Requirements:**
- Every service has failure mode documentation
- Recovery procedures tested quarterly
- Incident commander rotation schedule

---

## 12. OPEN QUESTIONS & CONSTRAINTS

See `TBD.md` for unresolved architectural decisions requiring stakeholder input.

---

## 13. CONTINUOUS IMPROVEMENT

This document is a living artifact. Update it when:
- New architectural patterns are adopted
- Performance budgets change
- Regulatory requirements evolve
- Post-incident learnings require process changes

**Version History:**
- `v1.0.0` - Initial architecture foundation (2025-11-09)

---

**Last Updated:** 2025-11-09
**Document Owner:** System Architect
**Review Cadence:** Monthly
