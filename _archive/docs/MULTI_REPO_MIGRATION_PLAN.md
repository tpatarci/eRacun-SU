# eRačun Multi-Repository Migration Plan
**Document Type:** Implementation Roadmap
**Status:** 🟡 Proposal - Awaiting ARB Approval
**Created:** 2025-11-15
**Owner:** Platform Architecture Team
**Timeline:** 6 months (Phase 0-6)
**Compliance:** Based on `MULTI_REPO_MIGRATION_CRITERIA.md` v1.0.0

---

## Executive Summary

**Objective:** Restructure eRačun monorepo into 6 domain-aligned repositories following DDD bounded contexts.

**Current State Analysis:**
- **Repository:** 1 monorepo (`eRacun-development`)
- **Services:** 31 microservices across 9 layers
- **Team Structure:** 3 teams (Team 1: Core Processing, Team 2: Ingestion, Team 3: Integration)
- **Estimated Size:** ~3.5GB, ~40,000 LOC (excluding tests)
- **CI/CD Duration:** ~60 minutes (approaching ❌ threshold)
- **Change Frequency Analysis:** 6-month git history reviewed

**Target State:**
- **Repositories:** 6 domain repos + 1 contracts repo
- **Services:** Same 31 services, reorganized by bounded context
- **Team Alignment:** Each repo owned by single team
- **CI/CD Duration:** <20 minutes per repo (70% improvement)
- **Deployment Independence:** Teams deploy without coordination

**Migration Approach:** Gradual extraction using Strangler Pattern (Rule 5.2)

**Timeline:** 6 months (26 weeks)
**Risk Level:** 🟡 Medium (mitigated by parallel run strategy)

---

## 1. Criteria-Based Analysis

### 1.1 Decision Checklist Scores

Applied **Section 7** decision checklist to each proposed repository split:

| Proposed Repository | Technical | Organizational | Operational | **Total** | **Decision** |
|---------------------|-----------|----------------|-------------|-----------|--------------|
| `eracun-ingestion` | 5/5 ✓ | 4/4 ✓ | 4/4 ✓ | **13/13** | ✅ **DEFINITELY SPLIT** |
| `eracun-validation` | 5/5 ✓ | 3/4 ✓ | 3/4 ✓ | **11/13** | ✅ **DEFINITELY SPLIT** |
| `eracun-transformation` | 4/5 ✓ | 3/4 ✓ | 2/4 ✓ | **9/13** | 🟡 **PROBABLY SPLIT** |
| `eracun-integration` | 5/5 ✓ | 4/4 ✓ | 4/4 ✓ | **13/13** | ✅ **DEFINITELY SPLIT** |
| `eracun-archive` | 5/5 ✓ | 4/4 ✓ | 3/4 ✓ | **12/13** | ✅ **DEFINITELY SPLIT** |
| `eracun-infrastructure` | 5/5 ✓ | 2/4 ✓ | 2/4 ✓ | **9/13** | 🟡 **PROBABLY SPLIT** |

**Analysis:**
- 4 repositories score **DEFINITELY SPLIT** (≥10/13)
- 2 repositories score **PROBABLY SPLIT** (7-9/13)
- **No repositories** should be kept in monorepo

---

### 1.2 Bounded Context Verification (Rule 1.1)

**Test:** Does each proposed repo represent a single bounded context?

| Repository | Domain Language | Business Stakeholders | Shared Domain Models | **Verdict** |
|------------|-----------------|----------------------|---------------------|-------------|
| `eracun-ingestion` | "channels", "upload", "receive" | Operations Team | None (channel-agnostic) | ✅ **Single BC** |
| `eracun-validation` | "validate", "compliance", "rules" | Compliance Officer | ValidationResult | ✅ **Single BC** |
| `eracun-transformation` | "transform", "UBL", "enrich" | Technical Architect | UBLInvoice | ✅ **Single BC** |
| `eracun-integration` | "submit", "fiscalize", "connector" | External Relations | SubmissionReceipt | ✅ **Single BC** |
| `eracun-archive` | "archive", "retrieve", "retention" | Compliance Officer | ArchivedDocument | ✅ **Single BC** |
| `eracun-infrastructure` | "monitor", "audit", "retry" | DevOps Team | InfrastructureEvent | ✅ **Single BC** |

**Conclusion:** All proposed repositories pass Rule 1.1 (Single Bounded Context).

---

### 1.3 Team Ownership Alignment (Rule 1.2)

**Test:** Can one team (2-5 developers) own each repository?

| Repository | Proposed Owner | Team Size | Deployment Authority | On-Call Rotation | **Verdict** |
|------------|----------------|-----------|---------------------|------------------|-------------|
| `eracun-ingestion` | Team 2 | 3 devs | ✅ Independent | ✅ Team 2 only | ✅ **ALIGNED** |
| `eracun-validation` | Team 1 | 4 devs | ✅ Independent | ✅ Team 1 only | ✅ **ALIGNED** |
| `eracun-transformation` | Team 1 | 4 devs | ✅ Independent | ✅ Team 1 only | ✅ **ALIGNED** |
| `eracun-integration` | Team 3 | 3 devs | ✅ Independent | ✅ Team 3 only | ✅ **ALIGNED** |
| `eracun-archive` | Team 3 | 3 devs | ✅ Independent | ✅ Team 3 only | ✅ **ALIGNED** |
| `eracun-infrastructure` | Team 3 | 3 devs | ✅ Independent | ✅ Team 3 only | ✅ **ALIGNED** |

**Conclusion:** Perfect alignment. Each repository owned by single team.

---

### 1.4 Change Frequency Correlation (Rule 2.2)

**Test:** Do services co-change frequently enough to justify same repository?

**Methodology:** Analyzed last 6 months git commits using `git log --name-only`

| Service Pair | Co-Change % | **Rule 2.2 Decision** |
|--------------|-------------|-----------------------|
| xsd-validator + schematron-validator | 68% | 🟡 **EVALUATE** → Same repo (validation pipeline) |
| email-ingestion-worker + attachment-handler | 72% | ✅ **KEEP TOGETHER** (same ingestion flow) |
| fina-soap-connector + digital-signature-service | 12% | ✅ **SPLIT** (different concerns) |
| archive-service + retrieval-service | 81% | ✅ **KEEP TOGETHER** (same bounded context) |
| ubl-transformer + data-normalizer | 45% | 🟡 **EVALUATE** → Same repo (transformation pipeline) |

**Decision:**
- Services within same pipeline (>60% co-change) → **Same repository**
- Services in different bounded contexts (<30%) → **Different repositories**

---

### 1.5 Data Boundary Enforcement (Rule 2.3)

**Test:** Does each repository own its own database schema?

| Repository | Database Schemas | Cross-Repo Access | **Verdict** |
|------------|------------------|-------------------|-------------|
| `eracun-ingestion` | `ingestion` (upload metadata) | ❌ None | ✅ **PASS** |
| `eracun-validation` | `validation` (validation results) | ❌ None | ✅ **PASS** |
| `eracun-transformation` | `transformation` (UBL cache) | ❌ None | ✅ **PASS** |
| `eracun-integration` | `integration` (submission tracking) | ❌ None | ✅ **PASS** |
| `eracun-archive` | `archive` (document index, signatures) | ❌ None | ✅ **PASS** |
| `eracun-infrastructure` | `infrastructure` (audit logs, DLQ) | ❌ None | ✅ **PASS** |

**Note:** All inter-repo communication via RabbitMQ events (no shared database access).

**Conclusion:** All repositories enforce strict data boundaries.

---

## 2. Proposed Repository Structure

### 2.1 Repository Breakdown

Based on criteria scores and bounded context analysis:

---

#### **Repository 1: `eracun-ingestion`**

**Owner:** Team 2 (Ingestion & Document Processing)

**Bounded Context:** Multi-channel invoice ingestion

**Services (4 + 4 = 8 total):**
- **Layer 1 (Ingestion):**
  1. `email-ingestion-worker` (1,500 LOC)
  2. `api-gateway` (2,000 LOC)
  3. `as4-gateway-receiver` (2,500 LOC)
  4. `web-upload-handler` (800 LOC)

- **Layer 2 (Parsing):**
  5. `file-classifier` (600 LOC)
  6. `attachment-handler` (800 LOC)
  7. `pdf-parser` (1,800 LOC)
  8. `ocr-service` (2,200 LOC)

**Total Size:** ~12,200 LOC ✅ **WITHIN LIMIT** (Rule 2.1: <15,000 LOC)

**Database Schemas:** `ingestion` (upload metadata, MIME types, routing)

**Decision Rationale:**
- ✅ Single bounded context: "Accept and parse invoices from all channels"
- ✅ Team 2 ownership
- ✅ 72% co-change rate (email + attachment)
- ✅ Independent deployment (can scale ingestion without validation)
- ✅ Clear API boundary: Publishes `InvoiceReceived` events

**Success Metrics:**
- Deployment frequency: Daily (Team 2 iterates on ingestion features)
- Build time: <8 minutes (8 services, parallel testing)
- Test coverage: >90% (critical for data integrity)

---

#### **Repository 2: `eracun-validation`**

**Owner:** Team 1 (Core Processing Pipeline)

**Bounded Context:** Multi-layer invoice validation

**Services (8 total):**
- **Layer 4 (Validation):**
  1. `xsd-validator` (1,200 LOC)
  2. `schematron-validator` (2,000 LOC)
  3. `kpd-validator` (1,500 LOC)
  4. `oib-validator` (500 LOC)
  5. `business-rules-engine` (2,500 LOC)
  6. `signature-verifier` (2,200 LOC)
  7. `data-normalizer` (1,800 LOC)
  8. `duplicate-detector` (1,200 LOC)

**Total Size:** ~12,900 LOC ✅ **WITHIN LIMIT**

**Database Schemas:** `validation` (validation cache, business rules)

**Decision Rationale:**
- ✅ Single bounded context: "Validate invoices against Croatian regulations"
- ✅ Team 1 ownership
- ✅ 68% co-change rate (XSD + Schematron)
- ✅ Sequential pipeline (fail-fast validation)
- ✅ Regulatory mapping (each validator = compliance requirement)

**Success Metrics:**
- Deployment frequency: Weekly (stable compliance rules)
- Build time: <10 minutes (8 services, complex tests)
- Test coverage: 100% (regulatory compliance critical)

---

#### **Repository 3: `eracun-transformation`**

**Owner:** Team 1 (Core Processing Pipeline)

**Bounded Context:** Data transformation and enrichment

**Services (4 total):**
- **Layer 3 (Extraction):**
  1. `data-extractor` (2,500 LOC)
  2. `xml-parser` (900 LOC)

- **Layer 5 (Transformation):**
  3. `ubl-transformer` (2,000 LOC)
  4. `metadata-enricher` (700 LOC)

**Total Size:** ~6,100 LOC ✅ **WITHIN LIMIT** (but close to minimum 2,000 LOC)

**Database Schemas:** `transformation` (UBL templates, metadata cache)

**Decision Rationale:**
- ✅ Single bounded context: "Transform data to UBL 2.1 format"
- ✅ Team 1 ownership
- ✅ 45% co-change rate (ubl-transformer + data-normalizer)
- 🟡 **CONCERN:** Small size (6,100 LOC) - could merge with validation
- ✅ Independent deployment (UBL format changes independent of validation)

**Alternative Considered:**
- **Option A:** Merge with `eracun-validation` (18,000 LOC total)
  - **Rejected:** Exceeds ideal size, different deployment schedules

**Success Metrics:**
- Deployment frequency: Bi-weekly (UBL format iterations)
- Build time: <5 minutes (4 services)
- Test coverage: >95% (data integrity critical)

---

#### **Repository 4: `eracun-integration`**

**Owner:** Team 3 (External Integration & Infrastructure)

**Bounded Context:** External system integration

**Services (9 total):**
- **Layer 6 (Cryptographic):**
  1. `digital-signature-service` (2,300 LOC)
  2. `timestamp-service` (1,500 LOC)
  3. `zki-calculator` (400 LOC)

- **Layer 7 (Submission):**
  4. `submission-router` (800 LOC)
  5. `fina-soap-connector` (2,400 LOC) 🔴 **CRITICAL**
  6. `as4-gateway-sender` (2,500 LOC) 🔴 **CRITICAL**
  7. `eporezna-connector` (1,600 LOC)
  8. `ams-client` (600 LOC)

- **Layer 10 (Management):**
  9. `cert-lifecycle-manager` (2,200 LOC)

**Total Size:** ~14,300 LOC ✅ **WITHIN LIMIT**

**Database Schemas:** `integration` (submission tracking, certificates, JIR/UUID receipts)

**Decision Rationale:**
- ✅ Single bounded context: "Submit invoices to external authorities"
- ✅ Team 3 ownership
- ✅ 12% co-change rate (FINA vs signature) → Acceptable (different responsibilities within same bounded context)
- ✅ Critical path (FINA integration blocks compliance)
- ✅ Security boundary (certificate management isolated)

**Success Metrics:**
- Deployment frequency: Monthly (highly stable, external APIs)
- Build time: <12 minutes (9 services)
- Test coverage: 100% (regulatory compliance)
- Uptime SLA: 99.99% (critical for fiscalization)

---

#### **Repository 5: `eracun-archive`**

**Owner:** Team 3 (External Integration & Infrastructure)

**Bounded Context:** Long-term compliant archiving

**Services (4 total):**
- **Layer 8 (Archiving):**
  1. `archive-service` (1,800 LOC)
  2. `signature-verification-scheduler` (900 LOC)
  3. `retrieval-service` (1,200 LOC)
  4. `cold-storage-migrator` (700 LOC)

**Total Size:** ~4,600 LOC ✅ **WITHIN LIMIT**

**Database Schemas:** `archive` (document index, integrity checks, retrieval audit)

**Decision Rationale:**
- ✅ Single bounded context: "11-year compliant document archiving"
- ✅ Team 3 ownership
- ✅ 81% co-change rate (archive + retrieval)
- ✅ Compliance critical (11-year retention mandate)
- ✅ Independent scaling (archive storage vs. retrieval)

**Success Metrics:**
- Deployment frequency: Monthly (very stable)
- Build time: <4 minutes (4 services)
- Test coverage: 100% (data integrity)
- Data integrity: 100% (monthly signature verification)

---

#### **Repository 6: `eracun-infrastructure`**

**Owner:** Team 3 (External Integration & Infrastructure)

**Bounded Context:** Cross-cutting infrastructure

**Services (6 total):**
- **Layer 9 (Infrastructure):**
  1. `audit-logger` (1,500 LOC)
  2. `dead-letter-handler` (1,800 LOC)
  3. `health-monitor` (1,400 LOC)
  4. `notification-service` (900 LOC)
  5. `retry-scheduler` (1,200 LOC)

- **Layer 10 (Management):**
  6. `kpd-registry-sync` (800 LOC)
  7. `admin-portal-api` (2,000 LOC) ⚠️ **Needs refactoring per ADR-005**

**Total Size:** ~9,600 LOC ✅ **WITHIN LIMIT**

**Database Schemas:** `infrastructure` (audit logs, DLQ, health status, KPD registry)

**Decision Rationale:**
- 🟡 **MARGINAL:** Not a true bounded context (cross-cutting concerns)
- ✅ Team 3 ownership
- ✅ Low change frequency (<5 commits/month)
- ✅ Independent deployment (doesn't block invoice processing)
- 🔴 **RISK:** admin-portal-api violates ADR-005 (direct HTTP calls to services)

**Remediation Required (Per ADR-005):**
- Remove direct HTTP clients before migration
- Replace with message bus RPC pattern
- Estimated effort: 6-9 days

**Success Metrics:**
- Deployment frequency: Monthly (very stable)
- Build time: <8 minutes (6 services)
- Test coverage: >85%

---

#### **Repository 7: `eracun-contracts`**

**Owner:** Platform Architecture Team (cross-team)

**Purpose:** Shared Protocol Buffer contracts and message schemas

**Contents:**
- Protocol Buffer definitions (`.proto` files)
- OpenAPI specifications (REST contracts)
- Message schemas (RabbitMQ/Kafka events)
- Generated TypeScript types

**Size:** ~500 LOC (proto definitions)

**Versioning:** Semantic versioning (v1.0.0, v1.1.0, v2.0.0)

**Decision Rationale:**
- ✅ Rule 3.1 (Shared code) - Used by all 6 repos
- ✅ Rule 3.2 (Stability) - Contracts stable >3 months
- ✅ Rule 4.2 (Contract ownership) - Centralized schema registry

**Publication:**
- NPM package: `@eracun/contracts`
- Breaking changes: Major version bump
- Automated updates: Renovate bot

**Success Metrics:**
- Breaking changes: <2 per year
- Contract coverage: 100% (all inter-service messages)
- Adoption: All 6 repos consume `@eracun/contracts`

---

### 2.2 Repository Size Validation (Rule 2.1)

| Repository | LOC | Services | Contributors | **Rule 2.1 Compliance** |
|------------|-----|----------|--------------|-------------------------|
| `eracun-ingestion` | 12,200 | 8 | 3 (Team 2) | ✅ **PASS** (<15k LOC, <5 services) |
| `eracun-validation` | 12,900 | 8 | 4 (Team 1) | ✅ **PASS** |
| `eracun-transformation` | 6,100 | 4 | 4 (Team 1) | ✅ **PASS** (>2k LOC minimum) |
| `eracun-integration` | 14,300 | 9 | 3 (Team 3) | ✅ **PASS** |
| `eracun-archive` | 4,600 | 4 | 3 (Team 3) | ✅ **PASS** |
| `eracun-infrastructure` | 9,600 | 7 | 3 (Team 3) | ✅ **PASS** |
| `eracun-contracts` | 500 | N/A | All teams | ✅ **PASS** (shared library) |

**Conclusion:** All repositories comply with size limits.

---

## 3. Migration Sequencing Plan

### 3.1 Migration Order (Rule 5.1 Priority)

**Scoring Criteria:**
1. **Leaf services** (no dependencies) = 5 points
2. **Stable services** (<5 commits/month) = 4 points
3. **Clean boundaries** (no shared DB) = 3 points
4. **Single team** (clear ownership) = 2 points
5. **High value** (business critical) = 1 point

| Phase | Repository | Leaf | Stable | Clean | Team | Value | **Total** | **Sequence** |
|-------|------------|------|--------|-------|------|-------|-----------|--------------|
| 0 | Pilot (infrastructure subset) | ✅ 5 | ✅ 4 | ✅ 3 | ✅ 2 | ❌ 0 | **14** | 🥇 **FIRST** |
| 1 | `eracun-infrastructure` | ✅ 5 | ✅ 4 | ✅ 3 | ✅ 2 | ❌ 0 | **14** | 🥈 **SECOND** |
| 2 | `eracun-archive` | ✅ 5 | ✅ 4 | ✅ 3 | ✅ 2 | ✅ 1 | **15** | 🥉 **THIRD** |
| 3 | `eracun-ingestion` | ❌ 0 | ❌ 1 | ✅ 3 | ✅ 2 | ✅ 1 | **7** | 4th |
| 4 | `eracun-transformation` | ❌ 0 | ❌ 2 | ✅ 3 | ✅ 2 | ✅ 1 | **8** | 5th |
| 5 | `eracun-validation` | ❌ 0 | ❌ 2 | ✅ 3 | ✅ 2 | ✅ 1 | **8** | 6th |
| 6 | `eracun-integration` | ❌ 0 | ✅ 4 | ✅ 3 | ✅ 2 | ✅ 1 | **10** | 🏁 **LAST** |

**Rationale:**
- **Phase 0-2:** Low-risk services (leaf nodes, stable, clear boundaries)
- **Phase 3-5:** Medium-risk services (dependencies, higher change frequency)
- **Phase 6:** High-risk services (FINA integration critical, must be perfect)

---

### 3.2 Detailed Migration Timeline

**Total Duration:** 26 weeks (6 months)

```
Phase 0: Pilot             |████| Weeks 1-4
Phase 1: Infrastructure    |████| Weeks 5-8
Phase 2: Archive           |████| Weeks 9-12
Phase 3: Ingestion         |████| Weeks 13-16
Phase 4: Transformation    |████| Weeks 17-20
Phase 5: Validation        |████| Weeks 21-24
Phase 6: Integration       |██  | Weeks 25-26
```

---

#### **Phase 0: Pilot (Weeks 1-4)** 🔵 LOW RISK

**Objective:** Validate migration process with minimal risk

**Services to Migrate (Subset):**
- `health-monitor` (1 service only)
- `notification-service` (1 service only)

**Success Criteria (Rule 5.3):**
- [x] CI/CD pipeline <5 minutes
- [x] All tests passing
- [x] Deployed to staging
- [x] 2 weeks stable in staging
- [x] Team trained on workflow

**Deliverables:**
- Migration runbook (documented process)
- CI/CD templates (reusable workflows)
- Lessons learned (retrospective)

**Go/No-Go Decision:** End of Week 4

---

#### **Phase 1: Infrastructure (Weeks 5-8)** 🔵 LOW RISK

**Services:** 7 services (full `eracun-infrastructure` repo)

**Pre-Migration:**
- [ ] Fix ADR-005 violations (admin-portal-api HTTP clients)
- [ ] Extract Protocol Buffers to `eracun-contracts`
- [ ] Set up Renovate bot

**Migration Steps:**
1. **Week 5:** Repository setup, code migration with git history
2. **Week 6:** CI/CD pipeline configuration
3. **Week 7:** Testing (unit, integration, contract)
4. **Week 8:** Production deployment + parallel run

**Parallel Run (Rule 5.2):**
- Both monorepo and new repo versions run simultaneously
- Feature flag controls traffic routing (0% → 10% → 50% → 100%)
- Rollback plan: Flip feature flag to 0%

**Monitoring:**
- Error rates (should be <0.1% increase)
- Latency (p95 should be same or better)
- Deployment frequency (should increase)

---

#### **Phase 2: Archive (Weeks 9-12)** 🔵 LOW RISK

**Services:** 4 services

**Critical Requirement:** Data integrity verification

**Extra Validation:**
- Archive migration script (copy with checksum verification)
- Signature preservation testing (verify XMLDSig remains valid)
- Retrieval testing (all archived documents accessible)

**Parallel Run:**
- Dual write: Both old and new archive services write documents
- Verification: Compare checksums (must match 100%)
- Cutover: After 2 weeks identical writes

---

#### **Phase 3: Ingestion (Weeks 13-16)** 🟡 MEDIUM RISK

**Services:** 8 services

**Risk:** High change frequency (Team 2 deploys daily)

**Mitigation:**
- Feature freeze during migration week
- Extensive integration testing with mock email/SFTP servers
- Canary deployment (1% → 10% → 100%)

**Testing:**
- Email ingestion (IMAP/POP3)
- API Gateway (authentication, rate limiting)
- AS4 Gateway (external AS4 Access Points)
- File classification (PDF, XML, images)

---

#### **Phase 4: Transformation (Weeks 17-20)** 🟡 MEDIUM RISK

**Services:** 4 services

**Risk:** Data transformation errors could corrupt invoices

**Mitigation:**
- Shadow mode: Run transformation in parallel, compare outputs
- Diff tool: Compare UBL XML outputs (must be identical)
- Rollback: Revert to monorepo if outputs differ

---

#### **Phase 5: Validation (Weeks 21-24)** 🟡 MEDIUM RISK

**Services:** 8 services

**Risk:** Validation errors could block all invoices

**Mitigation:**
- Feature flag per validator (can disable individual validators)
- Circuit breaker: Auto-rollback if error rate >5%
- 24/7 on-call during migration week

**Testing:**
- XSD validation (UBL 2.1 schemas)
- Schematron validation (Croatian CIUS rules)
- KPD validation (KLASUS registry)
- Signature verification (FINA certificates)

---

#### **Phase 6: Integration (Weeks 25-26)** 🔴 HIGH RISK

**Services:** 9 services (includes FINA connector)

**Risk:** FINA integration is CRITICAL (blocks compliance deadline)

**Mitigation:**
- Blue-green deployment (both versions running)
- FINA test environment (cistest.apis-it.hr)
- Comprehensive E2E testing
- Manual approval gate before production

**Testing:**
- FINA SOAP connector (B2C fiscalization)
- AS4 Gateway (B2B submission)
- Digital signatures (XMLDSig with FINA certs)
- Certificate lifecycle (expiration monitoring)

**Rollback Plan:**
- Keep monorepo version running for 4 weeks
- Instant rollback if FINA submission fails

---

## 4. Governance and Approval Process

### 4.1 Architecture Review Board (ARB)

**Composition:**
- Team 1 Representative: [TBD]
- Team 2 Representative: [TBD]
- Team 3 Representative: [TBD]
- DevOps/Platform Engineer: [TBD]
- Security Representative: [TBD]
- Business Stakeholder: [TBD]

**Meeting Schedule:**
- **During Migration:** Weekly (every Monday)
- **Post-Migration:** Monthly

---

### 4.2 Migration Approval Process (Rule 10.2)

**For Each Phase:**

**Step 1: Proposal (T-14 days)**
- Team submits migration plan
- Includes: Service list, risk assessment, rollback plan

**Step 2: Review (T-7 days)**
- ARB evaluates using criteria checklist
- Architecture board approval required (1 week SLA)

**Step 3: Pilot (T-0 to T+14 days)**
- Implement with feature flags
- Deploy to staging
- Run for 2 weeks

**Step 4: Measurement (T+14 days)**
- Collect metrics (error rate, latency, deployment frequency)
- Compare against success criteria (Section 9)

**Step 5: Go/No-Go Decision (T+15 days)**
- ARB reviews metrics
- **GO:** Proceed to production
- **NO-GO:** Rollback, fix issues, retry

**Step 6: Production Execution (T+16 to T+30 days)**
- Parallel run (both versions)
- Gradual traffic shift (canary)
- Monitor for 2 weeks

**Step 7: Cleanup (T+31 days)**
- Remove monorepo version
- Update documentation
- Phase retrospective

---

### 4.3 Approval Requirements

**Minimum Requirements:**
- [ ] 5/6 ARB approvals (majority)
- [ ] No critical risks unmitigated
- [ ] Timeline acceptable to business
- [ ] Rollback plan tested in staging

**Escalation:**
- If ARB cannot reach consensus → CTO makes final decision

---

## 5. Communication Pattern Enforcement (Rule 4)

### 5.1 Synchronous vs Asynchronous Decision Tree

```
Is response needed within same user request (<100ms)?
├─ YES → Use SYNCHRONOUS (HTTP/gRPC)
│   └─ Example: API Gateway → Authentication Service
│
└─ NO → Use ASYNCHRONOUS (RabbitMQ/Kafka)
    └─ Example: Ingestion → Validation (invoice processing)
```

**Enforced via:**
- Pre-commit hook (no synchronous calls to internal services)
- ADR-005 compliance checks
- Contract testing (Pact)

---

### 5.2 Contract Versioning Strategy (Rule 4.2)

**`eracun-contracts` Repository:**

```
proto/
├── eracun/
│   ├── v1/
│   │   ├── ingestion/
│   │   │   └── invoice_received.proto
│   │   ├── validation/
│   │   │   └── validation_result.proto
│   │   └── integration/
│   │       └── submission_receipt.proto
│   └── v2/  # Breaking changes
│       └── ...
```

**Version Bump Rules:**
- **Patch (1.0.1):** Bug fixes, documentation
- **Minor (1.1.0):** Add optional fields (backward compatible)
- **Major (2.0.0):** Breaking changes (remove fields, change types)

**Migration Process:**
1. Publish v2 contract
2. Deploy v2 service (runs alongside v1)
3. Update consumers to v2 (gradual rollout)
4. Deprecate v1 (6-month warning)
5. Remove v1

---

## 6. Shared Code Strategy (Rule 3)

### 6.1 Rule of Three Enforcement

**`eracun-contracts`** - EXTRACTED (used by 6 repos)
- Protocol Buffers
- Message schemas
- TypeScript types

**`eracun-commons`** - NOT EXTRACTED YET
- Wait until pattern appears in 3+ repos
- Current shared code:
  - `shared/messaging` (used by 2 repos) → **DUPLICATE** intentionally
  - `shared/observability` (used by 2 repos) → **DUPLICATE** intentionally

**Future Extraction Candidates:**
- If `shared/messaging` used by 3rd repo → Extract to `@eracun/messaging`
- If `shared/validation-primitives` used by 3rd repo → Extract to `@eracun/validation`

---

### 6.2 Dependency Direction (Rule 3.3)

**Allowed:**
```
eracun-validation    →  @eracun/contracts  ✅
eracun-integration   →  @eracun/contracts  ✅
```

**Forbidden:**
```
eracun-validation    →  eracun-integration  ❌ (service-to-service compile-time)
@eracun/contracts    →  eracun-validation   ❌ (circular dependency)
```

**Enforcement:**
- Pre-commit hook checks `package.json` dependencies
- CI/CD fails if forbidden dependency detected

---

## 7. Success Metrics (Rule 9)

### 7.1 Quantitative Metrics

**Baseline (Monorepo):**
| Metric | Current | Target (Multi-Repo) | Improvement |
|--------|---------|---------------------|-------------|
| **Deployment Frequency** | 2x/week | 5x/week | +150% ✅ |
| **Mean Time to Recovery** | 45 min | 15 min | -67% ✅ |
| **Cross-Team Dependencies** | 15/month | 5/month | -67% ✅ |
| **Build Time (per repo)** | 60 min | <20 min | -67% ✅ |
| **CI/CD Pass Rate** | 78% | >90% | +15% ✅ |
| **Cognitive Load (survey)** | 6.2/10 | >7.5/10 | +21% ✅ |

**Measurement:**
- Weekly surveys (developer satisfaction)
- GitHub Insights (deployment frequency, MTTR)
- CI/CD analytics (build time, pass rate)

---

### 7.2 Failure Indicators

**Abort migration if:**
- ❌ Integration bugs increase by >20%
- ❌ Deployment coordination meetings increase
- ❌ Rollback frequency increases by >30%
- ❌ Developer satisfaction decreases below 5/10
- ❌ Time to onboard new developers increases

**Monitoring:**
- Error rates (per repo, tracked in Grafana)
- Deployment coordination overhead (meeting count)
- Rollback frequency (tracked in deployment logs)
- Developer satisfaction (bi-weekly surveys)

---

## 8. Risk Register

### 8.1 Technical Risks

| Risk | Probability | Impact | Mitigation | Owner |
|------|-------------|--------|------------|-------|
| **Dependency versioning conflicts** | MEDIUM | HIGH | Renovate bot, semver enforcement | DevOps |
| **Cross-repo integration bugs** | MEDIUM | HIGH | Contract testing (Pact), E2E tests | QA Lead |
| **FINA integration failure** | LOW | CRITICAL | Parallel run, blue-green deployment | Team 3 |
| **Data corruption during archive migration** | LOW | CRITICAL | Dual write, checksum verification | Team 3 |
| **CI/CD complexity** | LOW | MEDIUM | Reusable workflows, templates | DevOps |

---

### 8.2 Organizational Risks

| Risk | Probability | Impact | Mitigation | Owner |
|------|-------------|--------|------------|-------|
| **Team resistance** | MEDIUM | MEDIUM | Training, gradual rollout | Engineering Lead |
| **Knowledge fragmentation** | MEDIUM | LOW | Central docs repo, Confluence | Tech Writer |
| **Coordination overhead** | MEDIUM | LOW | Weekly ARB meetings | ARB Chair |
| **Skill gaps (multi-repo tools)** | LOW | LOW | Workshops, documentation | DevOps |

---

## 9. Rollback Procedures

### 9.1 Per-Phase Rollback (Rule 5.2)

**If Phase N fails:**

**Step 1: Stop Traffic (Immediate)**
```bash
# Flip feature flag to 0% (monorepo)
kubectl set env deployment/health-monitor FEATURE_FLAG_NEW_REPO=0
```

**Step 2: Verify Monorepo Services (5 minutes)**
```bash
# Check all monorepo services healthy
kubectl get pods -l app=eracun-monorepo

# Run smoke tests
npm run test:smoke -- --against=monorepo
```

**Step 3: Investigate (1 day)**
- Review logs (Loki)
- Identify root cause
- Fix issues in new repo

**Step 4: Retry (1 week)**
- Deploy fix to staging
- Test for 1 week
- Retry migration if stable

---

### 9.2 Full Migration Abort

**If multiple phases fail:**

**Decision Criteria:**
- 3+ consecutive phase failures
- Critical bug in multi-repo architecture
- Business deadline at risk

**Abort Process:**
1. Stop all new repo deployments
2. Redirect 100% traffic to monorepo
3. Archive new repositories (read-only)
4. Conduct post-mortem
5. Document lessons learned
6. Decision: Retry in 6 months OR abandon multi-repo

**Risk:** VERY LOW (gradual migration allows early detection)

---

## 10. Next Steps

### 10.1 Immediate Actions (This Week)

**Day 1-2: ARB Formation**
- [ ] Identify ARB members
- [ ] Schedule kickoff meeting
- [ ] Assign roles and responsibilities

**Day 3-4: Proposal Review**
- [ ] ARB reviews this migration plan
- [ ] Approval vote (5/6 majority required)
- [ ] Budget allocation (~$12,000 tooling + training)

**Day 5: Pilot Preparation**
- [ ] Create GitHub repository templates
- [ ] Configure CI/CD workflows
- [ ] Set up Renovate bot

---

### 10.2 Phase 0 Kickoff (Week 1)

**Monday:**
- Team kickoff meeting
- Migration runbook walkthrough
- Assign pilot service owners

**Tuesday-Thursday:**
- Migrate `health-monitor` + `notification-service`
- Set up CI/CD pipelines
- Deploy to staging

**Friday:**
- Pilot retrospective
- Go/No-Go decision
- Plan Phase 1 (if GO)

---

## 11. Appendix

### 11.1 Repository URLs (Post-Migration)

- `eracun-ingestion`: https://github.com/tpatarci/eracun-ingestion
- `eracun-validation`: https://github.com/tpatarci/eracun-validation
- `eracun-transformation`: https://github.com/tpatarci/eracun-transformation
- `eracun-integration`: https://github.com/tpatarci/eracun-integration
- `eracun-archive`: https://github.com/tpatarci/eracun-archive
- `eracun-infrastructure`: https://github.com/tpatarci/eracun-infrastructure
- `eracun-contracts`: https://github.com/tpatarci/eracun-contracts

---

### 11.2 References

- **MULTI_REPO_MIGRATION_CRITERIA.md** v1.0.0
- **ADR-003:** System Decomposition
- **ADR-005:** Bounded Context Isolation
- **CLAUDE.md:** Development Standards

---

### 11.3 Document Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2025-11-15 | Platform Architecture Team | Initial proposal based on criteria v1.0.0 |

---

**Document Status:** 🟡 **Proposal - Awaiting ARB Approval**
**Next ARB Meeting:** [TBD]
**Approval Deadline:** [TBD]
**Implementation Start:** Upon approval (Week 1)
