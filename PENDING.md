# PENDING - Critical Issues Requiring Resolution

**Purpose:** Track identified problems that MUST be addressed before related work can proceed.

**Difference from TBD.md:**
- **TBD.md** = Open architectural questions without clear answers yet
- **PENDING.md** = Identified work with known scope, just deferred for prioritization

---

## Priority Levels

- **🔴 P0 (Critical):** Blocks all work, must resolve immediately
- **🟡 P1 (High):** Blocks significant work, resolve this sprint
- **🟢 P2 (Medium):** Important but not blocking, resolve soon
- **⚪ P3 (Low):** Nice to have, address when convenient

---

## Active Items

### 🔴 [PENDING-007](docs/pending/007-critical-test-coverage-gaps.md) - Critical Test Coverage Gaps

**Priority:** 🔴 P0 (Critical)
**Created:** 2025-11-14
**Estimated Effort:** 12 engineering days (2 engineers × 1 week)
**Deadline:** 2025-11-21 (7 days)

**Problem:** 8 core business logic services (oib-validator, kpd-validator, xsd-validator, schematron-validator, xml-parser, digital-signature-service, fina-connector, pdf-parser) have ZERO test coverage, violating mandatory 100% coverage requirement for legally compliant invoice processing.

**Blocks:**
- ⛔ ALL production deployments (DEPLOYMENT FREEZE in effect)
- ⛔ Staging deployments
- ⛔ January 1, 2026 compliance deadline (47 days remaining)
- ⛔ Legal compliance (€66,360 penalty risk + criminal liability)
- ⛔ FINA integration certification

**Does NOT Block:**
- Development of other services (can proceed in parallel)
- Infrastructure work (monitoring, logging, etc.)

**Deliverables Required:**
- [ ] Test infrastructure setup (Jest + TypeScript) for all 8 services
- [ ] Unit tests achieving 100% coverage for core business logic
- [ ] Integration tests for external dependencies
- [ ] Coverage reports and CI/CD integration
- [ ] Documentation of infrastructure exemptions
- [ ] Lift deployment freeze after verification

**Next Action:** Assign 2 Senior Backend Engineers, begin Phase 1 (test infrastructure setup)

**Deferred Because:** Discovered during TASK 1 coverage audit on 2025-11-14. Test infrastructure not installed during initial service development.

**Related:** TASK 1 Coverage Audit Report (`docs/reports/2025-11-14-TASK-1-coverage-audit.md`)

---

### 🔴 [PENDING-008](docs/pending/008-fina-integration-testing.md) - FINA Integration Testing & Certificates

**Priority:** 🔴 P0 (Critical)
**Created:** 2025-11-14
**Estimated Effort:** 10 engineering days (2 weeks)
**Deadline:** 2025-12-05 (21 days)
**Prerequisite:** PENDING-007 must be resolved first

**Problem:** No FINA (Croatian Tax Authority) integration testing performed, and no certificates (demo or production) acquired. Without FINA connectivity, invoices cannot be fiscalized, making the system non-compliant with January 1, 2026 requirements.

**Blocks:**
- ⛔ Invoice fiscalization (cannot submit to Tax Authority)
- ⛔ JIR receipts (B2C) / UUID confirmations (B2B)
- ⛔ January 1, 2026 compliance deadline (47 days remaining)
- ⛔ Legal compliance (€66,360 penalty risk + criminal liability)

**Does NOT Block:**
- Internal testing (after PENDING-007 resolved)
- Other service development

**Deliverables Required:**
- [ ] Acquire FINA demo certificates (free, 1-year validity)
- [ ] Apply for FINA production certificates (€39.82 + VAT, 5-10 days processing)
- [ ] Test connectivity to cistest.apis-it.hr:8449
- [ ] 10+ successful B2C fiscalization tests (verify JIR receipts)
- [ ] 5+ successful B2B exchange tests (verify UUID confirmations)
- [ ] Error handling and circuit breaker verification
- [ ] Integration test report + Certificate status report

**Next Action:** Acquire demo certificates from FINA (cms.fina.hr), test connectivity to test environment

**Deferred Because:** Discovered during TASK 2 compliance assessment on 2025-11-14. Blocked by PENDING-007 (must have passing tests before integration testing).

**Related:** TASK 2 Compliance Assessment (`docs/reports/2025-11-14-TASK-2-compliance-assessment.md`)

---

### 🔴 [PENDING-006](docs/pending/006-architecture-compliance-remediation.md) - Architecture Compliance Remediation

**Priority:** 🔴 P0 (Critical)
**Created:** 2025-11-12
**Estimated Effort:** 2-3 weeks (15-20 engineering days)

**Problem:** 5 architectural violations detected across 3 services: `admin-portal-api` has direct HTTP clients to 3 services, `cert-lifecycle-manager` and `health-monitor` call `notification-service` directly. This violates hub-and-spokes architecture.

**Blocks:**
- Production scalability (cannot scale services independently)
- Fault tolerance (cascade failures)
- Independent deployment (deployment dependencies)

**Does NOT Block:**
- 2026-01-01 compliance deadline (no regulatory impact)
- Archive-service implementation (can proceed in parallel)

**Deliverables Required:**
- [ ] Delete `admin-portal-api/src/clients/` (3 HTTP client files)
- [ ] Remediate `cert-lifecycle-manager/src/alerting.ts` (replace with message bus)
- [ ] Remediate `health-monitor/src/alerting.ts` (replace with message bus)
- [ ] Implement message bus RPC (request-reply pattern)
- [ ] Migrate all queries to message bus
- [ ] Install pre-commit hooks (husky + compliance script)
- [ ] Add CI/CD compliance checks

**Next Action:** Approve remediation plan and assign engineers (1 senior backend + 1 DevOps)

**Deferred Because:** ADR-005 created 2025-11-12 after discovering violations. This is remediation for existing code.

**Compliance Script:** Run `./scripts/check-architecture-compliance.sh` to verify fixes

---

### 🟢 [PENDING-002](docs/pending/002-test-execution-verification.md) - Test Execution Verification (xsd-validator)

**Priority:** 🟢 P2 (Medium)
**Created:** 2025-11-11
**Estimated Effort:** 30 minutes

**Problem:** Test suite written (65+ tests) but not executed to verify all pass and 85% coverage threshold met.

**Blocks:**
- Staging deployment (xsd-validator)
- Production deployment (xsd-validator)

**Does NOT Block:**
- Implementing other services (can proceed in parallel)

**Next Action:** Run `npm install && npm run test:coverage` in `services/xsd-validator/` before staging deployment

**Deferred Because:** User prioritized "Continue building" over immediate verification

---

### 🟡 [PENDING-004](docs/pending/004-archive-performance-benchmarking.md) - Archive Service Performance Benchmarking

**Priority:** 🟡 P1 (High)
**Created:** 2025-11-12
**Estimated Effort:** 3-4 days

**Problem:** Monthly signature validation for 10M invoices requires 278 validations/second sustained throughput. No benchmarks exist to verify digital-signature-service and archive-service can meet this SLA.

**Blocks:**
- M4 milestone (monthly validation workflow integration)
- Production deployment (M6)
- Capacity planning decisions

**Does NOT Block:**
- Service skeleton implementation (completed)
- Database migrations (in progress)

**Deliverables Required:**
- [ ] Benchmark digital-signature-service throughput (single + parallel)
- [ ] Benchmark archive-service monthly validation workflow (100k invoices)
- [ ] Extrapolate to 10M invoices: Confirm <1 hour SLA OR document optimization plan
- [ ] Configure Prometheus alerting thresholds
- [ ] Update runbook with performance expectations

**Next Action:** Wait for M2 infrastructure provisioning (staging environment + sample data)

**Deferred Because:** Infrastructure not ready, higher priority design work (ADR-004) completed first

---

### 🟢 [PENDING-005](docs/pending/005-property-based-testing-implementation.md) - Property-Based Testing Implementation

**Priority:** 🟢 P2 (Medium)
**Created:** 2025-11-12
**Estimated Effort:** 2 days

**Problem:** CLAUDE.md §3.3 mandates property-based testing for validators using fast-check. Current test suite lacks property tests, relying solely on example-based unit tests.

**Blocks:**
- Quality confidence (long-term)
- Unhandled edge case detection

**Does NOT Block:**
- Service deployment (quality enhancement, not blocking)

**Deliverables Required:**
- [ ] Install fast-check in archive-service
- [ ] Implement 5+ properties per validator (payload, hash, idempotency)
- [ ] Extend digital-signature-service with signature verification properties
- [ ] Document property testing patterns in docs/testing/

**Next Action:** Implement after M3 milestone (core service functionality complete)

**Deferred Because:** Higher priority work (service skeleton, migrations, performance benchmarking)

---

### ⚪ [PENDING-003] - Service Documentation Gap (pdf-parser, file-classifier)

**Priority:** ⚪ P3 (Low)
**Created:** 2025-11-12
**Estimated Effort:** 2 hours

**Problem:** pdf-parser and file-classifier services lack README.md files documenting purpose, API contracts, dependencies, and operational characteristics.

**Blocks:**
- Onboarding new developers to these services
- Operational runbooks (understanding failure modes)

**Does NOT Block:**
- Production deployment (services are functional)
- Other service development

**Deliverables Required:**
- [ ] `services/pdf-parser/README.md` with standard service documentation
- [ ] `services/file-classifier/README.md` with standard service documentation
- [ ] Document API contracts (HTTP endpoints, message formats)
- [ ] Document failure modes and recovery procedures

**Next Action:** Create README.md files following template in CLAUDE.md section 2.2

**Deferred Because:** P1 service implementations prioritized (attachment-handler, ubl-transformer)

**Note:** Identified in Team B verification report (2025-11-12-team-b-verification.md)

---

## Completed Items

### ✅ [PENDING-001](docs/pending/001-configuration-security-strategy.md) - Configuration & Secrets Management Strategy

**Status:** ✅ Completed
**Created:** 2025-11-09
**Resolved:** 2025-11-09
**Implementation Time:** ~8 hours (1 day)

**Problem:** No defined strategy for configuration management and secrets protection on DigitalOcean droplets.

**Solution Implemented:**
- **Secrets Management:** SOPS + age encryption (Mozilla open source, €0 cost)
- **Configuration Strategy:** Filesystem-based `/etc/eracun/` hierarchy (ADR-001)
- **Deployment:** systemd service orchestration with Unix conventions

**Deliverables Completed:**
- ✅ ADR-001: Configuration Management Strategy (filesystem-based)
- ✅ ADR-002: Secrets Management with SOPS + age
- ✅ Directory structure: `config/`, `secrets/`, `deployment/systemd/`
- ✅ systemd service template + decrypt-secrets.sh script
- ✅ Configuration templates (.conf.example files)
- ✅ .gitignore with comprehensive secret protection
- ✅ Operational documentation (deployment/systemd/README.md)
- ✅ Updated CLAUDE.md sections 2.1, 3.4, 6.1, 6.2

**Git Commits:**
- `86fa9ad` - feat(config): implement Unix/systemd configuration and secrets management
- `85c70bc` - chore(gitignore): add comprehensive secret protection rules
- `89b9424` - docs(claude): update deployment architecture to Unix/systemd

**Outcome:** Service development can now proceed with secure configuration and secrets management infrastructure.

---

## Process Guidelines

### When to Create a PENDING Item

**Create when:**
- ✅ Critical architectural gap identified
- ✅ Scope is clear (you know what needs deciding/building)
- ✅ Blocks or significantly impacts other work
- ✅ Can't/shouldn't address immediately due to higher priority

**Don't create when:**
- ❌ Simple bug (create GitHub issue or fix immediately)
- ❌ Vague concern without clear scope (discuss first, then create if needed)
- ❌ Already covered in TBD.md (use existing structure)

### Workflow

1. **Identify Issue**
   - During architecture review, code review, or development
   - Recognize it blocks or risks other work

2. **Capture Details**
   - Create `docs/pending/{number}-{slug}.md`
   - Number sequentially (001, 002, etc.)
   - Include: problem statement, scope, decisions required, blockers, deliverables

3. **Add to PENDING.md**
   - List in appropriate priority section
   - Link to detailed file
   - Note what it blocks

4. **Resolve**
   - Complete deliverables (ADRs, code, docs)
   - Move from "Active Items" to "Completed Items"
   - Update related documents (CLAUDE.md, TBD.md)

5. **Reference**
   - Git commit messages: `fix(pending-001): implement Vault configuration strategy`
   - ADRs: `See PENDING-001 for background`

### Priority Triage

**Review PENDING.md weekly:**
- Are P0s still blocking? (Should be resolved ASAP)
- Can P1s be promoted to P0? (If blocking work increases)
- Can P2/P3 be closed? (If no longer relevant)

### Integration with TBD.md

**TBD.md** = Questions without answers
**PENDING.md** = Work with known scope

**Example:**
- TBD.md: "Should we use GraphQL or REST for query API?"
- PENDING.md: "Implement API gateway with chosen protocol (REST decided)"

**Flow:**
```
TBD Question → Decision Made → PENDING Implementation → Completed → Closed
```

---

## References

- **TBD.md** - Open architectural decisions
- **docs/adr/** - Architectural Decision Records (outcomes)
- **docs/pending/** - Detailed pending item specifications

---

**Maintainer:** Technical Lead
**Last Updated:** 2025-11-12 (PENDING-003 added: service documentation gap)
**Review Cadence:** Weekly (during planning)
