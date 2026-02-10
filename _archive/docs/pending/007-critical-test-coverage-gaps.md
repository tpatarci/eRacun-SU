# PENDING-007: Critical Test Coverage Gaps

**Priority:** 🔴 P0 (Critical)
**Created:** 2025-11-14
**Estimated Effort:** 12 engineering days (2 engineers × 1 week)
**Deadline:** 2025-11-21 (7 days)

---

## Problem Statement

**CRITICAL COMPLIANCE FAILURE:** 8 core business logic services have ZERO test coverage, violating the mandatory 100% coverage requirement for legally compliant invoice processing. This exposes the system to potential €66,360 penalties, VAT deduction loss, and criminal liability.

**Root Cause:** Test infrastructure (Jest + TypeScript) not installed or configured in core validation services.

---

## Affected Services

### 🔴 P0 Critical - Core Validation Services (IMMEDIATE)

1. **oib-validator** - OIB number validation (ISO 7064 Mod 11,10 check digit)
   - Impact: Invalid OIB numbers could be accepted, leading to FINA rejection
   - Business Logic: 11-digit validation + checksum algorithm
   - Coverage: **0%**

2. **kpd-validator** - KPD classification validation (KLASUS 2025 codes)
   - Impact: Incorrect KLASUS codes could cause compliance violations
   - Business Logic: 6-digit code validation against KLASUS registry
   - Coverage: **0%**

3. **xsd-validator** - XML Schema validation (UBL 2.1)
   - Impact: Malformed UBL 2.1 XML could be submitted to FINA
   - Business Logic: XML Schema validation, structure verification
   - Coverage: **0%**

4. **schematron-validator** - Croatian CIUS business rules
   - Impact: Croatian CIUS business rules violations
   - Business Logic: Business rule validation (VAT rates, required fields)
   - Coverage: **0%**

5. **xml-parser** - XML parsing with XXE protection
   - Impact: XXE attacks, billion laughs attacks, security vulnerabilities
   - Business Logic: XML parsing, external entity disabling, size limits
   - Coverage: **0%**

6. **digital-signature-service** - XMLDSig signature generation/verification
   - Impact: Invalid signatures could be generated
   - Business Logic: XMLDSig signature generation and verification
   - Coverage: **0%**

### 🔴 P0 Critical - Integration Services (URGENT)

7. **fina-connector** - FINA Tax Authority SOAP API integration
   - Impact: Submission failures, timeout handling, retry logic
   - Business Logic: SOAP API integration, certificate management, error handling
   - Coverage: **0%**

8. **pdf-parser** - PDF text extraction
   - Impact: Text extraction failures, OCR fallback issues
   - Business Logic: PDF text extraction, metadata extraction
   - Coverage: **0%**

---

## What This Blocks

### Blocks EVERYTHING (DEPLOYMENT FREEZE)

- ⛔ **All production deployments** - Cannot deploy without core validation coverage
- ⛔ **Staging deployments** - Same regulatory requirements apply
- ⛔ **January 1, 2026 compliance deadline** - 47 days remaining
- ⛔ **Legal compliance** - Exposed to €66,360 penalties + criminal liability
- ⛔ **Regulatory approval** - FINA integration certification requires proof of testing

### Does NOT Block

- ✅ Development of other services (can proceed in parallel)
- ✅ Infrastructure work (monitoring, logging, etc.)
- ✅ Documentation updates

---

## Scope

### Phase 1: Test Infrastructure Setup (Days 1-2)

**For each of the 8 services:**
- [ ] Install Jest + TypeScript dependencies
- [ ] Create `jest.config.js` with 100% coverage threshold
- [ ] Create test directory structure (`tests/unit/`, `tests/integration/`)
- [ ] Configure coverage reporters (json-summary, text, html, lcov)
- [ ] Add test scripts to `package.json`
- [ ] Verify test runner executes successfully

### Phase 2: Unit Tests - Pure Functions (Days 3-5)

**oib-validator:**
- [ ] Valid OIB numbers (real examples)
- [ ] Invalid checksum
- [ ] Invalid format (not 11 digits)
- [ ] Edge cases (all zeros, all nines, etc.)
- [ ] Mod 11,10 algorithm correctness

**kpd-validator:**
- [ ] Valid KLASUS 2025 codes
- [ ] Invalid codes (not in registry)
- [ ] Edge cases (6-digit format validation)
- [ ] Registry update handling

**xsd-validator:**
- [ ] Valid UBL 2.1 XML documents
- [ ] Invalid XML structure
- [ ] Missing required fields
- [ ] Invalid data types
- [ ] Schema version validation

**schematron-validator:**
- [ ] All Croatian CIUS business rules
- [ ] VAT rate validation (25%, 13%, 5%, 0%)
- [ ] Required field validation
- [ ] Cross-field validation
- [ ] Error message correctness

**xml-parser:**
- [ ] Valid XML parsing
- [ ] XXE attack prevention (disabled external entities)
- [ ] Entity expansion limits (billion laughs protection)
- [ ] Size limit enforcement (max 10MB)
- [ ] Malformed XML handling

**digital-signature-service:**
- [ ] Signature generation (XMLDSig)
- [ ] Signature verification
- [ ] Certificate validation
- [ ] Certificate expiry handling
- [ ] Invalid signature detection

**fina-connector:**
- [ ] Successful SOAP submission
- [ ] Network failure handling
- [ ] Timeout handling
- [ ] Circuit breaker behavior
- [ ] Retry logic (exponential backoff)
- [ ] Certificate authentication

**pdf-parser:**
- [ ] Valid PDF text extraction
- [ ] Scanned image handling
- [ ] Corrupted PDF handling
- [ ] Metadata extraction
- [ ] Empty PDF handling

### Phase 3: Integration Tests (Days 6-7)

**For each service:**
- [ ] External API integration tests (mocked)
- [ ] Database integration tests (Testcontainers)
- [ ] Circuit breaker failure scenarios
- [ ] Retry logic verification
- [ ] Error path coverage

### Phase 4: Verification & Documentation (Day 7)

**For each service:**
- [ ] Run `npm run test:coverage`
- [ ] Verify 100% coverage (or document valid exemptions)
- [ ] Add coverage badge to README.md
- [ ] Document infrastructure exemptions in `jest.config.js`
- [ ] Add tests to CI/CD pipeline
- [ ] Generate HTML coverage report
- [ ] Archive coverage for compliance audit

---

## Deliverables Required

### Per-Service Deliverables (8 services × checklist)

1. **Test Infrastructure**
   - [ ] `package.json` with Jest dependencies
   - [ ] `jest.config.js` with 100% threshold
   - [ ] `tests/` directory structure

2. **Unit Tests**
   - [ ] Tests for all pure functions
   - [ ] Edge case coverage
   - [ ] Error path coverage
   - [ ] Target: 100% coverage

3. **Integration Tests**
   - [ ] External API integration tests
   - [ ] Database integration tests
   - [ ] Circuit breaker tests
   - [ ] Retry logic tests

4. **Documentation**
   - [ ] Infrastructure exemptions documented
   - [ ] Test coverage badge in README
   - [ ] Coverage report generated
   - [ ] Added to CI/CD pipeline

### Aggregate Deliverables

5. **Coverage Dashboard**
   - [ ] HTML dashboard for all 8 services
   - [ ] Consolidated coverage report
   - [ ] CI/CD integration

6. **Quality Gates**
   - [ ] CI/CD fails on coverage drop
   - [ ] Pre-commit hooks enforce test execution
   - [ ] Coverage reports archived

---

## Open Questions Requiring Decisions

1. **Mutation Testing Timeline**
   - Question: Should mutation testing (Stryker) be included in Phase 1 or deferred to Phase 2?
   - Options:
     - A) Include in Phase 1 (adds 3 days)
     - B) Defer to Phase 2 (after 100% coverage achieved)
   - Recommendation: Defer to Phase 2 (prioritize 100% coverage first)

2. **Contract Testing Timeline**
   - Question: Should Pact contract tests be included in Phase 1?
   - Options:
     - A) Include in Phase 1 (adds 2 days)
     - B) Defer to Phase 2 (separate PENDING item)
   - Recommendation: Defer to Phase 2 (PENDING-008)

3. **Property-Based Testing**
   - Question: Should fast-check property tests be included?
   - Options:
     - A) Include in Phase 1 (adds 1 day)
     - B) Defer to PENDING-005 (existing item)
   - Recommendation: Defer to PENDING-005

---

## Why Deferred Until Now

1. **Team 2 Focus:** Team 2 (Ingestion & Document Processing) was building their services first
2. **Parallel Work:** Core validation services were built by different teams
3. **Discovery:** Test coverage audit (TASK 1) revealed gaps on 2025-11-14
4. **Prioritization:** Other P0 work (architecture compliance, configuration) took precedence

---

## Remediation Plan

### Timeline: 7 Days (2025-11-15 to 2025-11-21)

**Assigned:** 2 Senior Backend Engineers

**Daily Milestones:**

**Day 1 (2025-11-15):**
- Setup test infrastructure for all 8 services
- Verify test runners execute successfully
- Create test file templates

**Days 2-4 (2025-11-16 to 2025-11-18):**
- Write unit tests for all pure functions
- Engineer 1: oib-validator, kpd-validator, xsd-validator, schematron-validator
- Engineer 2: xml-parser, digital-signature-service, fina-connector, pdf-parser

**Days 5-6 (2025-11-19 to 2025-11-20):**
- Write integration tests
- Increase coverage to 100% (or document exemptions)
- Fix failing tests

**Day 7 (2025-11-21):**
- Verify 100% coverage achieved
- Generate coverage reports
- Add to CI/CD pipeline
- Update documentation
- LIFT DEPLOYMENT FREEZE ✅

---

## Success Criteria

### Must Achieve (Non-Negotiable)

- ✅ 100% statement coverage for all 8 services
- ✅ 100% branch coverage for validation logic
- ✅ 100% function coverage for core functions
- ✅ All infrastructure exemptions documented
- ✅ CI/CD pipeline enforces coverage threshold
- ✅ Coverage reports archived for compliance audit

### Red Flags (Auto-Fail)

- ❌ Any uncovered validation logic
- ❌ Missing tests for error paths
- ❌ Undocumented coverage exemptions
- ❌ Tests without assertions
- ❌ Disabled or skipped tests

---

## Risk Assessment

### If NOT Resolved by 2025-11-21

**Legal Risk:**
- €66,360 penalties for non-compliance
- VAT deduction loss (retroactive tax liability)
- Criminal liability for data destruction
- 11-year audit liability

**Business Risk:**
- January 1, 2026 deadline at risk (47 days remaining)
- FINA integration certification blocked
- Production deployment freeze continues
- Customer onboarding delayed

**Technical Risk:**
- Undetected bugs in core validation logic
- Security vulnerabilities (XXE, signature bypass)
- Data corruption (invalid OIBs, KPD codes)
- Integration failures (FINA connector)

---

## Escalation Path

**Immediate:**
- [x] Engineering Lead notified via TASK-1 coverage audit report
- [ ] 2 Senior Backend Engineers assigned
- [ ] Daily standup scheduled (9:00 AM, 15-minute timebox)
- [ ] DEPLOYMENT FREEZE in effect

**Daily (Until Resolved):**
- [ ] Coverage metrics tracked
- [ ] Blockers escalated
- [ ] Engineering Lead receives status update

**Final (2025-11-21):**
- [ ] Coverage audit re-run
- [ ] Deployment freeze lifted (if 100% achieved)
- [ ] Completion report filed

---

## Related Documentation

- **Coverage Audit Report:** `docs/reports/2025-11-14-TASK-1-coverage-audit.md`
- **TASK 1 Instructions:** `TASK_1.md`
- **Development Standards:** `@docs/DEVELOPMENT_STANDARDS.md` (Section 2: Testing)
- **Compliance Requirements:** `@docs/COMPLIANCE_REQUIREMENTS.md`
- **CLAUDE.md:** Project overview and testing philosophy

---

## Next Actions

**Immediate (Today):**
1. ✅ Create this PENDING-007 item (DONE)
2. ⏳ Update PENDING.md with PENDING-007
3. ⏳ Assign 2 Senior Backend Engineers
4. ⏳ Schedule daily standup (9:00 AM)
5. ⏳ Communicate DEPLOYMENT FREEZE to all teams

**Tomorrow (2025-11-15):**
6. ⏳ Begin Phase 1: Test infrastructure setup
7. ⏳ First daily standup: verify engineers have access and understand scope

**Weekly (2025-11-21):**
8. ⏳ Re-run TASK 1 coverage audit
9. ⏳ Verify 100% coverage achieved
10. ⏳ Lift deployment freeze
11. ⏳ File completion report

---

**Priority:** 🔴 P0 (Critical)
**Status:** ⏳ Active
**Assigned:** TBD (2 Senior Backend Engineers)
**Created By:** Team B (TASK 1 Coverage Audit)
**Last Updated:** 2025-11-14
