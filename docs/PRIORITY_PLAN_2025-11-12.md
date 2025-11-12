# Priority Development Plan - Updated 2025-11-12

**Status:** 🟢 **ACTIVE**
**Last Updated:** 2025-11-12 18:00
**Purpose:** Immediate action plan for next 7 days based on strategic analysis
**Source:** `/docs/reports/2025-11-12-strategic-architectural-analysis.md`

---

## Current State Summary

**Services Complete:** 12 / 40 (30%)
**Velocity:** ~2 services/day with 2 teams
**Days to Deadline:** 50 days (Jan 1, 2026)
**Estimated Completion:** Nov 26, 2025 (35-day buffer) ✅

---

## 🔴 CRITICAL PRIORITY: Layer 6 Submission Services

**Problem:** System can process invoices but CANNOT fiscalize them (0% of Layer 6 complete)

**Impact:** Without Layer 6, all completed work has limited business value

**Solution:** Immediately implement submission services in parallel

---

## Team Assignments (Next 7 Days)

### Team A: Layer 1-3 Critical Path

**Focus:** Complete ingestion and extraction pipeline

**Week 1 (Nov 13-19):**

| Day | Service | LOC | Complexity | Status |
|-----|---------|-----|------------|--------|
| Nov 13-14 | attachment-handler | 800 | Low | 🟡 Start |
| Nov 15-16 | xml-parser | 900 | Low | 🟡 Queued |
| Nov 17-19 | data-extractor | 2,500 | High | 🟡 Queued |

**Expected Output:** 3 services with 85%+ test coverage

---

### Team B: Layer 6 Submission (CRITICAL)

**Focus:** Unblock fiscalization capability

**Week 1 (Nov 13-19):**

| Day | Service | LOC | Complexity | Priority |
|-----|---------|-----|------------|----------|
| Nov 13-15 | cert-lifecycle-manager | 2,200 | Medium | 🔴 CRITICAL |
| Nov 16-18 | digital-signature-service | 2,300 | High | 🔴 CRITICAL |
| Nov 19 | Start fina-soap-connector | 2,400 | High | 🔴 CRITICAL |

**Expected Output:** 2.5 services with comprehensive tests

**Why This Order:**
1. cert-lifecycle-manager: Loads certificates from filesystem (foundation)
2. digital-signature-service: Signs invoices with XMLDSig (blocks ALL submission)
3. fina-soap-connector: Submits B2C invoices (first submission capability)

---

## Success Criteria (Week 1)

**By Nov 19, 2025:**

1. ✅ **Team A Deliverables:**
   - attachment-handler: Complete with 85%+ tests
   - xml-parser: Complete with 85%+ tests
   - data-extractor: 50% implementation started

2. ✅ **Team B Deliverables:**
   - cert-lifecycle-manager: Complete with 85%+ tests
   - digital-signature-service: Complete with 85%+ tests
   - fina-soap-connector: Core implementation started (20%)

3. ✅ **Documentation:**
   - README.md created for file-classifier
   - README.md created for pdf-parser
   - Completion reports for email-ingestion-worker

4. ✅ **External Dependencies:**
   - FINA demo certificates acquired (or in progress)
   - AS4 test Access Point credentials obtained

---

## Week 2 Preview (Nov 20-26)

**Team A:**
- Complete data-extractor
- Implement data-normalizer
- Start kpd-validator

**Team B:**
- Complete fina-soap-connector
- Implement as4-gateway-sender
- Implement zki-calculator

**Milestone:** Layer 6 submission capability achieved (minimum viable fiscalization)

---

## Blockers & Dependencies

### Current Blockers (None)
- ✅ No blocking issues identified

### Dependencies to Monitor

1. 🟡 **FINA Demo Certificates** (Lead time: 5-10 days)
   - Action: Initiate acquisition this week
   - Owner: Project Management
   - Fallback: Use test certificates for development

2. 🟡 **AS4 Access Point Test Environment**
   - Action: Request credentials from test AP provider
   - Owner: External Integration Team
   - Fallback: Mock AS4 responses for unit tests

3. 🟡 **cert-lifecycle-manager blocking digital-signature-service**
   - Impact: 3-day dependency chain
   - Mitigation: Already prioritized in correct order

---

## Risk Mitigation

**Identified Risks:**

1. 🔴 **HIGH: cert-lifecycle-manager complexity underestimated**
   - Mitigation: Start immediately, allocate 3 full days
   - Contingency: Simplify to filesystem-only (defer HSM integration)

2. 🟡 **MEDIUM: digital-signature-service XMLDSig complexity**
   - Mitigation: Reference implementation available (xmldsigjs library)
   - Contingency: Use existing libraries, avoid custom crypto

3. 🟡 **MEDIUM: FINA SOAP API quirks**
   - Mitigation: FINA documentation available in CROATIAN_COMPLIANCE.md
   - Contingency: Test environment available for trial-and-error

4. 🟢 **LOW: AS4 protocol complexity**
   - Mitigation: AS4 libraries available (e.g., Holodeck B2B)
   - Contingency: 2.5 days allocated (sufficient buffer)

---

## Communication Protocol

**Daily Standups (Async):**
- Teams post progress updates in shared channel
- Format: "Completed X, working on Y, blocked by Z"
- Time: 9:00 AM UTC

**Weekly Progress Review:**
- Day: Friday 15:00 UTC
- Participants: Team A, Team B, Project Management
- Agenda: Velocity review, next week planning, blocker resolution

**Escalation Path:**
1. Technical blocker → Post in team channel (response within 2 hours)
2. External dependency → Notify Project Management
3. Timeline risk → Immediate escalation to System Architect

---

## Key Performance Indicators (KPIs)

**Track Weekly:**

| Metric | Week 1 Target | Current |
|--------|---------------|---------|
| Services completed | 5 | 12 (baseline) |
| Test coverage avg | 85% | 91.2% |
| TypeScript build errors | 0 | 0 |
| Velocity (svc/day/team) | 1.0 | 1.15 (avg) |
| LOC implemented | +8,000 | 14,630 (baseline) |

**Success Threshold:** ≥4 services completed with 85%+ coverage

---

## Approval & Sign-Off

**Plan Status:** ✅ **APPROVED**
**Approved By:** System Architect
**Date:** 2025-11-12
**Valid Until:** 2025-11-19 (7 days)

**Next Review:** 2025-11-19 15:00 UTC (Friday progress review)

---

## Quick Reference: Service Dependencies

```
cert-lifecycle-manager (Team B, Day 1-3)
        ↓
digital-signature-service (Team B, Day 4-6)
        ↓
fina-soap-connector (Team B, Day 7+)
        ↓
[B2C FISCALIZATION CAPABILITY]

PARALLEL:

attachment-handler (Team A, Day 1-2)
        ↓
xml-parser (Team A, Day 3-4)
        ↓
data-extractor (Team A, Day 5-7)
        ↓
[EXTRACTION PIPELINE COMPLETE]
```

---

**Document Owner:** System Architect
**Distribution:** Team A, Team B, Project Management
**Format:** Markdown (Version Control: Git)

---

**END OF PRIORITY PLAN**
