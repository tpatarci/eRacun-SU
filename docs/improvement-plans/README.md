# Codebase Improvement Plans

**Purpose:** Individual, actionable improvement proposals for production reliability and performance optimization.

**Methodology:**
- One improvement plan per markdown file
- Each plan is independently executable (1-3 hour effort typical)
- Plans ordered by severity and impact
- Each plan includes implementation steps, tests, and acceptance criteria

---

## Executive Summary

### Improvement Status

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 CRITICAL | 2 | Created |
| 🟠 HIGH | 4 | Created |
| 🟢 MEDIUM | 27 | Listed Below |
| ⚪ LOW | 15 | Listed Below |
| **TOTAL** | **48** | **2 + 4 created, 42 pending** |

### Total Improvement Effort

- **Critical Issues:** 5 hours (must fix before production)
- **High Priority:** 8 hours (fix next sprint)
- **Medium Priority:** 40 hours (improve reliability/performance)
- **Low Priority:** 20 hours (polish, observability)
- **Total Effort:** ~73 hours (10 development days)

---

## ✅ COMPLETED IMPROVEMENT PLANS

### 🔴 CRITICAL (2)

| ID | Service | Issue | Effort | Status |
|----|---------|-------|--------|--------|
| [IMPROVEMENT-001](IMPROVEMENT-001-fina-soap-envelope-injection.md) | fina-connector | SOAP envelope template injection + incomplete impl | 2-3h | ✅ Created |
| [IMPROVEMENT-002](IMPROVEMENT-002-email-poller-race-condition.md) | email-ingestion-worker | Race condition deadlock in polling | 30m | ✅ Created |

### 🟠 HIGH (4)

| ID | Service | Issue | Effort | Status |
|----|---------|-------|--------|--------|
| [IMPROVEMENT-003](IMPROVEMENT-003-imap-listener-memory-leak.md) | email-ingestion-worker | IMAP event listeners not re-registered on reconnect | 1-2h | ✅ Created |
| [IMPROVEMENT-004](IMPROVEMENT-004-certificate-loading-cache.md) | digital-signature-service | Certificate loaded from disk 10,000x/day | 1h | ✅ Created |
| IMPROVEMENT-005 | email-ingestion-worker | Entire email loaded into memory (no streaming) | 2h | ⏳ Pending |
| IMPROVEMENT-006 | fina-connector | WSDL cache never expires | 1h | ⏳ Pending |

---

## 📋 PENDING IMPROVEMENT PLANS

### 🟢 MEDIUM (27 issues)

**XML & Validation Pipeline:**

| ID | Service | Issue | Impact |
|----|---------|-------|--------|
| IMPROVEMENT-007 | xml-parser | Expensive entity regex in hot path | 5-10% throughput loss |
| IMPROVEMENT-008 | xml-parser | Redundant depth estimation (called twice) | 1-2ms per document |
| IMPROVEMENT-009 | xml-parser | Character-by-character iteration without early exit | Wasted CPU on deep XML |
| IMPROVEMENT-010 | xml-parser | Multiple Buffer.byteLength() calls on same string | 4 redundant native calls |
| IMPROVEMENT-011 | xsd-validator | Repeated XML parsing in validation flow | 100% overhead |
| IMPROVEMENT-012 | xsd-validator | Schema cache with no eviction policy | Memory leak risk |
| IMPROVEMENT-013 | xsd-validator | Unbounded error array iteration | Potential DoS |
| IMPROVEMENT-014 | xsd-validator | No message schema validation | Reliability risk |
| IMPROVEMENT-015 | xsd-validator | 100% OpenTelemetry sampling | Latency impact |

**Digital Signatures & Crypto:**

| ID | Service | Issue | Impact |
|----|---------|-------|--------|
| IMPROVEMENT-016 | digital-signature-service | String slicing for XML manipulation (fragile) | Breaks on formatting changes |
| IMPROVEMENT-017 | digital-signature-service | Hard-coded XPath for signature insertion | Assumes specific structure |
| IMPROVEMENT-018 | digital-signature-service | Redundant XML parsing | 50% overhead |
| IMPROVEMENT-019 | digital-signature-service | Complex DN extraction allocates unnecessary arrays | Memory inefficiency |
| IMPROVEMENT-020 | xsd-validator | XXE vulnerability in entity resolution | Security risk |

**FINA Integration:**

| ID | Service | Issue | Impact |
|----|---------|-------|--------|
| IMPROVEMENT-021 | fina-connector | Axios instance created per client | Connection pool waste |
| IMPROVEMENT-022 | fina-connector | Deep object traversal without null checks | Fragile parsing |
| IMPROVEMENT-023 | fina-connector | Multiple passes through response object | Cache misses |
| IMPROVEMENT-024 | fina-connector | Retry implementation without jitter | Thundering herd |
| IMPROVEMENT-025 | fina-connector | ZKI generated per fiscalization | Latency on critical path |
| IMPROVEMENT-026 | fina-connector | N+1 queries in offline queue stats | Excessive DB load |
| IMPROVEMENT-027 | fina-connector | No scheduled cleanup cron job | Table grows unbounded |
| IMPROVEMENT-028 | fina-connector | JSON.stringify() without circular ref protection | Silent failures |

**Email Processing:**

| ID | Service | Issue | Impact |
|----|---------|-------|--------|
| IMPROVEMENT-029 | email-ingestion-worker | Crypto module require in loop | 5ms overhead per attachment |
| IMPROVEMENT-030 | email-ingestion-worker | Complex address parsing allocates intermediate arrays | Memory inefficiency |
| IMPROVEMENT-031 | email-ingestion-worker | Sequential email processing prevents parallelization | 5-10x throughput loss |
| IMPROVEMENT-032 | email-ingestion-worker | Error swallowing in email processing | Reduced visibility |

**PDF Processing:**

| ID | Service | Issue | Impact |
|----|---------|-------|--------|
| IMPROVEMENT-033 | pdf-parser | Redundant string operations in scanned detection | Memory waste |
| IMPROVEMENT-034 | pdf-parser | Regex compiled per detection call | Pattern recompiled 1000s times |

---

### ⚪ LOW (15 issues)

| ID | Service | Issue | Priority |
|----|---------|-------|----------|
| IMPROVEMENT-035 | pdf-parser | Heuristic-based scanned detection unreliable | Misclassification |
| IMPROVEMENT-036 | pdf-parser | Fragile PDF date parsing | Silent failures on non-standard dates |
| IMPROVEMENT-037 | pdf-parser | No parallelization of page processing | 5-10x slower than optimal |
| IMPROVEMENT-038 | pdf-parser | Entire PDF loaded into memory | Memory pressure under load |
| IMPROVEMENT-039 | pdf-parser | No quality metrics in response | Missing observability |
| IMPROVEMENT-040 | email-ingestion-worker | Base64 encoding per message | Minor per-message overhead |
| IMPROVEMENT-041 | email-ingestion-worker | No batching in message publishing | 10x throughput loss |
| IMPROVEMENT-042 | email-ingestion-worker | URL masking creates new URL object per publish | Minor memory impact |
| IMPROVEMENT-043 | email-ingestion-worker | No retry logic for failed publishes | Failures not retried |
| IMPROVEMENT-044 | fina-connector | Deep object traversal without null checks | Null pointer risk |
| IMPROVEMENT-045 | digital-signature-service | Certificate reuse without verification | Potential mutation |
| IMPROVEMENT-046 | xml-parser | Validation order (security checks after parsing) | Poor layering |
| IMPROVEMENT-047 | imap-client | Keepalive configuration hard-coded | Operational inflexibility |
| IMPROVEMENT-048 | email-ingestion-worker | Complex To/CC address parsing | Memory inefficiency |

---

## How to Use These Plans

### For Development Teams

1. **Pick a plan** from "COMPLETED IMPROVEMENT PLANS" or "PENDING" sections
2. **Read the full markdown file** in this directory
3. **Follow implementation steps** exactly as documented
4. **Run the tests** to verify the fix
5. **Commit and push** with clear commit message
6. **Update this README** with ✅ status when complete

### For Prioritization

**Start here (blocking production):**
- IMPROVEMENT-001: FINA SOAP envelope (must fix before FINA integration)
- IMPROVEMENT-002: Email poller deadlock (must fix for email ingestion stability)
- IMPROVEMENT-003: IMAP reconnection (must fix for email ingestion reliability)

**Next (before staging deployment):**
- IMPROVEMENT-004: Certificate caching (5-10% latency improvement)
- IMPROVEMENT-005: Email streaming (memory efficiency)
- IMPROVEMENT-006: WSDL cache expiration (reliability)

**Ongoing (performance optimization):**
- Medium priority items (when you have spare capacity)
- Low priority items (polish, observability)

---

## Execution Pattern

Each improvement plan follows this pattern:

```markdown
# Improvement Plan: [Issue Title]

**Priority:** [CRITICAL|HIGH|MEDIUM|LOW]
**Service:** [service-name]
**Issue ID:** [number]
**Effort Estimate:** [time]
**Impact:** [what improves]

---

## Problem Statement
[What's broken]

---

## Root Cause Analysis
[Why it's broken]

---

## Solution Design
[How to fix it]

---

## Implementation Steps
[Exact steps to execute]

---

## Validation Checklist
[How to verify it works]

---

## Acceptance Criteria
[Done when ✅]
```

---

## Metrics to Track

After implementing improvements, track:

| Metric | Target | Current | Post-Fix |
|--------|--------|---------|----------|
| Email polling uptime | 99.9% | ? | ? |
| IMAP reconnection latency | <5s | ? | ? |
| Signature operation latency | <100ms | ~100ms | ~90ms |
| Certificate disk reads/hour | 0 | 10,000+ | 0 |
| Memory usage under load | <512MB | ? | ? |
| FINA submission success rate | 99.9% | ? | ? |

---

## Related Documents

- `CLAUDE.md` - System architecture and standards
- `TODO.md` - Project timeline and dependencies
- `TBD.md` - Pending architectural decisions
- `docs/adr/` - Architecture decision records
- `docs/reports/` - Completion reports from previous work

---

## Questions?

Each improvement plan includes:
- Exact file paths and line numbers
- Code examples
- Test templates
- Deployment notes

If clarification needed on a specific plan:
1. Read the full markdown file carefully
2. Check the test section for expected behavior
3. Review acceptance criteria for done definition

---

**Last Updated:** 2025-11-12
**Improvement Plans Created:** 4 / 48 (8%)
**Effort Remaining:** ~69 hours

