# PENDING-008: FINA Integration Testing & Certificates

**Priority:** 🔴 P0 (Critical)
**Created:** 2025-11-14
**Estimated Effort:** 10 engineering days (2 weeks)
**Deadline:** 2025-12-05 (21 days)
**Prerequisite:** PENDING-007 must be resolved first

---

## Problem Statement

**CRITICAL COMPLIANCE GAP:** No FINA (Croatian Tax Authority) integration testing has been performed, and no certificates (demo or production) have been acquired. Without FINA connectivity, invoices cannot be fiscalized, making the system non-compliant with January 1, 2026 mandatory requirements.

**Root Cause:** Development focused on service implementation without live integration testing against FINA test environment.

---

## What This Blocks

### Blocks GO-LIVE (DEPLOYMENT FREEZE CONTINUES)

- ⛔ **Invoice fiscalization** - Cannot submit invoices to Tax Authority
- ⛔ **JIR receipts** (B2C) - No proof of fiscalization
- ⛔ **UUID confirmations** (B2B) - No B2B exchange capability
- ⛔ **January 1, 2026 compliance** - 47 days remaining
- ⛔ **Legal compliance** - €66,360 penalty risk + criminal liability

### Does NOT Block

- ✅ Internal testing (after PENDING-007 resolved)
- ✅ Other service development
- ✅ Documentation updates

---

## Scope

### Phase 1: FINA Demo Certificates (Week 1 - Nov 22-28)

**Acquire Demo Certificates:**
- [ ] Contact FINA support (01 4404 707)
- [ ] Access CMS portal (cms.fina.hr)
- [ ] Authenticate via NIAS (eGrađani)
- [ ] Request demo application certificate (FREE, 1-year validity)
- [ ] Download .p12 file (PKCS#12 format)
- [ ] Store securely in `/etc/eracun/secrets/` (SOPS encrypted)
- [ ] Document certificate details (issuer, expiry, serial number)

**Certificate Details:**
- Type: Qualified digital certificate for fiscalization
- Cost: FREE (demo), ~39.82 EUR + VAT (production)
- Validity: 1 year (demo), 5 years (production)
- Format: .p12 soft certificate (PKCS#12)
- Issuer: FINA (primary) or AKD (alternative)
- Algorithm: SHA-256 with RSA
- Standard: XMLDSig (enveloped signature)

**Installation:**
- [ ] Decrypt .p12 file and extract private key
- [ ] Configure fina-connector to use certificate
- [ ] Test certificate loads without errors
- [ ] Verify certificate chain validation

### Phase 2: Test Environment Connectivity (Week 1 - Nov 22-28)

**FINA Test Endpoint:**
- URL: `https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest`
- Available since: September 1, 2025
- Protocol: SOAP 1.1 (B2C) / AS4 (B2B)

**Connectivity Tests:**
- [ ] Test HTTPS connection to test endpoint
- [ ] Verify TLS handshake with demo certificate
- [ ] Test SOAP WSDL import
- [ ] Test AS4 four-corner model setup
- [ ] Document connection parameters

### Phase 3: B2C Fiscalization Testing (Week 2 - Nov 29-Dec 5)

**Test Cases:**
- [ ] Submit valid B2C invoice
- [ ] Verify JIR receipt (Jedinstveni Identifikator Računa)
- [ ] Test invalid invoice (expect rejection)
- [ ] Test malformed XML (expect error)
- [ ] Test timeout scenario
- [ ] Test network failure handling
- [ ] Test circuit breaker behavior
- [ ] Test retry logic (exponential backoff)
- [ ] Test idempotency (submit same invoice twice)

**Success Criteria:**
- Valid invoices return JIR within 5 seconds
- Invalid invoices return descriptive errors
- Circuit breaker opens after 50% failure rate
- Retries occur with backoff (2s, 4s, 8s)
- Idempotent submissions return same JIR

### Phase 4: B2B Exchange Testing (Week 2 - Nov 29-Dec 5)

**Test Cases:**
- [ ] Register Access Point with AMS (Address Metadata Service)
- [ ] Submit B2B invoice via AS4 protocol
- [ ] Verify UUID confirmation
- [ ] Test four-corner model message flow
- [ ] Test delivery acknowledgments
- [ ] Test error notifications

**AS4 Four-Corner Model:**
```
[Sender] ---(1)---> [Access Point 1] ---(2)---> [Access Point 2] ---(3)---> [Receiver]
                           |                            |
                           +----(4) Acknowledgment------+
```

**Success Criteria:**
- Messages successfully delivered via four-corner model
- UUIDs returned for all submissions
- Delivery acknowledgments received
- Error scenarios handled correctly

### Phase 5: Production Certificate Acquisition (Week 1-3 - Nov 22-Dec 12)

**Timeline:**
- **Application:** Nov 22, 2025
- **Processing:** 5-10 business days
- **Receipt:** Dec 5-12, 2025 (latest)
- **Installation:** Dec 13, 2025

**Production Certificate Application:**
- [ ] Submit application to FINA (cms.fina.hr)
- [ ] Pay certificate fee (€39.82 + VAT)
- [ ] Authenticate via NIAS (eGrađani)
- [ ] Provide organization details (OIB, company name, etc.)
- [ ] Await FINA approval (5-10 days)
- [ ] Download production .p12 file
- [ ] Store securely in `/etc/eracun/secrets/`
- [ ] Install in staging environment first
- [ ] Test with production endpoint: `https://cis.porezna-uprava.hr:8449/FiskalizacijaService`

**Certificate Lifecycle:**
- [ ] Document expiry date (5 years from issuance)
- [ ] Set renewal reminder (30 days before expiry)
- [ ] Document revocation procedure
- [ ] Configure cert-lifecycle-manager integration

### Phase 6: Error Scenario Testing (Week 2 - Nov 29-Dec 5)

**FINA Error Codes:**
- [ ] Test all documented FINA error codes
- [ ] Verify error messages are descriptive
- [ ] Verify errors are logged correctly
- [ ] Verify errors are surfaced to users

**Network Failures:**
- [ ] Simulate network timeout
- [ ] Simulate connection refused
- [ ] Simulate TLS handshake failure
- [ ] Simulate certificate expiry
- [ ] Simulate invalid certificate

**FINA Outages:**
- [ ] Simulate FINA service unavailable (5xx errors)
- [ ] Verify circuit breaker opens
- [ ] Verify retry logic with backoff
- [ ] Verify dead letter queue behavior
- [ ] Verify alerts are sent

---

## Deliverables Required

### Per-Phase Deliverables

**Phase 1:**
- [ ] Demo certificates acquired and installed
- [ ] Certificate documentation (issuer, expiry, serial)
- [ ] SOPS-encrypted certificate storage

**Phase 2:**
- [ ] Connectivity test results
- [ ] TLS handshake verification
- [ ] WSDL import confirmation
- [ ] Connection parameter documentation

**Phase 3:**
- [ ] 10+ successful B2C test submissions
- [ ] JIR receipts for all valid invoices
- [ ] Error handling verification
- [ ] Circuit breaker test results
- [ ] Retry logic test results

**Phase 4:**
- [ ] Access Point registration confirmation
- [ ] 5+ successful B2B test submissions
- [ ] UUID confirmations received
- [ ] Four-corner model flow verified

**Phase 5:**
- [ ] Production certificate application submitted
- [ ] Production certificate received
- [ ] Production certificate installed
- [ ] cert-lifecycle-manager configured

**Phase 6:**
- [ ] All error scenarios tested
- [ ] Error handling documentation
- [ ] Monitoring alerts configured
- [ ] Runbook updated

### Aggregate Deliverables

**FINA Integration Test Report:**
- [ ] Test environment connectivity confirmed
- [ ] B2C fiscalization successful
- [ ] B2B exchange successful
- [ ] Error handling verified
- [ ] Performance metrics documented

**Certificate Status Report:**
- [ ] Demo certificate installed
- [ ] Production certificate acquired
- [ ] Certificate lifecycle documented
- [ ] Renewal process documented

---

## Open Questions Requiring Decisions

1. **Certificate Storage**
   - Question: Should certificates be stored in Hardware Security Module (HSM) or SOPS-encrypted files?
   - Options:
     - A) SOPS + age (current approach, €0 cost)
     - B) HSM (higher security, ~€500-1000/month)
   - Recommendation: SOPS + age for MVP, migrate to HSM post-launch

2. **Access Point Provider (B2B)**
   - Question: Use third-party Access Point or build own?
   - Options:
     - A) Third-party (faster, monthly fee)
     - B) Build own (slower, no recurring cost)
   - Recommendation: Third-party for MVP (faster go-live)

3. **Production Certificate Timing**
   - Question: Apply for production cert in Week 1 or wait for demo testing?
   - Options:
     - A) Apply Week 1 (parallel with demo testing)
     - B) Wait until demo testing complete
   - Recommendation: Apply Week 1 (5-10 day lead time requires early start)

---

## Why Deferred Until Now

1. **PENDING-007 Priority:** Test coverage must be resolved before integration testing
2. **Service Implementation:** fina-connector implementation prioritized over live testing
3. **Test Environment Availability:** FINA test environment only available since Sep 1, 2025
4. **Organizational Dependencies:** Certificate acquisition may require organizational approval/payment

---

## Remediation Plan

### Timeline: 14 Days (2025-11-22 to 2025-12-05)

**Prerequisites:**
- PENDING-007 resolved (test coverage complete)
- fina-connector service has passing unit tests

**Week 1 (Nov 22-28):**
- **Day 1-2:** Acquire demo certificates + Test connectivity
- **Day 3-4:** B2C fiscalization testing (5+ test cases)
- **Day 5:** Apply for production certificate

**Week 2 (Nov 29-Dec 5):**
- **Day 1-2:** B2B exchange testing (AS4 protocol)
- **Day 3-4:** Error scenario testing
- **Day 5:** Integration test report + Certificate status report

**Week 3 (Dec 6-12):**
- **Buffer:** Await production certificate arrival
- **Day 13 (Dec 13):** Install production certificate in staging

---

## Success Criteria

### Must Achieve (Non-Negotiable)

- ✅ Demo certificates acquired and tested
- ✅ Production certificates applied for (awaiting receipt)
- ✅ Test environment connectivity confirmed
- ✅ 10+ successful B2C test submissions
- ✅ 5+ successful B2B test submissions
- ✅ JIR and UUID receipts verified
- ✅ Error handling tested
- ✅ Circuit breaker functional
- ✅ Retry logic verified

### Red Flags (Auto-Fail)

- ❌ Demo certificates cannot be acquired
- ❌ Test environment not accessible
- ❌ JIR receipts not returned
- ❌ Circuit breaker does not open
- ❌ Retry logic does not work
- ❌ Production certificate processing >10 days

---

## Risk Assessment

### If NOT Resolved by 2025-12-05

**Legal Risk:**
- Cannot fiscalize invoices (mandatory Jan 1, 2026)
- €66,360 penalties for non-compliance
- Criminal liability for intentional non-compliance

**Business Risk:**
- January 1, 2026 deadline at risk (27 days after this deadline)
- Customer onboarding blocked
- Revenue loss (cannot issue legal invoices)

**Technical Risk:**
- Integration issues discovered too late
- Production certificate delays
- AS4 protocol issues

---

## Escalation Path

**Immediate:**
- [ ] Engineering Lead assigned owner for FINA integration
- [ ] Finance/Admin notified for certificate payment approval
- [ ] Legal team notified of timeline risk

**Weekly (Until Resolved):**
- [ ] Progress updates to Engineering Lead
- [ ] Blockers escalated immediately
- [ ] Certificate status tracked daily (after application)

**Final (2025-12-05):**
- [ ] Integration test report filed
- [ ] Certificate status confirmed
- [ ] Go-live readiness assessed

---

## Related Documentation

- **Compliance Assessment:** `docs/reports/2025-11-14-TASK-2-compliance-assessment.md`
- **TASK 2 Instructions:** `TASK_2.md`
- **FINA Connector README:** `services/fina-connector/README.md`
- **Compliance Requirements:** `@docs/COMPLIANCE_REQUIREMENTS.md`
- **Certificate Guide:** `@docs/guides/certificate-setup.md` (if exists)
- **FINA Testing Guide:** `@docs/guides/fina-testing.md` (if exists)

---

## Next Actions

**Immediate (After PENDING-007 Resolved):**
1. ⏳ Assign owner for FINA integration
2. ⏳ Contact FINA support for demo certificate
3. ⏳ Apply for production certificate (parallel)
4. ⏳ Schedule integration testing sprint (Nov 22-Dec 5)

**Week 1 (Nov 22-28):**
5. ⏳ Acquire and install demo certificates
6. ⏳ Test connectivity to cistest.apis-it.hr
7. ⏳ Begin B2C fiscalization testing

**Week 2 (Nov 29-Dec 5):**
8. ⏳ Complete B2B exchange testing
9. ⏳ Complete error scenario testing
10. ⏳ File integration test report

---

## Status Updates

### 2025-11-15

- Added TLS client certificate loading + centralized config module in
  `services/fina-connector` to consume decrypted assets under
  `/etc/eracun/secrets/certificates/`.
- Documented the SOPS storage workflow in `secrets/certificates/README.md` and
  captured the current blocker state in
  `docs/reports/2025-11-15-PENDING-008-fina-certificate-status.md`.
- Added Jest coverage for `cert-lifecycle-manager` expiration monitoring to prove
  alerting works once real certificates are imported.
- Demo/prod certificate acquisition, PostgreSQL imports, and SOAP/AS4 smoke tests
  remain blocked because this environment lacks NIAS credentials, SOPS age keys,
  and connectivity to `cms.fina.hr` / `cistest.apis-it.hr`.

---

**Priority:** 🔴 P0 (Critical)
**Status:** ⏳ Active (blocked on PENDING-007)
**Assigned:** TBD (1 Senior Backend Engineer)
**Created By:** Team B (TASK 2 Compliance Assessment)
**Last Updated:** 2025-11-14
