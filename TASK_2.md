# TASK 2: Compliance Readiness Assessment

## Task Priority
**CRITICAL** - Hard deadline January 1, 2026 for Croatian Fiskalizacija 2.0

## Objective
Verify complete readiness for Croatian Fiskalizacija 2.0 compliance, ensuring all mandatory requirements are implemented and tested against both test and production endpoints.

## Scope
Comprehensive compliance validation covering:
- Document format standards (UBL 2.1, EN 16931, Croatian CIUS)
- Mandatory data elements (OIB, KPD, VAT)
- Integration with Tax Authority systems
- Audit and archiving requirements
- Legal entity registration status

## Detailed Approach

### 1. Document Standards Verification (Day 1)
**Validate implementation of required formats:**
```bash
# Test UBL 2.1 schema validation
npm run validate:schema -- --standard=UBL2.1

# Test Croatian CIUS business rules
npm run validate:cius -- --ruleset=croatian

# Verify EN 16931 compliance
npm run validate:en16931
```

**Check validation layers (all 6 must be operational):**
- [ ] Layer 1: XSD schema validation
- [ ] Layer 2: Schematron business rules
- [ ] Layer 3: KPD classification validation
- [ ] Layer 4: Semantic validation
- [ ] Layer 5: AI-based anomaly detection
- [ ] Layer 6: Triple redundancy consensus

### 2. Mandatory Data Elements Audit (Day 1-2)
**Verify all required fields are captured and validated:**

#### OIB Number Validation
- [ ] Issuer OIB (BT-31) - 11 digits, mod-11 check
- [ ] Operator OIB (HR-BT-5) - Required for service providers
- [ ] Recipient OIB (BT-48) - Validated against registry

#### KPD Classification
- [ ] KLASUS 2025 codes implemented (6-digit)
- [ ] Every line item has KPD code
- [ ] Codes validated against official registry
- [ ] Mapping tool for product catalog

#### VAT Breakdown
- [ ] All rates supported (25%, 13%, 5%, 0%)
- [ ] Category codes properly assigned
- [ ] Reverse charge mechanism implemented
- [ ] EU cross-border rules applied

### 3. Digital Signature Verification (Day 2)
**Test XMLDSig implementation:**
- [ ] SHA-256 with RSA algorithm
- [ ] Enveloped signature support
- [ ] Certificate chain validation
- [ ] Timestamp verification (eIDAS-compliant)
- [ ] Signature preservation in archive

### 4. FINA Integration Testing (Day 2-3)
**Test environment validation (cistest.apis-it.hr):**
```bash
# Test B2C fiscalization
curl -X POST https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest \
  --cert /path/to/demo-cert.p12 \
  --data @test-invoice.xml

# Verify response contains JIR
```

**Production readiness checks:**
- [ ] Demo certificates obtained and tested
- [ ] Production certificate application submitted
- [ ] Both SOAP and AS4 protocols tested
- [ ] Error handling for FINA outages
- [ ] Retry logic with exponential backoff

### 5. Registration Status Verification (Day 3)
**Confirm all administrative requirements:**
- [ ] Entity registered with ePorezna portal
- [ ] Information system provider confirmed
- [ ] Fiscalization authorization granted
- [ ] AMS endpoints registered
- [ ] Monthly reporting (eIzvještavanje) tested

### 6. Timeline Compliance Check (Day 3-4)
**Critical dates verification:**
- [ ] September 1, 2025: Test environment access confirmed
- [ ] Certificate acquisition initiated (5-10 day processing)
- [ ] KPD product mapping completed
- [ ] Integration testing scheduled
- [ ] Production deployment plan approved

## Required Tools
- XSD validators (xmllint, saxon)
- Schematron processor
- FINA test certificates
- SOAP/AS4 testing tools
- Croatian business registry API access

## Pass/Fail Criteria

### MUST PASS (Legal requirement)
- ✅ All 6 validation layers operational
- ✅ OIB validation with mod-11 check
- ✅ KPD codes for all products
- ✅ Digital signatures valid and verifiable
- ✅ FINA test environment connectivity confirmed
- ✅ 11-year retention capability proven

### RED FLAGS (Compliance blockers)
- ❌ Missing Croatian CIUS implementation
- ❌ No FINA certificates obtained
- ❌ Incomplete VAT rate handling
- ❌ No audit trail for transformations
- ❌ Archive not immutable (WORM)

## Deliverables
1. **Compliance Checklist** - All requirements with status
2. **Test Results** - FINA integration test evidence
3. **Gap Analysis** - Any missing compliance elements
4. **Certificate Status** - Current state of FINA certificates
5. **Go-Live Readiness Report** - Executive summary

## Time Estimate
- **Duration:** 4 days
- **Effort:** 1 senior engineer + 1 compliance expert
- **Prerequisites:** FINA test access, demo certificates

## Risk Factors
- **Critical Risk:** No FINA certificates by December 2025
- **High Risk:** Croatian CIUS not fully implemented
- **High Risk:** Integration testing reveals issues
- **Medium Risk:** Performance under compliance load
- **Low Risk:** Documentation gaps

## Escalation Path
For any compliance gaps:
1. Immediate escalation to C-level management
2. Legal team notification for penalty assessment
3. Create P0 items for all gaps
4. Daily war room until resolved
5. Consider external compliance consultants

## Compliance Penalties (Reminder)
- **Fines:** Up to €66,360
- **VAT Loss:** Retroactive deduction denial
- **Criminal Liability:** Intentional non-compliance
- **Business Impact:** Cannot issue legal invoices

## Related Documentation
- @docs/COMPLIANCE_REQUIREMENTS.md
- @docs/standards/croatian-cius.pdf
- @docs/guides/fina-testing.md
- @docs/guides/certificate-setup.md
- Croatian Fiscalization Law (NN 89/25)

## Audit Checklist
- [ ] UBL 2.1 schemas imported and validated
- [ ] Croatian CIUS Schematron rules active
- [ ] EN 16931 semantic model implemented
- [ ] XMLDSig library configured correctly
- [ ] FINA WSDL imported and tested
- [ ] AS4 four-corner model understood
- [ ] Archive solution supports WORM
- [ ] 11-year retention policy configured
- [ ] Disaster recovery includes compliance data
- [ ] Monthly reporting automation ready

## Notes
This assessment must be completed by November 30, 2025 to allow time for remediation before the January 1, 2026 deadline. Any gaps identified are automatic P0 priority items.