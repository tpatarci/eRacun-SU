# Croatian E-Invoice Regulatory Compliance Guide

**Document Classification:** Legal & Technical Requirements
**Regulatory Framework:** Fiskalizacija 2.0 (NN 89/25)
**Effective Date:** 1 January 2026
**Last Updated:** 2025-11-09

---

## EXECUTIVE SUMMARY

From **1 January 2026**, all VAT-registered entities in Croatia must fiscalize B2B/B2G transactions via e-invoices. This document defines the complete regulatory, technical, and operational requirements for the eRacun platform to achieve full compliance with Croatian Tax Authority (Porezna uprava) regulations.

**Critical Compliance Pillars:**
1. **Dual API Integration** - SOAP (B2C) + AS4 (B2B) protocols
2. **UBL 2.1 Standard** - European EN 16931-1:2017 with Croatian CIUS extensions
3. **Digital Signatures** - FINA-issued X.509 certificates with XMLDSig
4. **KPD Classification** - Mandatory 6-digit product codes per KLASUS taxonomy
5. **11-Year XML Archiving** - Original format with preserved signatures/timestamps
6. **5-Day Fiscalization** - Receipt processing deadline for incoming invoices

**Transition Timeline:**
- **1 Sept 2025**: Testing environment live, transition period begins
- **1 Jan 2026**: MANDATORY for VAT entities (issuing + receiving)
- **1 Jan 2027**: MANDATORY for all non-VAT entities (issuing)

---

## 1. REGULATORY SCOPE & OBLIGATIONS

### 1.1 Obligor Categories

**Obligations are determined by VAT STATUS, NOT legal entity type.**

#### Category A: VAT-Registered Entities (PDV Obveznici)
**Threshold:** Annual revenue ≥ 40,000 EUR

**From 1 Jan 2026:**
- ✅ Issue e-invoices for all B2B/B2G transactions
- ✅ Receive and fiscalize incoming e-invoices (5-day deadline)
- ✅ Fiscalize all B2C transactions (cash and cashless)
- ✅ Full e-reporting (payment data + rejections)
- ⚠️ **MUST use certified Access Point** (proprietary or via intermediary)

**Applies to:** d.o.o., j.d.o.o., obrt (craft businesses) IN VAT system

---

#### Category B: Non-VAT Entities (Izvan PDV-a)
**Excluding flat-rate craftsmen**

**From 1 Jan 2026:**
- ✅ Receive and fiscalize incoming e-invoices (5-day deadline)
- ✅ Fiscalize B2C transactions
- ✅ Partial e-reporting (rejections only)
- ✅ Can use **FREE MIKROeRAČUN application** (via ePorezna portal)
- ❌ NOT required to issue e-invoices until 2027

**From 1 Jan 2027:**
- ✅ Issue e-invoices for B2B/B2G
- ✅ Full e-reporting

---

#### Category C: Flat-Rate Craftsmen (Paušalni Obrti)
**Requirements:**
- Annual income < 40,000 EUR
- Income tax obligors only (NOT applicable to d.o.o./j.d.o.o.)

**From 1 Jan 2026:**
- ✅ Receive and fiscalize incoming e-invoices
- ✅ Fiscalize B2C transactional receipts
- ✅ Can use FREE MIKROeRAČUN application
- ❌ **EXEMPT from issuing e-invoices** (until 2027)

**From 1 Jan 2027:**
- ✅ Issue e-invoices
- ✅ Full e-reporting

---

#### Category D: Public Administration (Javna Uprava)
**From 1 Jan 2026:**
- ✅ Receive e-invoices
- ✅ Process via designated systems

---

### 1.2 Transaction Types

**B2B (Business-to-Business):**
- E-invoice mandatory for VAT entities
- Bilateral fiscalization (issuer immediately, recipient within 5 working days)
- AS4 protocol exchange via Access Points

**B2G (Business-to-Government):**
- Identical requirements to B2B
- Public procurement integration

**B2C (Business-to-Consumer):**
- Fiscalization via SOAP API
- JIR (Unique Invoice Identifier) printed on receipt
- All payment methods (cash, card, online)

---

## 2. TECHNICAL STANDARDS

### 2.1 E-Invoice Format

**Primary Standard:**
- **EN 16931-1:2017** - European e-invoicing semantic model
- **Croatian CIUS** - "Specifikacija osnovne uporabe eRačuna s proširenjima"
- **Syntax:** UBL 2.1 (OASIS Universal Business Language) **← MANDATORY**
- **Alternative:** UN/CEFACT CII v.2.0 (less common)

**XML Document Structure:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <!-- Mandatory elements per section 2.2 -->
</Invoice>
```

---

### 2.2 Mandatory Data Elements

**Document Metadata:**
- **BT-1**: Invoice number (format: `{broj}-{poslovni_prostor}-{naplatni_uredjaj}`)
- **BT-2**: Issue date (ISO 8601: `YYYY-MM-DD`)
- **BT-3**: Invoice type code (UNTDID 1001)
  - `380` - Commercial invoice
  - `381` - Credit note (storno)
  - `384` - Corrected invoice
  - `386` - Prepayment/advance invoice
  - `389` - Self-billing

**Party Identifiers:**
- **BT-31**: Seller OIB (Croatian tax number - 11 digits)
- **HR-BT-5**: Operator OIB (**mandatory from 1 Sept 2025**)
- **BT-48**: Buyer OIB

**Monetary Totals (BG-22):**
- Sum of invoice lines (net amount)
- Sum of allowances/charges
- Invoice total (excluding VAT)
- Invoice total (VAT amount)
- Invoice total (including VAT)
- Amount due for payment

**VAT Breakdown (BG-23):**
- VAT category code (S=Standard, Z=Zero-rated, E=Exempt, etc.)
- VAT rate percentage (25%, 13%, 5% for Croatia)
- Taxable amount (base)
- VAT amount

**Payment Information (BG-16):**
- IBAN (Croatian format: HR + 19 digits)
- BIC/SWIFT code
- Payment due date
- Payment reference

**Line Items (BG-25):**
- **KPD 2025 classification code** (**MANDATORY**, minimum 6 digits)
- Item description
- Quantity + unit of measure
- Net price
- Line total

---

### 2.3 KPD Product Classification

**Regulatory Authority:** State Statistical Office (Državni zavod za statistiku)
**Classification System:** KLASUS 2025
**Format:** 6-digit numerical code (minimum)

**Implementation Requirements:**
- Every invoice line item MUST have valid KPD code
- Codes searchable via KLASUS web application
- Support contact: KPD@dzs.hr
- Pre-map all company products/services before 31 Dec 2025

**Example Codes:**
```
01.11.1 - Growing of cereals
62.01.0 - Computer programming activities
85.59.0 - Other education n.e.c.
```

**Validation:**
- System MUST validate against official KLASUS registry
- Invalid codes trigger rejection by Tax Authority

---

### 2.4 Digital Signature Requirements

**Cryptographic Standard:**
- **XMLDSig** (XML Digital Signature)
- **Hash Algorithm:** SHA-256 with RSA
- **Signature Placement:** Enveloped signature within XML document
- **Qualified Timestamp:** Required for e-invoices (eIDAS compliant)

**Certificate Requirements:**
- **Type:** Application digital certificate for fiscalization
- **Standard:** X.509 v3
- **Issuer:** FINA (primary) or AKD (alternative)
- **Format:** .p12 soft certificate (PKCS#12)
- **Validity:** 5 years
- **Cost:** ~39.82 EUR + VAT (production), FREE (demo/test)

**PKI Hierarchy:**
```
Fina Root CA
  └── Fina RDC 2015 CA
       └── Application Certificate (company-specific)
```

**ZKI (Protective Code):**
- MD5 hash of invoice data
- Signed with private key
- Included in B2C receipts for offline validation

**Certificate Lifecycle:**
1. **Issuance:** 5-10 business days via FINA
2. **Activation:** Online via CMS portal (cms.fina.hr)
3. **Installation:** Import .p12 into application keystore
4. **Renewal:** 30 days before expiration
5. **Revocation:** Immediate notification to FINA required

---

## 3. API INTEGRATION SPECIFICATIONS

### 3.1 B2C Fiscalization API

**Protocol:** SOAP Web Services
**Transport Security:** 1-way TLS/SSL

**Endpoints:**
- **Production:** `https://cis.porezna-uprava.hr:8449/FiskalizacijaService`
- **Test:** `https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest`

**WSDL Version:** 1.9 (active from 5 Nov 2025)

**Operations:**
- `racuni` - Submit invoice data (B2C transactions)
- `echo` - Test service availability
- `provjera` - Validate invoice (TEST environment only)

**Request Format:**
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:tns="http://www.apis-it.hr/fin/2012/types/f73">
  <soapenv:Body>
    <tns:RacunZahtjev>
      <!-- Digitally signed invoice data -->
    </tns:RacunZahtjev>
  </soapenv:Body>
</soapenv:Envelope>
```

**Response:**
- **Success:** JIR (Jedinstveni Identifikator Računa) - Unique Invoice Identifier
- **Failure:** Error codes + descriptive messages

**Performance Requirements:**
- Response time: < 2 seconds (typical)
- Availability: 24/7 (99.9% SLA)
- Retry logic: Exponential backoff (3 attempts)
- Offline fallback: Queue for submission within 48 hours

---

### 3.2 B2B E-Invoice Exchange (AS4)

**Protocol:** AS4 Profile (OASIS ebMS 3.0)
**Topology:** Four-corner model

**Architecture:**
```
[Sender] → [Access Point 1] → [Central Exchange] → [Access Point 2] → [Recipient]
```

**Access Point Options:**
1. **Proprietary:** Self-certified via Compliance Testing Portal
2. **Intermediary Services:**
   - FINA eRačun
   - ePoslovanje.hr
   - Hrvatski Telekom
   - mStart

**Message Structure:**
- AS4 envelope (ebMS3 headers)
- UBL 2.1 invoice payload
- Digital signature + timestamp
- Routing metadata (sender/recipient identifiers)

**Transmission Security:**
- TLS 1.2+ (transport layer)
- Message-level encryption (optional)
- Non-repudiation (signed delivery receipts)

---

### 3.3 Metadata Services

#### AMS (Address Metadata Service)
**Purpose:** Recipient lookup directory
**Protocols:** REST and SOAP
**Function:** Find recipient's Access Point endpoint

**Use Case:**
```
Query: OIB 12345678901
Response: Access Point URL, supported formats, capabilities
```

---

#### MPS (Metadata Service)
**Purpose:** Service capability discovery
**Protocol:** SOAP HTTP 1.1
**Authentication:** Client certificate (2-way TLS)

**Information Provided:**
- Supported document types (UBL 2.1, CII)
- Routing preferences
- SLA commitments
- Technical contact

---

### 3.4 Validation Requirements

**Pre-Submission Validation:**
1. **XSD Schema Validation** - Syntactic correctness (UBL 2.1 schema)
2. **Schematron Rules** - Business logic compliance (Croatian CIUS)
3. **KPD Code Validation** - Active classification codes
4. **OIB Validation** - Valid Croatian tax numbers
5. **Signature Verification** - Valid certificate chain, unexpired

**Tax Authority Validation:**
- Server-side validation after submission
- Synchronous error response (immediate rejection)
- Error codes documented in technical specification

**Recommended Approach:**
- Implement local validator matching Tax Authority Schematron rules
- Cache validation results (idempotent operations)
- Pre-validate before signature application (avoid wasted signatures)

---

## 4. OPERATIONAL PROCEDURES

### 4.1 Registration & Onboarding

**Timeline:** Must complete by 31 Dec 2025

**Step 1: KPD Product Mapping**
- Map all products/services to KLASUS 2025 codes
- Minimum 6-digit precision
- Store in product master database
- Support: KPD@dzs.hr

**Step 2: Select Access Point Strategy**
- **Option A:** Proprietary Access Point (full control, higher complexity)
- **Option B:** Intermediary service (faster deployment, managed infrastructure)
- **Decision factors:** Volume, technical capability, budget

**Step 3: Obtain FINA Certificate**

**Required Documentation (Legal Entities):**
- Application for application certificate
- Service agreement (2 copies)
- Copy of certificate administrator ID
- Proof of payment (39.82 EUR + VAT)
- DZS notification (business registry extract)

**Required Documentation (Sole Traders):**
- Application and agreement
- Copy of administrator ID
- Proof of payment

**Submission Methods:**
- Physical: FINA registration office
- Electronic: OSPD portal (requires qualified e-signature)

**Processing Time:** 5-10 business days

**Step 4: Configure FiskAplikacija**
- Access via ePorezna portal (NIAS authentication)
- Confirm intermediary service provider
- Grant fiscalization authorization
- Link certificate to OIB

**Step 5: Register with AMS**
- Submit receiving endpoint address
- Configure routing preferences
- Test connectivity

**Step 6: System Testing**
- Use demo certificates (free, 1-year validity)
- Test environment available from 1 Sept 2025
- Validate against reference implementations
- Certify Access Point (if proprietary)

---

### 4.2 Fiscalization Workflows

#### B2C Transaction Flow
```
1. Generate invoice in accounting system
2. Calculate ZKI protective code (MD5 hash + signature)
3. Submit SOAP request to Fiscalization Service
4. Receive JIR (Unique Invoice Identifier)
5. Print JIR on receipt
6. Archive signed XML (11 years)
```

**Timing:** Immediate (before providing receipt to customer)

**Offline Scenarios:**
- Queue invoices locally
- Mark receipt with "Offline mode" indicator
- Submit within 48 hours when connection restored
- Include original timestamp in submission

---

#### B2B Issuing Flow
```
1. Create UBL 2.1 invoice with KPD codes
2. Validate against XSD + Schematron
3. Apply digital signature + timestamp
4. Submit to own Access Point
5. Access Point routes via AS4 to recipient
6. Receive delivery confirmation
7. Archive signed XML (11 years)
8. Fiscalize own copy (immediately)
```

---

#### B2B Receiving Flow
```
1. Receive AS4 message at Access Point
2. Verify digital signature + timestamp
3. Validate invoice (XSD, Schematron, business rules)
4. Accept or reject invoice
5. Fiscalize accepted invoice (max 5 working days)
6. Send rejection notification if invalid
7. Archive original XML (11 years)
```

**Rejection Criteria:**
- Invalid signature or expired certificate
- Schema validation failure
- Incorrect recipient OIB
- Duplicate invoice number
- Business logic errors (incorrect VAT, amounts mismatch)

---

### 4.3 E-Reporting Obligations

**Frequency:** Monthly
**Deadline:** 20th day of following month
**Method:** ePorezna portal or API submission

**Issuer Reports:**
- Payment data for issued e-invoices
- Amounts received per invoice
- Payment method and date

**Recipient Reports:**
- Rejected invoices (reason codes)
- Invoices where e-invoice issuance was not possible

**Penalties for Non-Reporting:**
- 1,320 - 26,540 EUR (legal entities)
- Repeated violations: Cumulative fines

---

### 4.4 Archiving Requirements

**Regulatory Mandate:** 11 YEARS

**Format Requirements:**
- ✅ Original XML with UBL 2.1 structure
- ✅ Preserved digital signature (must remain valid)
- ✅ Preserved qualified timestamp
- ✅ Metadata (submission confirmations, JIR/UUID)
- ❌ PDF conversion NOT compliant
- ❌ Paper printouts NOT compliant

**Storage Criteria:**
- Immutable storage (WORM - Write Once Read Many)
- Geographic redundancy (backup to second location)
- Access control (audit trail of retrievals)
- Encryption at rest (AES-256 minimum)
- Regular integrity checks (signature verification)

**Consequences of Non-Compliance:**
- Fines up to 66,360 EUR
- **Loss of VAT deduction rights** (severe tax liability)
- Criminal liability for tax evasion (intentional destruction)

**Recommended Architecture:**
- Primary: S3-compatible object storage (DigitalOcean Spaces)
- Secondary: Archive to Glacier-class cold storage (after 1 year)
- Index: PostgreSQL with full-text search
- Signature check: Automated monthly validation job

---

## 5. COMPLIANCE TESTING

### 5.1 Test Environment

**Availability:** 1 Sept 2025 - ongoing
**Purpose:** Pre-production validation

**Resources Provided:**
- Demo FINA certificates (free, 1-year validity)
- Test API endpoints
- Reference invoice samples
- Schematron validator
- `provjera` validation operation (test-only)

**Testing Phases:**
1. **Unit Testing:** Invoice generation, signature, validation
2. **Integration Testing:** API communication, AS4 exchange
3. **End-to-End Testing:** Full workflow with demo data
4. **Performance Testing:** Volume, concurrency, error handling
5. **Certification:** Access Point compliance (if proprietary)

---

### 5.2 Compliance Checklist

**Pre-Launch Validation:**
- [ ] All products mapped to valid KPD codes
- [ ] UBL 2.1 XML generation implemented
- [ ] Digital signature with FINA certificate working
- [ ] SOAP API integration tested (B2C)
- [ ] AS4 message exchange tested (B2B)
- [ ] Schematron validation rules implemented
- [ ] Archiving system operational (11-year retention)
- [ ] Offline fallback mechanism tested
- [ ] Error handling for all API failure modes
- [ ] E-reporting integration configured
- [ ] User training completed
- [ ] Runbooks documented
- [ ] Disaster recovery tested

---

### 5.3 Certification Process (Proprietary Access Point)

**Authority:** Tax Authority Compliance Testing Portal

**Requirements:**
- Successful AS4 message exchange with test partners
- Signature verification
- Schema compliance
- Error handling validation
- Performance benchmarks (throughput, latency)

**Outcome:** Certificate of compliance (required before production use)

---

## 6. PENALTIES & ENFORCEMENT

### 6.1 Financial Penalties

**Non-Fiscalization of Invoices:**
- Legal entities: 2,650 - 66,360 EUR
- Responsible persons: 530 - 2,650 EUR

**Non-Compliance with E-Reporting:**
- Legal entities: 1,320 - 26,540 EUR
- Responsible persons: 265 - 1,320 EUR

**Improper Archiving (Not Preserving XML):**
- Legal entities: Up to 66,360 EUR
- **Loss of VAT deduction rights** (retroactive tax liability)

**Repeated Violations:**
- Progressive penalties
- Potential business license suspension

---

### 6.2 Audits & Inspections

**Tax Authority Powers:**
- Request archived invoices (must provide XML)
- Verify signature validity
- Cross-check against fiscalization records
- Inspect systems and procedures

**Taxpayer Obligations:**
- Provide invoices within specified timeframe
- Demonstrate archiving compliance
- Explain discrepancies

**Red Flags for Audits:**
- Missing e-reporting submissions
- High rejection rates
- Frequent offline mode usage
- Signature verification failures

---

## 7. CHANGE MANAGEMENT

### 7.1 Regulatory Updates

**Monitoring Sources:**
- Porezna uprava official announcements (porezna.gov.hr)
- Croatian Tax Chamber (Porezna komora)
- Professional tax advisors
- FINA technical bulletins

**Update Categories:**
- CIUS specification revisions
- KPD classification updates (annual)
- API versioning (WSDL updates)
- Schematron rule changes
- Certificate policy modifications

**Response Protocol:**
1. Assess impact on platform
2. Update technical specifications
3. Modify implementation
4. Test in demo environment
5. Deploy to production
6. Notify customers
7. Update documentation

---

### 7.2 Backward Compatibility

**Versioning Strategy:**
- UBL versions: Support current + previous major version
- API versions: Maintain compatibility for 12 months after deprecation
- Certificate transitions: 6-month overlap period

**Migration Plans:**
- Automated data transformation scripts
- Dual-write during transition periods
- Rollback procedures

---

## 8. TECHNICAL REFERENCE

### 8.1 Official Documentation

**Tax Authority Resources:**
- Tehnička specifikacija Fiskalizacija eRačuna i eIzvještavanje
- CIUS Croatian specification with extensions
- Technical standards AMS/MPS/Access Point connectivity
- WSDL 1.9 specification
- Schematron validator (XML business rules)
- Sample UBL 2.1 invoices (reference implementations)
- XSD schemas

**Download:** porezna.gov.hr/fiskalizacija section

---

### 8.2 Standards Bodies

**International Standards:**
- OASIS UBL TC: UBL 2.1 specification
- CEN TC 434: EN 16931 European e-invoicing
- CEF eInvoicing: Pan-European e-invoice framework

**Croatian Authorities:**
- Porezna uprava (Tax Authority): Regulation enforcement
- Državni zavod za statistiku (DZS): KPD classification
- FINA: Certificate issuance, e-banking infrastructure
- Financijska agencija: Payment system oversight

---

### 8.3 Support Contacts

**KPD Classification:**
- Email: KPD@dzs.hr
- KLASUS Application: Web-based lookup

**Fiscalization Technical Support:**
- Portal: porezna.gov.hr → "Pišite nam" (web form)
- Phone: (available on portal)

**FINA Certificate Support:**
- Phone: 01 4404 707
- Portal: cms.fina.hr
- Email: Available on FINA website

**Intermediary Services:**
- Each provider maintains dedicated support channels

---

## 9. RISK REGISTER

### 9.1 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Certificate expiration | High - Service outage | Automated renewal 30 days before expiry |
| API downtime | High - Cannot fiscalize | Offline queue + 48h grace period |
| Invalid KPD codes | Medium - Invoice rejection | Pre-validation against KLASUS registry |
| Signature verification failure | High - Non-compliance | Certificate monitoring + backup certificates |
| Archive corruption | Critical - VAT deduction loss | Immutable storage + geographic redundancy |
| Schematron rule changes | Medium - Validation errors | Monitoring + regression testing |

---

### 9.2 Compliance Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Late fiscalization (>5 days) | Medium - Penalties | Automated workflows + alerts |
| Missing e-reports | High - Fines + audit trigger | Calendar automation + validation |
| Non-XML archiving | Critical - VAT loss | Policy enforcement + audits |
| Unauthorized signature use | Critical - Legal liability | Access control + audit logs |
| Incorrect VAT calculations | High - Tax liability | Multi-layer validation + AI checks |

---

### 9.3 Operational Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Staff turnover | Medium - Knowledge loss | Documentation + cross-training |
| Vendor lock-in | Medium - Migration difficulty | Standard-based architecture |
| Scalability limits | High - Service degradation | Horizontal scaling + load testing |
| Data breach | Critical - GDPR violation | Encryption + access control + audits |
| Disaster (data center failure) | Critical - Service outage | Geographic redundancy + DR drills |

---

## 10. IMPLEMENTATION RECOMMENDATIONS

### 10.1 Phased Rollout

**Phase 1: Foundation (Sept - Oct 2025)**
- Obtain demo certificates
- Implement UBL 2.1 generator
- Build signature module
- Integrate test SOAP API

**Phase 2: Validation (Oct - Nov 2025)**
- Implement Schematron validator
- KPD integration
- OIB validation
- End-to-end testing

**Phase 3: Integration (Nov - Dec 2025)**
- AS4 Access Point integration
- AMS/MPS connectivity
- E-reporting module
- Archive system

**Phase 4: Certification (Dec 2025)**
- Production certificates
- Compliance testing
- User acceptance testing
- Runbook completion

**Phase 5: Launch (1 Jan 2026)**
- Production deployment
- Monitoring
- Support readiness
- Continuous improvement

---

### 10.2 Critical Success Factors

1. **Early Start** - Begin testing September 2025 (not December)
2. **Expertise** - Engage Croatian tax consultant for business rules
3. **Automation** - Minimize manual processes (error-prone)
4. **Redundancy** - Triple validation as per value proposition
5. **Monitoring** - Real-time alerts for failures
6. **Documentation** - Runbooks for all failure scenarios
7. **Training** - Internal team + customer education
8. **Support** - Dedicated compliance helpdesk

---

## APPENDICES

### Appendix A: Acronym Glossary

- **AMS** - Adresar Metapodatkovnih Servisa (Address of Metadata Services)
- **AS4** - Applicability Statement 4 (OASIS messaging standard)
- **CIUS** - Core Invoice Usage Specification
- **JIR** - Jedinstveni Identifikator Računa (Unique Invoice Identifier)
- **KPD** - Klasifikacija Proizvoda po Djelatnostima (Product Classification)
- **KLASUS** - Croatian product classification system (DZS)
- **MPS** - Metapodatkovni Servis (Metadata Service)
- **OIB** - Osobni Identifikacijski Broj (Personal/Company Tax Number)
- **PDV** - Porez na Dodanu Vrijednost (Value Added Tax - VAT)
- **UBL** - Universal Business Language (OASIS standard)
- **XMLDSig** - XML Digital Signature
- **ZKI** - Zaštitni Kod Izdavatelja (Issuer Protective Code)

---

### Appendix B: Invoice Type Codes (UNTDID 1001)

| Code | Description | Use Case |
|------|-------------|----------|
| 380 | Commercial invoice | Standard sale |
| 381 | Credit note | Return, cancellation |
| 384 | Corrected invoice | Error correction |
| 386 | Prepayment invoice | Advance payment |
| 389 | Self-billing invoice | Buyer issues on behalf of seller |

---

### Appendix C: VAT Category Codes

| Code | Description | Rate (Croatia) |
|------|-------------|----------------|
| S | Standard rate | 25% |
| AA | Lower rate | 13% |
| A | Reduced rate | 5% |
| Z | Zero rated | 0% |
| E | Exempt from tax | 0% |
| AE | Reverse charge | 0% (buyer liable) |

---

### Appendix D: Sample Invoice Numbers

**Format:** `{sequential}-{business_space}-{cash_register}`

Examples:
- `1-ZAGREB1-POS1` - First invoice, Zagreb office, cash register 1
- `2547-WEB-API` - Invoice 2547, web channel, API endpoint
- `100-SPLIT2-MOBILE` - Invoice 100, Split location 2, mobile device

**Rules:**
- Sequential numbering per fiscal year
- Business space: Alphanumeric identifier (consistent)
- Cash register: Physical device or logical endpoint
- No gaps in sequence (must explain missing numbers)

---

**Document Status:** LIVING DOCUMENT
**Next Review:** Upon regulatory updates or Q1 2026 post-launch assessment
**Owner:** Compliance Team + Technical Lead
**Distribution:** All development teams, legal, finance, customer success

---

*This document synthesized from official Porezna uprava specifications, Law on Fiscalization (NN 89/25), and technical standards published November 2025.*
