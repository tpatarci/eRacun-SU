# TEAM B - Implementation Task List

**Team Focus:** Submission Services, Validation, Business Rules, External Integrations
**Current Sprint:** 2025-11-12 onwards
**Target Velocity:** 2-3 services per week
**Status:** 20/40 services complete (50%)

---

## ✅ RECENTLY COMPLETED (2025-11-12)

### Sprint Achievement: 4 Validation Services

**Summary:** All "easy win" validation services completed with 100% test coverage.

| Service | Status | Tests | Coverage | Commit | LOC |
|---------|--------|-------|----------|--------|-----|
| **oib-validator** | ✅ Complete | 39 | 100% | 0ab4163 | 362 + 1,200 tests |
| **iban-validator** | ✅ Complete | 66 | 100% | 0c09602 | 288 + 1,800 tests |
| **kpd-validator** | ✅ Complete | 55 | 100% | d3dbfda | 380 + 1,400 tests |
| **xml-parser** | ✅ Complete | 67 | 100% | 0e077a5 | 362 + 2,100 tests |

**Total Achievement:** 227 tests, 100% coverage on all services (statements, branches, functions, lines)

#### Service Details

**1. oib-validator** ✅ `services/oib-validator/`
- ISO 7064 MOD 11-10 checksum validation
- Support for individual and business OIBs
- Batch validation support
- Property-based testing with fast-check
- Error handling for all edge cases

**2. iban-validator** ✅ `services/iban-validator/`
- ISO 13616 MOD-97 checksum validation
- Croatian bank code validation (HNB registry mock)
- Country-specific validation rules
- Batch validation support
- SEPA zone validation

**3. kpd-validator** ✅ `services/kpd-validator/`
- Croatian product classification (KLASUS 2025)
- Database abstraction with dependency injection
- Hierarchical validation support (6-digit codes)
- Mock database implementation for testing
- Search and lookup functionality

**4. xml-parser** ✅ `services/xml-parser/`
- Secure XML parsing for UBL 2.1 e-invoices
- Security: XXE prevention, billion laughs protection
- Size and depth limit enforcement (10MB, 20 levels)
- Property-based testing with fast-check
- Comprehensive error handling and metadata extraction

**Next Phase:** Complex services requiring external integrations (AS4 protocol, Tax Authority APIs, tax consultant review)

---

## 🎯 IMMEDIATE PRIORITIES (Week 1)

### P0: b2b-access-point (AS4 Protocol Integration)

**Priority:** 🔴 CRITICAL - Blocks all B2B invoice submissions
**Estimated Effort:** 5 days
**LOC Estimate:** 3,500-4,000
**Dependencies:** cert-lifecycle-manager ✅, digital-signature-service ✅

**Purpose:**
Implement AS4 (OASIS ebMS 3.0) protocol integration for B2B invoice exchange via four-corner model. This is the Croatian B2B fiscalization endpoint - separate from FINA B2C SOAP API.

**Technical Specifications:**

1. **AS4 Message Handling**
   - ebMS 3.0 Header parsing and generation
   - Multi-hop routing support
   - Message partitioning for large invoices
   - Attachment handling (UBL XML + supporting documents)

2. **Security Requirements**
   - mTLS (mutual TLS) with FINA Access Point
   - WS-Security (UsernameToken + BinarySecurityToken)
   - XMLDSig message-level signatures
   - Message integrity verification (SHA-256 digests)

3. **Reliable Messaging**
   - Receipt acknowledgments (AS4 Receipt signals)
   - Error handling (AS4 Error signals)
   - Message retransmission (duplicate detection)
   - Non-repudiation via signed receipts

4. **Integration Points**
   - **Inbound:** Receive B2B invoices from other businesses
   - **Outbound:** Send B2B invoices to Access Point
   - **Message Queue:** RabbitMQ for async processing
   - **Database:** PostgreSQL for message tracking
   - **Crypto:** digital-signature-service for signatures

5. **Access Point Configuration**
   - Register endpoint with AMS (Address Metadata Service)
   - Configure SMP (Service Metadata Provider)
   - Test environment: Use FINA test Access Point
   - Production: Connect to cis.porezna-uprava.hr AS4 endpoint

**Acceptance Criteria:**
- [ ] Send B2B invoice via AS4 to test Access Point
- [ ] Receive B2B invoice from test Access Point
- [ ] Handle AS4 Receipt signals correctly
- [ ] Handle AS4 Error signals with retry logic
- [ ] 100% test coverage (Jest + integration tests)
- [ ] OpenTelemetry tracing for message lifecycle
- [ ] Prometheus metrics (message counts, latency, errors)
- [ ] RUNBOOK.md with operational procedures

**Resources:**
- AS4 Profile: `docs/standards/eDelivery_AS4_Profile_v1.12.pdf`
- Croatian CIUS: `docs/standards/CIUS-HR/`
- ebMS 3.0 Spec: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/
- PEPPOL AS4 (similar): https://docs.peppol.eu/edelivery/as4/

**Risk:** AS4 is complex - allocate 2 days for protocol research before coding.

---

### P1: e-reporting-service (Monthly Tax Authority Reporting)

**Priority:** 🟡 HIGH - Mandatory by 20th of each month
**Estimated Effort:** 3 days
**LOC Estimate:** 1,800-2,200
**Dependencies:** fina-connector ✅

**Purpose:**
Automated monthly e-reporting (eIzvještavanje) to Tax Authority. Issuers report payment data, recipients report rejections. Penalties 1,320-26,540 EUR for non-compliance.

**Technical Specifications:**

1. **Data Aggregation**
   - Query all invoices for previous month (PostgreSQL)
   - Aggregate payment data (amounts, dates, methods)
   - Aggregate rejection data (reason codes, counts)
   - Generate CSV or XML reports (format TBD - research required)

2. **Submission Mechanism**
   - **Option A:** ePorezna portal upload (manual fallback)
   - **Option B:** API submission (preferred - research if available)
   - NIAS authentication (Croatian e-identity)
   - Submission confirmation tracking

3. **Report Types**
   - **Issuer Report:** Payment data for issued invoices
     - Invoice UUID
     - Payment amount received
     - Payment date
     - Payment method (bank transfer, cash, card)
   - **Recipient Report:** Rejected invoices
     - Invoice UUID
     - Rejection reason code
     - Rejection date
     - Alternative fiscalization method (if applicable)

4. **Scheduling**
   - Cron job runs on 15th of month (5-day buffer before deadline)
   - Manual trigger via REST API (for corrections)
   - Email notifications to admin on success/failure
   - Retry logic for submission failures

5. **Compliance Tracking**
   - Store submission confirmations (11-year retention)
   - Audit trail of all report generations
   - Alert if approaching deadline without submission

**Acceptance Criteria:**
- [ ] Generate issuer payment report for test data
- [ ] Generate recipient rejection report
- [ ] Submit report to test environment (ePorezna sandbox)
- [ ] Receive submission confirmation
- [ ] Cron-based automated generation
- [ ] 100% test coverage
- [ ] Prometheus metrics (report size, submission time)
- [ ] RUNBOOK.md with manual submission procedure

**Research Required:**
- **CRITICAL:** Determine e-reporting API availability vs portal-only
- Contact: Tax Authority support or FINA technical team
- Fallback: Selenium/Puppeteer automation for portal upload (non-ideal)

**Resources:**
- `docs/standards/CROATIAN_COMPLIANCE.md` section 4.3
- ePorezna portal: https://eporezna.porezna-uprava.hr/
- NIAS authentication: Research required

---

### ✅ P1: oib-validator (Croatian Personal/Business ID Validation) - COMPLETED

**Status:** ✅ COMPLETED (commit 0ab4163)
**Priority:** 🟡 HIGH - Blocks invoice validation
**Actual Effort:** 1 day
**Actual LOC:** 362 (src) + 1,200 (tests)
**Dependencies:** None

**Purpose:**
Validate OIB (Osobni Identifikacijski Broj) - Croatian personal and business identification numbers. Required for ALL invoices (issuer OIB, recipient OIB, operator OIB).

**Technical Specifications:**

1. **OIB Format Validation**
   - 11 digits exactly
   - No letters, spaces, or special characters
   - Mod-11, ISO 7064 checksum algorithm
   - First digit cannot be 0

2. **Checksum Algorithm (ISO 7064, MOD 11-10)**
   ```
   1. Start with remainder = 10
   2. For each digit (left to right):
      a. Add digit to remainder
      b. Remainder = (remainder mod 10) or 10 if zero
      c. Remainder = (remainder * 2) mod 11
   3. Final check: (11 - remainder) mod 10 should equal 11th digit
   ```

3. **API Design**
   - **HTTP REST API** (Express.js)
   - `POST /validate` - Single OIB validation
   - `POST /validate/batch` - Batch validation (up to 100 OIBs)
   - JSON request/response
   - Rate limiting: 1000 requests/min

4. **RabbitMQ Integration**
   - Subscribe to `invoice.validation.oib` queue
   - Validate OIB fields in invoice
   - Publish validation result to `invoice.validation.completed` exchange

5. **Response Format**
   ```json
   {
     "oib": "12345678903",
     "valid": true,
     "errors": [],
     "metadata": {
       "type": "business", // or "personal"
       "checksum_valid": true
     }
   }
   ```

**Acceptance Criteria:**
- [x] Validate correct OIB: `12345678903` (example test OIB)
- [x] Reject invalid checksum: `12345678901`
- [x] Reject wrong length: `123456789`
- [x] Reject non-numeric: `1234567890A`
- [x] Batch validation endpoint works
- [x] 100% test coverage achieved (39 tests, all metrics)
- [x] Property-based testing (generate valid/invalid OIBs)
- [ ] RabbitMQ message processing (deferred to integration layer)
- [ ] Prometheus metrics (deferred to REST API wrapper)

**Resources:**
- OIB Algorithm: https://regos.hr/app/uploads/2018/07/PRERACUNAVANJE-KONTROLNE-ZNAMENKE-OIB.pdf
- Wikipedia: https://hr.wikipedia.org/wiki/Osobni_identifikacijski_broj
- Test OIBs: Use OIB generator for unit tests (create utility function)

**Note:** Do NOT validate against actual Tax Authority database (no lookup API exists). Only validate format + checksum.

---

## 🎯 SECONDARY PRIORITIES (Week 2)

### ✅ P2: iban-validator (Croatian Bank Account Validation) - COMPLETED

**Status:** ✅ COMPLETED (commit 0c09602)
**Priority:** 🟢 MEDIUM - Required for payment instructions
**Actual Effort:** 1 day
**Actual LOC:** 288 (src) + 1,800 (tests)
**Dependencies:** None

**Purpose:**
Validate IBAN (International Bank Account Number) for Croatian bank accounts. Required for invoice payment instructions (BT-86 Payment account identifier in UBL).

**Technical Specifications:**

1. **IBAN Format Validation**
   - Croatian IBAN: `HR` + 19 digits (21 characters total)
   - Example: `HR1210010051863000160`
   - Breakdown:
     - `HR` - Country code
     - `12` - Check digits (MOD-97 algorithm)
     - `1001005` - Bank code (7 digits)
     - `1863000160` - Account number (10 digits)

2. **MOD-97 Checksum Algorithm (ISO 13616)**
   ```
   1. Move first 4 characters to end: 1210010051863000160HR12
   2. Replace letters with numbers: H=17, R=27
   3. Result: 121001005186300016017272
   4. Calculate: number mod 97
   5. Valid if result = 1
   ```

3. **Croatian Bank Code Validation**
   - Maintain list of valid Croatian bank codes (7-digit)
   - Periodic sync with HNB (Croatian National Bank) registry
   - Examples: 1001005 (Erste banka), 2340009 (Privredna banka Zagreb)

4. **API Design** (similar to oib-validator)
   - `POST /validate` - Single IBAN validation
   - `POST /validate/batch` - Batch validation
   - Returns: valid, bank_name, bank_code, errors

**Acceptance Criteria:**
- [x] Validate correct Croatian IBAN
- [x] Reject invalid MOD-97 checksum
- [x] Reject wrong country code (non-HR)
- [x] Reject invalid bank code (not in registry)
- [x] Identify bank name from code
- [x] 100% test coverage achieved (66 tests, all metrics)
- [ ] RabbitMQ integration (deferred to integration layer)
- [ ] Update bank registry via cron (deferred - mock registry in place)

**Resources:**
- IBAN Algorithm: https://www.iban.com/structure
- HNB Bank List: https://www.hnb.hr/en/core-functions/banking-supervision/credit-institution-registers
- ISO 13616 Standard

---

### ✅ P2: kpd-validator (Product Classification Validation) - COMPLETED

**Status:** ✅ COMPLETED (commit d3dbfda)
**Priority:** 🟢 MEDIUM - Critical for compliance (mandatory 1 Jan 2026)
**Actual Effort:** 1 day
**Actual LOC:** 380 (src) + 1,400 (tests)
**Dependencies:** Database abstraction implemented (mock for testing)

**Purpose:**
Validate KPD (Klasifikacija Proizvoda po Djelatnostima) codes - Croatian product classification based on KLASUS 2025. Every invoice line item MUST have valid 6-digit KPD code.

**Technical Specifications:**

1. **KPD Code Validation**
   - 6 digits exactly (e.g., `012345`)
   - Hierarchical structure:
     - 2 digits: Section (01-99)
     - 4 digits: Division (0101-9999)
     - 6 digits: Group (010101-999999)
   - Validate against PostgreSQL registry (kpd-registry-sync maintains)

2. **Registry Lookup**
   - Query kpd-registry-sync database
   - Check if code exists and is active
   - Return code description (Croatian + English)
   - Handle deprecated codes (provide replacement suggestions)

3. **Bulk Validation**
   - Invoice may have 100+ line items
   - Batch validation to reduce DB queries
   - Cache frequently used codes (Redis future consideration)

4. **API Design**
   - `POST /validate` - Single KPD validation
   - `POST /validate/batch` - Batch validation
   - `GET /search?q=keyword` - Search KPD by description
   - `GET /code/:kpdCode` - Get KPD details

5. **Response Format**
   ```json
   {
     "kpd_code": "012345",
     "valid": true,
     "description_hr": "Pšenica i raž",
     "description_en": "Wheat and rye",
     "section": "01",
     "section_name": "Products of agriculture, forestry and fishing",
     "active": true,
     "deprecated": false,
     "replacement_code": null
   }
   ```

**Acceptance Criteria:**
- [x] Validate existing KPD code (query registry via database interface)
- [x] Reject non-existent code
- [x] Reject deprecated code with warning
- [x] Suggest replacement for deprecated codes
- [x] Batch validation for 100+ codes
- [x] Search by keyword (Croatian/English)
- [x] 100% test coverage achieved (55 tests, all metrics)
- [x] Database abstraction with dependency injection
- [ ] RabbitMQ integration (deferred to integration layer)
- [ ] Prometheus metrics (deferred to REST API wrapper)

**Resources:**
- KPD Registry: `services/kpd-registry-sync/` (already implemented ✅)
- KLASUS 2025: Contact KPD@dzs.hr for official registry
- `docs/standards/CROATIAN_COMPLIANCE.md` section 2.3

---

### P2: business-rules-engine (Tax Calculation & VAT Logic)

**Priority:** 🟢 MEDIUM - Blocks invoice generation
**Estimated Effort:** 5 days
**LOC Estimate:** 3,000-4,000
**Dependencies:** oib-validator, kpd-validator

**Purpose:**
Implement Croatian tax calculation rules, VAT validation, and business logic for invoice generation. This is the "brain" that ensures invoices comply with Croatian tax law.

**Technical Specifications:**

1. **VAT Rate Determination**
   - Input: KPD code + product description + customer type (B2B/B2C)
   - Output: VAT category (S/AA/A/Z/E/AE) + rate (25%/13%/5%/0%)
   - Logic:
     - Standard (S): 25% - Default for most goods/services
     - Lower (AA): 13% - Books, newspapers, hotel accommodation
     - Reduced (A): 5% - Food, water supply, pharma, medical devices
     - Zero (Z): 0% - Exports outside EU
     - Exempt (E): 0% - Healthcare, education, insurance
     - Reverse Charge (AE): 0% - B2B construction, scrap metal, telecom

2. **Tax Calculation Rules**
   - Line item: `tax_amount = taxable_amount * vat_rate`
   - Rounding: 2 decimal places, standard banker's rounding
   - Invoice total: Sum of all line item tax amounts
   - Validation: Verify invoice total matches sum of lines

3. **Reverse Charge Detection**
   - Trigger conditions:
     - B2B transaction (both parties have OIB + VAT registration)
     - Specific sectors: construction, waste, emissions, energy
     - Cross-border EU sales (intra-community supply)
   - Output: VAT category = AE, note on invoice

4. **Cross-Border Rules**
   - **Intra-EU B2B:** Reverse charge (seller 0%, buyer self-assesses)
   - **Intra-EU B2C:** Seller charges VAT if >€10,000 annual sales to that country
   - **Export outside EU:** 0% VAT with customs documentation
   - **Import:** VAT paid at customs (outside invoice scope)

5. **Special Schemes**
   - **Margin Scheme:** Used goods, art, antiques (VAT on margin only)
   - **Small Business Exemption:** <300,000 HRK annual (opt-out of VAT)
   - **Farmers:** Flat-rate scheme (compensatory percentage)
   - **Travel Services:** Special calculation method

6. **API Design**
   - `POST /calculate` - Calculate tax for invoice
   - Input: Line items (KPD, amount, quantity, customer OIB, customer country)
   - Output: VAT breakdown, total tax, special notes
   - Business rule validation (e.g., reverse charge applicability)

**Acceptance Criteria:**
- [ ] Calculate 25% VAT for standard goods
- [ ] Calculate 13% VAT for books
- [ ] Calculate 5% VAT for food
- [ ] Apply reverse charge for B2B construction
- [ ] Handle intra-EU B2B (0% with note)
- [ ] Round correctly (2 decimal places)
- [ ] 90%+ test coverage
- [ ] Property-based testing (totals always sum correctly)
- [ ] Integration with oib-validator and kpd-validator
- [ ] RUNBOOK.md with tax rule references

**Critical Note:**
**REQUIRES TAX CONSULTANT REVIEW** - Tax law is complex. All implemented rules must be reviewed by Croatian tax consultant before production deployment. Budget for 8-hour consultation.

**Resources:**
- Croatian VAT Law (ZPDV): https://www.porezna-uprava.hr/
- VAT Rates Table: `docs/standards/CROATIAN_COMPLIANCE.md` Appendix C
- EU VAT Directive: 2006/112/EC
- UBL Tax Mapping: `docs/standards/UBL-2.1/` + EN 16931-1

---

### ✅ P2: xml-parser (Secure UBL XML Parser) - COMPLETED

**Status:** ✅ COMPLETED (commit 0e077a5)
**Priority:** 🟢 MEDIUM - Required for receiving B2B invoices
**Actual Effort:** 1 day
**Actual LOC:** 362 (src) + 2,100 (tests)
**Dependencies:** None (security-focused parser, validation services will integrate separately)

**Purpose:**
Parse incoming UBL 2.1 XML invoices received from other businesses (B2B). Extract structured data for storage, validation, and processing.

**Technical Specifications:**

1. **XML Parsing**
   - Use `xml2js` or `fast-xml-parser` (performance comparison needed)
   - Parse UBL 2.1 namespaces correctly
   - Handle extensions (Croatian CIUS extensions)
   - Extract all mandatory fields (BT-* from EN 16931)

2. **Data Extraction**
   - Invoice header: ID, issue date, type code, currency
   - Parties: Supplier, customer, payee (with addresses, OIBs)
   - Line items: Description, quantity, price, KPD code, VAT
   - Totals: Subtotal, VAT breakdown, grand total
   - Payment terms: Due date, payment means, IBAN

3. **Validation Pipeline Integration**
   - Step 1: XSD validation (call xsd-validator service)
   - Step 2: Schematron validation (call schematron-validator service)
   - Step 3: Business rules (call business-rules-engine)
   - Step 4: OIB validation (call oib-validator)
   - Step 5: KPD validation (call kpd-validator)
   - Aggregate validation results, return consolidated report

4. **Database Storage**
   - Store parsed invoice in PostgreSQL
   - JSON/JSONB for flexible structure
   - Index on invoice ID, OIBs, dates for fast search
   - Link to original XML (S3 storage reference)

5. **Error Handling**
   - Malformed XML → reject with clear error message
   - Missing mandatory fields → list all missing fields
   - Invalid checksums (OIB, IBAN) → detailed validation report
   - Schema violations → XSD/Schematron error details

**Acceptance Criteria:**
- [x] Parse valid UBL 2.1 invoice XML
- [x] XXE attack prevention implemented
- [x] Billion laughs attack prevention implemented
- [x] Reject malformed XML with clear errors
- [x] Size and depth limit enforcement (10MB, 20 levels)
- [x] Extract nested elements safely (extractElement function)
- [x] Validate XML structure against required fields
- [x] 100% test coverage achieved (67 tests, all metrics: statements, branches, functions, lines)
- [x] Property-based testing with fast-check
- [ ] Integration with schema validation services (separate layer)
- [ ] Store parsed data in PostgreSQL (integration layer)
- [ ] RabbitMQ integration (deferred to integration layer)

**Resources:**
- UBL 2.1 Samples: `docs/standards/UBL-2.1/examples/`
- EN 16931 Mapping: `docs/standards/EN-16931/`
- Croatian CIUS: `docs/standards/CIUS-HR/`

---

## 🎯 STRETCH GOALS (If Time Permits)

### P3: api-gateway (External B2B API)

**Priority:** ⚪ LOW - Nice to have for enterprise customers
**Estimated Effort:** 4 days
**LOC Estimate:** 2,500-3,500

**Purpose:**
Expose REST API for enterprise customers to submit invoices programmatically (alternative to email/web upload).

**Technical Specifications:**

1. **Authentication**
   - OAuth 2.0 client credentials flow
   - API keys for simpler integrations
   - JWT tokens with 1-hour expiration
   - Rate limiting per customer (configurable)

2. **API Endpoints**
   - `POST /v1/invoices` - Submit invoice (JSON or XML)
   - `GET /v1/invoices/:id` - Get invoice status
   - `GET /v1/invoices` - List invoices (pagination)
   - `DELETE /v1/invoices/:id` - Cancel invoice
   - `GET /v1/health` - Health check
   - `GET /v1/openapi.json` - OpenAPI 3.1 spec

3. **Request Formats**
   - Accept JSON (custom schema)
   - Accept UBL XML (direct passthrough)
   - Convert JSON to UBL internally (via ubl-transformer)

4. **Async Processing**
   - Return 202 Accepted immediately
   - Process invoice async via RabbitMQ
   - Webhooks for status updates (optional)
   - Polling endpoint for status checks

5. **Security**
   - HTTPS only (TLS 1.3)
   - Input validation (JSON schema)
   - SQL injection prevention (parameterized queries)
   - Rate limiting: 100 req/min per API key
   - IP whitelisting (optional, per customer)

**Acceptance Criteria:**
- [ ] OAuth 2.0 token generation
- [ ] Submit invoice via JSON
- [ ] Submit invoice via UBL XML
- [ ] Async processing with status tracking
- [ ] Rate limiting works (429 Too Many Requests)
- [ ] OpenAPI 3.1 spec generated
- [ ] 100% test coverage
- [ ] Load test: 1000 req/sec sustained

---

### P3: ocr-service (Optical Character Recognition)

**Priority:** ⚪ LOW - Required for scanned invoice processing
**Estimated Effort:** 5 days
**LOC Estimate:** 2,000-3,000

**Purpose:**
Extract text from scanned invoice images (JPEG, PNG, PDF scans) using OCR. Critical for manual invoice ingestion.

**Technical Specifications:**

1. **OCR Engine Selection**
   - **Option A:** Tesseract (open source, free, self-hosted)
   - **Option B:** Google Cloud Vision (managed, high accuracy, $$)
   - **Option C:** Azure Computer Vision (good Croatian support, $$)
   - **Decision:** Start with Tesseract, add Cloud Vision fallback if accuracy <90%

2. **Image Preprocessing**
   - Deskew (correct rotation)
   - Noise reduction (Gaussian blur)
   - Contrast enhancement (adaptive histogram)
   - Binarization (Otsu's method)
   - Scale to optimal DPI (300 DPI recommended)

3. **Text Extraction**
   - Language: Croatian (hrv) + English (eng)
   - Output: Plain text + bounding boxes
   - Confidence scores per word/line
   - Field detection (use pattern matching for invoice fields)

4. **Structured Data Extraction**
   - Invoice number: Regex pattern matching
   - Date: Regex + date parsing (Croatian format: DD.MM.YYYY)
   - OIB: 11-digit pattern
   - Amounts: Number extraction with currency
   - Line items: Table detection (challenging!)

5. **AI Validation Integration**
   - Send OCR output to ai-validation-service
   - Human review if confidence <80%
   - Store corrections for model training

**Acceptance Criteria:**
- [ ] Extract text from scanned PDF
- [ ] Detect Croatian text correctly (>90% accuracy)
- [ ] Extract invoice number, date, total amount
- [ ] Return confidence scores
- [ ] Preprocess images correctly (deskew, denoise)
- [ ] 100% test coverage
- [ ] Benchmark: Process A4 page in <3 seconds
- [ ] RabbitMQ integration

**Resources:**
- Tesseract: https://github.com/tesseract-ocr/tesseract
- Croatian Training Data: Download `hrv.traineddata`
- Invoice Preprocessing: Research invoice-specific techniques

---

## 📋 GENERAL GUIDELINES FOR ALL TASKS

### Code Quality Standards

1. **TypeScript Strict Mode:** ALL services use `strict: true`
2. **Test Coverage:** 100% (enforced by Jest) - NON-NEGOTIABLE
3. **Linting:** ESLint with Airbnb config + Prettier
4. **Error Handling:** No silent failures, structured errors
5. **Logging:** Pino JSON logs with request ID propagation
6. **Metrics:** Prometheus prom-client in every service
7. **Tracing:** OpenTelemetry instrumentation
8. **Documentation:** README.md + RUNBOOK.md for each service

### Service Template Structure

```
services/{service-name}/
├── src/
│   ├── index.ts              # Entry point
│   ├── api.ts                # Express REST API
│   ├── worker.ts             # RabbitMQ message consumer
│   ├── lib/                  # Core business logic
│   ├── config.ts             # Configuration loading
│   └── observability.ts      # Prom + OpenTelemetry setup
├── tests/
│   ├── unit/                 # Unit tests (70%)
│   ├── integration/          # Integration tests (25%)
│   └── e2e/                  # End-to-end tests (5%)
├── package.json              # Dependencies
├── tsconfig.json             # TypeScript config
├── jest.config.js            # Jest config
├── .eslintrc.js              # ESLint config
├── README.md                 # Service documentation
├── RUNBOOK.md                # Operational procedures
└── Dockerfile                # Future: Container image
```

### Testing Requirements

**CRITICAL: 100% Test Coverage Required (Non-Negotiable)**

This system handles legally binding financial documents where failures result in:
- **66,360 EUR penalties** for non-compliance
- **Loss of VAT deduction rights** (retroactive tax liability)
- **11-year audit liability** (criminal prosecution)
- **Zero error tolerance** (Tax Authority rejects invalid invoices)

**Tests that prove "code reads CLI and writes to disk" are proof of non-garbage, not proof of correctness. We require proof of correctness.**

**Coverage Enforcement:**
```javascript
// Use shared Jest config: shared/jest-config/base.config.js
coverageThreshold: {
  global: {
    branches: 100,
    functions: 100,
    lines: 100,
    statements: 100
  }
}
```

**Jest Configuration:**
```javascript
// In your service's jest.config.js
const baseConfig = require('../../shared/jest-config/base.config.js');
module.exports = {
  ...baseConfig,
  displayName: 'your-service-name'
};
```

**Test Types:**
1. **Unit Tests (70%):** Mock all external dependencies
2. **Integration Tests (25%):** Use Testcontainers for PostgreSQL/RabbitMQ
3. **E2E Tests (5%):** Critical user journeys only
4. **Property-Based Tests:** Use `fast-check` for validators (mandatory for validators)
5. **Contract Tests:** Use Pact for service boundaries (future consideration)
6. **Performance Tests:** Benchmark critical paths (<100ms p95)

**Documentation:** See `shared/jest-config/README.md` for complete testing guide

### Git Workflow

1. **Branch Naming:** `teamb/{service-name}-implementation`
2. **Commit Messages:** Conventional Commits format
   ```
   feat(b2b-access-point): implement AS4 message parsing
   test(oib-validator): add property-based checksum tests
   docs(kpd-validator): document registry lookup API
   ```
3. **Pull Requests:** One service per PR, request review from Team A lead
4. **Merge:** Squash commits, update CHANGELOG.md

### Communication Protocol

1. **Daily Standup:** 09:00 CET (async via Slack if remote)
2. **Blockers:** Report immediately (don't wait for standup)
3. **Questions:** Technical questions to Team A lead or architect
4. **Documentation:** Update TODO.md after each service completion
5. **Demos:** Weekly demo of completed services (Friday 16:00 CET)

---

## 📊 SUCCESS METRICS

**Week 1 Actual Completion:** 4 services complete ✅ (2025-11-12)
- ✅ oib-validator (P1) - commit 0ab4163
- ✅ iban-validator (P2) - commit 0c09602
- ✅ kpd-validator (P2) - commit d3dbfda
- ✅ xml-parser (P2) - commit 0e077a5

**Week 1 Remaining (Complex Services):**
- ⏸️ b2b-access-point (P0) - Requires AS4 protocol research (5 days)
- ⏸️ e-reporting-service (P1) - Requires Tax Authority API research
- ⏸️ business-rules-engine (P2) - Requires tax consultant review (5 days)

**Week 2 Targets:** Complex integrations
- api-gateway (P3) - OAuth 2.0 + REST API
- ocr-service (P3) - Tesseract integration

**Achievement Summary:**
- **Completed:** 4/4 "easy win" validators (100% of simple services)
- **Total Tests:** 227 tests, 100% coverage across all services
- **Project Status:** 20/40 services complete (50%, up from 40%)
- **Next Phase:** Complex services requiring external dependencies and coordination

---

## 🚀 GETTING STARTED

1. **Read CLAUDE.md** - System architecture foundation
2. **Read CROATIAN_COMPLIANCE.md** - Regulatory requirements
3. **Study existing services:**
   - `services/cert-lifecycle-manager/` - REST API example
   - `services/fina-connector/` - SOAP + RabbitMQ example
   - `services/xsd-validator/` - Validation service example
4. **Set up development environment:**
   ```bash
   cd /home/user/eRacun-development
   # Install dependencies for service you're working on
   cd services/{service-name}
   npm install
   npm run dev  # Start development server
   npm test     # Run tests
   ```
5. **Create service from template** (use existing service as base)
6. **Implement → Test → Document → PR → Merge**

---

## ❓ QUESTIONS? BLOCKERS?

**Technical Lead:** Available for architecture questions
**Tax Consultant:** Available for business rules clarification (book via calendar)
**FINA Support:** 01 4404 707 (for certificate/integration questions)
**KPD Registry:** KPD@dzs.hr (for classification questions)

**Slack Channels:**
- `#team-b-dev` - Daily development chat
- `#eracun-architecture` - Architecture discussions
- `#eracun-compliance` - Regulatory questions

---

**Last Updated:** 2025-11-12 (Evening - Sprint Update)
**Document Owner:** Technical Lead
**Team B Lead:** [TO BE ASSIGNED]
**Sprint End:** 2025-11-26

**Status Update:** 4 validation services completed with 100% test coverage (227 tests total). All "easy win" validators complete. Next phase requires external coordination (AS4 protocol docs, Tax Authority API specs, tax consultant review).

**Let's ship this! 🚀**
