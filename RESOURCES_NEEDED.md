# RESOURCES NEEDED - External Standards, Documentation & Registries

**Purpose:** Track all external resources required for development and compliance
**Owner:** Technical Lead
**Last Updated:** 2025-11-12

---

## 🔴 CRITICAL PRIORITY (Blocks Development)

### 1. UBL 2.1 Schema Files (XSD)

**Status:** ⏳ NEEDED
**Blocks:** xml-parser, ubl-transformer, xsd-validator (schema files)
**Required By:** Week 1 (2025-11-15)

**What We Need:**
- UBL 2.1 Invoice XSD schema files (complete package)
- UBL 2.1 CreditNote XSD schema (for corrections)
- Common aggregate components (CAC)
- Common basic components (CBC)
- Common extension components (if used)

**Where to Get:**
- **Official Source:** OASIS UBL 2.1 - https://docs.oasis-open.org/ubl/os-UBL-2.1/
- **Direct Download:** http://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.zip
- **Mirror:** UniversalBusinessLanguage.org

**File Structure Expected:**
```
docs/standards/UBL-2.1/
├── xsd/
│   ├── maindoc/
│   │   ├── UBL-Invoice-2.1.xsd
│   │   └── UBL-CreditNote-2.1.xsd
│   └── common/
│       ├── UBL-CommonAggregateComponents-2.1.xsd
│       ├── UBL-CommonBasicComponents-2.1.xsd
│       └── UBL-CommonExtensionComponents-2.1.xsd
└── examples/
    └── UBL-Invoice-2.1-Example.xml
```

**Action:** Download, extract, verify schemas validate sample documents

---

### 2. Croatian CIUS (Core Invoice Usage Specification)

**Status:** ⏳ NEEDED
**Blocks:** schematron-validator, business-rules-engine, xml-parser
**Required By:** Week 1 (2025-11-15)

**What We Need:**
- Croatian CIUS Schematron rules (.sch files)
- Croatian extensions to EN 16931
- Business rule validation tables
- Croatian-specific BT-* field mappings
- Code lists (payment means, tax categories, etc.)

**Where to Get:**
- **Primary:** Croatian Tax Authority (Porezna Uprava) website
- **Contact:** FINA technical support (01 4404 707)
- **Alternative:** EU CEF eInvoicing website - https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Specifications
- **Possible URL:** https://www.porezna-uprava.hr/ (search for "CIUS" or "e-Račun")

**Expected Structure:**
```
docs/standards/CIUS-HR/
├── schematron/
│   ├── CIUS-HR-Invoice.sch
│   ├── CIUS-HR-CreditNote.sch
│   └── business-rules.sch
├── documentation/
│   ├── CIUS-HR-specification.pdf
│   └── field-mapping-table.xlsx
└── codelists/
    ├── payment-means-codes.json
    ├── tax-category-codes.json
    └── unit-codes.json
```

**Action:** Request from FINA technical team or download if publicly available

**Risk:** May require NDA or official registration to access

---

### 3. EN 16931-1:2017 Standard (European Semantic Model)

**Status:** ⏳ NEEDED
**Blocks:** xml-parser, ubl-transformer, compliance validation
**Required By:** Week 1 (2025-11-15)

**What We Need:**
- EN 16931-1:2017 specification document (PDF)
- Semantic data model tables
- BT-* field definitions (Business Terms)
- BG-* group definitions (Business Groups)
- Business rule catalog (BR-XX rules)

**Where to Get:**
- **Official (Paid):** CEN (European Committee for Standardization) - https://standards.cen.eu/
- **Free Alternative:** EU CEF eInvoicing documentation - https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/Semantic+Model
- **Implementation Guide:** https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Documentation

**Cost:** Official standard ~€100-150 EUR (may be worth purchasing)

**Expected Files:**
```
docs/standards/EN-16931/
├── EN-16931-1-2017.pdf (specification)
├── semantic-model.xlsx (field tables)
├── business-rules.xlsx (validation rules)
└── implementation-guide.pdf
```

**Action:** Purchase official standard OR use free EU implementation guides

---

### 4. KLASUS 2025 KPD Registry (Product Classification)

**Status:** ⏳ NEEDED
**Blocks:** kpd-validator, kpd-registry-sync (update data)
**Required By:** Week 2 (2025-11-20)

**What We Need:**
- KLASUS 2025 complete registry (CSV, XML, or database dump)
- 6-digit KPD codes with Croatian + English descriptions
- Hierarchical structure (section → division → group)
- Active/deprecated flag per code
- Effective date ranges

**Where to Get:**
- **Official:** Croatian Bureau of Statistics (DZS) - https://www.dzs.hr/
- **Contact:** KPD@dzs.hr (mentioned in CROATIAN_COMPLIANCE.md)
- **Possible URL:** https://www.dzs.hr/Hrv/important/klasus/klasus.html

**Expected Format:**
```csv
kpd_code,section,division,description_hr,description_en,active,effective_date
010101,01,0101,Pšenica i raž,Wheat and rye,true,2025-01-01
```

**Storage Target:**
```
data/registries/
├── klasus-2025-full.csv
├── klasus-2025-hierarchy.json
└── klasus-2025-import.sql
```

**Action:** Email KPD@dzs.hr requesting KLASUS 2025 registry for e-invoicing compliance

**Note:** Service `kpd-registry-sync` already exists but may have placeholder/old data

---

## 🟡 HIGH PRIORITY (Required Soon)

### 5. AS4 Profile Specification (B2B Invoice Exchange)

**Status:** ⏳ NEEDED
**Blocks:** b2b-access-point service
**Required By:** Week 1 (2025-11-18)

**What We Need:**
- OASIS ebMS 3.0 specification
- eDelivery AS4 Profile (EU standard for document exchange)
- Croatian AS4 implementation guide (if exists)
- WSDL/XSD for AS4 message structure
- Example AS4 messages (UserMessage, Receipt, Error)

**Where to Get:**
- **OASIS ebMS:** https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/
- **eDelivery AS4:** https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eDelivery+AS4+-+1.15
- **PEPPOL AS4 (similar):** https://docs.peppol.eu/edelivery/as4/specification/
- **CEF Documentation:** https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eDelivery

**Expected Files:**
```
docs/standards/AS4/
├── ebms-3.0-core-spec.pdf
├── eDelivery-AS4-Profile-v1.15.pdf
├── as4-message-structure.xsd
├── croatian-as4-guide.pdf (if available)
└── examples/
    ├── as4-usermessage.xml
    ├── as4-receipt.xml
    └── as4-error.xml
```

**Action:** Download OASIS + eDelivery specs, check with FINA for Croatian-specific guide

---

### 6. FINA API Documentation (SOAP WSDL + Test Credentials)

**Status:** ⏳ NEEDED (Test Environment Access)
**Blocks:** fina-connector testing, staging deployment
**Required By:** Week 2 (2025-11-20)

**What We Need:**
- WSDL 1.9 file for fiscalization service (if not already obtained)
- Test environment credentials (demo certificates)
- Test OIB numbers (valid for sandbox)
- API rate limits documentation
- Error code reference table
- Test data samples (valid/invalid requests)

**Where to Get:**
- **Contact:** FINA Support - 01 4404 707
- **Portal:** cms.fina.hr (may require registration)
- **Test Endpoint:** cistest.apis-it.hr:8449/FiskalizacijaServiceTest

**Expected Files:**
```
docs/integration/FINA/
├── FiskalizacijaService-WSDL-1.9.xml
├── fina-api-documentation.pdf
├── error-codes-reference.pdf
├── test-credentials.txt (gitignored)
└── test-samples/
    ├── valid-b2c-invoice.xml
    └── error-scenarios.md
```

**Action:** Contact FINA support to request test environment access + demo certificates

**Timeline:** 5-10 business days for certificate issuance

---

### 7. HNB Bank Registry (Croatian Banks)

**Status:** ⏳ NEEDED
**Blocks:** iban-validator service
**Required By:** Week 2 (2025-11-22)

**What We Need:**
- List of Croatian bank codes (7-digit)
- Bank names (Croatian + English)
- SWIFT/BIC codes
- Active/inactive status
- Update frequency (for periodic sync)

**Where to Get:**
- **Official:** Croatian National Bank (HNB) - https://www.hnb.hr/
- **Direct Link:** https://www.hnb.hr/en/core-functions/banking-supervision/credit-institution-registers
- **Alternative:** SWIFT registry (paid)

**Expected Format:**
```json
[
  {
    "bank_code": "1001005",
    "bank_name": "Erste banka",
    "bank_name_en": "Erste Bank",
    "swift_bic": "ESBCHR22",
    "active": true
  },
  {
    "bank_code": "2340009",
    "bank_name": "Privredna banka Zagreb",
    "bank_name_en": "Privredna Banka Zagreb",
    "swift_bic": "PBZGHR2X",
    "active": true
  }
]
```

**Storage Target:**
```
data/registries/
├── hnb-banks.json
└── hnb-banks-import.sql
```

**Action:** Scrape HNB website or request official registry

**Update Frequency:** Monthly (automated cron job in iban-validator)

---

## 🟢 MEDIUM PRIORITY (Future Needs)

### 8. OIB Validation Algorithm Reference

**Status:** ✅ DOCUMENTED (but verify implementation)
**Blocks:** oib-validator service
**Required By:** Week 2 (2025-11-22)

**What We Need:**
- Official OIB checksum algorithm specification (MOD-11, ISO 7064)
- Test OIB numbers (valid/invalid pairs)
- Edge cases documentation

**Where to Get:**
- **Official PDF:** REGOS - https://regos.hr/app/uploads/2018/07/PRERACUNAVANJE-KONTROLNE-ZNAMENKE-OIB.pdf
- **Wikipedia:** https://hr.wikipedia.org/wiki/Osobni_identifikacijski_broj
- **ISO 7064 Standard:** (if needed for verification)

**Status:** Algorithm documented in TEAM_B.md, but verify against official source

**Action:** Download official spec, implement property-based tests

---

### 9. Croatian Tax Law References (VAT Rates & Rules)

**Status:** ⏳ NEEDED (for business-rules-engine)
**Blocks:** business-rules-engine, tax calculation validation
**Required By:** Week 2 (2025-11-25)

**What We Need:**
- Croatian VAT Law (ZPDV - Zakon o PDV-u)
- VAT rate tables (current + historical)
- Reverse charge scenarios documentation
- Special schemes documentation (margin, small business)
- Cross-border rules (intra-EU)

**Where to Get:**
- **Tax Authority:** https://www.porezna-uprava.hr/
- **Official Gazette:** Narodne Novine (NN) - legal database
- **EU VAT Directive:** 2006/112/EC (for EU-wide rules)

**Expected Files:**
```
docs/compliance/tax-law/
├── ZPDV-consolidated-version.pdf
├── vat-rates-table-2025.pdf
├── reverse-charge-guide.pdf
└── cross-border-vat-rules.pdf
```

**Critical:** Book 8-hour consultation with Croatian tax consultant to review implementation

**Action:** Download laws, schedule tax consultant meeting

---

### 10. XMLDSig Specification (Digital Signatures)

**Status:** ✅ LIKELY AVAILABLE (common standard)
**Blocks:** digital-signature-service (already implemented, verify compliance)
**Required By:** Not urgent (service exists)

**What We Need:**
- XML Signature Syntax and Processing (W3C Recommendation)
- Enveloped signature examples
- X.509 certificate integration guide

**Where to Get:**
- **Official:** https://www.w3.org/TR/xmldsig-core/
- **Examples:** https://www.w3.org/TR/xmldsig-core/#sec-Examples

**Action:** Download for reference, verify digital-signature-service implementation

---

### 11. eIDAS Regulation (Qualified Timestamps)

**Status:** ⏳ FUTURE CONSIDERATION
**Blocks:** Qualified timestamp integration (future requirement)
**Required By:** Unknown (may be optional for initial launch)

**What We Need:**
- eIDAS Regulation (EU) No 910/2014
- Qualified timestamp service provider list
- Integration specifications (RFC 3161)

**Where to Get:**
- **Official:** https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation
- **TSP List:** https://eidas.ec.europa.eu/efda/tl-browser/

**Action:** Research if qualified timestamps mandatory for B2B invoices

**Note:** May be optional or only required for certain invoice types

---

## 📋 RESOURCE ACQUISITION CHECKLIST

### Week 1 (2025-11-12 to 2025-11-15)
- [ ] Download UBL 2.1 schema package (XSD files)
- [ ] Request Croatian CIUS from FINA or Tax Authority
- [ ] Obtain EN 16931-1:2017 (purchase or use free guides)
- [ ] Download AS4/ebMS specifications
- [ ] Contact FINA for test environment access
- [ ] Email KPD@dzs.hr for KLASUS 2025 registry

### Week 2 (2025-11-18 to 2025-11-22)
- [ ] Download HNB bank registry
- [ ] Verify OIB algorithm against official spec
- [ ] Download Croatian VAT law documentation
- [ ] Schedule tax consultant consultation
- [ ] Set up FINA test credentials (if received)
- [ ] Organize all resources in `docs/standards/` structure

### Ongoing
- [ ] Monitor for updated versions of standards
- [ ] Set up quarterly review for registry updates (KPD, banks)
- [ ] Document resource version numbers in README files

---

## 📂 DIRECTORY STRUCTURE (Target)

```
eRacun-development/
├── docs/
│   ├── standards/
│   │   ├── UBL-2.1/              # ⏳ NEEDED
│   │   ├── EN-16931/             # ⏳ NEEDED
│   │   ├── CIUS-HR/              # ⏳ NEEDED
│   │   ├── AS4/                  # ⏳ NEEDED
│   │   └── XMLDSig/              # ✅ Public W3C
│   ├── integration/
│   │   └── FINA/                 # ⏳ NEEDED (credentials)
│   └── compliance/
│       ├── tax-law/              # ⏳ NEEDED
│       └── eidas/                # 🔮 FUTURE
└── data/
    └── registries/
        ├── klasus-2025/          # ⏳ NEEDED
        └── hnb-banks/            # ⏳ NEEDED
```

---

## 🚨 BLOCKERS & RISKS

**Risk 1: Croatian CIUS Not Publicly Available**
- Mitigation: Use EN 16931 standard + contact FINA for guidance
- Fallback: Implement EN 16931 core, extend based on Croatian requirements

**Risk 2: FINA Test Access Delay (5-10 days)**
- Mitigation: Start certificate request NOW, develop against mock responses
- Fallback: Use placeholder WSDL, implement full integration when credentials received

**Risk 3: KLASUS Registry Access Restrictions**
- Mitigation: Use public CPA 2015 (similar EU classification) temporarily
- Fallback: Manual data entry for common product categories

**Risk 4: EN 16931 Standard Cost (€100-150)**
- Mitigation: Budget for purchase, or use free EU implementation guides
- Fallback: Free guides sufficient for initial implementation

---

## 📞 CONTACTS FOR RESOURCE REQUESTS

| Resource | Contact | Method | Expected Response Time |
|----------|---------|--------|----------------------|
| Croatian CIUS | FINA Technical Support | 01 4404 707 | 2-3 business days |
| FINA Test Access | FINA Portal | cms.fina.hr | 5-10 business days (certificate) |
| KLASUS Registry | DZS | KPD@dzs.hr | 3-5 business days |
| HNB Bank Registry | HNB Website | Self-service scrape | Immediate |
| Tax Consultation | Croatian Tax Consultant | [TBD - need consultant contact] | Schedule 1-2 weeks ahead |

---

**Next Actions:**
1. **TODAY:** Download publicly available specs (UBL, AS4, XMLDSig)
2. **TODAY:** Email KPD@dzs.hr for KLASUS registry
3. **TODAY:** Call FINA support for CIUS + test access
4. **WEEK 1:** Organize all downloaded resources in `docs/standards/`
5. **WEEK 2:** Verify all critical resources obtained before Team B implementation sprint

---

**Last Updated:** 2025-11-12
**Owned By:** Technical Lead
**Review Frequency:** Weekly until all resources obtained
