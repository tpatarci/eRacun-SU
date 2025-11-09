# CIUS-HR - Croatian Core Invoice Usage Specification

**Full Name:** Croatian CIUS (Core Invoice Usage Specification) for Fiskalizacija 2.0
**Based On:** EN 16931-1:2017 + UBL 2.1
**Published:** Expected Q4 2025 (draft specifications available)
**Authority:** Ministarstvo financija (Ministry of Finance) + Porezna uprava (Tax Authority)
**Status:** 🟡 IN DEVELOPMENT - Final spec expected Oct 30, 2025
**Effective Date:** 1 January 2026 (MANDATORY)
**Last Verified:** 2025-11-09

---

## Official Source

**Primary:** https://www.porezna-uprava.hr/ (Tax Authority)
**Fiskalizacija Portal:** https://www.fiskalizacija.hr/
**Technical Docs:** To be published at https://www.fiskalizacija.hr/dokumentacija/
**Support Contact:** fiskalizacija@porezna-uprava.hr

**Legal Framework:** See `/CROATIAN_COMPLIANCE.md` section 1

---

## What is CIUS-HR?

**CIUS** = Core Invoice Usage Specification

A **CIUS restricts or extends** the base EN 16931 standard to meet national requirements. The Croatian CIUS:
- Makes certain EN 16931 optional fields **mandatory**
- Adds **Croatian-specific extensions** (HR-BT-xxx fields)
- Defines **national business rules** (HR-BR-xxx codes)
- Specifies **Croatian code lists** (OIB, KPD, business premises)

**Compliance Hierarchy:**
```
EN 16931-1:2017 (European baseline)
    ↓ restricted/extended by
Croatian CIUS (national requirements)
    ↓ implemented in
UBL 2.1 XML (syntax)
    ↓ validated by
Schematron rules (.sch files)
```

---

## Directory Contents

```
CIUS-HR/
├── README.md                  # This file
├── schematron/                # Validation rules (to be added after Oct 30, 2025)
│   ├── CIUS-HR-UBL.sch       # Croatian business rules
│   └── examples/             # Test cases
├── extensions/                # Croatian-specific fields
│   ├── operator-oib.md       # HR-BT-5 specification
│   ├── business-premises.md  # HR-BT-6 specification
│   ├── cash-register.md      # HR-BT-7 specification
│   └── fiscalization-ids.md  # JIR, ZKI, ZOI codes
└── business-rules/            # HR-BR-xxx validation rules
    ├── oib-validation.md     # OIB checksum rules
    ├── kpd-mandatory.md      # Product classification rules
    └── invoice-format.md     # Croatian invoice number format
```

---

## Croatian Extensions (HR-BT-xxx Fields)

**These fields are NOT in base EN 16931.** They are Croatian-specific additions.

### HR-BT-5: Operator OIB
**Field Name:** Operator personal identification number (OIB)
**Cardinality:** [1..1] (Mandatory from **1 September 2025**)
**Format:** 11 digits (ISO 7064 checksum validated)
**Purpose:** Identify the person who issued the invoice (cashier/operator)
**UBL XPath:** `/Invoice/cac:AccountingSupplierParty/cac:Party/cac:Contact/cbc:ID[@schemeID='HR:OIB:OPERATOR']`

**Example:**
```xml
<cac:AccountingSupplierParty>
  <cac:Party>
    <cac:Contact>
      <cbc:ID schemeID="HR:OIB:OPERATOR">12345678901</cbc:ID>
      <cbc:Name>Ivan Horvat</cbc:Name>
    </cac:Contact>
  </cac:Party>
</cac:AccountingSupplierParty>
```

### HR-BT-6: Business Premises Code
**Field Name:** Poslovni prostor (Business premises identifier)
**Cardinality:** [1..1] (Mandatory for B2C fiscalization)
**Format:** Alphanumeric, max 20 characters
**Purpose:** Identify physical location where invoice was issued
**UBL XPath:** Extension (custom namespace)

**Example:** `ZAGREB1`, `SPLIT-TRGOVINA`, `WEBSHOP`

### HR-BT-7: Cash Register Code
**Field Name:** Naplatni uređaj (Cash register/POS identifier)
**Cardinality:** [1..1] (Mandatory for B2C fiscalization)
**Format:** Alphanumeric, max 20 characters
**Purpose:** Identify specific device that issued invoice
**UBL XPath:** Extension (custom namespace)

**Example:** `POS1`, `KASA2`, `ONLINE`

### HR-BT-8: JIR (Unique Invoice Identifier)
**Field Name:** Jedinstveni identifikator računa
**Cardinality:** [1..1] (Assigned by Tax Authority during B2C fiscalization)
**Format:** UUID (e.g., `123e4567-e89b-12d3-a456-426614174000`)
**Purpose:** Immutable receipt confirmation from FINA/Porezna
**UBL XPath:** Extension (custom namespace)

**When Assigned:** After successful B2C fiscalization SOAP call
**Critical:** Must be stored with invoice for 11-year retention period

### HR-BT-9: ZKI (Security Code)
**Field Name:** Zaštitni kod izdavatelja
**Cardinality:** [1..1] (Calculated before B2C fiscalization)
**Format:** 32 hexadecimal characters (MD5 hash)
**Purpose:** Cryptographic proof of invoice integrity
**Calculation:** MD5(OIB + IssueDateTime + InvoiceNumber + BusinessPremises + CashRegister + TotalAmount + PrivateKey)

**Example:** `a1b2c3d4e5f6789012345678901234ab`

**See:** `/docs/research/XMLDSIG_GUIDE.md` for ZKI calculation algorithm

---

## Croatian Business Rules (HR-BR-xxx)

### HR-BR-01: KPD Code Mandatory
**Rule:** Every invoice line item (cac:InvoiceLine) MUST contain a valid KPD code.
**Field:** BT-157 (Item standard identifier) with `schemeID="HR:KPD"`
**Validation:**
  1. Format: Minimum 6 digits
  2. Exists in KLASUS 2025 registry
  3. Status: Active (not deprecated)

**Error if missing:** `CIUS-HR-001: KPD code missing on line {line_id}`

**See:** `/docs/standards/KLASUS-2025/README.md` for KPD validation

### HR-BR-02: Seller OIB Checksum
**Rule:** Seller OIB (BT-31) MUST pass ISO 7064 Mod 11,10 checksum validation.
**Algorithm:** See `/docs/research/OIB_CHECKSUM.md`
**Error if invalid:** `CIUS-HR-002: Seller OIB checksum invalid`

**Example Valid OIB:** `12345678901` (11th digit is checksum)

### HR-BR-03: Buyer OIB Checksum
**Rule:** Buyer OIB (BT-48) MUST pass ISO 7064 Mod 11,10 checksum validation.
**Algorithm:** See `/docs/research/OIB_CHECKSUM.md`
**Error if invalid:** `CIUS-HR-003: Buyer OIB checksum invalid`

### HR-BR-04: Operator OIB Mandatory (from 1 Sept 2025)
**Rule:** Operator OIB (HR-BT-5) MUST be present for all invoices issued after 1 September 2025.
**Exemption:** Not required for invoices issued before transition period.
**Error if missing:** `CIUS-HR-004: Operator OIB required (effective 1 Sept 2025)`

### HR-BR-05: Invoice Number Format
**Rule:** Invoice number (BT-1) MUST follow Croatian format for B2C fiscalization.
**Format:** `{sequential_number}-{business_premises}-{cash_register}`
**Example:** `1-ZAGREB1-POS1`, `42-WEBSHOP-ONLINE`
**Components:**
  - Sequential number: Integer (resets yearly)
  - Business premises: Alphanumeric (max 20 chars)
  - Cash register: Alphanumeric (max 20 chars)

**Regex:** `^\d+-[A-Za-z0-9]{1,20}-[A-Za-z0-9]{1,20}$`

**Error if invalid:** `CIUS-HR-005: Invoice number format invalid`

**Note:** For B2B-only invoices, format may be simpler (confirm with Tax Authority)

### HR-BR-06: Currency Must Be EUR
**Rule:** Document currency code (BT-5) MUST be `EUR`.
**Effective:** Since Croatia joined eurozone (1 January 2023)
**Error if not EUR:** `CIUS-HR-006: Currency must be EUR (Croatia is eurozone member)`

**Historical Note:** HRK (kuna) was phased out. Old invoices may reference HRK but new invoices (2023+) must use EUR.

### HR-BR-07: VAT Category Code Validation
**Rule:** VAT category codes (BT-151) must be from approved Croatian list.
**Allowed Values:**
  - `S` (Standard 25%)
  - `AA` (Lower 13%)
  - `A` (Reduced 5%)
  - `Z` (Zero-rated 0%)
  - `E` (Exempt with reason)
  - `AE` (Reverse charge)

**Error if invalid:** `CIUS-HR-007: Invalid VAT category code`

**See:** `/docs/research/VAT_RULES_HR.md` for complete VAT logic

### HR-BR-08: Digital Signature Required (B2B)
**Rule:** B2B/B2G invoices MUST contain qualified electronic signature (XMLDSig).
**Standard:** XMLDSig with FINA X.509 certificate
**Exemption:** B2C fiscalized receipts (signature embedded in ZKI code)
**Error if missing:** `CIUS-HR-008: Digital signature required for B2B invoices`

**See:** `/docs/research/XMLDSIG_GUIDE.md` for signature implementation

### HR-BR-09: Qualified Timestamp Required (B2B)
**Rule:** B2B/B2G invoices MUST contain eIDAS-compliant qualified timestamp.
**Purpose:** Non-repudiation of invoice issue time
**Exemption:** B2C fiscalized receipts (timestamp from JIR response)
**Error if missing:** `CIUS-HR-009: Qualified timestamp required for B2B invoices`

### HR-BR-10: Arithmetic Consistency
**Rule:** Monetary totals MUST be arithmetically consistent.
**Validations:**
  1. Sum of line amounts = Σ(BT-131)
  2. VAT total = Σ(taxable_amount × rate) for all VAT categories
  3. Tax inclusive amount = Tax exclusive amount + VAT total
  4. Payable amount = Tax inclusive amount - prepaid + rounding

**Tolerance:** ±0.01 EUR (rounding)
**Error if violated:** `CIUS-HR-010: Arithmetic inconsistency detected`

---

## Mandatory Fields (Stricter than Base EN 16931)

**EN 16931 marks some fields as optional. Croatian CIUS makes these MANDATORY:**

| BT Code | Field Name | EN 16931 | CIUS-HR | Reason |
|---------|------------|----------|---------|--------|
| BT-34 | Seller electronic address | [0..1] | [1..1] | Required for AS4 routing |
| BT-49 | Buyer electronic address | [0..1] | [1..1] | Required for AS4 delivery |
| BT-157 | Item standard identifier | [0..1] | [1..1] | KPD code mandatory |
| BT-31 | Seller VAT identifier | [0..1] | [1..1] | OIB mandatory for all entities |
| BT-48 | Buyer VAT identifier | [0..1] | [1..1] | OIB mandatory for all entities |

---

## Schematron Validation Files

**Expected Publication:** **30 October 2025**

**Files to be published:**
- `CIUS-HR-UBL-validation.sch` - Croatian business rules
- `CIUS-HR-codelists.sch` - Code list validation (VAT, currency, etc.)
- `CIUS-HR-extensions.sch` - Croatian-specific field validation

**Download Location:** https://www.fiskalizacija.hr/dokumentacija/ (when available)

**Service Integration:**
- `schematron-validator` service will load these .sch files
- Validates against HR-BR-xxx rules
- Returns structured error codes

**Before Publication:**
- Use draft specifications from CROATIAN_COMPLIANCE.md
- Implement custom validation in `business-rules-engine` service
- Update when official Schematron published

---

## Code Lists (Croatian-Specific)

### VAT Rates (Croatia)
| Category | Code | Rate | Effective Date | Items |
|----------|------|------|----------------|-------|
| Standard | S | 25% | 2013-present | Most goods/services |
| Lower | AA | 13% | 2013-present | Specific goods (food, utilities) |
| Reduced | A | 5% | 2013-present | Books, newspapers, medicine |
| Zero-rated | Z | 0% | - | Exports, intra-EU supplies |
| Exempt | E | 0% | - | Financial services, education |
| Reverse charge | AE | 0% | - | Construction services, scrap metal |

**See:** `/docs/research/VAT_RULES_HR.md` for item-by-item classification

### Invoice Type Codes (Croatian Usage)
| Code | EN 16931 Name | Croatian Usage |
|------|---------------|----------------|
| 380 | Commercial invoice | ✅ Standard invoice |
| 381 | Credit note | ✅ Storno (corrections/refunds) |
| 384 | Corrected invoice | ✅ Amendments (error corrections) |
| 386 | Prepayment invoice | 🟡 Supported (rarely used) |

---

## B2C vs B2B Differences

### B2C Fiscalization (Cash Register Receipts)
**Process:**
1. Generate invoice with ZKI code
2. Submit to FINA SOAP API in real-time (<3s)
3. Receive JIR confirmation
4. Print/display receipt with JIR + QR code

**Required Croatian Extensions:**
- HR-BT-6 (Business premises)
- HR-BT-7 (Cash register)
- HR-BT-9 (ZKI code)
- HR-BT-8 (JIR - assigned by FINA)

**Digital Signature:** NOT required (ZKI code provides integrity)

### B2B Exchange (Electronic Invoices)
**Process:**
1. Generate UBL 2.1 invoice
2. Add qualified electronic signature (XMLDSig)
3. Add qualified timestamp
4. Submit to AS4 Access Point
5. Receive delivery confirmation (AsyncMDN)

**Required Croatian Extensions:**
- HR-BT-5 (Operator OIB)
- KPD codes on all line items
- Digital signature with FINA certificate
- Qualified timestamp (eIDAS)

**Real-time Fiscalization:** NOT required (monthly e-reporting instead)

---

## AS4 Profile (Four-Corner Model)

**Access Point Registration:**
- Register with AMS (Address Metadata Service)
- Obtain AS4 endpoint certificate
- Configure SMP (Service Metadata Publisher)

**Message Structure:**
```
AS4 Message
  └─ ebMS Header (routing metadata)
      └─ UBL 2.1 Invoice (business payload)
          └─ XMLDSig signature
```

**Croatian Requirements:**
- **Protocol:** AS4 (OASIS ebMS 3.0)
- **Profile:** PEPPOL AS4 v2.0 (adapted for Croatia)
- **Identifiers:** OIB-based addressing (iso6523-actorid-upis::9914:{OIB})

**See:** `/CROATIAN_COMPLIANCE.md` section 3.3 for complete AS4 specification

---

## Testing and Validation

### Pre-Production Checklist
- [ ] Download official CIUS-HR Schematron rules (after Oct 30, 2025)
- [ ] Integrate into `schematron-validator` service
- [ ] Test with OASIS UBL sample invoices
- [ ] Test with Croatian sample invoices (when published)
- [ ] Validate all HR-BR-xxx rules
- [ ] Confirm OIB checksum validation works
- [ ] Confirm KPD code validation against KLASUS registry
- [ ] Test B2C fiscalization in test environment
- [ ] Test B2B AS4 exchange in test environment

### Test Environment
**B2C Fiscalization:** https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest
**B2B AS4:** Test Access Points (to be announced)
**Credentials:** Demo FINA certificates (free, 1-year validity)

---

## Compliance Penalties

**Non-Compliance with CIUS-HR:**
- **Missing KPD codes:** Invoice rejected by Tax Authority
- **Invalid OIB checksum:** Invoice rejected
- **Missing digital signature (B2B):** Invoice not legally valid
- **Incorrect invoice number format:** Fiscalization failure
- **Arithmetic errors:** Invoice rejected

**Financial Penalties:**
- Minor violations: 1,300 - 6,600 EUR
- Repeated violations: 13,300 - 66,360 EUR
- Criminal liability: Intentional tax evasion

**See:** `/CROATIAN_COMPLIANCE.md` section 6 for complete penalty framework

---

## External Resources

- **Porezna uprava:** https://www.porezna-uprava.hr/
- **Fiskalizacija portal:** https://www.fiskalizacija.hr/
- **FINA support:** 01 4404 707
- **Technical contact:** fiskalizacija@porezna-uprava.hr

---

## Related Standards

- **EN 16931-1:2017** - European baseline (See `/docs/standards/EN-16931/`)
- **UBL 2.1** - Syntax implementation (See `/docs/standards/UBL-2.1/`)
- **KLASUS 2025** - Product classification (See `/docs/standards/KLASUS-2025/`)
- **ISO 7064** - OIB checksum algorithm (See `/docs/research/OIB_CHECKSUM.md`)

---

## Version Control

**This directory tracks CIUS-HR specification evolution.**
**This directory contains IMMUTABLE reference materials.**

**Update Policy:**
- ❌ Do NOT rewrite or "clarify" official HR-BT/HR-BR rule text.
- ❌ Do NOT modify official Schematron rules once committed.
- ✅ Add official Schematron files when published (Oct 30, 2025).
- ✅ Document all specification changes with dates.
- ✅ Track regulatory updates in decision log and reference official bulletins in commit messages.

**Version Tracking:**
```bash
# Tag CIUS-HR versions
git add docs/standards/CIUS-HR/schematron/
git commit -m "data(cius-hr): add official Schematron rules (2025-10-30)"
git tag cius-hr-2025-v1.0
```

---

## Usage in Service Specifications

**Services MUST reference this directory, NOT duplicate content.**

### ✅ Correct Reference (in service CLAUDE.md):
```markdown
## Croatian-Specific Validation
**CIUS-HR Rules:** `/docs/standards/CIUS-HR/business-rules/`
**Schematron:** `/docs/standards/CIUS-HR/schematron/CIUS-HR-UBL.sch`
**See:** `/docs/standards/CIUS-HR/README.md` for complete specification
```

### ❌ Wrong (duplication):
```markdown
## Croatian Rules
HR-BR-01: KPD codes are mandatory
HR-BR-02: OIB checksum must be valid
[... 100 lines of rules copied ...]
```

---

**Maintainer:** Compliance Team + Technical Lead
**Last Updated:** 2025-11-09
**Next Review:** **30 October 2025** (Official Schematron publication)
**Critical Action:** Download and integrate official CIUS-HR Schematron rules on Oct 30, 2025
