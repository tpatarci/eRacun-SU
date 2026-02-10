# EN 16931-1:2017 - European E-Invoicing Semantic Model

**Full Name:** Electronic invoicing - Part 1: Semantic data model of the core elements of an electronic invoice
**Version:** EN 16931-1:2017
**Published:** June 2017
**Authority:** CEN (European Committee for Standardization)
**Status:** ✅ ACTIVE - Required for Croatian e-invoicing
**Last Verified:** 2025-11-09

---

## Official Source

**Primary:** https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Compliance+with+eInvoicing+standard
**CEN Purchase:** https://www.cen.eu/ (Official standard purchase)
**EU Directive:** 2014/55/EU (Legal basis)

**Croatian Requirement:** See `/CROATIAN_COMPLIANCE.md` section 2.1

---

## What is EN 16931?

EN 16931-1:2017 defines the **semantic data model** for electronic invoices across the EU. It specifies:
- **Mandatory business terms** (BT-xxx codes)
- **Optional business terms**
- **Business rules** (BR-xxx codes)
- **Information requirements** for cross-border invoicing

This is the **foundation** for Croatian CIUS. Croatian e-invoicing MUST comply with EN 16931 + Croatian extensions.

---

## Directory Contents

```
EN-16931/
├── README.md              # This file
├── business-terms.md      # BT-xxx field catalog (to be created)
├── business-rules.md      # BR-xxx validation rules (to be created)
└── examples/              # Compliant invoice examples
    ├── minimal_b2b.xml    # Minimum required fields
    └── full_fields.xml    # All optional fields included
```

---

## Relationship to UBL 2.1

**EN 16931 is syntax-agnostic.** It defines WHAT data is required, not HOW to encode it.

**UBL 2.1 is one implementation syntax** for EN 16931 semantic model.

```
EN 16931 Semantic Model (WHAT)
    ↓ mapped to
UBL 2.1 XML Syntax (HOW)
    ↓ extended by
Croatian CIUS (Croatian-specific rules)
```

**Mapping Example:**
- **EN 16931 BT-1** (Invoice number) → UBL `/Invoice/cbc:ID`
- **EN 16931 BT-31** (Seller VAT identifier) → UBL `/Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID[@schemeID='VAT']`
- **Croatian HR-BT-5** (Operator OIB) → UBL extension (not in base EN 16931)

---

## Mandatory Business Terms (BT-xxx)

**Note:** Complete catalog in `business-terms.md`. Key terms below.

### Core Invoice Information
| BT Code | Field Name | UBL XPath | Croatian Mandatory |
|---------|------------|-----------|-------------------|
| BT-1 | Invoice number | `/Invoice/cbc:ID` | ✅ YES |
| BT-2 | Issue date | `/Invoice/cbc:IssueDate` | ✅ YES |
| BT-3 | Invoice type code | `/Invoice/cbc:InvoiceTypeCode` | ✅ YES (380, 381, 384) |
| BT-5 | Document currency code | `/Invoice/cbc:DocumentCurrencyCode` | ✅ YES (EUR) |

### Seller Information
| BT Code | Field Name | UBL XPath | Croatian Mandatory |
|---------|------------|-----------|-------------------|
| BT-27 | Seller name | `/Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName` | ✅ YES |
| BT-31 | Seller VAT identifier | `/Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID` | ✅ YES (OIB) |
| BT-34 | Seller electronic address | `/Invoice/cac:AccountingSupplierParty/cac:Party/cbc:EndpointID` | ✅ YES |
| BT-35 | Seller address line 1 | `/Invoice/cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cbc:StreetName` | ✅ YES |

### Buyer Information
| BT Code | Field Name | UBL XPath | Croatian Mandatory |
|---------|------------|-----------|-------------------|
| BT-44 | Buyer name | `/Invoice/cac:AccountingCustomerParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName` | ✅ YES |
| BT-48 | Buyer VAT identifier | `/Invoice/cac:AccountingCustomerParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID` | ✅ YES (OIB) |
| BT-49 | Buyer electronic address | `/Invoice/cac:AccountingCustomerParty/cac:Party/cbc:EndpointID` | ✅ YES |

### Line Items
| BT Code | Field Name | UBL XPath | Croatian Mandatory |
|---------|------------|-----------|-------------------|
| BT-126 | Line identifier | `/Invoice/cac:InvoiceLine/cbc:ID` | ✅ YES |
| BT-129 | Invoiced quantity | `/Invoice/cac:InvoiceLine/cbc:InvoicedQuantity` | ✅ YES |
| BT-131 | Line net amount | `/Invoice/cac:InvoiceLine/cbc:LineExtensionAmount` | ✅ YES |
| BT-153 | Item name | `/Invoice/cac:InvoiceLine/cac:Item/cbc:Name` | ✅ YES |
| BT-157 | Item standard identifier | `/Invoice/cac:InvoiceLine/cac:Item/cac:StandardItemIdentification/cbc:ID` | ✅ YES (KPD code) |

### Monetary Totals
| BT Code | Field Name | UBL XPath | Croatian Mandatory |
|---------|------------|-----------|-------------------|
| BT-106 | Sum of line amounts | `/Invoice/cac:LegalMonetaryTotal/cbc:LineExtensionAmount` | ✅ YES |
| BT-109 | Tax exclusive amount | `/Invoice/cac:LegalMonetaryTotal/cbc:TaxExclusiveAmount` | ✅ YES |
| BT-110 | VAT total | `/Invoice/cac:TaxTotal/cbc:TaxAmount` | ✅ YES |
| BT-112 | Tax inclusive amount | `/Invoice/cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount` | ✅ YES |
| BT-115 | Payable amount | `/Invoice/cac:LegalMonetaryTotal/cbc:PayableAmount` | ✅ YES |

---

## Business Rules (BR-xxx)

**Note:** Complete validation rules in `business-rules.md`. Critical rules below.

### Calculation Rules
- **BR-CO-10:** Sum of line amounts = Σ(BT-131) across all invoice lines
- **BR-CO-12:** Tax exclusive amount = Sum of line amounts - Sum of allowances + Sum of charges
- **BR-CO-13:** Tax inclusive amount = Tax exclusive amount + VAT total
- **BR-CO-15:** Payable amount = Tax inclusive amount - Prepaid amount + Rounding amount

### VAT Rules
- **BR-S-08:** For standard VAT (S), rate MUST be specified
- **BR-Z-08:** For zero-rated VAT (Z), rate MUST be 0%
- **BR-E-08:** For exempt VAT (E), exemption reason MUST be provided
- **BR-AE-08:** For reverse charge (AE), exemption reason MUST be provided

### Document-Level Rules
- **BR-01:** Invoice MUST contain BT-1 (Invoice number)
- **BR-02:** Invoice MUST contain BT-2 (Issue date)
- **BR-04:** Invoice MUST contain BT-5 (Currency code)
- **BR-CO-04:** Invoice MUST contain at least one invoice line (cac:InvoiceLine)

### Croatian-Specific Extensions
- **HR-BR-01:** Every line item MUST have KPD code (BT-157 with schemeID="HR:KPD")
- **HR-BR-02:** Seller OIB MUST pass ISO 7064 checksum validation
- **HR-BR-03:** Buyer OIB MUST pass ISO 7064 checksum validation
- **HR-BR-04:** Operator OIB MUST be present (HR-BT-5) from 1 Sept 2025
- **HR-BR-05:** Invoice number format: {broj}-{poslovni_prostor}-{naplatni_uredjaj}

---

## Compliance Validation Layers

Croatian e-invoicing requires **multi-layer validation**:

```
Layer 1: XSD Schema Validation
  ↓ (Syntax correctness)
Layer 2: EN 16931 Business Rules
  ↓ (Semantic correctness)
Layer 3: Croatian CIUS Rules
  ↓ (National requirements)
Layer 4: KPD Code Validation
  ↓ (Product classification)
Layer 5: OIB Checksum Validation
  ↓ (Tax identifier integrity)
```

**Services implementing validation:**
- `xsd-validator` → Layer 1
- `schematron-validator` → Layers 2+3
- `kpd-validator` → Layer 4
- `business-rules-engine` → Layer 5 + arithmetic checks

---

## Code Lists and Allowed Values

### BT-3: Invoice Type Codes
| Code | Description | Croatian Usage |
|------|-------------|----------------|
| 380 | Commercial invoice | ✅ Standard B2B/B2C |
| 381 | Credit note | ✅ Storno (corrections) |
| 384 | Corrected invoice | ✅ Amendments |
| 386 | Prepayment invoice | ❌ Not supported in Phase 1 |

### BT-5: Currency Codes (ISO 4217)
| Code | Description | Croatian Usage |
|------|-------------|----------------|
| EUR | Euro | ✅ MANDATORY (Croatia eurozone since 2023) |
| HRK | Croatian Kuna | ❌ DEPRECATED (phased out 2023) |

### BT-151: Tax Category Codes
| Code | Description | Rate (Croatia) |
|------|-------------|----------------|
| S | Standard rate | 25% |
| AA | Lower rate | 13% |
| A | Reduced rate | 5% |
| Z | Zero rate | 0% |
| E | Exempt | 0% (with reason) |
| AE | Reverse charge | 0% (buyer pays) |

**See:** `/docs/research/VAT_RULES_HR.md` for complete Croatian VAT logic

---

## Croatian Extensions (Not in Base EN 16931)

**Croatian CIUS adds these mandatory fields:**

| HR Code | Field Name | Purpose | Format |
|---------|------------|---------|--------|
| HR-BT-5 | Operator OIB | Cashier/operator identification | 11 digits (OIB) |
| HR-BT-6 | Business premises code | Physical location | Alphanumeric |
| HR-BT-7 | Cash register code | Device identifier | Alphanumeric |
| HR-BT-8 | JIR (Unique ID) | Tax authority receipt code | UUID (from FINA) |
| HR-BT-9 | ZKI (Security code) | MD5 hash signature | 32 hex chars |

**Effective Dates:**
- HR-BT-5 (Operator OIB): Mandatory from **1 September 2025**
- HR-BT-6, HR-BT-7: Mandatory for B2C fiscalization (already active)
- HR-BT-8, HR-BT-9: Assigned by FINA during B2C fiscalization

---

## Schematron Validation Rules

**EN 16931 business rules are enforced via ISO Schematron files.**

**Official Schematron:**
- **Source:** https://github.com/ConnectingEurope/eInvoicing-EN16931
- **Files:** `EN16931-UBL-validation.sch` (UBL syntax binding)
- **Croatian CIUS Extension:** To be published by Porezna uprava (Oct 30, 2025)

**Service Integration:**
- `schematron-validator` service loads official .sch files
- Validates against EN 16931 rules + Croatian CIUS rules
- Returns structured error codes (BR-xxx violations)

**See:** `/docs/standards/CIUS-HR/README.md` for Croatian Schematron rules

---

## Cardinality Rules

**Notation:** `[min..max]` where `*` = unbounded

| Element | Cardinality | Meaning |
|---------|-------------|---------|
| BT-1 (Invoice number) | [1..1] | Exactly one, mandatory |
| BT-10 (Buyer reference) | [0..1] | Optional, max one |
| BT-126 (Line ID) | [1..1] | Mandatory per line |
| cac:InvoiceLine | [1..*] | At least one line required |
| cac:AllowanceCharge | [0..*] | Optional, unbounded |

---

## External Resources

- **EU eInvoicing Portal:** https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eInvoicing
- **EN 16931 GitHub:** https://github.com/ConnectingEurope/eInvoicing-EN16931
- **CEN Official Standard:** https://www.cen.eu/work-areas/cen-sectors/eInvoicing (Purchase required)
- **Directive 2014/55/EU:** https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32014L0055

---

## Related Standards

- **UBL 2.1** - Syntax implementation (See `/docs/standards/UBL-2.1/`)
- **Croatian CIUS** - National extensions (See `/docs/standards/CIUS-HR/`)
- **UN/CEFACT CII** - Alternative syntax (NOT used in Croatian implementation)
- **PEPPOL BIS Billing 3.0** - Pan-European profile (Reference only, NOT mandatory for Croatia)

---

## Version Control

**This directory contains IMMUTABLE reference materials.**

**Update Policy:**
- ❌ Do NOT modify official business rules
- ❌ Do NOT interpret or "simplify" EN 16931 spec
- ✅ If CEN publishes updates, create dated subdirectory
- ✅ Document version in git commit messages

---

## Usage in Service Specifications

**Services MUST reference this directory, NOT duplicate content.**

### ✅ Correct Reference (in service CLAUDE.md):
```markdown
## Validation Against
**EN 16931 Business Rules:** `/docs/standards/EN-16931/business-rules.md`
**Authority:** CEN (European Committee for Standardization)
**See:** `/docs/standards/EN-16931/README.md` for complete semantic model
```

### ❌ Wrong (duplication):
```markdown
## EN 16931 Business Rules
Here is a list of all business rules:
BR-CO-10: Sum of line amounts = Σ(BT-131)
BR-CO-12: Tax exclusive amount = ...
[... 200 lines of rules copied ...]
```

---

**Maintainer:** Compliance Team + Technical Lead
**Last Updated:** 2025-11-09
**Next Review:** Upon CEN updates (monitor https://www.cen.eu/)
