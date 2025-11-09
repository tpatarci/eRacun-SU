# UBL 2.1 Standard - Universal Business Language

**Version:** 2.1
**Published:** December 2013
**Authority:** OASIS (Organization for the Advancement of Structured Information Standards)
**Status:** ✅ ACTIVE - Required for Croatian e-invoicing
**Last Verified:** 2025-11-09

---

## Official Source

**Primary:** https://docs.oasis-open.org/ubl/UBL-2.1.html
**Download:** https://docs.oasis-open.org/ubl/os-UBL-2.1/
**GitHub Mirror:** https://github.com/oasis-tcs/ubl

---

## What is UBL 2.1?

Universal Business Language (UBL) is an XML-based standard for electronic business documents. UBL 2.1 is the version **mandated by Croatian CIUS** for e-invoice fiscalization.

**Croatian Requirement:** See `/CROATIAN_COMPLIANCE.md` section 2.1

---

## Directory Contents

```
UBL-2.1/
├── README.md              # This file
├── xsd/                   # XSD Schema files (XML validation)
│   ├── UBL-Invoice-2.1.xsd           # Main invoice schema
│   ├── UBL-CreditNote-2.1.xsd        # Credit note schema
│   ├── common/                        # Common components
│   └── ...
├── examples/              # Sample UBL documents
│   ├── valid_minimal.xml              # Minimal valid invoice
│   ├── valid_full.xml                 # All optional fields
│   └── croatian_sample.xml            # Croatian CIUS example
└── docs/                  # UBL specification PDFs
    ├── UBL-2.1-Specification.pdf
    └── UBL-2.1-Field-Catalog.pdf
```

---

## XSD Schemas

**⚠️ CRITICAL:** These schemas are the **SINGLE SOURCE OF TRUTH** for XML validation.

### Required Schemas for Croatian e-invoicing:

| File | Purpose | Services Using This |
|------|---------|---------------------|
| `UBL-Invoice-2.1.xsd` | Main invoice structure | xsd-validator, ubl-generator |
| `UBL-CreditNote-2.1.xsd` | Credit notes (storno) | xsd-validator, ubl-generator |
| `common/UBL-CommonAggregateComponents-2.1.xsd` | Shared components | All validators |
| `common/UBL-CommonBasicComponents-2.1.xsd` | Basic elements | All validators |

### How to Obtain Schemas:

```bash
# Download official OASIS UBL 2.1 package
wget https://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.zip

# Extract XSD files
unzip UBL-2.1.zip -d UBL-2.1-package
cp -r UBL-2.1-package/xsd/* docs/standards/UBL-2.1/xsd/

# Verify integrity (SHA256)
sha256sum UBL-2.1.zip
# Expected: [TO BE FILLED AFTER DOWNLOAD]
```

### Schema Verification:

```bash
# Verify schema files are valid XML
xmllint --noout docs/standards/UBL-2.1/xsd/UBL-Invoice-2.1.xsd

# Expected: No output (success)
```

---

## Mandatory Fields (Croatian CIUS)

**See:** `/CROATIAN_COMPLIANCE.md` section 2.2 for complete list

**Key Croatian Requirements:**
- **BT-1:** Invoice number (format: `{broj}-{poslovni_prostor}-{naplatni_uredjaj}`)
- **BT-2:** Issue date (ISO 8601: `YYYY-MM-DD`)
- **BT-31:** Seller OIB (11 digits)
- **HR-BT-5:** Operator OIB (mandatory from 1 Sept 2025)
- **BT-48:** Buyer OIB
- **KPD:** 6-digit KLASUS 2025 codes on EVERY line item

---

## Example Documents

### Minimal Valid Invoice

**File:** `examples/valid_minimal.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius:2025</cbc:CustomizationID>
  <cbc:ID>1-ZAGREB1-POS1</cbc:ID>
  <cbc:IssueDate>2026-01-15</cbc:IssueDate>
  <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>

  <!-- Seller (Issuer) -->
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">12345678901</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>Tvrtka d.o.o.</cbc:Name>
      </cac:PartyName>
    </cac:Party>
  </cac:AccountingSupplierParty>

  <!-- Buyer -->
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">98765432109</cbc:ID>
      </cac:PartyIdentification>
    </cac:Party>
  </cac:AccountingCustomerParty>

  <!-- Line Item -->
  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID>
    <cbc:InvoicedQuantity unitCode="C62">1</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="EUR">100.00</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Description>Usluga</cbc:Description>
      <cac:ClassifiedTaxCategory>
        <cbc:ID>S</cbc:ID>
        <cbc:Percent>25</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:ClassifiedTaxCategory>
      <!-- KPD Code (Croatian requirement) -->
      <cac:StandardItemIdentification>
        <cbc:ID schemeID="HR:KPD">620100</cbc:ID>
      </cac:StandardItemIdentification>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="EUR">100.00</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>

  <!-- Monetary Totals -->
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="EUR">100.00</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="EUR">100.00</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="EUR">125.00</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="EUR">125.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>

  <!-- VAT Breakdown -->
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="EUR">25.00</cbc:TaxAmount>
    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="EUR">100.00</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="EUR">25.00</cbc:TaxAmount>
      <cac:TaxCategory>
        <cbc:ID>S</cbc:ID>
        <cbc:Percent>25</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:TaxCategory>
    </cac:TaxSubtotal>
  </cac:TaxTotal>
</Invoice>
```

---

## XPath Reference (Common Fields)

| Field | XPath | Mandatory | Type |
|-------|-------|-----------|------|
| Invoice ID | `/Invoice/cbc:ID` | YES | String |
| Issue Date | `/Invoice/cbc:IssueDate` | YES | Date (YYYY-MM-DD) |
| Seller OIB | `/Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyIdentification/cbc:ID[@schemeID='HR:OIB']` | YES | String (11 digits) |
| Buyer OIB | `/Invoice/cac:AccountingCustomerParty/cac:Party/cac:PartyIdentification/cbc:ID[@schemeID='HR:OIB']` | YES | String (11 digits) |
| Line KPD Code | `/Invoice/cac:InvoiceLine/cac:Item/cac:StandardItemIdentification/cbc:ID[@schemeID='HR:KPD']` | YES | String (6+ digits) |
| VAT Category | `/Invoice/cac:InvoiceLine/cac:Item/cac:ClassifiedTaxCategory/cbc:ID` | YES | Code (S,AA,A,Z,E,AE) |
| VAT Rate | `/Invoice/cac:InvoiceLine/cac:Item/cac:ClassifiedTaxCategory/cbc:Percent` | YES | Decimal |

---

## Changes from UBL 2.0

**Not applicable** - UBL 2.1 is the baseline for Croatian e-invoicing. UBL 2.0 is **NOT accepted**.

---

## Validation Rules

**XSD validation is ONLY syntactic.** It does NOT enforce:
- Business rules (e.g., VAT calculation correctness)
- Croatian CIUS rules (e.g., OIB checksum)
- KPD code validity

**For complete validation, see:**
- `/docs/standards/CIUS-HR/` - Schematron business rules
- `/docs/standards/KLASUS-2025/` - KPD code validation
- `/docs/research/OIB_CHECKSUM.md` - OIB validation algorithm

---

## Related Standards

- **EN 16931-1:2017** - European semantic model (See `/docs/standards/EN-16931/`)
- **Croatian CIUS** - Croatian extensions (See `/docs/standards/CIUS-HR/`)
- **PEPPOL BIS** - Pan-European specification (Reference only, NOT required for Croatia)

---

## Version Control

**This directory contains IMMUTABLE reference materials.**

**Update Policy:**
- ❌ Do NOT modify XSD files
- ❌ Do NOT "fix" or "improve" schemas
- ✅ If OASIS publishes UBL 2.2 in future, create separate `/docs/standards/UBL-2.2/` directory
- ✅ Document version in git commit messages

**Verification:**
```bash
# Check if files match official OASIS distribution
sha256sum -c UBL-2.1-checksums.txt
```

---

## Usage in Service Specifications

**Services MUST reference this directory, NOT duplicate content.**

### ✅ Correct Reference (in service CLAUDE.md):
```markdown
## Validation Against
**XSD Schema:** `/docs/standards/UBL-2.1/xsd/UBL-Invoice-2.1.xsd`
**Version:** UBL 2.1 (see `/docs/standards/UBL-2.1/README.md`)
```

### ❌ Wrong (duplication):
```markdown
## UBL 2.1 Structure
UBL 2.1 has the following elements:
- Invoice ID (cbc:ID)
- Issue Date (cbc:IssueDate)
[... 500 lines of UBL spec copied ...]
```

---

## External Resources

- **OASIS UBL TC:** https://www.oasis-open.org/committees/ubl/
- **UBL 2.1 Specification (PDF):** https://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.pdf
- **Field Catalog:** https://docs.oasis-open.org/ubl/os-UBL-2.1/cl/UBL-DefaultDTQ-2.1.html

---

**Maintainer:** Technical Lead
**Last Updated:** 2025-11-09
**Next Review:** Upon OASIS UBL update (monitor https://www.oasis-open.org/committees/ubl/)
