# Croatian VAT Rules - Tax Calculation and Validation

**Country:** Croatia (Hrvatska)
**Tax System:** Value Added Tax (PDV - Porez na dodanu vrijednost)
**EU Member:** Yes (since 1 July 2013)
**Eurozone Member:** Yes (since 1 January 2023, replaced HRK with EUR)
**Legal Framework:** Zakon o PDV-u (VAT Law) - NN 73/13, amended
**Last Verified:** 2025-11-09

---

## Official Sources

**Primary:** https://www.porezna-uprava.hr/ (Croatian Tax Authority)
**EU VAT:** https://ec.europa.eu/taxation_customs/tedb/
**Legal Text:** https://www.zakon.hr/ (Narodne novine - Official Gazette)

---

## Croatian VAT Rates (2025)

### Standard Rate: 25%

**Code:** `S` (Standard)
**Effective Since:** 1 January 2013
**Applies To:** Most goods and services (default)

**Examples:**
- Electronics, appliances
- Furniture, home goods
- Professional services (legal, accounting, IT)
- Restaurant meals (dine-in)
- Hotel accommodation
- Construction services
- Clothing, footwear
- Cosmetics, personal care

### Lower Rate: 13%

**Code:** `AA` (Lower rate)
**Effective Since:** 1 January 2013
**Applies To:** Specific socially important goods/services

**Examples:**
- Edible oils and fats
- Baby food
- Sugar
- Cocoa, chocolate products
- Flour, bread products
- Salt
- Utilities (electricity, gas, water supply)
- Heating energy
- Firewood
- Restaurant meals (takeaway/delivery)
- Catering services

### Reduced Rate: 5%

**Code:** `A` (Reduced rate)
**Effective Since:** 1 January 2013
**Applies To:** Essential goods, cultural products

**Examples:**
- Books (printed)
- Newspapers, magazines
- Scientific journals
- Educational materials
- Prescription medicines
- Medical devices (specific categories)
- Baby diapers
- Orthopaedic products
- Prosthetics

### Zero-Rated: 0%

**Code:** `Z` (Zero-rated)
**Taxable:** Yes (but at 0% rate)
**VAT Deduction:** Supplier CAN deduct input VAT

**Applies To:**
- Exports outside EU
- Intra-EU supplies (B2B) - if valid VAT ID provided
- International transport services
- Services related to exported goods
- Supplies to ships/aircraft (international traffic)

**Important:** Requires documentation (customs export declaration, CMR, etc.)

### Exempt: 0% (No VAT)

**Code:** `E` (Exempt)
**Taxable:** No
**VAT Deduction:** Supplier CANNOT deduct input VAT
**Exemption Reason Required:** Yes (BT-121)

**Applies To:**
- Financial services (banking, insurance, securities)
- Postal services (Universal Service Obligation)
- Healthcare services (doctors, hospitals)
- Education (schools, universities, vocational training)
- Cultural services (museums, libraries, concerts - specific conditions)
- Real estate rentals (residential)
- Gambling, lotteries
- Sports activities (non-profit)

**Exemption Reason Codes (BT-121):**
- `VATEX-EU-79-C` - Financial services
- `VATEX-EU-132-1A` - Education services
- `VATEX-EU-135-1A` - Healthcare services
- `VATEX-EU-148` - Supply of goods after import

### Reverse Charge: 0% (Buyer Pays VAT)

**Code:** `AE` (Reverse charge)
**Mechanism:** Supplier invoices without VAT, buyer self-assesses
**Applies To:** Specific B2B transactions

**Croatian Reverse Charge Categories:**
- Construction services (if buyer is VAT-registered construction company)
- Scrap metal, waste materials
- Mobile phones, integrated circuits (anti-fraud measure)
- Emission allowances
- Intra-EU acquisitions
- Services from non-EU suppliers (B2B)

**Invoice Requirements:**
- Mention "Reverse charge" on invoice
- Specify exemption reason: `VATEX-EU-AE` or specific Croatian code
- Buyer's VAT number (OIB) required

---

## VAT Calculation Rules

### Basic Formula

```
Line Net Amount = Quantity × Unit Price
Line VAT Amount = Line Net Amount × VAT Rate
Line Gross Amount = Line Net Amount + Line VAT Amount

Invoice Subtotal = Σ(Line Net Amount) for all lines
Invoice VAT Total = Σ(Line VAT Amount) for all lines
Invoice Total = Invoice Subtotal + Invoice VAT Total - Prepaid Amount + Rounding
```

### EN 16931 Business Rules

**BR-CO-10:** Sum of Invoice line net amount = Σ Invoice line net amount (BT-131)

**BR-CO-12:** Invoice total VAT amount = Σ VAT category tax amount (BT-117)

**BR-CO-13:** Invoice total amount with VAT = Invoice total amount without VAT + Invoice total VAT amount

**BR-CO-15:** Invoice total amount due for payment = Invoice total amount with VAT - Paid amount + Rounding amount

### Rounding Rules

**Line-Level Rounding:** Round to **2 decimal places** (EUR cents)

**Invoice-Level Rounding:** Allowed difference ±0.01 EUR (due to cumulative rounding)

**Example:**
```
Line 1: 10.00 × 1.25 = 12.50
Line 2: 10.01 × 1.25 = 12.5125 → rounds to 12.51
Line 3: 10.02 × 1.25 = 12.525 → rounds to 12.53

Total: 12.50 + 12.51 + 12.53 = 37.54
Alternative: (10.00 + 10.01 + 10.02) × 1.25 = 30.03 × 1.25 = 37.5375 → rounds to 37.54

✅ Both methods yield same result (acceptable)
```

**Tolerance:** If difference > 0.01 EUR, recalculate or add explicit rounding line item (BT-114)

---

## UBL Encoding

### Invoice Line VAT

```xml
<cac:InvoiceLine>
  <cbc:ID>1</cbc:ID>
  <cbc:InvoicedQuantity unitCode="C62">10</cbc:InvoicedQuantity>
  <cbc:LineExtensionAmount currencyID="EUR">100.00</cbc:LineExtensionAmount>
  <cac:Item>
    <cbc:Name>Product Name</cbc:Name>
    <cac:ClassifiedTaxCategory>
      <cbc:ID>S</cbc:ID> <!-- Standard rate -->
      <cbc:Percent>25</cbc:Percent>
      <cac:TaxScheme>
        <cbc:ID>VAT</cbc:ID>
      </cac:TaxScheme>
    </cac:ClassifiedTaxCategory>
  </cac:Item>
  <cac:Price>
    <cbc:PriceAmount currencyID="EUR">10.00</cbc:PriceAmount>
  </cac:Price>
</cac:InvoiceLine>
```

### Invoice-Level VAT Breakdown

```xml
<cac:TaxTotal>
  <cbc:TaxAmount currencyID="EUR">25.00</cbc:TaxAmount>

  <!-- Standard rate (25%) -->
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

  <!-- Add more TaxSubtotal elements for each VAT category present -->
</cac:TaxTotal>
```

### Exempt VAT with Reason

```xml
<cac:ClassifiedTaxCategory>
  <cbc:ID>E</cbc:ID>
  <cbc:Percent>0</cbc:Percent>
  <cbc:TaxExemptionReasonCode>VATEX-EU-132-1A</cbc:TaxExemptionReasonCode>
  <cbc:TaxExemptionReason>Education services</cbc:TaxExemptionReason>
  <cac:TaxScheme>
    <cbc:ID>VAT</cbc:ID>
  </cac:TaxScheme>
</cac:ClassifiedTaxCategory>
```

---

## Validation Rules

### VAT Category Validation

**Rule:** VAT category code MUST be from allowed list

**Allowed Codes:**
- `S` - Standard rate (25%)
- `AA` - Lower rate (13%)
- `A` - Reduced rate (5%)
- `Z` - Zero-rated
- `E` - Exempt
- `AE` - Reverse charge

**Error:** `VAT_INVALID_CATEGORY` if code not in list

### VAT Rate Validation

**Rule:** VAT rate MUST match category

| Category | Expected Rate | Tolerance |
|----------|---------------|-----------|
| S | 25.00% | Exact match |
| AA | 13.00% | Exact match |
| A | 5.00% | Exact match |
| Z | 0.00% | Exact match |
| E | 0.00% | Exact match |
| AE | 0.00% | Exact match |

**Error:** `VAT_RATE_MISMATCH` if rate doesn't match category

**Example Violations:**
```xml
<!-- WRONG: Standard rate with incorrect percentage -->
<cbc:ID>S</cbc:ID>
<cbc:Percent>20</cbc:Percent> <!-- Should be 25 -->

<!-- WRONG: Reduced rate with wrong code -->
<cbc:ID>AA</cbc:ID> <!-- Should be A -->
<cbc:Percent>5</cbc:Percent>
```

### Arithmetic Validation

**Rule:** VAT amount MUST equal taxable amount × rate (within rounding tolerance)

```
Calculated VAT = ROUND(Taxable Amount × Rate, 2)
Tolerance = ±0.01 EUR
```

**Error:** `VAT_AMOUNT_MISMATCH` if outside tolerance

**Example:**
```
Taxable: 100.00 EUR
Rate: 25%
Expected VAT: 100.00 × 0.25 = 25.00 EUR

✅ Acceptable: 25.00 EUR
✅ Acceptable: 24.99 EUR (within tolerance)
✅ Acceptable: 25.01 EUR (within tolerance)
❌ Invalid: 25.05 EUR (outside tolerance)
```

### Exemption Reason Validation

**Rule:** If category = `E` (Exempt), exemption reason MUST be provided

**Required Fields:**
- `cbc:TaxExemptionReasonCode` (BT-121) - Optional but recommended
- `cbc:TaxExemptionReason` (BT-120) - Mandatory if code omitted

**Error:** `VAT_EXEMPTION_REASON_MISSING`

### Multiple VAT Categories

**Rule:** Invoice CAN have multiple VAT categories

**Requirements:**
- Each line item has exactly ONE VAT category
- Invoice-level `<cac:TaxTotal>` has ONE `<cac:TaxSubtotal>` per category
- Sum of TaxSubtotal amounts = Total TaxAmount

**Example:**
```
Line 1: Standard (25%) - 100 EUR → VAT 25 EUR
Line 2: Reduced (5%) - 50 EUR → VAT 2.50 EUR
Line 3: Standard (25%) - 200 EUR → VAT 50 EUR

Invoice TaxTotal:
  TaxSubtotal (S, 25%): Taxable 300 EUR, VAT 75 EUR
  TaxSubtotal (A, 5%): Taxable 50 EUR, VAT 2.50 EUR
  Total VAT: 77.50 EUR
```

---

## Special Cases

### Intra-EU Supply (B2B)

**Scenario:** Croatian company sells to German VAT-registered company

**VAT Treatment:**
- **Supplier (Croatian):** Zero-rated (0%)
- **Buyer (German):** Reverse charge (self-assess German VAT)

**Invoice Requirements:**
- VAT category: `Z` (Zero-rated)
- Buyer VAT ID: Must be valid EU VAT number (e.g., DE123456789)
- Invoice note: "Intra-Community supply - Article 42 VAT Directive"

**UBL Example:**
```xml
<cac:ClassifiedTaxCategory>
  <cbc:ID>Z</cbc:ID>
  <cbc:Percent>0</cbc:Percent>
  <cbc:TaxExemptionReasonCode>VATEX-EU-IC</cbc:TaxExemptionReasonCode>
  <cbc:TaxExemptionReason>Intra-Community supply</cbc:TaxExemptionReason>
  <cac:TaxScheme>
    <cbc:ID>VAT</cbc:ID>
  </cac:TaxScheme>
</cac:ClassifiedTaxCategory>
```

### Export (Non-EU)

**Scenario:** Croatian company sells to US company

**VAT Treatment:** Zero-rated (0%)

**Requirements:**
- VAT category: `Z`
- Customs export declaration (required)
- Proof of export (CMR, bill of lading)

### Reverse Charge (Construction)

**Scenario:** Subcontractor invoices construction company for building work

**VAT Treatment:**
- **Supplier:** Invoice without VAT (0%)
- **Buyer:** Self-assess VAT and claim deduction (net effect: 0 if fully deductible)

**Invoice Requirements:**
- VAT category: `AE`
- Invoice note: "Reverse charge - Construction services"
- Buyer OIB: Required

**UBL Example:**
```xml
<cac:ClassifiedTaxCategory>
  <cbc:ID>AE</cbc:ID>
  <cbc:Percent>0</cbc:Percent>
  <cbc:TaxExemptionReasonCode>VATEX-EU-AE</cbc:TaxExemptionReasonCode>
  <cbc:TaxExemptionReason>Reverse charge - Construction services</cbc:TaxExemptionReason>
  <cac:TaxScheme>
    <cbc:ID>VAT</cbc:ID>
  </cac:TaxScheme>
</cac:ClassifiedTaxCategory>
```

---

## Historical VAT Rates (Reference)

**Croatia joined EU VAT system:** 1 July 2013

| Period | Standard | Lower | Reduced |
|--------|----------|-------|---------|
| 2013-01-01 to present | 25% | 13% | 5% |
| 2012-03-01 to 2012-12-31 | 25% | 10% | - |
| 2009-08-01 to 2012-02-29 | 23% | 10% | - |

**Note:** For invoices dated before 2013, different rates applied. This platform assumes **2026+ invoices only** (all post-EU-accession).

---

## Product/Service Classification Examples

### Standard Rate (25%) - Common Items

**IT Services:**
- Software development
- IT consulting
- Website hosting
- SaaS subscriptions

**Professional Services:**
- Legal services
- Accounting services
- Marketing, advertising
- Engineering services

**Goods:**
- Electronics (laptops, phones)
- Furniture
- Clothing
- Appliances

### Lower Rate (13%) - Common Items

**Food & Beverages:**
- Cooking oils
- Sugar, flour
- Chocolate

**Services:**
- Restaurant takeaway
- Catering

**Utilities:**
- Electricity bills
- Natural gas
- District heating

### Reduced Rate (5%) - Common Items

**Publications:**
- Books (printed)
- Newspapers
- Magazines

**Healthcare:**
- Prescription medicines
- Medical devices
- Baby diapers

---

## Integration in Services

### `business-rules-engine` Service

**Responsibilities:**
- Validate VAT category codes
- Verify rate matches category
- Check arithmetic consistency
- Validate exemption reasons

**Error Codes:**
```typescript
enum VATValidationError {
  VAT_INVALID_CATEGORY = 'VAT_INVALID_CATEGORY',
  VAT_RATE_MISMATCH = 'VAT_RATE_MISMATCH',
  VAT_AMOUNT_MISMATCH = 'VAT_AMOUNT_MISMATCH',
  VAT_EXEMPTION_REASON_MISSING = 'VAT_EXEMPTION_REASON_MISSING',
  VAT_SUBTOTAL_MISMATCH = 'VAT_SUBTOTAL_MISMATCH',
}
```

**Service Spec:** `/services/validation/business-rules-engine/CLAUDE.md`

### `ubl-generator` Service

**Responsibilities:**
- Map product catalog VAT category to UBL codes
- Calculate VAT amounts
- Generate `<cac:TaxTotal>` structure
- Aggregate VAT by category

**Input:** Product catalog with VAT classification
**Output:** UBL-compliant invoice with VAT breakdown

**Service Spec:** `/services/transformation/ubl-generator/CLAUDE.md`

---

## Testing Data

### Sample Invoice with Multiple VAT Rates

```
Line 1: IT Consulting - 1000 EUR (Standard 25%) → VAT 250 EUR
Line 2: Electricity - 200 EUR (Lower 13%) → VAT 26 EUR
Line 3: Books - 100 EUR (Reduced 5%) → VAT 5 EUR

Subtotals:
  Standard (25%): Taxable 1000 EUR, VAT 250 EUR
  Lower (13%): Taxable 200 EUR, VAT 26 EUR
  Reduced (5%): Taxable 100 EUR, VAT 5 EUR

Invoice Total:
  Net: 1300 EUR
  VAT: 281 EUR
  Gross: 1581 EUR
```

---

## External Resources

- **Porezna uprava (Tax Authority):** https://www.porezna-uprava.hr/
- **VAT Law (Croatian):** https://www.zakon.hr/ (search "Zakon o PDV-u")
- **EU VAT Rates:** https://ec.europa.eu/taxation_customs/tedb/
- **VIES (VAT validation):** https://ec.europa.eu/taxation_customs/vies/

---

## Related Documentation

- **CIUS-HR VAT Rules:** `/docs/standards/CIUS-HR/README.md` (HR-BR-07)
- **EN 16931 Business Rules:** `/docs/standards/EN-16931/README.md` (BR-S/Z/E/AE-08)
- **UBL VAT Encoding:** `/docs/standards/UBL-2.1/README.md` (TaxCategory examples)

---

**Maintainer:** Compliance Team + Tax Specialist
**Last Updated:** 2025-11-09
**Next Review:** Annually (January) - Monitor for VAT rate changes
