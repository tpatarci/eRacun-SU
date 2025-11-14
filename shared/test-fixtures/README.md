# @eracun/test-fixtures

Test data generators for eRačun invoice processing platform.

## Purpose

This module provides generators for creating valid and invalid test data, including:
- **UBL Invoices** - Valid and invalid invoice objects
- **XML Documents** - UBL 2.1 compliant XML
- **Edge Cases** - Boundary conditions and error scenarios

## Installation

```bash
npm install @eracun/test-fixtures
```

## Usage

### Invoice Generation

```typescript
import { InvoiceGenerator } from '@eracun/test-fixtures';

// Generate valid invoice
const validInvoice = InvoiceGenerator.generateValidInvoice();

// Generate invoice with invalid OIB
const invalidOIB = InvoiceGenerator.generateInvoiceWithInvalidOIB();

// Generate invoice with missing KPD codes
const missingKPD = InvoiceGenerator.generateInvoiceWithMissingKPD();

// Generate invoice with invalid VAT
const invalidVAT = InvoiceGenerator.generateInvoiceWithInvalidVAT();

// Generate batch of invoices
const batch = InvoiceGenerator.generateBatch(100);

// Generate custom invoice
const custom = InvoiceGenerator.generateCustomInvoice({
  invoiceNumber: 'TEST-001',
  amounts: {
    net: 1000,
    vat: [{ rate: 25, base: 1000, amount: 250, category: 'STANDARD' }],
    gross: 1250,
    currency: 'EUR'
  }
});
```

### XML Generation

```typescript
import { XMLGenerator, InvoiceGenerator } from '@eracun/test-fixtures';

// Generate UBL 2.1 XML
const invoice = InvoiceGenerator.generateValidInvoice();
const xml = XMLGenerator.generateUBL21XML(invoice);

// Generate invalid XML for negative testing
const invalidXML = XMLGenerator.generateInvalidXML();

// Generate malformed XML (for XXE testing)
const malformedXML = XMLGenerator.generateMalformedXML();
```

### OIB Generation

```typescript
import { InvoiceGenerator } from '@eracun/test-fixtures';

// Generate valid Croatian OIB with check digit
const oib = InvoiceGenerator.generateValidOIB();
console.log(oib); // e.g., "12345678901" (with valid check digit)
```

## Test Scenarios

### Valid Scenarios
- ✅ Valid UBL 2.1 invoice with all required fields
- ✅ Valid OIB format with correct check digit
- ✅ Valid KPD codes (6 digits)
- ✅ Correct VAT calculations
- ✅ Multiple line items with different VAT rates

### Invalid Scenarios
- ❌ Invalid OIB check digit
- ❌ Missing KPD codes
- ❌ Invalid KPD code format
- ❌ Incorrect VAT calculations
- ❌ Negative amounts
- ❌ Missing required fields
- ❌ Malformed XML

## Property-Based Testing

Use with `fast-check` for property-based testing:

```typescript
import * as fc from 'fast-check';
import { InvoiceGenerator } from '@eracun/test-fixtures';

it('should always validate valid invoices', () => {
  fc.assert(
    fc.property(fc.constant(null), () => {
      const invoice = InvoiceGenerator.generateValidInvoice();
      const result = validator.validate(invoice);
      return result.valid === true;
    })
  );
});
```

## Development

```bash
# Build
npm run build

# Watch mode
npm run watch

# Type checking
npm run typecheck
```

---

**Version:** 1.0.0
**Maintained by:** Team 1
**Dependencies:** @eracun/contracts, @faker-js/faker
