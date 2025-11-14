# ubl-transformer

**Convert various invoice formats to UBL 2.1 standard with Croatian CIUS extensions.**

## Purpose

The UBL Transformer service converts invoices from various formats (PDF, XML, JSON, EDI) into standardized UBL 2.1 XML with Croatian CIUS (Core Invoice Usage Specification) extensions required for FINA compliance.

## Features

- ✅ **Format Detection** - Automatic detection of PDF, XML, JSON, EDI formats
- ✅ **UBL 2.1 Transformation** - Converts all formats to UBL 2.1 XML
- ✅ **Croatian CIUS Extensions** - Adds mandatory Croatian extensions
- ✅ **Validation** - Post-transformation validation
- ✅ **Performance Optimized** - Handles large files efficiently

## Supported Formats

| Format | Status | Notes |
|--------|--------|-------|
| **UBL 2.1 XML** | ✅ Fully supported | Validates and adds CIUS if needed |
| **JSON** | ✅ Fully supported | Transforms to UBL 2.1 XML |
| **PDF** | ⚠️ Requires OCR | Depends on Team 2's OCR service |
| **EDI** | ⚠️ Planned | EDIFACT/X12 support coming soon |

## Croatian CIUS Extensions

The transformer automatically adds required Croatian extensions:

```xml
<cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
<cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>
```

## Usage

```typescript
import { UBLTransformer } from './transformers/ubl-transformer';

const transformer = container.get<UBLTransformer>(UBLTransformer);

// Transform JSON invoice
const jsonInvoice = JSON.stringify(invoiceObject);
const result = await transformer.transform(jsonInvoice);

if (result.success) {
  console.log('UBL 2.1 XML:', result.xml);
  console.log('Processing time:', result.processingTime, 'ms');
} else {
  console.error('Transformation failed:', result.error);
}
```

## Architecture

**Bounded Context:** Format Transformation
**Priority:** P1 - Core transformation capability
**Service Limit:** 2,500 LOC

### Components

- **FormatDetector** - Detects invoice format from content
- **UBLTransformer** - Main transformation logic
- **CIUS Handler** - Adds Croatian-specific extensions

## Performance

- **Target:** <1s (p95) for transformation
- **Large files:** Optimized for files up to 10MB
- **Throughput:** 1,000 transformations/hour minimum

## Dependencies

- **Upstream:** invoice-gateway-api, invoice-orchestrator
- **Downstream:** validation-coordinator (for post-transformation validation)
- **External:** OCR service (Team 2) for PDF processing

---

**Version:** 1.0.0
**Status:** ✅ Week 2 Day 8-9 Implementation Complete
**Maintained by:** Team 1
