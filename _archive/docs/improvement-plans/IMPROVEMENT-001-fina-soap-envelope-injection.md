# Improvement Plan: Fix SOAP Envelope Template Injection in fina-connector

**Priority:** 🔴 **CRITICAL**
**Service:** `services/fina-connector/`
**Issue ID:** 3.6
**Status:** Blocking Production Deployment
**Effort Estimate:** 2-3 hours
**Risk if Not Fixed:** Template injection vulnerability + incomplete implementation = cannot safely submit invoices to FINA

---

## Problem Statement

The `buildSoapEnvelope()` method in `services/fina-connector/src/fiscalization.ts` is currently a **stub implementation with hardcoded string templates**.

**Critical Issues:**
1. **Template Injection:** Invoicing data (customer names, descriptions, amounts) are inserted directly into XML template without escaping
2. **Incomplete:** Contains TODO comments indicating it was never finished
3. **No Validation:** Template assumes all fields exist and are valid XML-safe

**Example Vulnerability:**
```xml
<!-- If invoice.brojRacuna = "123&456<injection>" -->
<tns:BrOznRac>123&456<injection></tns:BrOznRac>
<!-- Results in malformed XML + potential entity injection -->
```

**Compliance Risk:** FINA submission will fail or be rejected due to malformed XML signatures.

---

## Technical Analysis

### Current Code (Line 357-382)
```typescript
private buildSoapEnvelope(invoice: FINAInvoice): string {
  // TODO: Implement proper SOAP envelope generation
  return `<?xml version="1.0" encoding="UTF-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <tns:racuni xmlns:tns="...">
          <tns:BrOznRac>${invoice.brojRacuna}</tns:BrOznRac>
          ...
```

### Why This Breaks

1. **No XML escaping:** Special characters (`<`, `>`, `&`, `"`, `'`) cause XML parsing errors
2. **No schema validation:** Doesn't verify required FINA fields are present
3. **Fragile string building:** If FINA schema changes, template breaks
4. **Debugging nightmare:** String template errors surface as cryptic SOAP faults from FINA

---

## Solution Design

### Approach: Use XML Library Instead of String Templates

**Why:**
- Type-safe XML construction
- Automatic escaping
- Validates structure matches schema
- Easy to maintain when FINA schema updates

**Tool Choice:** `xmlbuilder2` npm package
- Lightweight, zero dependencies
- Supports namespace prefixes (required for SOAP/UBL)
- Output matches expected FINA format exactly

### Implementation Steps

#### Step 1: Install Dependency
```bash
npm install xmlbuilder2
```

#### Step 2: Create SOAP Envelope Builder

**File:** `services/fina-connector/src/soap-envelope-builder.ts` (NEW)

```typescript
import { create as createXML } from 'xmlbuilder2';

export interface SOAPEnvelopeRequest {
  invoice: FINAInvoice;
  operation: 'racuni' | 'provjera' | 'echo';
}

export class SOAPEnvelopeBuilder {
  buildRacuniRequest(invoice: FINAInvoice): string {
    // Create root SOAP Envelope
    const root = createXML()
      .ele('soap:Envelope', {
        'xmlns:soap': 'http://schemas.xmlsoap.org/soap/envelope/',
        'xmlns:tns': 'http://fina.example.com/schema', // Real namespace from WSDL
      });

    const body = root.ele('soap:Body');
    const racuni = body.ele('tns:racuni');

    // Add invoice fields with automatic XML escaping
    racuni.ele('tns:BrOznRac').txt(invoice.brojRacuna); // Escapes special chars
    racuni.ele('tns:OznRac').txt(invoice.oznRac);
    racuni.ele('tns:DatumRac').txt(invoice.datumRacuna);
    racuni.ele('tns:VrijemeRac').txt(invoice.vrijemeRacuna);

    // Add UBL XML (pre-signed) as CDATA to prevent parsing
    racuni.ele('tns:UblXml').cdata(invoice.ublXmlSigned);

    // Add signature
    racuni.ele('tns:Potpis').txt(invoice.signature);

    return root.end({ prettyPrint: false });
  }

  buildProveraRequest(invoice: FINAInvoice): string {
    // Similar pattern for validation operation
    const root = createXML()
      .ele('soap:Envelope', {
        'xmlns:soap': 'http://schemas.xmlsoap.org/soap/envelope/',
        'xmlns:tns': 'http://fina.example.com/schema',
      });

    const body = root.ele('soap:Body');
    const provjera = body.ele('tns:provjera');
    provjera.ele('tns:UblXml').cdata(invoice.ublXmlSigned);

    return root.end({ prettyPrint: false });
  }

  buildEchoRequest(): string {
    // Test connectivity
    const root = createXML()
      .ele('soap:Envelope', {
        'xmlns:soap': 'http://schemas.xmlsoap.org/soap/envelope/',
        'xmlns:tns': 'http://fina.example.com/schema',
      });

    root.ele('soap:Body').ele('tns:echo');
    return root.end({ prettyPrint: false });
  }
}
```

#### Step 3: Replace Stub Implementation

**File:** `services/fina-connector/src/fiscalization.ts`

Replace:
```typescript
private buildSoapEnvelope(invoice: FINAInvoice): string {
  // OLD STUB CODE
}
```

With:
```typescript
private buildSoapEnvelope(invoice: FINAInvoice): string {
  const builder = new SOAPEnvelopeBuilder();
  return builder.buildRacuniRequest(invoice);
}
```

#### Step 4: Add Tests

**File:** `services/fina-connector/src/soap-envelope-builder.spec.ts` (NEW)

```typescript
describe('SOAPEnvelopeBuilder', () => {
  let builder: SOAPEnvelopeBuilder;

  beforeEach(() => {
    builder = new SOAPEnvelopeBuilder();
  });

  it('should escape special characters in invoice fields', () => {
    const invoice: FINAInvoice = {
      brojRacuna: '123&456<injection>test',
      // ... other fields
    };

    const xml = builder.buildRacuniRequest(invoice);

    // Verify special chars are escaped
    expect(xml).toContain('123&amp;456&lt;injection&gt;test');
    expect(xml).not.toContain('123&456<injection>test');
  });

  it('should include all required FINA fields', () => {
    const invoice: FINAInvoice = { /* ... */ };
    const xml = builder.buildRacuniRequest(invoice);

    // Verify required elements exist
    expect(xml).toContain('<tns:BrOznRac>');
    expect(xml).toContain('<tns:UblXml>');
    expect(xml).toContain('<tns:Potpis>');
  });

  it('should wrap UBL XML in CDATA to prevent parsing', () => {
    const invoice: FINAInvoice = {
      ublXmlSigned: '<Invoice><cac:InvoiceLine>...</cac:InvoiceLine></Invoice>',
      // ...
    };

    const xml = builder.buildRacuniRequest(invoice);

    // CDATA should preserve XML structure
    expect(xml).toContain('<![CDATA[');
    expect(xml).toContain(']]>');
  });

  it('should produce valid XML parseable by xml2js', async () => {
    const invoice: FINAInvoice = { /* ... */ };
    const xml = builder.buildRacuniRequest(invoice);

    const parser = new xml2js.Parser();
    // Should not throw
    await parser.parseStringPromise(xml);
  });
});
```

### Validation Checklist

- [ ] SOAP envelope structure validated against FINA WSDL
- [ ] All required fields (brojRacuna, OznRac, DatumRac, VrijemeRac, UblXml, Potpis) included
- [ ] Special characters properly escaped (e.g., `&` → `&amp;`)
- [ ] UBL XML wrapped in CDATA to prevent double-parsing
- [ ] Namespace prefixes match FINA expectations
- [ ] Generated XML parseable by standard XML parsers
- [ ] Tests confirm injection attempts fail safely
- [ ] Error handling for missing required fields

---

## Acceptance Criteria

✅ **Code Review:** XML structure reviewed against FINA WSDL v1.9
✅ **Security Review:** Template injection tests all fail safely
✅ **Test Coverage:** 100% of SOAPEnvelopeBuilder covered
✅ **Integration:** Successfully submits test invoices to FINA staging (cistest.apis-it.hr)
✅ **Regression:** Existing fina-connector tests still pass

---

## Risk Mitigation

**If Implementation Breaks Existing Tests:**
- Rollback to previous version
- Review FINA WSDL namespace definitions more carefully
- Adjust namespace URIs in SOAPEnvelopeBuilder

**If FINA Rejects Generated XML:**
- Enable XML logging (pretty-print in development)
- Compare with FINA example submissions
- Verify CDATA wrapping preserves UBL structure

---

## Deployment Notes

1. **No Database Changes** - Pure refactoring
2. **No Configuration Changes** - Uses existing invoice data
3. **Backward Compatibility** - External API unchanged
4. **Breaking Change:** None - internal method refactored

**Rollout Strategy:**
- Merge to `main` after code review
- Test in staging with FINA demo certificates
- Can immediately deploy to production (no special precautions needed)

---

## Related Issues

- Issue 3.7: ZKI generated per fiscalization (should be cached)
- Issue 3.8: N+1 queries in offline queue stats (should batch)
- Issue 3.9: Cleanup cron never runs (schedule it)

---

**Owner:** Codex
**Due Date:** Before FINA integration testing (Sprint 2)
**Blocked By:** None
**Blocks:** fina-connector E2E tests, staging deployment

