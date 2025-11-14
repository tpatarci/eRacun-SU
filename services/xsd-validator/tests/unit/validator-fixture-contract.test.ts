import { parseXml } from 'libxmljs2';
import { InvoiceGenerator } from '../../../../shared/test-fixtures/src/InvoiceGenerator';
import { XMLGenerator } from '../../../../shared/test-fixtures/src/XMLGenerator';
import { XSDValidator, SchemaType, ValidationStatus } from '../../src/validator.js';

function seedMinimalSchemaCache(validator: XSDValidator): void {
  const schemaSource = `<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
           xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
           elementFormDefault="qualified">
  <xs:element name="Invoice">
    <xs:complexType>
      <xs:sequence>
        <xs:any minOccurs="0" maxOccurs="unbounded" processContents="lax" />
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>`;

  const schemaDoc = parseXml(schemaSource);
  const schemaCache = (validator as unknown as { schemaCache: Map<SchemaType, any> }).schemaCache;
  schemaCache.set(SchemaType.UBL_INVOICE_2_1, {
    document: schemaDoc,
    loadedAt: Date.now(),
    ttl: Number.MAX_SAFE_INTEGER,
  });
}

describe('XSDValidator – shared fixture integration', () => {
  let validator: XSDValidator;

  beforeEach(() => {
    validator = new XSDValidator();
    seedMinimalSchemaCache(validator);
  });

  it('validates XML generated from the canonical InvoiceGenerator', async () => {
    const invoice = InvoiceGenerator.generateValidInvoice();
    const xml = XMLGenerator.generateUBL21XML(invoice);

    const result = await validator.validate(xml, SchemaType.UBL_INVOICE_2_1);

    expect(result.status).toBe(ValidationStatus.VALID);
    expect(result.errors).toHaveLength(0);
    expect(result.validationTimeMs).toBeGreaterThanOrEqual(0);
  });

  it('rejects malformed XML from the shared fixtures to enforce XXE protection', async () => {
    const malformed = XMLGenerator.generateMalformedXML();
    const result = await validator.validate(malformed, SchemaType.UBL_INVOICE_2_1);

    expect(result.status).toBe(ValidationStatus.ERROR);
    expect(result.errors[0].code).toBe('XXE_VULNERABILITY');
  });
});
