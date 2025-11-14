/**
 * UBL Transformer Tests
 */

import { UBLTransformer } from '../../../src/transformers/ubl-transformer';
import { FormatDetector, InvoiceFormat } from '../../../src/transformers/format-detector';
import { UBLInvoice } from '@eracun/contracts';
import { InvoiceGenerator, XMLGenerator } from '@eracun/test-fixtures';

describe('UBLTransformer', () => {
  let transformer: UBLTransformer;
  let mockFormatDetector: jest.Mocked<FormatDetector>;

  beforeEach(() => {
    mockFormatDetector = {
      detect: jest.fn(),
    } as any;

    transformer = new UBLTransformer(mockFormatDetector);
  });

  describe('UBL 2.1 Transformation', () => {
    it('should preserve valid UBL 2.1 XML with Croatian CIUS', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const validUblXml = XMLGenerator.generateUBL21XML(testInvoice);

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(validUblXml);

      expect(result.success).toBe(true);
      expect(result.xml).toBeDefined();
      expect(result.format).toBe(InvoiceFormat.UBL_21);
      expect(result.xml).toContain('urn:fina.hr:cius-hr');
      expect(result.processingTime).toBeGreaterThan(0);
    });

    it('should add Croatian CIUS to UBL 2.1 XML without it', async () => {
      const ublXmlWithoutCius = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>INV-001</cbc:ID>
  <cbc:IssueDate>2025-11-14</cbc:IssueDate>
</Invoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(ublXmlWithoutCius);

      expect(result.success).toBe(true);
      expect(result.xml).toContain('urn:fina.hr:cius-hr:2.0');
      expect(result.xml).toContain('<cbc:CustomizationID>');
      expect(result.xml).toContain('<cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>');
    });

    it('should add ProfileID if missing', async () => {
      const ublXmlWithCiusButNoProfile = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
  <cbc:ID>INV-001</cbc:ID>
  <cbc:IssueDate>2025-11-14</cbc:IssueDate>
</Invoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(ublXmlWithCiusButNoProfile);

      expect(result.success).toBe(true);
      expect(result.xml).toContain('<cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>');
    });

    it('should validate required UBL elements', async () => {
      const invalidUblXml = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <!-- Missing required elements -->
</Invoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(invalidUblXml);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Missing required element');
    });
  });

  describe('JSON Transformation', () => {
    it('should transform valid JSON to UBL 2.1 XML', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const jsonContent = JSON.stringify(testInvoice);

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.JSON);

      const result = await transformer.transform(jsonContent);

      expect(result.success).toBe(true);
      expect(result.xml).toBeDefined();
      expect(result.xml).toContain('<?xml');
      expect(result.xml).toContain('<Invoice');
      expect(result.xml).toContain('urn:fina.hr:cius-hr');
      expect(result.xml).toContain(testInvoice.invoiceNumber);
      expect(result.format).toBe(InvoiceFormat.JSON);
    });

    it('should fail on invalid JSON', async () => {
      const invalidJson = '{ invalid json }';

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.JSON);

      const result = await transformer.transform(invalidJson);

      expect(result.success).toBe(false);
      expect(result.error).toContain('JSON transformation failed');
    });

    it('should include Croatian CIUS in transformed JSON', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const jsonContent = JSON.stringify(testInvoice);

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.JSON);

      const result = await transformer.transform(jsonContent);

      expect(result.success).toBe(true);
      expect(result.xml).toContain('urn:fina.hr:cius-hr:2.0');
      expect(result.xml).toContain('<cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>');
    });
  });

  describe('PDF Transformation', () => {
    it('should reject PDF transformation with appropriate error', async () => {
      const pdfContent = '%PDF-1.4\nsome binary content';

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.PDF);

      const result = await transformer.transform(pdfContent);

      expect(result.success).toBe(false);
      expect(result.error).toContain('PDF transformation requires OCR service');
      expect(result.error).toContain('Team 2 dependency');
      expect(result.format).toBe(InvoiceFormat.UNKNOWN);
    });
  });

  describe('EDI Transformation', () => {
    it('should reject EDI transformation as not implemented', async () => {
      const ediContent = "UNB+UNOC:3+SENDER+RECEIVER+250101:1200+REF123'";

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.EDI);

      const result = await transformer.transform(ediContent);

      expect(result.success).toBe(false);
      expect(result.error).toContain('EDI transformation not yet implemented');
      expect(result.format).toBe(InvoiceFormat.UNKNOWN);
    });
  });

  describe('Unknown Format', () => {
    it('should reject unknown format', async () => {
      const unknownContent = 'Some unknown format';

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UNKNOWN);

      const result = await transformer.transform(unknownContent);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Unsupported format');
      expect(result.format).toBe(InvoiceFormat.UNKNOWN);
    });
  });

  describe('Validation', () => {
    it('should reject empty XML', async () => {
      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      // Mock internal method to return empty XML
      const result = await transformer.transform('');

      expect(result.success).toBe(false);
    });

    it('should check for required Invoice element', async () => {
      const xmlWithoutInvoice = `<?xml version="1.0" encoding="UTF-8"?>
<NotInvoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
  <cbc:ID>INV-001</cbc:ID>
  <cbc:IssueDate>2025-11-14</cbc:IssueDate>
</NotInvoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(xmlWithoutInvoice);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Missing required element');
    });

    it('should check for required ID element', async () => {
      const xmlWithoutId = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
  <cbc:IssueDate>2025-11-14</cbc:IssueDate>
</Invoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(xmlWithoutId);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Missing required element: cbc:ID');
    });

    it('should check for required IssueDate element', async () => {
      const xmlWithoutIssueDate = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
  <cbc:ID>INV-001</cbc:ID>
</Invoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(xmlWithoutIssueDate);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Missing required element: cbc:IssueDate');
    });

    it('should verify Croatian CIUS after transformation', async () => {
      // Create a mock scenario where CIUS is somehow missing after transformation
      const ublXml = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>INV-001</cbc:ID>
  <cbc:IssueDate>2025-11-14</cbc:IssueDate>
</Invoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(ublXml);

      // Should succeed because CIUS is added during transformation
      expect(result.success).toBe(true);
      expect(result.xml).toContain('urn:fina.hr:cius-hr');
    });
  });

  describe('Processing Time', () => {
    it('should track processing time for successful transformation', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const jsonContent = JSON.stringify(testInvoice);

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.JSON);

      const result = await transformer.transform(jsonContent);

      expect(result.success).toBe(true);
      expect(result.processingTime).toBeGreaterThanOrEqual(0);
      expect(result.processingTime).toBeLessThan(5000); // Should be fast
      expect(typeof result.processingTime).toBe('number');
    });

    it('should track processing time for failed transformation', async () => {
      const invalidJson = '{ invalid }';

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.JSON);

      const result = await transformer.transform(invalidJson);

      expect(result.success).toBe(false);
      expect(result.processingTime).toBeGreaterThanOrEqual(0);
      expect(typeof result.processingTime).toBe('number');
    });
  });

  describe('Buffer Input', () => {
    it('should handle Buffer input for JSON transformation', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const jsonBuffer = Buffer.from(JSON.stringify(testInvoice), 'utf-8');

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.JSON);

      const result = await transformer.transform(jsonBuffer);

      expect(result.success).toBe(true);
      expect(result.xml).toContain(testInvoice.invoiceNumber);
    });

    it('should handle Buffer input for UBL XML', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xmlBuffer = Buffer.from(XMLGenerator.generateUBL21XML(testInvoice), 'utf-8');

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(xmlBuffer);

      expect(result.success).toBe(true);
      expect(result.xml).toContain('urn:fina.hr:cius-hr');
    });
  });

  describe('Croatian CIUS Extensions', () => {
    it('should include EN 16931 compliance in CustomizationID', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const jsonContent = JSON.stringify(testInvoice);

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.JSON);

      const result = await transformer.transform(jsonContent);

      expect(result.success).toBe(true);
      expect(result.xml).toContain('urn:cen.eu:en16931:2017#compliant');
    });

    it('should not duplicate CustomizationID', async () => {
      const ublWithCius = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
  <cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>
  <cbc:ID>INV-001</cbc:ID>
  <cbc:IssueDate>2025-11-14</cbc:IssueDate>
</Invoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(ublWithCius);

      expect(result.success).toBe(true);
      // Count occurrences of CustomizationID
      const customizationIdCount = (result.xml!.match(/<cbc:CustomizationID>/g) || []).length;
      expect(customizationIdCount).toBe(1);
    });

    it('should not duplicate ProfileID', async () => {
      const ublWithCius = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
  <cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>
  <cbc:ID>INV-001</cbc:ID>
  <cbc:IssueDate>2025-11-14</cbc:IssueDate>
</Invoice>`;

      mockFormatDetector.detect.mockReturnValue(InvoiceFormat.UBL_21);

      const result = await transformer.transform(ublWithCius);

      expect(result.success).toBe(true);
      // Count occurrences of ProfileID
      const profileIdCount = (result.xml!.match(/<cbc:ProfileID>/g) || []).length;
      expect(profileIdCount).toBe(1);
    });
  });
});
