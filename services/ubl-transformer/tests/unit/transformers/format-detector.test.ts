/**
 * Format Detector Tests
 */

import { FormatDetector, InvoiceFormat } from '../../../src/transformers/format-detector';

describe('FormatDetector', () => {
  let detector: FormatDetector;

  beforeEach(() => {
    detector = new FormatDetector();
  });

  describe('PDF Detection', () => {
    it('should detect PDF format by magic bytes', () => {
      const pdfContent = '%PDF-1.4\n%âãÏÓ\nsome binary content';
      const format = detector.detect(pdfContent);
      expect(format).toBe(InvoiceFormat.PDF);
    });

    it('should detect PDF from Buffer', () => {
      const pdfBuffer = Buffer.from('%PDF-1.7\nsome content');
      const format = detector.detect(pdfBuffer);
      expect(format).toBe(InvoiceFormat.PDF);
    });

    it('should handle PDF with no additional content', () => {
      const format = detector.detect('%PDF-');
      expect(format).toBe(InvoiceFormat.PDF);
    });
  });

  describe('JSON Detection', () => {
    it('should detect JSON object', () => {
      const jsonContent = JSON.stringify({
        invoiceNumber: 'INV-001',
        issueDate: '2025-11-14',
      });
      const format = detector.detect(jsonContent);
      expect(format).toBe(InvoiceFormat.JSON);
    });

    it('should detect JSON array', () => {
      const jsonContent = JSON.stringify([{ id: 1 }, { id: 2 }]);
      const format = detector.detect(jsonContent);
      expect(format).toBe(InvoiceFormat.JSON);
    });

    it('should detect JSON with whitespace', () => {
      const jsonContent = '  \n  { "test": "value" }  \n  ';
      const format = detector.detect(jsonContent);
      expect(format).toBe(InvoiceFormat.JSON);
    });

    it('should reject invalid JSON', () => {
      const invalidJson = '{ invalid json }';
      const format = detector.detect(invalidJson);
      expect(format).not.toBe(InvoiceFormat.JSON);
    });

    it('should reject non-JSON starting with bracket', () => {
      const notJson = '{not valid';
      const format = detector.detect(notJson);
      expect(format).not.toBe(InvoiceFormat.JSON);
    });
  });

  describe('UBL 2.1 Detection', () => {
    it('should detect UBL 2.1 XML with declaration', () => {
      const ublXml = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>INV-001</cbc:ID>
</Invoice>`;
      const format = detector.detect(ublXml);
      expect(format).toBe(InvoiceFormat.UBL_21);
    });

    it('should detect UBL 2.1 XML without declaration', () => {
      const ublXml = `<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <cbc:ID>INV-001</cbc:ID>
</Invoice>`;
      const format = detector.detect(ublXml);
      expect(format).toBe(InvoiceFormat.UBL_21);
    });

    it('should reject XML without UBL namespace', () => {
      const nonUblXml = `<?xml version="1.0"?>
<Invoice>
  <ID>INV-001</ID>
</Invoice>`;
      const format = detector.detect(nonUblXml);
      expect(format).not.toBe(InvoiceFormat.UBL_21);
    });

    it('should reject invalid XML', () => {
      const invalidXml = '<Invoice><unclosed>';
      const format = detector.detect(invalidXml);
      expect(format).not.toBe(InvoiceFormat.UBL_21);
    });

    it('should reject non-XML content', () => {
      const notXml = 'This is not XML';
      const format = detector.detect(notXml);
      expect(format).not.toBe(InvoiceFormat.UBL_21);
    });
  });

  describe('EDI Detection', () => {
    it('should detect EDIFACT format', () => {
      const edifactContent = "UNB+UNOC:3+SENDER+RECEIVER+250101:1200+REF123'";
      const format = detector.detect(edifactContent);
      expect(format).toBe(InvoiceFormat.EDI);
    });

    it('should detect X12 format', () => {
      const x12Content = 'ISA*00*          *00*          *ZZ*SENDER         ';
      const format = detector.detect(x12Content);
      expect(format).toBe(InvoiceFormat.EDI);
    });

    it('should detect EDIFACT with whitespace', () => {
      const edifactContent = '  \n  UNB+UNOC:3+SENDER  ';
      const format = detector.detect(edifactContent);
      expect(format).toBe(InvoiceFormat.EDI);
    });

    it('should reject non-EDI content starting with similar characters', () => {
      const notEdi = 'UNB but not EDI format';
      const format = detector.detect(notEdi);
      expect(format).not.toBe(InvoiceFormat.EDI);
    });
  });

  describe('Unknown Format', () => {
    it('should return UNKNOWN for plain text', () => {
      const plainText = 'This is just plain text';
      const format = detector.detect(plainText);
      expect(format).toBe(InvoiceFormat.UNKNOWN);
    });

    it('should return UNKNOWN for empty string', () => {
      const format = detector.detect('');
      expect(format).toBe(InvoiceFormat.UNKNOWN);
    });

    it('should return UNKNOWN for random binary data', () => {
      const binaryData = Buffer.from([0x00, 0x01, 0x02, 0xff]);
      const format = detector.detect(binaryData);
      expect(format).toBe(InvoiceFormat.UNKNOWN);
    });

    it('should return UNKNOWN for HTML', () => {
      const html = '<html><body>Invoice</body></html>';
      const format = detector.detect(html);
      expect(format).toBe(InvoiceFormat.UNKNOWN);
    });
  });

  describe('Buffer Handling', () => {
    it('should convert Buffer to string correctly', () => {
      const jsonBuffer = Buffer.from('{"test": "value"}', 'utf-8');
      const format = detector.detect(jsonBuffer);
      expect(format).toBe(InvoiceFormat.JSON);
    });

    it('should handle Buffer with UBL XML', () => {
      const ublXml = `<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <cbc:ID>INV-001</cbc:ID>
</Invoice>`;
      const buffer = Buffer.from(ublXml, 'utf-8');
      const format = detector.detect(buffer);
      expect(format).toBe(InvoiceFormat.UBL_21);
    });
  });

  describe('Priority Order', () => {
    it('should prioritize PDF over other formats', () => {
      // PDF magic bytes take precedence
      const content = '%PDF-1.4\n{"test": "value"}';
      const format = detector.detect(content);
      expect(format).toBe(InvoiceFormat.PDF);
    });

    it('should check JSON before UBL', () => {
      // Valid JSON that happens to contain XML-like text
      const content = '{"xml": "<Invoice>test</Invoice>"}';
      const format = detector.detect(content);
      expect(format).toBe(InvoiceFormat.JSON);
    });
  });
});
