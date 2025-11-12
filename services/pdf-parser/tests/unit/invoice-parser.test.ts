/**
 * Invoice Parser Module Tests
 */

import { InvoiceParser } from '../../src/invoice-parser';

describe('InvoiceParser', () => {
  let parser: InvoiceParser;

  beforeEach(() => {
    parser = new InvoiceParser();
  });

  describe('parseInvoice', () => {
    it('should extract invoice number from Croatian format', () => {
      const text = `
        RAČUN
        Račun br.: R-2024-00123
        Datum: 12.11.2024
      `;

      const result = parser.parseInvoice(text);

      expect(result.invoiceNumber).toBe('R-2024-00123');
      expect(result.extractedFields).toContain('invoiceNumber');
    });

    it('should extract invoice number from English format', () => {
      const text = 'Invoice No.: INV-456789';

      const result = parser.parseInvoice(text);

      expect(result.invoiceNumber).toBe('INV-456789');
    });

    it('should extract invoice date in DD.MM.YYYY format', () => {
      const text = 'Datum računa: 12.11.2024';

      const result = parser.parseInvoice(text);

      expect(result.invoiceDate).toBeInstanceOf(Date);
      expect(result.invoiceDate?.getDate()).toBe(12);
      expect(result.invoiceDate?.getMonth()).toBe(10); // 0-indexed
      expect(result.invoiceDate?.getFullYear()).toBe(2024);
    });

    it('should extract due date', () => {
      const text = 'Rok plaćanja: 26.11.2024';

      const result = parser.parseInvoice(text);

      expect(result.dueDate).toBeInstanceOf(Date);
      expect(result.dueDate?.getDate()).toBe(26);
    });

    it('should extract vendor OIB', () => {
      const text = `
        IZDAVATELJ
        OIB: 12345678901
      `;

      const result = parser.parseInvoice(text);

      expect(result.vendor.oib).toBe('12345678901');
      expect(result.extractedFields).toContain('vendor.oib');
    });

    it('should extract vendor IBAN', () => {
      const text = 'IBAN: HR1234567890123456789';

      const result = parser.parseInvoice(text);

      expect(result.vendor.iban).toBe('HR1234567890123456789');
    });

    it('should extract customer OIB (second OIB in document)', () => {
      const text = `
        Izdavatelj OIB: 11111111111
        Kupac OIB: 22222222222
      `;

      const result = parser.parseInvoice(text);

      expect(result.vendor.oib).toBe('11111111111');
      expect(result.customer.oib).toBe('22222222222');
      expect(result.extractedFields).toContain('customer.oib');
    });

    it('should extract total amount in HRK', () => {
      const text = 'Ukupno: 1.234,56 kn';

      const result = parser.parseInvoice(text);

      expect(result.amounts.total).toBeCloseTo(1234.56, 2);
      expect(result.amounts.currency).toBe('HRK');
      expect(result.extractedFields).toContain('amounts.total');
    });

    it('should extract total amount in EUR', () => {
      const text = 'Total: 567.89 EUR';

      const result = parser.parseInvoice(text);

      expect(result.amounts.total).toBeCloseTo(567.89, 2);
      expect(result.amounts.currency).toBe('EUR');
    });

    it('should extract VAT amount', () => {
      const text = `
        Ukupno: 1.000,00 kn
        PDV (25%): 200,00
      `;

      const result = parser.parseInvoice(text);

      expect(result.amounts.vatAmount).toBeCloseTo(200.00, 2);
      expect(result.amounts.subtotal).toBeCloseTo(800.00, 2);
    });

    it('should extract line items with amounts', () => {
      const text = `
        Proizvod A 100,00 kn
        Usluga B 250,50 kn
        Stavka C 75,25 EUR
      `;

      const result = parser.parseInvoice(text);

      expect(result.lineItems.length).toBeGreaterThan(0);
      expect(result.extractedFields).toContain('lineItems');
    });

    it('should calculate high confidence with all critical fields', () => {
      const text = `
        Račun br.: R-2024-123
        Datum: 12.11.2024
        OIB: 12345678901
        Ukupno: 1.000,00 kn
        Stavka 1 500,00 kn
        Kupac OIB: 98765432109
      `;

      const result = parser.parseInvoice(text);

      expect(result.confidence).toBe('high');
      expect(result.extractedFields.length).toBeGreaterThanOrEqual(6);
    });

    it('should calculate medium confidence with some fields', () => {
      const text = `
        Račun br.: R-2024-123
        Datum: 12.11.2024
        Ukupno: 1.000,00 kn
      `;

      const result = parser.parseInvoice(text);

      expect(result.confidence).toBe('medium');
    });

    it('should calculate low confidence with few fields', () => {
      const text = 'Some random PDF content without invoice structure';

      const result = parser.parseInvoice(text);

      expect(result.confidence).toBe('low');
      expect(result.extractedFields.length).toBeLessThan(3);
    });

    it('should handle empty text', () => {
      const result = parser.parseInvoice('');

      expect(result.confidence).toBe('low');
      expect(result.extractedFields).toHaveLength(0);
    });

    it('should handle Croatian special characters', () => {
      const text = 'Kupac: ČEŠKA REPUBLIKA d.o.o.';

      const result = parser.parseInvoice(text);

      expect(result).toBeDefined();
    });

    it('should parse complete invoice example', () => {
      const text = `
        RAČUN R-2024-00456

        Datum računa: 12.11.2024
        Rok plaćanja: 26.11.2024

        Izdavatelj:
        TEST d.o.o.
        OIB: 12345678901
        IBAN: HR1234567890123456789

        Kupac:
        KLIJENT d.o.o.
        OIB: 98765432109

        Proizvod A     1 kom     500,00 kn
        Usluga B       2 h       250,00 kn

        Osnovica: 600,00 kn
        PDV (25%): 150,00

        Ukupno za platiti: 750,00 kn
      `;

      const result = parser.parseInvoice(text);

      expect(result.invoiceNumber).toBe('R-2024-00456');
      expect(result.invoiceDate).toBeDefined();
      expect(result.dueDate).toBeDefined();
      expect(result.vendor.oib).toBe('12345678901');
      expect(result.customer.oib).toBe('98765432109');
      expect(result.amounts.total).toBeCloseTo(750, 0);
      expect(result.amounts.vatAmount).toBeCloseTo(150, 0);
      expect(result.lineItems.length).toBeGreaterThan(0);
      expect(result.confidence).toBe('high');
    });
  });
});
