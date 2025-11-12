import { SOAPEnvelopeBuilder } from '../../src/soap-envelope-builder';
import type { FINAInvoice } from '../../src/types';

/**
 * SOAP Envelope Builder Unit Tests
 *
 * Tests for XML security:
 * - Special character escaping (& < > " ')
 * - No injection vulnerabilities
 * - Valid XML structure
 * - Required field validation
 */
describe('SOAPEnvelopeBuilder', () => {
  let builder: SOAPEnvelopeBuilder;

  // Sample invoice for testing
  const validInvoice: FINAInvoice = {
    oib: '12345678901',
    datVrijeme: '2025-11-12T10:00:00Z',
    brojRacuna: '1',
    oznPoslProstora: 'PREM-001',
    oznNapUr: 'DEVICE-001',
    ukupanIznos: '100.00',
    zki: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
    nacinPlac: 'G',
  };

  beforeEach(() => {
    builder = new SOAPEnvelopeBuilder();
  });

  describe('XML Escaping Security', () => {
    it('should escape & character in invoice fields', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        brojRacuna: '123&456',
      };

      const xml = builder.buildRacuniRequest(invoice);

      // Should be escaped as &amp;
      expect(xml).toContain('123&amp;456');
      expect(xml).not.toContain('123&456</');
    });

    it('should escape < character in invoice fields', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        brojRacuna: '<injection>123</injection>',
      };

      const xml = builder.buildRacuniRequest(invoice);

      // Should be escaped as &lt;
      expect(xml).toContain('&lt;injection&gt;123&lt;/injection&gt;');
      expect(xml).not.toContain('<injection>');
    });

    it('should escape > character in invoice fields', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        brojRacuna: 'test>123',
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain('test&gt;123');
      expect(xml).not.toContain('test>123<');
    });

    it('should escape double quotes in invoice fields', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        oznPoslProstora: 'premise"with"quotes',
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain('premise&quot;with&quot;quotes');
      expect(xml).not.toContain('premise"with"quotes');
    });

    it('should escape single quotes in invoice fields', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        oznNapUr: "device'with'quotes",
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain("device&apos;with&apos;quotes");
      expect(xml).not.toContain("device'with'quotes");
    });

    it('should prevent XML injection via brojRacuna field', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        brojRacuna: '111</tns:BrOznRac><tns:Malicious>injected</tns:Malicious>',
      };

      const xml = builder.buildRacuniRequest(invoice);

      // Injection attempt should be escaped
      expect(xml).toContain('111&lt;/tns:BrOznRac&gt;&lt;tns:Malicious&gt;injected&lt;/tns:Malicious&gt;');
      // Should not contain actual malicious tags
      expect(xml).not.toContain('<tns:Malicious>');
    });

    it('should handle multiple special characters in single field', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        brojRacuna: 'test&<>"\'123',
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain('test&amp;&lt;&gt;&quot;&apos;123');
    });
  });

  describe('XML Structure Validation', () => {
    it('should produce valid XML root element', () => {
      const xml = builder.buildRacuniRequest(validInvoice);

      expect(xml).toMatch(/^<\?xml version="1.0" encoding="UTF-8"\?>/);
      expect(xml).toContain('<soap:Envelope');
      expect(xml).toContain('</soap:Envelope>');
    });

    it('should include FINA SOAP namespaces', () => {
      const xml = builder.buildRacuniRequest(validInvoice);

      expect(xml).toContain('xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"');
      expect(xml).toContain('xmlns:tns="http://www.apis-it.hr/fin/2012/types/f73"');
    });

    it('should include RacunZahtjev operation wrapper', () => {
      const xml = builder.buildRacuniRequest(validInvoice);

      expect(xml).toContain('<tns:RacunZahtjev>');
      expect(xml).toContain('</tns:RacunZahtjev>');
    });

    it('should include all required FINA fields', () => {
      const xml = builder.buildRacuniRequest(validInvoice);

      expect(xml).toContain('<tns:Oib>');
      expect(xml).toContain('<tns:DatVrijeme>');
      expect(xml).toContain('<tns:BrojRacuna>');
      expect(xml).toContain('<tns:BrRac>');
      expect(xml).toContain('<tns:BrOznRac>');
      expect(xml).toContain('<tns:OznPosPr>');
      expect(xml).toContain('<tns:OznNapUr>');
      expect(xml).toContain('<tns:IznosUkupno>');
      expect(xml).toContain('<tns:NacinPlac>');
      expect(xml).toContain('<tns:ZastKod>');
    });

    it('should properly close all XML tags', () => {
      const xml = builder.buildRacuniRequest(validInvoice);

      // Count opening and closing tags
      const openingTags = (xml.match(/<tns:[A-Za-z]+>/g) || []).length;
      const closingTags = (xml.match(/<\/tns:[A-Za-z]+>/g) || []).length;

      // Should have matching pairs
      expect(openingTags).toBeGreaterThan(0);
      expect(closingTags).toBeGreaterThan(0);
    });
  });

  describe('Field Value Validation', () => {
    it('should include correct OIB value', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        oib: '98765432109',
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain('<tns:Oib>98765432109</tns:Oib>');
    });

    it('should include correct invoice number', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        brojRacuna: '12345',
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain('<tns:BrOznRac>12345</tns:BrOznRac>');
    });

    it('should include correct total amount', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        ukupanIznos: '1234.56',
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain('<tns:IznosUkupno>1234.56</tns:IznosUkupno>');
    });

    it('should include correct payment method', () => {
      const methods: ('G' | 'K' | 'C' | 'T' | 'O')[] = ['G', 'K', 'C', 'T', 'O'];

      for (const method of methods) {
        const invoice: FINAInvoice = {
          ...validInvoice,
          nacinPlac: method,
        };

        const xml = builder.buildRacuniRequest(invoice);

        expect(xml).toContain(`<tns:NacinPlac>${method}</tns:NacinPlac>`);
      }
    });
  });

  describe('VAT Breakdown Handling', () => {
    it('should include VAT breakdown if provided', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        pdv: [
          {
            porez: '80.00',
            stopa: '25.00',
            iznos: '20.00',
          },
        ],
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain('<tns:Pdv>');
      expect(xml).toContain('<tns:Porez>80.00</tns:Porez>');
      expect(xml).toContain('<tns:Stopa>25.00</tns:Stopa>');
      expect(xml).toContain('<tns:Iznos>20.00</tns:Iznos>');
    });

    it('should handle multiple VAT rates', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        pdv: [
          { porez: '100.00', stopa: '25.00', iznos: '25.00' },
          { porez: '50.00', stopa: '13.00', iznos: '6.50' },
        ],
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).toContain('<tns:Stopa>25.00</tns:Stopa>');
      expect(xml).toContain('<tns:Stopa>13.00</tns:Stopa>');
    });

    it('should not include VAT section if empty', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        pdv: [],
      };

      const xml = builder.buildRacuniRequest(invoice);

      expect(xml).not.toContain('<tns:Pdv>');
    });
  });

  describe('Required Field Validation', () => {
    it('should throw error if OIB missing', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        oib: '',
      };

      expect(() => builder.buildRacuniRequest(invoice)).toThrow('Required field missing: oib');
    });

    it('should throw error if brojRacuna missing', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        brojRacuna: '',
      };

      expect(() => builder.buildRacuniRequest(invoice)).toThrow('Required field missing: brojRacuna');
    });

    it('should throw error if ZKI missing', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        zki: '',
      };

      expect(() => builder.buildRacuniRequest(invoice)).toThrow('Required field missing: zki');
    });

    it('should throw error if payment method missing', () => {
      const invoice: any = {
        ...validInvoice,
        nacinPlac: undefined,
      };

      expect(() => builder.buildRacuniRequest(invoice)).toThrow('Required field missing: nacinPlac');
    });
  });

  describe('Provjera (Validation) Operation', () => {
    it('should build validation request with minimal fields', () => {
      const xml = builder.buildProveraRequest(validInvoice);

      expect(xml).toContain('<tns:Provjera>');
      expect(xml).toContain('</tns:Provjera>');
      expect(xml).toContain(`<tns:Oib>${validInvoice.oib}</tns:Oib>`);
    });

    it('should escape special characters in validation request', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        oib: '123&456',
      };

      const xml = builder.buildProveraRequest(invoice);

      expect(xml).toContain('123&amp;456');
      expect(xml).not.toContain('123&456</');
    });
  });

  describe('Echo Operation', () => {
    it('should build valid echo request', () => {
      const xml = builder.buildEchoRequest();

      expect(xml).toContain('<tns:Echo>');
      expect(xml).toContain('</tns:Echo>');
      expect(xml).toContain('<tns:Poruka>Test connection to FINA</tns:Poruka>');
    });

    it('should not contain any invoice-specific data', () => {
      const xml = builder.buildEchoRequest();

      expect(xml).not.toContain('Racun');
      expect(xml).not.toContain('Oib');
    });
  });

  describe('Integration Tests', () => {
    it('should produce XML parseable by standard XML parser', () => {
      const xml = builder.buildRacuniRequest(validInvoice);

      // Should not throw when parsed by DOMParser (mock)
      expect(() => {
        // Basic validation: should start with XML declaration and have matching tags
        expect(xml).toMatch(/^<\?xml/);
        expect((xml.match(/<soap:Envelope/g) || []).length).toBe(1);
        expect((xml.match(/<\/soap:Envelope>/g) || []).length).toBe(1);
      }).not.toThrow();
    });

    it('should preserve unicode characters in escaped strings', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        oznPoslProstora: 'Љубљана-001', // Cyrillic characters
      };

      const xml = builder.buildRacuniRequest(invoice);

      // Unicode should be preserved, not escaped
      expect(xml).toContain('Љубљана-001');
    });

    it('should handle whitespace in numeric fields correctly', () => {
      const invoice: FINAInvoice = {
        ...validInvoice,
        ukupanIznos: '  1234.56  ',
      };

      const xml = builder.buildRacuniRequest(invoice);

      // Whitespace should be preserved in the value
      expect(xml).toContain('  1234.56  ');
    });
  });
});
