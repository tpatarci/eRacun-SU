import {
  SOAPEnvelopeBuilder,
  createSOAPEnvelopeBuilder,
} from '../../../src/fina/soap-envelope-builder';
import type { FINAInvoice } from '../../../src/fina/types';

describe('SOAP Envelope Builder', () => {
  let builder: SOAPEnvelopeBuilder;

  beforeAll(() => {
    builder = createSOAPEnvelopeBuilder();
  });

  const validInvoice: FINAInvoice = {
    oib: '12345678903',
    datVrijeme: '2026-01-15T10:30:00',
    brojRacuna: '1/PP1/1',
    oznPoslProstora: 'PP1',
    oznNapUr: '1',
    ukupanIznos: '1250.00',
    zki: 'abcdef1234567890abcdef1234567890',
    nacinPlac: 'T',
  };

  describe('buildRacuniRequest', () => {
    it('should build SOAP envelope with required elements (Test 4.1)', () => {
      const xml = builder.buildRacuniRequest(validInvoice);

      expect(xml).toContain('<soap:Envelope');
      expect(xml).toContain('<tns:RacunZahtjev>');
      expect(xml).toContain('<tns:Oib>12345678903</tns:Oib>');
    });

    it('should throw error for missing required field (Test 4.2)', () => {
      const incomplete = { ...validInvoice, oib: '' };

      expect(() => builder.buildRacuniRequest(incomplete))
        .toThrow('Required field missing: oib');
    });

    it('should escape XML special characters (Test 4.3)', () => {
      const invoiceWithSpecialChars: FINAInvoice = {
        ...validInvoice,
        brojRacuna: '<script>alert("xss")</script>',
      };

      const xml = builder.buildRacuniRequest(invoiceWithSpecialChars);

      expect(xml).toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
      expect(xml).not.toContain('<script>');
    });

    it('should include VAT breakdown section (Test 4.4)', () => {
      const invoiceWithVAT: FINAInvoice = {
        ...validInvoice,
        pdv: [
          { porez: '1000.00', stopa: '25.00', iznos: '250.00' },
        ],
      };

      const xml = builder.buildRacuniRequest(invoiceWithVAT);

      expect(xml).toContain('<tns:Pdv>');
      expect(xml).toContain('<tns:Porez>1000.00</tns:Porez>');
      expect(xml).toContain('<tns:Stopa>25.00</tns:Stopa>');
      expect(xml).toContain('<tns:Iznos>250.00</tns:Iznos>');
    });

    it('should include non-taxable section', () => {
      const invoiceWithPNP: FINAInvoice = {
        ...validInvoice,
        pnp: [
          { porez: '100.00', stopa: '0.00', iznos: '0.00' },
        ],
      };

      const xml = builder.buildRacuniRequest(invoiceWithPNP);

      expect(xml).toContain('<tns:Pnp>');
    });

    it('should include other taxes section', () => {
      const invoiceWithOtherTax: FINAInvoice = {
        ...validInvoice,
        ostaliPor: [
          { naziv: 'Porez na potrošnju', stopa: '3.00', iznos: '30.00' },
        ],
      };

      const xml = builder.buildRacuniRequest(invoiceWithOtherTax);

      expect(xml).toContain('<tns:OstaliPor>');
      expect(xml).toContain('<tns:Naziv>Porez na potrošnju</tns:Naziv>');
    });
  });

  describe('buildProveraRequest', () => {
    it('should build validation request', () => {
      const xml = builder.buildProveraRequest(validInvoice);

      expect(xml).toContain('<tns:Provjera>');
      expect(xml).toContain('<tns:Oib>12345678903</tns:Oib>');
    });

    it('should throw error for missing required fields', () => {
      const incomplete = { ...validInvoice, oib: '' };

      expect(() => builder.buildProveraRequest(incomplete))
        .toThrow('Required field missing');
    });
  });

  describe('buildEchoRequest', () => {
    it('should build echo request (Test 4.5)', () => {
      const xml = builder.buildEchoRequest();

      expect(xml).toContain('<tns:Echo>');
      expect(xml).toContain('<tns:Poruka>Test connection to FINA</tns:Poruka>');
    });
  });

  describe('createSOAPEnvelopeBuilder', () => {
    it('should return new builder instance', () => {
      const newBuilder = createSOAPEnvelopeBuilder();
      expect(newBuilder).toBeInstanceOf(SOAPEnvelopeBuilder);
    });
  });
});
