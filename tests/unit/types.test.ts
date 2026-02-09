import type {
  FINAInvoice,
  FINAVATBreakdown,
  FINANonTaxable,
  FINAOtherTaxes,
  FINAFiscalizationRequest,
  FINAFiscalizationResponse,
  FINAError,
  Invoice,
  ArchiveRecord,
  JobPayload,
} from '../../src/shared/types';

describe('Types', () => {
  describe('FINA types', () => {
    it('should accept valid FINAInvoice', () => {
      const invoice: FINAInvoice = {
        oib: '12345678903',
        datVrijeme: '2026-01-15T10:30:00',
        brojRacuna: '1/PP1/1',
        oznPoslProstora: 'PP1',
        oznNapUr: '1',
        ukupanIznos: '1250.00',
        zki: 'abcdef1234567890abcdef1234567890',
        nacinPlac: 'T',
      };

      expect(invoice.oib).toBe('12345678903');
      expect(invoice.nacinPlac).toBe('T');
    });

    it('should accept FINAVATBreakdown', () => {
      const vat: FINAVATBreakdown = {
        porez: '1000.00',
        stopa: '25.00',
        iznos: '250.00',
      };

      expect(vat.porez).toBe('1000.00');
    });

    it('should accept FINANonTaxable', () => {
      const nonTaxable: FINANonTaxable = {
        porez: '100.00',
        stopa: '0.00',
        iznos: '0.00',
      };

      expect(nonTaxable.stopa).toBe('0.00');
    });

    it('should accept FINAOtherTaxes', () => {
      const otherTax: FINAOtherTaxes = {
        naziv: 'Porez na potrošnju',
        stopa: '3.00',
        iznos: '30.00',
      };

      expect(otherTax.naziv).toBe('Porez na potrošnju');
    });

    it('should accept FINAFiscalizationRequest', () => {
      const request: FINAFiscalizationRequest = {
        racun: {
          oib: '12345678903',
          datVrijeme: '2026-01-15T10:30:00',
          brojRacuna: '1/PP1/1',
          oznPoslProstora: 'PP1',
          oznNapUr: '1',
          ukupanIznos: '1250.00',
          zki: 'abc123',
          nacinPlac: 'T',
        },
      };

      expect(request.racun.oib).toBe('12345678903');
    });

    it('should accept FINAFiscalizationResponse', () => {
      const response: FINAFiscalizationResponse = {
        success: true,
        jir: 'JIR-12345',
      };

      expect(response.success).toBe(true);
      expect(response.jir).toBe('JIR-12345');
    });

    it('should accept FINAError', () => {
      const error: FINAError = {
        code: 's:001',
        message: 'Invalid OIB',
      };

      expect(error.code).toBe('s:001');
    });
  });

  describe('Internal domain types', () => {
    it('should accept Invoice', () => {
      const invoice: Invoice = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        oib: '12345678903',
        invoiceNumber: '1/PP1/1',
        originalXml: '<Invoice/>',
        signedXml: '<Invoice><Signature/></Invoice>',
        status: 'pending',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      expect(invoice.status).toBe('pending');
    });

    it('should accept ArchiveRecord', () => {
      const record: ArchiveRecord = {
        invoiceId: '550e8400-e29b-41d4-a716-446655440000',
        oib: '12345678903',
        invoiceNumber: '1/PP1/1',
        jir: 'JIR-12345',
        archivedAt: new Date(),
      };

      expect(record.jir).toBe('JIR-12345');
    });

    it('should accept JobPayload', () => {
      const payload: JobPayload = {
        invoiceId: '550e8400-e29b-41d4-a716-446655440000',
        oib: '12345678903',
        invoiceData: { amount: 1000 },
      };

      expect(payload.invoiceData.amount).toBe(1000);
    });
  });
});
