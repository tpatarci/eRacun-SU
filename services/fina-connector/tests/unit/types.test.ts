import { describe, it, expect } from '@jest/globals';
import type {
  FINAInvoice,
  FINAFiscalizationRequest,
  FINAFiscalizationResponse,
  FINAError,
} from '../../src/types';

describe('Types', () => {
  describe('FINAInvoice', () => {
    it('should accept valid invoice', () => {
      const invoice: FINAInvoice = {
        oib: '12345678901',
        datVrijeme: '2025-11-12T14:30:00',
        brojRacuna: '1',
        oznPoslProstora: 'PP1',
        oznNapUr: 'NAP1',
        ukupanIznos: '100.00',
        zki: 'a1b2c3d4e5f6789012345678901234567890abcd',
        nacinPlac: 'G',
      };

      expect(invoice.oib).toBe('12345678901');
      expect(invoice.nacinPlac).toBe('G');
    });

    it('should support payment methods', () => {
      const methods: Array<FINAInvoice['nacinPlac']> = ['G', 'K', 'C', 'T', 'O'];

      methods.forEach((method) => {
        const invoice: FINAInvoice = {
          oib: '12345678901',
          datVrijeme: '2025-11-12T14:30:00',
          brojRacuna: '1',
          oznPoslProstora: 'PP1',
          oznNapUr: 'NAP1',
          ukupanIznos: '100.00',
          zki: 'a1b2c3d4e5f6789012345678901234567890abcd',
          nacinPlac: method,
        };

        expect(invoice.nacinPlac).toBe(method);
      });
    });

    it('should support optional VAT breakdown', () => {
      const invoice: FINAInvoice = {
        oib: '12345678901',
        datVrijeme: '2025-11-12T14:30:00',
        brojRacuna: '1',
        oznPoslProstora: 'PP1',
        oznNapUr: 'NAP1',
        ukupanIznos: '100.00',
        zki: 'a1b2c3d4e5f6789012345678901234567890abcd',
        nacinPlac: 'G',
        pdv: [
          {
            porez: '80.00',
            stopa: '25.00',
            iznos: '20.00',
          },
        ],
      };

      expect(invoice.pdv).toBeDefined();
      expect(invoice.pdv![0].stopa).toBe('25.00');
    });
  });

  describe('FINAFiscalizationResponse', () => {
    it('should represent successful response', () => {
      const response: FINAFiscalizationResponse = {
        success: true,
        jir: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
      };

      expect(response.success).toBe(true);
      expect(response.jir).toBeDefined();
    });

    it('should represent error response', () => {
      const error: FINAError = {
        code: 's:001',
        message: 'Invalid invoice data',
      };

      const response: FINAFiscalizationResponse = {
        success: false,
        error,
      };

      expect(response.success).toBe(false);
      expect(response.error).toBeDefined();
      expect(response.error!.code).toBe('s:001');
    });
  });

  describe('FINAError', () => {
    it('should contain error code and message', () => {
      const error: FINAError = {
        code: 's:002',
        message: 'Invalid ZKI code',
      };

      expect(error.code).toBe('s:002');
      expect(error.message).toBe('Invalid ZKI code');
    });

    it('should optionally contain stack trace', () => {
      const error: FINAError = {
        code: 's:999',
        message: 'Unknown error',
        stack: 'Error: Unknown error\n    at ...',
      };

      expect(error.stack).toBeDefined();
    });
  });
});
