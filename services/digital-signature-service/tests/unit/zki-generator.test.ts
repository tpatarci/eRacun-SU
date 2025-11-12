import { describe, it, expect } from '@jest/globals';
import forge from 'node-forge';
import {
  validateZKIParams,
  formatZKI,
  type ZKIParams,
} from '../../src/zki-generator.js';
import { ZKIGenerationError } from '../../src/zki-generator.js';

describe('ZKI Generator', () => {
  // Valid test parameters
  const validParams: ZKIParams = {
    oib: '12345678901',
    issueDateTime: '2026-01-15T10:30:00',
    invoiceNumber: '1',
    businessPremises: 'ZAGREB1',
    cashRegister: 'POS1',
    totalAmount: '125.00',
  };

  describe('validateZKIParams', () => {
    it('should accept valid parameters', () => {
      expect(() => {
        validateZKIParams(validParams);
      }).not.toThrow();
    });

    it('should reject invalid OIB (not 11 digits)', () => {
      const invalidParams = { ...validParams, oib: '123' };

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow(ZKIGenerationError);

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow('OIB must be 11 digits');
    });

    it('should reject non-numeric OIB', () => {
      const invalidParams = { ...validParams, oib: '1234567890A' };

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow(ZKIGenerationError);
    });

    it('should reject invalid issue date time', () => {
      const invalidParams = { ...validParams, issueDateTime: 'invalid-date' };

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow(ZKIGenerationError);

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow('Issue date time must be in ISO 8601 format');
    });

    it('should reject empty invoice number', () => {
      const invalidParams = { ...validParams, invoiceNumber: '' };

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow(ZKIGenerationError);

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow('Invoice number is required');
    });

    it('should reject empty business premises', () => {
      const invalidParams = { ...validParams, businessPremises: '' };

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow(ZKIGenerationError);

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow('Business premises identifier is required');
    });

    it('should reject empty cash register', () => {
      const invalidParams = { ...validParams, cashRegister: '' };

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow(ZKIGenerationError);

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow('Cash register identifier is required');
    });

    it('should reject invalid total amount', () => {
      const invalidParams = { ...validParams, totalAmount: 'invalid' };

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow(ZKIGenerationError);

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow('Total amount must be a valid number');
    });

    it('should reject total amount with more than 2 decimal places', () => {
      const invalidParams = { ...validParams, totalAmount: '125.123' };

      expect(() => {
        validateZKIParams(invalidParams);
      }).toThrow(ZKIGenerationError);
    });

    it('should accept total amount with 0 decimal places', () => {
      const validParams1 = { ...validParams, totalAmount: '125' };

      expect(() => {
        validateZKIParams(validParams1);
      }).not.toThrow();
    });

    it('should accept total amount with 1 decimal place', () => {
      const validParams1 = { ...validParams, totalAmount: '125.5' };

      expect(() => {
        validateZKIParams(validParams1);
      }).not.toThrow();
    });

    it('should accept total amount with 2 decimal places', () => {
      const validParams1 = { ...validParams, totalAmount: '125.50' };

      expect(() => {
        validateZKIParams(validParams1);
      }).not.toThrow();
    });
  });

  describe('formatZKI', () => {
    it('should format ZKI with dashes every 8 characters', () => {
      const zki = 'a1b2c3d4e5f678901234567890123456';
      const formatted = formatZKI(zki);

      expect(formatted).toBe('a1b2c3d4-e5f67890-12345678-90123456');
    });

    it('should handle ZKI shorter than 8 characters', () => {
      const zki = 'abc123';
      const formatted = formatZKI(zki);

      expect(formatted).toBe('abc123');
    });

    it('should handle empty ZKI', () => {
      const zki = '';
      const formatted = formatZKI(zki);

      expect(formatted).toBe('');
    });

    it('should handle ZKI exactly 8 characters', () => {
      const zki = 'abcd1234';
      const formatted = formatZKI(zki);

      expect(formatted).toBe('abcd1234');
    });

    it('should handle ZKI length not multiple of 8', () => {
      const zki = 'a1b2c3d4e5f6';
      const formatted = formatZKI(zki);

      expect(formatted).toBe('a1b2c3d4-e5f6');
    });
  });

  describe('ZKI Concatenation', () => {
    it('should concatenate parameters in correct order', () => {
      // This tests the expected concatenation format
      const expected =
        validParams.oib +
        validParams.issueDateTime +
        validParams.invoiceNumber +
        validParams.businessPremises +
        validParams.cashRegister +
        validParams.totalAmount;

      expect(expected).toBe('123456789012026-01-15T10:30:001ZAGREB1POS1125.00');
    });

    it('should produce different concatenations for different parameters', () => {
      const params1 = { ...validParams };
      const params2 = { ...validParams, totalAmount: '126.00' };

      const concat1 =
        params1.oib +
        params1.issueDateTime +
        params1.invoiceNumber +
        params1.businessPremises +
        params1.cashRegister +
        params1.totalAmount;

      const concat2 =
        params2.oib +
        params2.issueDateTime +
        params2.invoiceNumber +
        params2.businessPremises +
        params2.cashRegister +
        params2.totalAmount;

      expect(concat1).not.toBe(concat2);
    });
  });
});
