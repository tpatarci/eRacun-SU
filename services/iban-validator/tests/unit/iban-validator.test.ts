import { describe, it, expect } from '@jest/globals';
import fc from 'fast-check';
import {
  validateIBAN,
  validateIBANFormat,
  validateIBANChecksum,
  validateIBANBatch,
  validateBankCode,
  generateValidIBAN,
  extractIBANMetadata,
} from '../../src/iban-validator';

describe('IBAN Validator', () => {
  describe('validateIBANFormat', () => {
    it('should accept valid Croatian IBAN format', () => {
      const errors = validateIBANFormat('HR1210010051863000160');
      expect(errors).toEqual([]);
    });

    it('should accept IBAN with spaces', () => {
      const errors = validateIBANFormat('HR12 1001 0051 8630 0016 0');
      expect(errors).toEqual([]);
    });

    it('should accept lowercase IBAN', () => {
      const errors = validateIBANFormat('hr1210010051863000160');
      expect(errors).toEqual([]);
    });

    it('should reject empty IBAN', () => {
      const errors = validateIBANFormat('');
      expect(errors).toContain('IBAN is required');
    });

    it('should reject whitespace-only IBAN', () => {
      const errors = validateIBANFormat('   ');
      expect(errors).toContain('IBAN is required');
    });

    it('should reject IBAN shorter than 21 characters', () => {
      const errors = validateIBANFormat('HR12100100518630');
      expect(errors).toContain('Croatian IBAN must be exactly 21 characters (got 16)');
    });

    it('should reject IBAN longer than 21 characters', () => {
      const errors = validateIBANFormat('HR121001005186300016000');
      expect(errors).toContain('Croatian IBAN must be exactly 21 characters (got 23)');
    });

    it('should reject IBAN with special characters', () => {
      const errors = validateIBANFormat('HR12-1001-0051-8630-0016-0');
      expect(errors).toContain('IBAN must contain only letters and numbers');
    });

    it('should reject IBAN not starting with HR', () => {
      const errors = validateIBANFormat('DE1210010051863000160');
      expect(errors).toContain('IBAN must start with HR (Croatian country code)');
    });

    it('should reject IBAN with non-numeric check digits', () => {
      const errors = validateIBANFormat('HRAB10010051863000160');
      expect(errors).toContain('IBAN check digits (positions 3-4) must be numeric');
    });

    it('should reject IBAN with non-numeric BBAN', () => {
      const errors = validateIBANFormat('HR12100100518630001AB');
      expect(errors).toContain('IBAN bank code and account number (positions 5-21) must be 17 digits');
    });

    it('should return multiple errors for invalid IBAN', () => {
      const errors = validateIBANFormat('DE12ABC');
      expect(errors.length).toBeGreaterThan(1);
    });
  });

  describe('validateIBANChecksum', () => {
    // Real valid Croatian IBANs (test examples)
    it('should validate correct IBAN checksum - example 1', () => {
      const valid = validateIBANChecksum('HR1210010051863000160');
      expect(valid).toBe(true);
    });

    it('should validate correct IBAN checksum - example 2', () => {
      const valid = validateIBANChecksum('HR9023400091110651131');
      expect(valid).toBe(true);
    });

    it('should validate IBAN with spaces', () => {
      const valid = validateIBANChecksum('HR12 1001 0051 8630 0016 0');
      expect(valid).toBe(true);
    });

    it('should validate lowercase IBAN', () => {
      const valid = validateIBANChecksum('hr1210010051863000160');
      expect(valid).toBe(true);
    });

    it('should reject IBAN with invalid checksum', () => {
      const valid = validateIBANChecksum('HR1310010051863000160'); // Wrong check digit
      expect(valid).toBe(false);
    });

    it('should reject IBAN with wrong length', () => {
      const valid = validateIBANChecksum('HR12100100518630');
      expect(valid).toBe(false);
    });

    it('should reject non-alphanumeric IBAN', () => {
      const valid = validateIBANChecksum('HR12-1001-0051-8630-0016-0');
      expect(valid).toBe(false);
    });
  });

  describe('extractIBANMetadata', () => {
    it('should extract metadata from valid IBAN', () => {
      const metadata = extractIBANMetadata('HR1210010051863000160');
      expect(metadata.countryCode).toBe('HR');
      expect(metadata.checkDigits).toBe('12');
      expect(metadata.bankCode).toBe('1001005');
      expect(metadata.accountNumber).toBe('1863000160');
    });

    it('should return empty metadata for invalid length', () => {
      const metadata = extractIBANMetadata('HR12');
      expect(metadata.countryCode).toBe('');
      expect(metadata.checkDigits).toBe('');
      expect(metadata.bankCode).toBe('');
      expect(metadata.accountNumber).toBe('');
    });
  });

  describe('validateBankCode', () => {
    it('should validate known bank code - HPB', () => {
      const bankName = validateBankCode('1001005');
      expect(bankName).toBe('Hrvatska poštanska banka');
    });

    it('should validate known bank code - PBZ', () => {
      const bankName = validateBankCode('2340009');
      expect(bankName).toBe('Privredna banka Zagreb');
    });

    it('should validate known bank code - Zagrebacka', () => {
      const bankName = validateBankCode('2410001');
      expect(bankName).toBe('Zagrebačka banka');
    });

    it('should return null for unknown bank code', () => {
      const bankName = validateBankCode('9999999');
      expect(bankName).toBeNull();
    });
  });

  describe('validateIBAN', () => {
    it('should validate correct IBAN', () => {
      const result = validateIBAN('HR1210010051863000160');
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.metadata.checksumValid).toBe(true);
      expect(result.metadata.countryCode).toBe('HR');
      expect(result.metadata.checkDigits).toBe('12');
      expect(result.metadata.bankCode).toBe('1001005');
      expect(result.metadata.accountNumber).toBe('1863000160');
    });

    it('should normalize IBAN with spaces', () => {
      const result = validateIBAN('HR12 1001 0051 8630 0016 0');
      expect(result.valid).toBe(true);
      expect(result.iban).toBe('HR1210010051863000160');
    });

    it('should normalize lowercase IBAN', () => {
      const result = validateIBAN('hr1210010051863000160');
      expect(result.valid).toBe(true);
      expect(result.iban).toBe('HR1210010051863000160');
    });

    it('should reject IBAN with format errors', () => {
      const result = validateIBAN('HR12');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.metadata.checksumValid).toBe(false);
    });

    it('should reject IBAN with invalid checksum', () => {
      const result = validateIBAN('HR1310010051863000160');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid IBAN checksum (ISO 13616, MOD-97)');
      expect(result.metadata.checksumValid).toBe(false);
    });

    it('should reject empty IBAN', () => {
      const result = validateIBAN('');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('IBAN is required');
    });

    it('should reject undefined as IBAN', () => {
      const result = validateIBAN(undefined as any);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('IBAN is required');
    });

    it('should reject null as IBAN', () => {
      const result = validateIBAN(null as any);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('IBAN is required');
    });

    it('should reject object as IBAN', () => {
      const result = validateIBAN({} as any);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('IBAN is required');
    });

    it('should reject number as IBAN', () => {
      const result = validateIBAN(123 as any);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('IBAN is required');
    });

    it('should include IBAN in result', () => {
      const result = validateIBAN('HR1210010051863000160');
      expect(result.iban).toBe('HR1210010051863000160');
    });

    it('should include metadata in result', () => {
      const result = validateIBAN('HR1210010051863000160');
      expect(result.metadata).toBeDefined();
      expect(result.metadata.countryCode).toBe('HR');
      expect(result.metadata.checkDigits).toBe('12');
      expect(result.metadata.bankCode).toBe('1001005');
      expect(result.metadata.accountNumber).toBe('1863000160');
      expect(result.metadata.checksumValid).toBe(true);
    });
  });

  describe('validateIBANBatch', () => {
    it('should validate multiple IBANs', () => {
      const ibans = [
        'HR1210010051863000160',
        'HR9023400091110651131',
        'HR1310010051863000160', // Invalid checksum
      ];
      const results = validateIBANBatch(ibans);

      expect(results).toHaveLength(3);
      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(true);
      expect(results[2].valid).toBe(false);
    });

    it('should handle empty array', () => {
      const results = validateIBANBatch([]);
      expect(results).toEqual([]);
    });

    it('should validate each IBAN independently', () => {
      const ibans = ['HR1210010051863000160', 'invalid', 'HR9023400091110651131'];
      const results = validateIBANBatch(ibans);

      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(false);
      expect(results[2].valid).toBe(true);
    });
  });

  describe('generateValidIBAN', () => {
    it('should generate valid IBAN without parameters', () => {
      const iban = generateValidIBAN();
      const result = validateIBAN(iban);

      expect(result.valid).toBe(true);
      expect(iban).toHaveLength(21);
      expect(iban.startsWith('HR')).toBe(true);
    });

    it('should generate valid IBAN with custom bank code', () => {
      const bankCode = '2340009'; // PBZ
      const iban = generateValidIBAN(bankCode);
      const result = validateIBAN(iban);

      expect(result.valid).toBe(true);
      expect(result.metadata.bankCode).toBe(bankCode);
    });

    it('should generate valid IBAN with custom bank code and account', () => {
      const bankCode = '2340009';
      const accountNumber = '1234567890';
      const iban = generateValidIBAN(bankCode, accountNumber);
      const result = validateIBAN(iban);

      expect(result.valid).toBe(true);
      expect(result.metadata.bankCode).toBe(bankCode);
      expect(result.metadata.accountNumber).toBe(accountNumber);
    });

    it('should reject invalid bank code length', () => {
      expect(() => generateValidIBAN('123')).toThrow('Bank code must be exactly 7 digits');
    });

    it('should reject non-numeric bank code', () => {
      expect(() => generateValidIBAN('123456A')).toThrow('Bank code must be exactly 7 digits');
    });

    it('should reject invalid account number length', () => {
      expect(() => generateValidIBAN('1001005', '123')).toThrow(
        'Account number must be exactly 10 digits'
      );
    });

    it('should reject non-numeric account number', () => {
      expect(() => generateValidIBAN('1001005', '123456789A')).toThrow(
        'Account number must be exactly 10 digits'
      );
    });

    it('should generate different IBANs on multiple calls', () => {
      const iban1 = generateValidIBAN();
      const iban2 = generateValidIBAN();
      const iban3 = generateValidIBAN();

      // With high probability, at least two should be different
      const allSame = iban1 === iban2 && iban2 === iban3;
      expect(allSame).toBe(false);
    });
  });

  // Property-based tests using fast-check
  describe('Property-Based Tests', () => {
    it('should always validate generated IBANs as valid', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000, max: 9999999 }),
          fc.integer({ min: 0, max: 9999999999 }),
          (bank, account) => {
            const bankCode = bank.toString().padStart(7, '0');
            const accountNumber = account.toString().padStart(10, '0');
            const iban = generateValidIBAN(bankCode, accountNumber);
            const result = validateIBAN(iban);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should always reject IBANs with modified check digits', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000, max: 9999999 }),
          fc.integer({ min: 0, max: 9999999999 }),
          (bank, account) => {
            const bankCode = bank.toString().padStart(7, '0');
            const accountNumber = account.toString().padStart(10, '0');
            const validIBAN = generateValidIBAN(bankCode, accountNumber);

            // Modify check digits
            const checkDigits = validIBAN.substring(2, 4);
            const wrongCheckDigits = ((parseInt(checkDigits, 10) + 1) % 100)
              .toString()
              .padStart(2, '0');
            const invalidIBAN = 'HR' + wrongCheckDigits + validIBAN.substring(4);

            // Skip if modified check digits are the same (edge case for 00 -> 00)
            if (invalidIBAN === validIBAN) return true;

            const result = validateIBAN(invalidIBAN);
            return result.valid === false;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should consistently validate the same IBAN', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000, max: 9999999 }),
          fc.integer({ min: 0, max: 9999999999 }),
          (bank, account) => {
            const bankCode = bank.toString().padStart(7, '0');
            const accountNumber = account.toString().padStart(10, '0');
            const iban = generateValidIBAN(bankCode, accountNumber);

            const result1 = validateIBAN(iban);
            const result2 = validateIBAN(iban);

            return result1.valid === result2.valid && result1.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle IBANs with spaces correctly', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000, max: 9999999 }),
          fc.integer({ min: 0, max: 9999999999 }),
          (bank, account) => {
            const bankCode = bank.toString().padStart(7, '0');
            const accountNumber = account.toString().padStart(10, '0');
            const iban = generateValidIBAN(bankCode, accountNumber);

            // Add spaces
            const ibanWithSpaces = `${iban.substring(0, 4)} ${iban.substring(4, 8)} ${iban.substring(8, 12)} ${iban.substring(12, 16)} ${iban.substring(16, 20)} ${iban.substring(20)}`;

            const result1 = validateIBAN(iban);
            const result2 = validateIBAN(ibanWithSpaces);

            return result1.valid === result2.valid && result1.iban === result2.iban;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  // Edge cases and error conditions
  describe('Edge Cases', () => {
    it('should handle IBAN with mixed case', () => {
      const result = validateIBAN('Hr1210010051863000160');
      expect(result.valid).toBe(true);
      expect(result.iban).toBe('HR1210010051863000160');
    });

    it('should handle IBAN with multiple spaces', () => {
      const result = validateIBAN('HR12  1001  0051  8630  0016  0');
      expect(result.valid).toBe(true);
    });

    it('should reject IBAN from different country', () => {
      const result = validateIBAN('DE89370400440532013000');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('IBAN must start with HR (Croatian country code)');
    });

    it('should handle IBAN with check digits 00', () => {
      const iban = generateValidIBAN('1001005', '0000000000');
      const result = validateIBAN(iban);
      expect(result.valid).toBe(true);
    });

    it('should handle IBAN with check digits 99', () => {
      // Find a combination that produces check digits close to 99
      const iban = generateValidIBAN('9999999', '9999999999');
      const result = validateIBAN(iban);
      expect(result.valid).toBe(true);
    });
  });
});
