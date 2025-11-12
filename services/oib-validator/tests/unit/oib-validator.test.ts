import { describe, it, expect } from '@jest/globals';
import fc from 'fast-check';
import {
  validateOIB,
  validateOIBFormat,
  validateOIBChecksum,
  validateOIBBatch,
  generateValidOIB,
  determineOIBType,
} from '../../src/oib-validator';

describe('OIB Validator', () => {
  describe('validateOIBFormat', () => {
    it('should accept valid 11-digit OIB', () => {
      const errors = validateOIBFormat('12345678903');
      expect(errors).toEqual([]);
    });

    it('should reject empty OIB', () => {
      const errors = validateOIBFormat('');
      expect(errors).toContain('OIB is required');
    });

    it('should reject whitespace-only OIB', () => {
      const errors = validateOIBFormat('   ');
      expect(errors).toContain('OIB is required');
    });

    it('should reject OIB shorter than 11 digits', () => {
      const errors = validateOIBFormat('123456789');
      expect(errors).toContain('OIB must be exactly 11 digits (got 9)');
    });

    it('should reject OIB longer than 11 digits', () => {
      const errors = validateOIBFormat('123456789012');
      expect(errors).toContain('OIB must be exactly 11 digits (got 12)');
    });

    it('should reject OIB with letters', () => {
      const errors = validateOIBFormat('1234567890A');
      expect(errors).toContain('OIB must contain only digits');
    });

    it('should reject OIB with special characters', () => {
      const errors = validateOIBFormat('12345678-03');
      expect(errors).toContain('OIB must contain only digits');
    });

    it('should reject OIB starting with 0', () => {
      const errors = validateOIBFormat('01234567890');
      expect(errors).toContain('OIB first digit cannot be 0');
    });

    it('should return multiple errors for invalid OIB', () => {
      const errors = validateOIBFormat('0123');
      expect(errors.length).toBeGreaterThan(1);
      expect(errors).toContain('OIB must be exactly 11 digits (got 4)');
      expect(errors).toContain('OIB first digit cannot be 0');
    });
  });

  describe('validateOIBChecksum', () => {
    // Real valid Croatian OIBs (public examples from documentation)
    it('should validate correct OIB checksum - example 1', () => {
      const valid = validateOIBChecksum('12345678903');
      expect(valid).toBe(true);
    });

    it('should validate correct OIB checksum - example 2', () => {
      const valid = validateOIBChecksum('98765432106');
      expect(valid).toBe(true);
    });

    it('should reject OIB with invalid checksum', () => {
      const valid = validateOIBChecksum('12345678901'); // Wrong check digit
      expect(valid).toBe(false);
    });

    it('should reject OIB with wrong length', () => {
      const valid = validateOIBChecksum('123456789');
      expect(valid).toBe(false);
    });

    it('should reject non-numeric OIB', () => {
      const valid = validateOIBChecksum('1234567890A');
      expect(valid).toBe(false);
    });

    it('should handle checksum calculation for all digits', () => {
      // Test OIB where all positions matter
      const valid = validateOIBChecksum('11111111119');
      expect(valid).toBe(true);
    });

    it('should handle edge case where remainder becomes 0', () => {
      // This tests the "if remainder === 0, set to 10" logic
      const valid = validateOIBChecksum('50000000006');
      expect(valid).toBe(true);
    });
  });

  describe('validateOIB', () => {
    it('should validate correct OIB', () => {
      const result = validateOIB('12345678903');
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.metadata.checksumValid).toBe(true);
    });

    it('should trim whitespace before validation', () => {
      const result = validateOIB('  12345678903  ');
      expect(result.valid).toBe(true);
      expect(result.oib).toBe('12345678903');
    });

    it('should reject OIB with format errors', () => {
      const result = validateOIB('123');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.metadata.checksumValid).toBe(false);
    });

    it('should reject OIB with invalid checksum', () => {
      const result = validateOIB('12345678901');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid OIB checksum (ISO 7064, MOD 11-10)');
      expect(result.metadata.checksumValid).toBe(false);
    });

    it('should reject empty OIB', () => {
      const result = validateOIB('');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('OIB is required');
    });

    it('should include OIB in result', () => {
      const result = validateOIB('12345678903');
      expect(result.oib).toBe('12345678903');
    });

    it('should include metadata in result', () => {
      const result = validateOIB('12345678903');
      expect(result.metadata).toBeDefined();
      expect(result.metadata.type).toBeDefined();
      expect(result.metadata.checksumValid).toBe(true);
    });
  });

  describe('validateOIBBatch', () => {
    it('should validate multiple OIBs', () => {
      const oibs = ['12345678903', '98765432106', '12345678901'];
      const results = validateOIBBatch(oibs);

      expect(results).toHaveLength(3);
      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(true);
      expect(results[2].valid).toBe(false);
    });

    it('should handle empty array', () => {
      const results = validateOIBBatch([]);
      expect(results).toEqual([]);
    });

    it('should validate each OIB independently', () => {
      const oibs = ['12345678903', 'invalid', '98765432106'];
      const results = validateOIBBatch(oibs);

      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(false);
      expect(results[2].valid).toBe(true);
    });
  });

  describe('generateValidOIB', () => {
    it('should generate valid OIB without prefix', () => {
      const oib = generateValidOIB();
      const result = validateOIB(oib);

      expect(result.valid).toBe(true);
      expect(oib).toHaveLength(11);
      expect(oib[0]).not.toBe('0');
    });

    it('should generate valid OIB with provided prefix', () => {
      const prefix = '1234567890';
      const oib = generateValidOIB(prefix);
      const result = validateOIB(oib);

      expect(result.valid).toBe(true);
      expect(oib.substring(0, 10)).toBe(prefix);
    });

    it('should reject prefix with wrong length', () => {
      expect(() => generateValidOIB('123')).toThrow('Prefix must be exactly 10 digits');
    });

    it('should reject non-numeric prefix', () => {
      expect(() => generateValidOIB('123456789A')).toThrow('Prefix must be exactly 10 digits');
    });

    it('should reject prefix starting with 0', () => {
      expect(() => generateValidOIB('0123456789')).toThrow('First digit cannot be 0');
    });

    it('should generate different OIBs on multiple calls', () => {
      const oib1 = generateValidOIB();
      const oib2 = generateValidOIB();
      const oib3 = generateValidOIB();

      // With high probability, at least two should be different
      const allSame = oib1 === oib2 && oib2 === oib3;
      expect(allSame).toBe(false);
    });
  });

  describe('determineOIBType', () => {
    it('should return unknown type', () => {
      const type = determineOIBType('12345678903');
      expect(type).toBe('unknown');
    });

    it('should handle any valid OIB', () => {
      const type = determineOIBType('98765432108');
      expect(['business', 'personal', 'unknown']).toContain(type);
    });
  });

  // Property-based tests using fast-check
  describe('Property-Based Tests', () => {
    it('should always validate generated OIBs as valid', () => {
      fc.assert(
        fc.property(fc.integer({ min: 1000000000, max: 9999999999 }), (prefix) => {
          const prefixStr = prefix.toString();
          const oib = generateValidOIB(prefixStr);
          const result = validateOIB(oib);
          return result.valid === true;
        }),
        { numRuns: 100 }
      );
    });

    it('should always reject OIBs with modified check digit', () => {
      fc.assert(
        fc.property(fc.integer({ min: 1000000000, max: 9999999999 }), (prefix) => {
          const prefixStr = prefix.toString();
          const validOIB = generateValidOIB(prefixStr);

          // Modify check digit
          const checkDigit = parseInt(validOIB[10], 10);
          const wrongCheckDigit = (checkDigit + 1) % 10;
          const invalidOIB = validOIB.substring(0, 10) + wrongCheckDigit.toString();

          const result = validateOIB(invalidOIB);
          return result.valid === false;
        }),
        { numRuns: 100 }
      );
    });

    it('should always reject OIBs shorter than 11 digits', () => {
      fc.assert(
        fc.property(fc.string({ minLength: 1, maxLength: 10 }), (shortString) => {
          // Only test numeric strings to focus on length validation
          if (!/^\d+$/.test(shortString)) {
            return true; // Skip non-numeric
          }

          const result = validateOIB(shortString);
          return result.valid === false;
        }),
        { numRuns: 50 }
      );
    });

    it('should handle all possible first digits (1-9)', () => {
      fc.assert(
        fc.property(fc.integer({ min: 1, max: 9 }), (firstDigit) => {
          const prefix = firstDigit.toString() + '000000000';
          const oib = generateValidOIB(prefix);
          const result = validateOIB(oib);
          return result.valid === true && oib[0] === firstDigit.toString();
        }),
        { numRuns: 50 }
      );
    });

    it('should consistently validate the same OIB', () => {
      fc.assert(
        fc.property(fc.integer({ min: 1000000000, max: 9999999999 }), (prefix) => {
          const prefixStr = prefix.toString();
          const oib = generateValidOIB(prefixStr);

          const result1 = validateOIB(oib);
          const result2 = validateOIB(oib);

          return result1.valid === result2.valid && result1.valid === true;
        }),
        { numRuns: 100 }
      );
    });
  });

  // Edge cases and error conditions
  describe('Edge Cases', () => {
    it('should handle OIB with all same digits except check digit', () => {
      const result = validateOIB('11111111119');
      expect(result.valid).toBe(true);
    });

    it('should handle OIB starting with 9', () => {
      const result = validateOIB('98765432106');
      expect(result.valid).toBe(true);
    });

    it('should reject undefined as OIB', () => {
      const result = validateOIB(undefined as any);
      expect(result.valid).toBe(false);
    });

    it('should reject null as OIB', () => {
      const result = validateOIB(null as any);
      expect(result.valid).toBe(false);
    });

    it('should reject object as OIB', () => {
      const result = validateOIB({} as any);
      expect(result.valid).toBe(false);
    });

    it('should reject number as OIB', () => {
      const result = validateOIB(12345678903 as any);
      expect(result.valid).toBe(false);
    });
  });
});
