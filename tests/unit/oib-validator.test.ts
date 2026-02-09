import {
  validateOIB,
  validateOIBFormat,
  validateOIBChecksum,
  validateOIBBatch,
  generateValidOIB,
  determineOIBType,
  type OIBValidationResult,
} from '../../src/validation/oib-validator';

describe('OIB Validator', () => {
  describe('validateOIB', () => {
    it('should accept valid OIB (Test 2.1)', () => {
      // Known valid OIB from Croatian Tax Authority documentation
      const result = validateOIB('33392005961');
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.oib).toBe('33392005961');
    });

    it('should reject invalid checksum (Test 2.2)', () => {
      const result = validateOIB('12345678901');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid OIB checksum (ISO 7064, MOD 11-10)');
      expect(result.metadata.checksumValid).toBe(false);
    });

    it('should reject wrong length (Test 2.3)', () => {
      const result = validateOIB('123');
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('exactly 11 digits'))).toBe(true);
    });

    it('should reject empty OIB (Test 2.4)', () => {
      const result = validateOIB('');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('OIB is required');
    });

    it('should reject non-numeric OIB (Test 2.5)', () => {
      const result = validateOIB('abcdefghijk');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('OIB must contain only digits');
    });

    it('should reject OIB starting with 0', () => {
      const result = validateOIB('01234567890');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('OIB first digit cannot be 0');
    });

    it('should trim whitespace', () => {
      const result = validateOIB('  33392005961  ');
      expect(result.valid).toBe(true);
      expect(result.oib).toBe('33392005961');
    });

    it('should handle null/undefined', () => {
      const result1 = validateOIB(null as unknown as string);
      expect(result1.valid).toBe(false);
      expect(result1.errors).toContain('OIB is required');

      const result2 = validateOIB(undefined as unknown as string);
      expect(result2.valid).toBe(false);
      expect(result2.errors).toContain('OIB is required');
    });
  });

  describe('validateOIBFormat', () => {
    it('should return no errors for valid format', () => {
      const errors = validateOIBFormat('33392005961');
      expect(errors).toEqual([]);
    });

    it('should return length error', () => {
      const errors = validateOIBFormat('123');
      expect(errors).toContain('OIB must be exactly 11 digits (got 3)');
    });

    it('should return digits-only error', () => {
      const errors = validateOIBFormat('12345a67890');
      expect(errors).toContain('OIB must contain only digits');
    });

    it('should return first-digit error', () => {
      const errors = validateOIBFormat('01234567890');
      expect(errors).toContain('OIB first digit cannot be 0');
    });

    it('should return multiple errors', () => {
      const errors = validateOIBFormat('abc');
      expect(errors.length).toBeGreaterThan(1);
    });
  });

  describe('validateOIBChecksum', () => {
    it('should validate correct checksum', () => {
      expect(validateOIBChecksum('33392005961')).toBe(true);
    });

    it('should reject incorrect checksum', () => {
      expect(validateOIBChecksum('12345678901')).toBe(false);
    });

    it('should reject non-numeric', () => {
      expect(validateOIBChecksum('abcdefghijk')).toBe(false);
    });

    it('should reject wrong length', () => {
      expect(validateOIBChecksum('123')).toBe(false);
    });
  });

  describe('determineOIBType', () => {
    it('should return unknown (cannot determine from format)', () => {
      const type = determineOIBType('33392005961');
      expect(type).toBe('unknown');
    });
  });

  describe('validateOIBBatch (Test 2.6)', () => {
    it('should validate multiple OIBs', () => {
      const results = validateOIBBatch(['33392005961', '12345678901', '99999999999']);
      expect(results).toHaveLength(3);
      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(false);
      expect(results[2].valid).toBe(false); // Wrong checksum
    });

    it('should return correct number of results', () => {
      const results = validateOIBBatch(['33392005961', '33392005961']);
      expect(results).toHaveLength(2);
    });
  });

  describe('generateValidOIB (Test 2.7, 2.8)', () => {
    it('should generate valid OIB with random prefix', () => {
      const oib = generateValidOIB();
      expect(oib).toHaveLength(11);
      expect(/^\d+$/.test(oib)).toBe(true);
      expect(oib[0]).not.toBe('0');

      const result = validateOIB(oib);
      expect(result.valid).toBe(true);
    });

    it('should generate valid OIB with custom prefix', () => {
      const oib = generateValidOIB('1234567890');
      expect(oib).toBe('12345678903');
      expect(validateOIB(oib).valid).toBe(true);
    });

    it('should be deterministic (Test 2.7)', () => {
      const oib1 = generateValidOIB('9876543210');
      const oib2 = generateValidOIB('9876543210');
      expect(oib1).toBe(oib2);
    });

    it('should reject invalid prefix', () => {
      expect(() => generateValidOIB('123')).toThrow('Prefix must be exactly 10 digits');
      expect(() => generateValidOIB('0123456789')).toThrow('First digit cannot be 0');
      expect(() => generateValidOIB('abcdefghij')).toThrow();
    });

    it('should have zero external dependencies (Test 2.8)', () => {
      const fs = require('fs');
      const content = fs.readFileSync('src/validation/oib-validator.ts', 'utf8');
      const importMatches = content.match(/^import/gm);
      expect(importMatches).toBeNull();
    });
  });

  describe('OIBValidationResult type', () => {
    it('should have correct structure', () => {
      const result: OIBValidationResult = {
        oib: '33392005961',
        valid: true,
        errors: [],
        metadata: {
          type: 'unknown',
          checksumValid: true,
        },
      };
      expect(result.valid).toBe(true);
    });
  });
});
