/**
 * Property-Based Tests for OIB Validation
 * Uses fast-check to generate hundreds of test cases
 */

import fc from 'fast-check';
import { InvoiceGenerator } from '../src/InvoiceGenerator';

describe('OIB Validation - Property-Based Tests', () => {
  describe('Valid OIB Generation', () => {
    it('should always generate valid 11-digit OIBs', () => {
      fc.assert(
        fc.property(fc.integer({ min: 1, max: 1000 }), () => {
          const oib = InvoiceGenerator.generateValidOIB();

          // Must be exactly 11 digits
          expect(oib).toMatch(/^\d{11}$/);

          // Must pass check digit validation
          expect(isValidOIBCheckDigit(oib)).toBe(true);

          return true;
        }),
        { numRuns: 1000 }
      );
    });

    it('should generate diverse OIBs (not all the same)', () => {
      const oibs = new Set<string>();

      fc.assert(
        fc.property(fc.integer({ min: 1, max: 100 }), () => {
          const oib = InvoiceGenerator.generateValidOIB();
          oibs.add(oib);
          return true;
        }),
        { numRuns: 100 }
      );

      // Should have generated at least 90 unique OIBs out of 100
      expect(oibs.size).toBeGreaterThan(90);
    });
  });

  describe('Check Digit Algorithm', () => {
    it('should calculate correct check digit for any 10-digit sequence', () => {
      fc.assert(
        fc.property(
          fc.array(fc.integer({ min: 0, max: 9 }), { minLength: 10, maxLength: 10 }),
          (digits) => {
            const checkDigit = calculateOIBCheckDigit(digits);

            // Check digit must be 0-9
            expect(checkDigit).toBeGreaterThanOrEqual(0);
            expect(checkDigit).toBeLessThanOrEqual(9);

            // Full OIB with check digit must validate
            const oib = digits.join('') + checkDigit;
            expect(isValidOIBCheckDigit(oib)).toBe(true);

            return true;
          }
        ),
        { numRuns: 500 }
      );
    });

    it('should reject OIBs with incorrect check digits', () => {
      fc.assert(
        fc.property(
          fc.array(fc.integer({ min: 0, max: 9 }), { minLength: 10, maxLength: 10 }),
          fc.integer({ min: 0, max: 9 }),
          (digits, wrongCheckDigit) => {
            const correctCheckDigit = calculateOIBCheckDigit(digits);

            // Skip if wrong digit happens to be correct
            if (wrongCheckDigit === correctCheckDigit) {
              return true;
            }

            const invalidOIB = digits.join('') + wrongCheckDigit;
            expect(isValidOIBCheckDigit(invalidOIB)).toBe(false);

            return true;
          }
        ),
        { numRuns: 500 }
      );
    });
  });

  describe('Edge Cases', () => {
    it('should handle all zeros except check digit', () => {
      const digits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      const checkDigit = calculateOIBCheckDigit(digits);
      const oib = '0000000000' + checkDigit;

      expect(isValidOIBCheckDigit(oib)).toBe(true);
    });

    it('should handle all nines except check digit', () => {
      const digits = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
      const checkDigit = calculateOIBCheckDigit(digits);
      const oib = '9999999999' + checkDigit;

      expect(isValidOIBCheckDigit(oib)).toBe(true);
    });

    it('should reject OIBs with wrong length', () => {
      expect(isValidOIBCheckDigit('123456789')).toBe(false); // Too short
      expect(isValidOIBCheckDigit('123456789012')).toBe(false); // Too long
      expect(isValidOIBCheckDigit('')).toBe(false); // Empty
    });

    it('should reject OIBs with non-numeric characters', () => {
      expect(isValidOIBCheckDigit('1234567890A')).toBe(false);
      expect(isValidOIBCheckDigit('12345 67890')).toBe(false);
      expect(isValidOIBCheckDigit('12345-67890')).toBe(false);
    });
  });

  describe('Known Valid OIBs', () => {
    // Test with known valid OIBs (if available from documentation)
    it('should validate known valid Croatian OIBs', () => {
      const knownValidOIBs = [
        '12345678903', // Example (check digit calculated)
        '98765432106', // Example (check digit calculated)
      ];

      knownValidOIBs.forEach((oib) => {
        expect(isValidOIBCheckDigit(oib)).toBe(true);
      });
    });
  });
});

describe('KPD Code Validation - Property-Based Tests', () => {
  describe('Valid KPD Format', () => {
    it('should validate all 6-digit codes', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 999999 }),
          (code) => {
            const kpdCode = code.toString().padStart(6, '0');

            // Must be exactly 6 digits
            expect(kpdCode).toMatch(/^\d{6}$/);
            expect(kpdCode.length).toBe(6);

            return true;
          }
        ),
        { numRuns: 1000 }
      );
    });

    it('should reject invalid KPD formats', () => {
      const invalidCodes = [
        '12345',     // Too short
        '1234567',   // Too long
        'ABCDEF',    // Letters
        '12-345',    // Dashes
        '',          // Empty
        '12 345',    // Spaces
      ];

      invalidCodes.forEach((code) => {
        expect(isValidKPDFormat(code)).toBe(false);
      });
    });
  });

  describe('KLASUS 2025 Code Ranges', () => {
    it('should accept codes in valid KLASUS ranges', () => {
      // KLASUS codes typically start with specific prefixes
      const validPrefixes = ['01', '02', '03', '04', '05', '06', '07', '08', '09'];

      fc.assert(
        fc.property(
          fc.constantFrom(...validPrefixes),
          fc.integer({ min: 0, max: 9999 }),
          (prefix, suffix) => {
            const kpdCode = prefix + suffix.toString().padStart(4, '0');

            expect(kpdCode).toMatch(/^\d{6}$/);
            expect(isValidKPDFormat(kpdCode)).toBe(true);

            return true;
          }
        ),
        { numRuns: 500 }
      );
    });
  });

  describe('Edge Cases', () => {
    it('should handle all zeros', () => {
      expect(isValidKPDFormat('000000')).toBe(true);
    });

    it('should handle all nines', () => {
      expect(isValidKPDFormat('999999')).toBe(true);
    });

    it('should handle leading zeros', () => {
      expect(isValidKPDFormat('000001')).toBe(true);
      expect(isValidKPDFormat('000123')).toBe(true);
    });
  });
});

describe('VAT Number Validation - Property-Based Tests', () => {
  describe('Croatian VAT Format (HR + 11-digit OIB)', () => {
    it('should validate VAT numbers with valid OIB', () => {
      fc.assert(
        fc.property(fc.integer({ min: 1, max: 100 }), () => {
          const oib = InvoiceGenerator.generateValidOIB();
          const vatNumber = `HR${oib}`;

          expect(isValidCroatianVAT(vatNumber)).toBe(true);

          return true;
        }),
        { numRuns: 200 }
      );
    });

    it('should reject VAT numbers with invalid OIB', () => {
      fc.assert(
        fc.property(
          fc.array(fc.integer({ min: 0, max: 9 }), { minLength: 10, maxLength: 10 }),
          fc.integer({ min: 0, max: 9 }),
          (digits, wrongCheckDigit) => {
            const correctCheckDigit = calculateOIBCheckDigit(digits);

            // Skip if wrong digit happens to be correct
            if (wrongCheckDigit === correctCheckDigit) {
              return true;
            }

            const invalidOIB = digits.join('') + wrongCheckDigit;
            const vatNumber = `HR${invalidOIB}`;

            expect(isValidCroatianVAT(vatNumber)).toBe(false);

            return true;
          }
        ),
        { numRuns: 200 }
      );
    });

    it('should reject VAT numbers without HR prefix', () => {
      const oib = InvoiceGenerator.generateValidOIB();
      expect(isValidCroatianVAT(oib)).toBe(false);
    });

    it('should reject VAT numbers with wrong country codes', () => {
      const oib = InvoiceGenerator.generateValidOIB();
      expect(isValidCroatianVAT(`DE${oib}`)).toBe(false);
      expect(isValidCroatianVAT(`SI${oib}`)).toBe(false);
      expect(isValidCroatianVAT(`IT${oib}`)).toBe(false);
    });
  });
});

// Helper functions (matching implementation in InvoiceGenerator)
function calculateOIBCheckDigit(digits: number[]): number {
  let a = 10;
  for (const digit of digits) {
    a = ((a + digit) % 10 || 10) * 2 % 11;
  }
  return (11 - a) % 10;
}

function isValidOIBCheckDigit(oib: string): boolean {
  if (!/^\d{11}$/.test(oib)) {
    return false;
  }

  const digits = oib.substring(0, 10).split('').map(Number);
  const checkDigit = parseInt(oib[10], 10);
  const expectedCheckDigit = calculateOIBCheckDigit(digits);

  return checkDigit === expectedCheckDigit;
}

function isValidKPDFormat(code: string): boolean {
  return /^\d{6}$/.test(code);
}

function isValidCroatianVAT(vat: string): boolean {
  if (!vat.startsWith('HR')) {
    return false;
  }

  const oib = vat.substring(2);
  return isValidOIBCheckDigit(oib);
}
