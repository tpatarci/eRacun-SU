import * as path from 'path';
import {
  loadCertificateFromFile,
  generateZKI,
  verifyZKI,
  formatZKI,
  validateZKIParams,
  ZKIGenerationError,
  type ZKIParams,
} from '../../../src/signing';

describe('ZKI Generator', () => {
  let testCertificate: Awaited<ReturnType<typeof loadCertificateFromFile>>;

  beforeAll(async () => {
    const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
    testCertificate = await loadCertificateFromFile(certPath, 'test123');
  });

  describe('generateZKI', () => {
    const validParams: ZKIParams = {
      oib: '12345678903',
      issueDateTime: '2026-01-15T10:30:00',
      invoiceNumber: '1/PP1/1',
      businessPremises: 'PP1',
      cashRegister: '1',
      totalAmount: '1250.00',
    };

    it('should generate hex ZKI code (Test 3.6)', async () => {
      const zki = await generateZKI(validParams, testCertificate);

      // RSA 2048-bit signature produces 256 bytes = 512 hex chars
      expect(zki.length).toBeGreaterThan(0);
      expect(/^[0-9a-f]+$/.test(zki)).toBe(true);
    });

    it('should be deterministic with same inputs (Test 3.7)', async () => {
      const zki1 = await generateZKI(validParams, testCertificate);
      const zki2 = await generateZKI(validParams, testCertificate);

      expect(zki1).toBe(zki2);
    });

    it('should validate parameters before generation', async () => {
      const invalidParams = { ...validParams, oib: '123' };

      await expect(generateZKI(invalidParams, testCertificate))
        .rejects.toThrow(ZKIGenerationError);
    });
  });

  describe('verifyZKI', () => {
    const validParams: ZKIParams = {
      oib: '12345678903',
      issueDateTime: '2026-01-15T10:30:00',
      invoiceNumber: '1/PP1/1',
      businessPremises: 'PP1',
      cashRegister: '1',
      totalAmount: '1250.00',
    };

    it('should verify correctly generated ZKI', async () => {
      const zki = await generateZKI(validParams, testCertificate);
      const isValid = await verifyZKI(zki, validParams, testCertificate);

      expect(isValid).toBe(true);
    });

    it('should reject tampered ZKI', async () => {
      const zki = await generateZKI(validParams, testCertificate);
      const tamperedZKI = zki.slice(0, -1) + '0';

      const isValid = await verifyZKI(tamperedZKI, validParams, testCertificate);
      expect(isValid).toBe(false);
    });
  });

  describe('validateZKIParams', () => {
    const validParams: ZKIParams = {
      oib: '12345678903',
      issueDateTime: '2026-01-15T10:30:00',
      invoiceNumber: '1/PP1/1',
      businessPremises: 'PP1',
      cashRegister: '1',
      totalAmount: '1250.00',
    };

    it('should accept valid parameters', () => {
      expect(() => validateZKIParams(validParams)).not.toThrow();
    });

    it('should reject invalid OIB', () => {
      const invalidParams = { ...validParams, oib: '123' };
      expect(() => validateZKIParams(invalidParams)).toThrow('OIB must be 11 digits');
    });

    it('should reject invalid issueDateTime', () => {
      const invalidParams = { ...validParams, issueDateTime: 'invalid-date' };
      expect(() => validateZKIParams(invalidParams)).toThrow('ISO 8601 format');
    });

    it('should reject empty invoiceNumber', () => {
      const invalidParams = { ...validParams, invoiceNumber: '' };
      expect(() => validateZKIParams(invalidParams)).toThrow('Invoice number is required');
    });

    it('should reject empty businessPremises', () => {
      const invalidParams = { ...validParams, businessPremises: '' };
      expect(() => validateZKIParams(invalidParams)).toThrow('Business premises identifier is required');
    });

    it('should reject empty cashRegister', () => {
      const invalidParams = { ...validParams, cashRegister: '' };
      expect(() => validateZKIParams(invalidParams)).toThrow('Cash register identifier is required');
    });

    it('should reject invalid totalAmount', () => {
      const invalidParams = { ...validParams, totalAmount: 'abc' };
      expect(() => validateZKIParams(invalidParams)).toThrow('Total amount must be a valid number');
    });
  });

  describe('formatZKI', () => {
    it('should format ZKI with dashes', () => {
      const zki = 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890';
      const formatted = formatZKI(zki);

      // Should contain dashes every 8 characters
      expect(formatted).toContain('-');
      expect(formatted.split('-')[0]).toHaveLength(8);
    });

    it('should handle empty string', () => {
      expect(formatZKI('')).toBe('');
    });

    it('should handle odd-length ZKI', () => {
      const zki = 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f6789';
      const formatted = formatZKI(zki);

      expect(formatted).toContain('-');
    });
  });

  describe('ZKIGenerationError', () => {
    it('should create error with message', () => {
      const error = new ZKIGenerationError('Test error');
      expect(error.message).toBe('Test error');
      expect(error.name).toBe('ZKIGenerationError');
    });

    it('should support cause error', () => {
      const cause = new Error('Underlying error');
      const error = new ZKIGenerationError('Test error', cause);
      expect(error.cause).toBe(cause);
    });
  });
});
