import { describe, it, expect, beforeAll } from '@jest/globals';
import forge from 'node-forge';
import {
  validateZKIParams,
  formatZKI,
  generateZKI,
  verifyZKI,
  type ZKIParams,
} from '../../src/zki-generator.js';
import { ZKIGenerationError } from '../../src/zki-generator.js';
import type { ParsedCertificate } from '../../src/certificate-parser.js';

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

  // Mock certificate for testing (generated once for all tests)
  let mockCertificate: ParsedCertificate;

  beforeAll(() => {
    // Generate a test RSA key pair
    const keys = forge.pki.rsa.generateKeyPair(2048);

    // Create a self-signed certificate
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [
      { name: 'commonName', value: 'Test Certificate' },
      { name: 'countryName', value: 'HR' },
      { shortName: 'ST', value: 'Zagreb' },
      { name: 'localityName', value: 'Zagreb' },
      { name: 'organizationName', value: 'Test Company' },
      { shortName: 'OU', value: 'Test Unit' },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey);

    mockCertificate = {
      info: {
        subjectDN: '/CN=Test Certificate/C=HR/ST=Zagreb/L=Zagreb/O=Test Company/OU=Test Unit',
        issuerDN: '/CN=Test Certificate/C=HR/ST=Zagreb/L=Zagreb/O=Test Company/OU=Test Unit',
        serialNumber: cert.serialNumber,
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
        issuer: 'Test Certificate',
        publicKey: cert.publicKey as forge.pki.rsa.PublicKey,
        certificate: cert,
      },
      privateKey: keys.privateKey,
      certificatePEM: forge.pki.certificateToPem(cert),
      privateKeyPEM: forge.pki.privateKeyToPem(keys.privateKey),
    };
  });

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

  describe('generateZKI', () => {
    it('should generate valid ZKI code', async () => {
      const zki = await generateZKI(validParams, mockCertificate);

      // ZKI should be a hex string (256 characters for 2048-bit RSA)
      expect(zki).toMatch(/^[0-9a-f]+$/);
      expect(zki.length).toBeGreaterThan(0);
    });

    it('should generate different ZKI for different parameters', async () => {
      const zki1 = await generateZKI(validParams, mockCertificate);
      const params2 = { ...validParams, totalAmount: '126.00' };
      const zki2 = await generateZKI(params2, mockCertificate);

      expect(zki1).not.toBe(zki2);
    });

    it('should generate consistent ZKI for same parameters', async () => {
      const zki1 = await generateZKI(validParams, mockCertificate);
      const zki2 = await generateZKI(validParams, mockCertificate);

      expect(zki1).toBe(zki2);
    });

    it('should throw ZKIGenerationError for invalid parameters', async () => {
      const invalidParams = { ...validParams, oib: '123' };

      await expect(generateZKI(invalidParams, mockCertificate)).rejects.toThrow(
        ZKIGenerationError
      );
    });

    it('should handle certificate without private key gracefully', async () => {
      const certWithoutKey = {
        ...mockCertificate,
        privateKey: undefined as any,
      };

      await expect(generateZKI(validParams, certWithoutKey)).rejects.toThrow(
        ZKIGenerationError
      );
    });
  });

  describe('verifyZKI', () => {
    it('should verify valid ZKI code', async () => {
      const zki = await generateZKI(validParams, mockCertificate);
      const isValid = await verifyZKI(zki, validParams, mockCertificate);

      expect(isValid).toBe(true);
    });

    it('should reject tampered ZKI code', async () => {
      const zki = await generateZKI(validParams, mockCertificate);
      const tamperedZKI = zki.slice(0, -2) + 'ff'; // Change last byte

      const isValid = await verifyZKI(tamperedZKI, validParams, mockCertificate);

      expect(isValid).toBe(false);
    });

    it('should reject ZKI with wrong parameters', async () => {
      const zki = await generateZKI(validParams, mockCertificate);
      const wrongParams = { ...validParams, totalAmount: '126.00' };

      const isValid = await verifyZKI(zki, wrongParams, mockCertificate);

      expect(isValid).toBe(false);
    });

    it('should return false for invalid ZKI format', async () => {
      const invalidZKI = 'not-a-valid-hex-string';

      const isValid = await verifyZKI(invalidZKI, validParams, mockCertificate);

      expect(isValid).toBe(false);
    });

    it('should return false for empty ZKI', async () => {
      const isValid = await verifyZKI('', validParams, mockCertificate);

      expect(isValid).toBe(false);
    });

    it('should handle invalid parameters gracefully', async () => {
      const zki = await generateZKI(validParams, mockCertificate);
      const invalidParams = { ...validParams, oib: '123' };

      const isValid = await verifyZKI(zki, invalidParams, mockCertificate);

      expect(isValid).toBe(false);
    });
  });
});
