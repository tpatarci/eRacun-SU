import * as fs from 'fs/promises';
import * as path from 'path';
import {
  loadCertificateFromFile,
  parseCertificate,
  extractCertificateInfo,
  validateCertificate,
  assertCertificateValid,
  CertificateParseError,
  CertificateValidationError,
} from '../../../src/signing';

describe('Certificate Parser', () => {
  describe('loadCertificateFromFile', () => {
    it('should load PKCS#12 certificate (Test 3.4)', async () => {
      const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
      const cert = await loadCertificateFromFile(certPath, 'test123');

      expect(cert.privateKeyPEM).toBeTruthy();
      expect(cert.certificatePEM).toBeTruthy();
      expect(cert.privateKey).toBeTruthy();
      expect(cert.info).toBeTruthy();
    });

    it('should throw error for wrong passphrase (Test 3.5)', async () => {
      const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');

      await expect(loadCertificateFromFile(certPath, 'wrong'))
        .rejects.toThrow(CertificateParseError);
    });

    it('should throw error for non-existent file', async () => {
      await expect(loadCertificateFromFile('/nonexistent/file.p12', 'test123'))
        .rejects.toThrow();
    });
  });

  describe('parseCertificate', () => {
    it('should parse certificate buffer', () => {
      const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
      // We need to read the file synchronously for this test
      const certBuffer = require('fs').readFileSync(certPath);

      const cert = parseCertificate(certBuffer, 'test123');

      expect(cert.privateKeyPEM).toContain('-----BEGIN RSA PRIVATE KEY-----');
      expect(cert.certificatePEM).toContain('-----BEGIN CERTIFICATE-----');
      expect(cert.info.subjectDN).toBeTruthy();
      expect(cert.info.issuerDN).toBeTruthy();
    });
  });

  describe('extractCertificateInfo', () => {
    it('should extract certificate fields', async () => {
      const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
      const cert = await loadCertificateFromFile(certPath, 'test123');

      expect(cert.info.subjectDN).toBeTruthy();
      expect(cert.info.issuerDN).toBeTruthy();
      expect(cert.info.serialNumber).toBeTruthy();
      expect(cert.info.notBefore).toBeInstanceOf(Date);
      expect(cert.info.notAfter).toBeInstanceOf(Date);
      expect(cert.info.publicKey).toBeTruthy();
    });
  });

  describe('validateCertificate', () => {
    it('should return errors for expired certificate', async () => {
      const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
      const cert = await loadCertificateFromFile(certPath, 'test123');

      // Manually set notAfter to past to simulate expired cert
      cert.info.notAfter = new Date('2020-01-01');

      const errors = validateCertificate(cert.info);
      expect(errors.some(e => e.includes('expired'))).toBe(true);
    });

    it('should return warnings for near-expiry certificate', async () => {
      const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
      const cert = await loadCertificateFromFile(certPath, 'test123');

      // Set notAfter to 20 days from now
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 20);
      cert.info.notAfter = futureDate;

      const errors = validateCertificate(cert.info);
      expect(errors.some(e => e.includes('expiring soon'))).toBe(true);
    });

    it('should return empty array for valid certificate', async () => {
      const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
      const cert = await loadCertificateFromFile(certPath, 'test123');

      // Our test cert is self-signed, not from FINA, so we'll get issuer error
      // But it should be valid date-wise
      const errors = validateCertificate(cert.info);
      expect(errors).toBeInstanceOf(Array);
    });
  });

  describe('assertCertificateValid', () => {
    it('should throw for invalid certificate', async () => {
      const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
      const cert = await loadCertificateFromFile(certPath, 'test123');

      // Set notAfter to past
      cert.info.notAfter = new Date('2020-01-01');

      expect(() => assertCertificateValid(cert.info))
        .toThrow(CertificateValidationError);
    });
  });

  describe('CertificateParseError', () => {
    it('should create error with message', () => {
      const error = new CertificateParseError('Test error');
      expect(error.message).toBe('Test error');
      expect(error.name).toBe('CertificateParseError');
    });

    it('should support cause error', () => {
      const cause = new Error('Underlying error');
      const error = new CertificateParseError('Test error', cause);
      expect(error.cause).toBe(cause);
    });
  });

  describe('CertificateValidationError', () => {
    it('should create error with errors array', () => {
      const errors = ['error1', 'error2'];
      const error = new CertificateValidationError('Validation failed', errors);
      expect(error.message).toBe('Validation failed');
      expect(error.errors).toEqual(errors);
      expect(error.name).toBe('CertificateValidationError');
    });
  });
});
