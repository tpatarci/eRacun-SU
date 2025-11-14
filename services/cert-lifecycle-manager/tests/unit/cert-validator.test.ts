import {
  validateCertificate,
  isExpiringSoon,
  isExpired,
  isTrustedIssuer,
  getCertificateStatus,
  getCertificateStatusWithRevocation,
  getAlertSeverity,
} from '../../src/cert-validator';
import { CertificateInfo } from '../../src/cert-parser';

// Mock revocation checker
jest.mock('../../src/revocation-check', () => ({
  getRevocationChecker: jest.fn(() => ({
    checkRevocation: jest.fn().mockResolvedValue({
      revoked: false,
      method: 'mock',
      checkedAt: new Date(),
    }),
  })),
}));

// Helper to create test certificate
function createTestCertificate(
  overrides: Partial<CertificateInfo> = {}
): CertificateInfo {
  const now = new Date();
  const futureDate = new Date();
  futureDate.setFullYear(futureDate.getFullYear() + 1);

  return {
    subjectDn: 'CN=Test Certificate, O=Test Org',
    serialNumber: '1234567890',
    issuer: 'Fina RDC 2015 CA',
    notBefore: now,
    notAfter: futureDate,
    fingerprint: 'ABCDEF1234567890',
    publicKey: 'PUBLIC_KEY',
    certType: 'production',
    ...overrides,
  };
}

describe('cert-validator', () => {
  describe('validateCertificate', () => {
    it('should validate a valid FINA certificate', async () => {
      const cert = createTestCertificate();

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject expired certificate', async () => {
      const pastDate = new Date();
      pastDate.setFullYear(pastDate.getFullYear() - 1);

      const cert = createTestCertificate({
        notAfter: pastDate,
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('expired'))).toBe(true);
    });

    it('should reject certificate not yet valid', async () => {
      const futureDate = new Date();
      futureDate.setFullYear(futureDate.getFullYear() + 1);

      const cert = createTestCertificate({
        notBefore: futureDate,
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('not yet valid'))).toBe(true);
    });

    it('should reject certificate from untrusted issuer', async () => {
      const cert = createTestCertificate({
        issuer: 'Untrusted CA',
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('not issued by trusted CA'))).toBe(
        true
      );
    });

    it('should warn about expiring certificate (within 30 days)', async () => {
      const soonDate = new Date();
      soonDate.setDate(soonDate.getDate() + 15);

      const cert = createTestCertificate({
        notAfter: soonDate,
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(true);
      expect(result.warnings.some((w) => w.includes('expiring soon'))).toBe(true);
    });

    it('should reject certificate with missing serial number', async () => {
      const cert = createTestCertificate({
        serialNumber: '',
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('serial number'))).toBe(true);
    });

    it('should reject certificate with missing subject DN', async () => {
      const cert = createTestCertificate({
        subjectDn: '',
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('subject DN'))).toBe(true);
    });

    it('should reject certificate with missing fingerprint', async () => {
      const cert = createTestCertificate({
        fingerprint: '',
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('fingerprint'))).toBe(true);
    });

    it('should warn about unknown certificate type', async () => {
      const cert = createTestCertificate({
        certType: 'invalid' as any,
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(true); // Not an error, just a warning
      expect(result.warnings.some((w) => w.includes('Unknown certificate type'))).toBe(true);
    });

    it('should warn about demo certificate in production environment', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const cert = createTestCertificate({
        certType: 'demo',
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(true);
      expect(result.warnings.some((w) => w.includes('Demo certificate detected in production'))).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });

    it('should warn about unusual validity period for production certificate', async () => {
      const now = new Date();
      const veryFarFuture = new Date();
      veryFarFuture.setFullYear(veryFarFuture.getFullYear() + 6); // 6 years (>1900 days)

      const cert = createTestCertificate({
        notBefore: now,
        notAfter: veryFarFuture,
        certType: 'production',
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(true);
      expect(result.warnings.some((w) => w.includes('Unusual validity period for production'))).toBe(true);
    });

    it('should warn about unusual validity period for demo certificate', async () => {
      const now = new Date();
      const tooLongDemo = new Date();
      tooLongDemo.setDate(tooLongDemo.getDate() + 450); // >400 days

      const cert = createTestCertificate({
        notBefore: now,
        notAfter: tooLongDemo,
        certType: 'demo',
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(true);
      expect(result.warnings.some((w) => w.includes('Unusual validity period for demo'))).toBe(true);
    });

    it('should handle validation error gracefully', async () => {
      // Force error by passing null as certificate (triggers exception)
      await expect(
        validateCertificate(null as any)
      ).rejects.toThrow();
    });
  });

  describe('isExpiringSoon', () => {
    it('should return true for certificate expiring in 15 days', () => {
      const soonDate = new Date();
      soonDate.setDate(soonDate.getDate() + 15);

      const cert = createTestCertificate({ notAfter: soonDate });

      expect(isExpiringSoon(cert, 30)).toBe(true);
    });

    it('should return false for certificate expiring in 60 days', () => {
      const farDate = new Date();
      farDate.setDate(farDate.getDate() + 60);

      const cert = createTestCertificate({ notAfter: farDate });

      expect(isExpiringSoon(cert, 30)).toBe(false);
    });

    it('should return false for expired certificate', () => {
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 10);

      const cert = createTestCertificate({ notAfter: pastDate });

      expect(isExpiringSoon(cert, 30)).toBe(false);
    });

    it('should use custom threshold', () => {
      const date = new Date();
      date.setDate(date.getDate() + 5);

      const cert = createTestCertificate({ notAfter: date });

      expect(isExpiringSoon(cert, 7)).toBe(true);
      expect(isExpiringSoon(cert, 3)).toBe(false);
    });
  });

  describe('isExpired', () => {
    it('should return true for expired certificate', () => {
      const pastDate = new Date();
      pastDate.setFullYear(pastDate.getFullYear() - 1);

      const cert = createTestCertificate({ notAfter: pastDate });

      expect(isExpired(cert)).toBe(true);
    });

    it('should return false for valid certificate', () => {
      const futureDate = new Date();
      futureDate.setFullYear(futureDate.getFullYear() + 1);

      const cert = createTestCertificate({ notAfter: futureDate });

      expect(isExpired(cert)).toBe(false);
    });
  });

  describe('isTrustedIssuer', () => {
    it('should return true for FINA issuer', () => {
      const cert = createTestCertificate({ issuer: 'Fina RDC 2015 CA' });

      expect(isTrustedIssuer(cert)).toBe(true);
    });

    it('should return true for Fina Root CA', () => {
      const cert = createTestCertificate({ issuer: 'Fina Root CA' });

      expect(isTrustedIssuer(cert)).toBe(true);
    });

    it('should return true for AKD issuer', () => {
      const cert = createTestCertificate({ issuer: 'AKD' });

      expect(isTrustedIssuer(cert)).toBe(true);
    });

    it('should return false for untrusted issuer', () => {
      const cert = createTestCertificate({ issuer: 'Untrusted CA' });

      expect(isTrustedIssuer(cert)).toBe(false);
    });
  });

  describe('getCertificateStatus', () => {
    it('should return "expired" for expired certificate', () => {
      const pastDate = new Date();
      pastDate.setFullYear(pastDate.getFullYear() - 1);

      const cert = createTestCertificate({ notAfter: pastDate });

      expect(getCertificateStatus(cert)).toBe('expired');
    });

    it('should return "expiring_soon" for certificate expiring in 15 days', () => {
      const soonDate = new Date();
      soonDate.setDate(soonDate.getDate() + 15);

      const cert = createTestCertificate({ notAfter: soonDate });

      expect(getCertificateStatus(cert)).toBe('expiring_soon');
    });

    it('should return "active" for certificate expiring in 60 days', () => {
      const farDate = new Date();
      farDate.setDate(farDate.getDate() + 60);

      const cert = createTestCertificate({ notAfter: farDate });

      expect(getCertificateStatus(cert)).toBe('active');
    });
  });

  describe('getAlertSeverity', () => {
    it('should return "urgent" for expired certificate', () => {
      expect(getAlertSeverity(-1)).toBe('urgent');
    });

    it('should return "urgent" for certificate expiring in 1 day', () => {
      expect(getAlertSeverity(1)).toBe('urgent');
    });

    it('should return "critical" for certificate expiring in 7 days', () => {
      expect(getAlertSeverity(7)).toBe('critical');
    });

    it('should return "warning" for certificate expiring in 14 days', () => {
      expect(getAlertSeverity(14)).toBe('warning');
    });

    it('should return "info" for certificate expiring in 30 days', () => {
      expect(getAlertSeverity(30)).toBe('info');
    });

    it('should return "info" for certificate expiring in 60 days', () => {
      expect(getAlertSeverity(60)).toBe('info');
    });
  });

  describe('validateCertificate with revocation checking', () => {
    it('should include revocation status in validation result', async () => {
      const cert = createTestCertificate();

      const result = await validateCertificate(cert);

      expect(result).toHaveProperty('revocationStatus');
      expect(result.revocationStatus).toBeDefined();
      expect(result.revocationStatus!.revoked).toBe(false);
      expect(result.revocationStatus!.method).toBe('mock');
    });

    it('should reject revoked certificate', async () => {
      const { getRevocationChecker } = require('../../src/revocation-check');
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockResolvedValue({
          revoked: true,
          method: 'mock',
          checkedAt: new Date(),
          reason: 'keyCompromise',
          revokedAt: new Date(),
        }),
      });

      const cert = createTestCertificate({
        serialNumber: 'TEST-REVOKED-001',
      });

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('revoked'))).toBe(true);
      expect(result.revocationStatus!.revoked).toBe(true);
      expect(result.revocationStatus!.reason).toBe('keyCompromise');

      // Reset mock
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockResolvedValue({
          revoked: false,
          method: 'mock',
          checkedAt: new Date(),
        }),
      });
    });

    it('should warn if revocation check fails', async () => {
      const { getRevocationChecker } = require('../../src/revocation-check');
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockResolvedValue({
          revoked: false,
          method: 'crl',
          checkedAt: new Date(),
          error: 'CRL download failed',
        }),
      });

      const cert = createTestCertificate();

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(true); // Not invalid, just warning
      expect(result.warnings.some((w) => w.includes('Could not verify revocation status'))).toBe(true);

      // Reset mock
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockResolvedValue({
          revoked: false,
          method: 'mock',
          checkedAt: new Date(),
        }),
      });
    });

    it('should handle revocation check exception gracefully', async () => {
      const { getRevocationChecker } = require('../../src/revocation-check');
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockRejectedValue(new Error('Network error')),
      });

      const cert = createTestCertificate();

      const result = await validateCertificate(cert);

      expect(result.valid).toBe(true); // Not invalid, just warning
      expect(result.warnings.some((w) => w.includes('Revocation check failed'))).toBe(true);

      // Reset mock
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockResolvedValue({
          revoked: false,
          method: 'mock',
          checkedAt: new Date(),
        }),
      });
    });
  });

  describe('getCertificateStatusWithRevocation', () => {
    it('should return "revoked" for revoked certificate', async () => {
      const { getRevocationChecker } = require('../../src/revocation-check');
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockResolvedValue({
          revoked: true,
          method: 'mock',
          checkedAt: new Date(),
          reason: 'keyCompromise',
        }),
      });

      const cert = createTestCertificate({
        serialNumber: 'TEST-REVOKED-001',
      });

      const status = await getCertificateStatusWithRevocation(cert);

      expect(status).toBe('revoked');

      // Reset mock
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockResolvedValue({
          revoked: false,
          method: 'mock',
          checkedAt: new Date(),
        }),
      });
    });

    it('should return "expired" for expired certificate even if not revoked', async () => {
      const pastDate = new Date();
      pastDate.setFullYear(pastDate.getFullYear() - 1);

      const cert = createTestCertificate({ notAfter: pastDate });

      const status = await getCertificateStatusWithRevocation(cert);

      expect(status).toBe('expired');
    });

    it('should return "expiring_soon" for expiring certificate', async () => {
      const soonDate = new Date();
      soonDate.setDate(soonDate.getDate() + 15);

      const cert = createTestCertificate({ notAfter: soonDate });

      const status = await getCertificateStatusWithRevocation(cert);

      expect(status).toBe('expiring_soon');
    });

    it('should return "active" for valid certificate', async () => {
      const farDate = new Date();
      farDate.setDate(farDate.getDate() + 60);

      const cert = createTestCertificate({ notAfter: farDate });

      const status = await getCertificateStatusWithRevocation(cert);

      expect(status).toBe('active');
    });

    it('should handle revocation check failure and continue', async () => {
      const { getRevocationChecker } = require('../../src/revocation-check');
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockRejectedValue(new Error('Network error')),
      });

      const cert = createTestCertificate();

      const status = await getCertificateStatusWithRevocation(cert);

      // Should continue with expiration check despite revocation error
      expect(status).toBe('active');

      // Reset mock
      getRevocationChecker.mockReturnValue({
        checkRevocation: jest.fn().mockResolvedValue({
          revoked: false,
          method: 'mock',
          checkedAt: new Date(),
        }),
      });
    });
  });
});
