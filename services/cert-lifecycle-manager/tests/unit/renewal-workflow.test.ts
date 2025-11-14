/**
 * Tests for Certificate Renewal Workflow
 */

import {
  RenewalWorkflow,
  MockCertificateAuthority,
  FINACertificateAuthority,
  createRenewalWorkflow,
  createCertificateAuthority,
  ICertificateAuthority,
  RenewalRequest,
} from '../../src/renewal-workflow';
import { CertificateRepository, Certificate } from '../../src/repository';
import { CertificateDistribution } from '../../src/cert-distribution';

// Mock dependencies
jest.mock('../../src/repository');
jest.mock('../../src/cert-distribution');
jest.mock('../../src/hsm/index', () => ({
  getHSM: jest.fn(() => ({
    generateKeyPair: jest.fn().mockResolvedValue({
      keyId: 'new-key-id',
      algorithm: 'RSA-2048',
      exportable: true,
      createdAt: new Date(),
      publicKey: 'PUBLIC_KEY',
    })),
    getKey: jest.fn().mockResolvedValue({
      keyId: 'new-key-id',
      algorithm: 'RSA-2048',
      exportable: true,
      createdAt: new Date(),
      publicKey: 'PUBLIC_KEY',
    }),
    sign: jest.fn().mockResolvedValue({
      signature: 'SIGNATURE',
      algorithm: 'RSA-SHA256',
      keyId: 'new-key-id',
      timestamp: new Date(),
    }),
    exportPrivateKey: jest.fn().mockResolvedValue('-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----'),
    importKey: jest.fn().mockResolvedValue({
      keyId: 'imported-key',
      algorithm: 'RSA-2048',
      exportable: true,
      createdAt: new Date(),
      publicKey: 'PUBLIC_KEY',
    }),
  })),
}));

describe('MockCertificateAuthority', () => {
  let ca: ICertificateAuthority;

  beforeEach(() => {
    ca = new MockCertificateAuthority();
  });

  describe('renewCertificate', () => {
    it('should renew certificate successfully', async () => {
      const request: RenewalRequest = {
        oldSerialNumber: '12345',
        csr: {
          csr: 'CSR_DATA',
          subject: 'CN=Test',
          publicKey: 'PUBLIC_KEY',
          algorithm: 'RSA-2048',
        },
        oib: '12345678901',
        reason: 'expiring',
      };

      const newCertPEM = await ca.renewCertificate(request);

      expect(newCertPEM).toContain('-----BEGIN CERTIFICATE-----');
      expect(newCertPEM).toContain('-----END CERTIFICATE-----');
      expect(newCertPEM).toContain('Subject: CN=Test');
    });

    it('should generate unique serial numbers', async () => {
      const request: RenewalRequest = {
        oldSerialNumber: '12345',
        csr: {
          csr: 'CSR_DATA',
          subject: 'CN=Test',
          publicKey: 'PUBLIC_KEY',
          algorithm: 'RSA-2048',
        },
        oib: '12345678901',
        reason: 'expiring',
      };

      const cert1 = await ca.renewCertificate(request);
      const cert2 = await ca.renewCertificate(request);

      // Extract serial numbers from certificates
      const serial1Match = cert1.match(/Serial: ([^\n]+)/);
      const serial2Match = cert2.match(/Serial: ([^\n]+)/);

      expect(serial1Match).toBeTruthy();
      expect(serial2Match).toBeTruthy();
      expect(serial1Match![1]).not.toBe(serial2Match![1]);
    });

    it('should simulate network delay', async () => {
      const request: RenewalRequest = {
        oldSerialNumber: '12345',
        csr: {
          csr: 'CSR_DATA',
          subject: 'CN=Test',
          publicKey: 'PUBLIC_KEY',
          algorithm: 'RSA-2048',
        },
        oib: '12345678901',
        reason: 'expiring',
      };

      const start = Date.now();
      await ca.renewCertificate(request);
      const duration = Date.now() - start;

      expect(duration).toBeGreaterThanOrEqual(250); // 500ms delay with margin
    });

    it('should handle different renewal reasons', async () => {
      const reasons: Array<'expiring' | 'compromised' | 'manual'> = [
        'expiring',
        'compromised',
        'manual',
      ];

      for (const reason of reasons) {
        const request: RenewalRequest = {
          oldSerialNumber: '12345',
          csr: {
            csr: 'CSR_DATA',
            subject: 'CN=Test',
            publicKey: 'PUBLIC_KEY',
            algorithm: 'RSA-2048',
          },
          oib: '12345678901',
          reason,
        };

        const cert = await ca.renewCertificate(request);
        expect(cert).toContain('-----BEGIN CERTIFICATE-----');
      }
    });
  });

  describe('healthCheck', () => {
    it('should always return true for mock CA', async () => {
      const healthy = await ca.healthCheck();
      expect(healthy).toBe(true);
    });
  });
});

describe('FINACertificateAuthority', () => {
  let ca: ICertificateAuthority;

  beforeEach(() => {
    ca = new FINACertificateAuthority('https://test.fina.hr', 'cert', 'key');
  });

  describe('renewCertificate', () => {
    it('should throw not implemented error', async () => {
      const request: RenewalRequest = {
        oldSerialNumber: '12345',
        csr: {
          csr: 'CSR_DATA',
          subject: 'CN=Test',
          publicKey: 'PUBLIC_KEY',
          algorithm: 'RSA-2048',
        },
        oib: '12345678901',
        reason: 'expiring',
      };

      await expect(ca.renewCertificate(request)).rejects.toThrow(
        'FINA integration not yet implemented'
      );
    });
  });

  describe('healthCheck', () => {
    it('should return false (not implemented)', async () => {
      const healthy = await ca.healthCheck();
      expect(healthy).toBe(false);
    });
  });
});

describe('RenewalWorkflow', () => {
  let workflow: RenewalWorkflow;
  let mockRepository: jest.Mocked<CertificateRepository>;
  let mockCA: jest.Mocked<ICertificateAuthority>;
  let mockDistribution: jest.Mocked<CertificateDistribution>;

  beforeEach(() => {
    mockRepository = {
      getAllActiveCertificates: jest.fn(),
      updateCertificateStatus: jest.fn(),
      createCertificate: jest.fn(),
    } as any;

    mockCA = {
      renewCertificate: jest.fn().mockResolvedValue('-----BEGIN CERTIFICATE-----\nNEW_CERT\n-----END CERTIFICATE-----'),
      healthCheck: jest.fn().mockResolvedValue(true),
    } as any;

    mockDistribution = {
      distributeToAll: jest.fn().mockResolvedValue([
        {
          success: true,
          target: { serviceName: 'digital-signature-service' },
          certId: 'new-cert-id',
          distributionId: 'dist-123',
          timestamp: new Date(),
        },
      ]),
    } as any;

    workflow = new RenewalWorkflow(mockRepository, mockCA, 60, mockDistribution);
  });

  describe('processRenewals', () => {
    it('should process no renewals when no certificates are expiring', async () => {
      mockRepository.getAllActiveCertificates.mockResolvedValue([]);

      const results = await workflow.processRenewals();

      expect(results).toHaveLength(0);
      expect(mockCA.renewCertificate).not.toHaveCalled();
    });

    it('should process renewal for expiring certificate', async () => {
      const expiringCert: Certificate = {
        certId: 'cert-123',
        serialNumber: '12345',
        subjectDn: 'CN=Test',
        issuer: 'Fina RDC 2015 CA',
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        fingerprint: 'FINGERPRINT',
        certType: 'production',
        status: 'active',
        oib: '12345678901',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockRepository.getAllActiveCertificates.mockResolvedValue([expiringCert]);

      const results = await workflow.processRenewals();

      expect(results).toHaveLength(1);
      expect(results[0].success).toBe(true);
      expect(results[0].oldCertId).toBe('cert-123');
      expect(mockCA.renewCertificate).toHaveBeenCalledTimes(1);
    });

    it('should not process certificates expiring beyond threshold', async () => {
      const cert: Certificate = {
        certId: 'cert-123',
        serialNumber: '12345',
        subjectDn: 'CN=Test',
        issuer: 'Fina RDC 2015 CA',
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days (beyond 60)
        fingerprint: 'FINGERPRINT',
        certType: 'production',
        status: 'active',
        oib: '12345678901',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockRepository.getAllActiveCertificates.mockResolvedValue([cert]);

      const results = await workflow.processRenewals();

      expect(results).toHaveLength(0);
      expect(mockCA.renewCertificate).not.toHaveBeenCalled();
    });

    it('should process multiple expiring certificates', async () => {
      const certs: Certificate[] = [
        {
          certId: 'cert-1',
          serialNumber: '111',
          subjectDn: 'CN=Test1',
          issuer: 'Fina RDC 2015 CA',
          notBefore: new Date(),
          notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          fingerprint: 'FP1',
          certType: 'production',
          status: 'active',
          oib: '12345678901',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          certId: 'cert-2',
          serialNumber: '222',
          subjectDn: 'CN=Test2',
          issuer: 'Fina RDC 2015 CA',
          notBefore: new Date(),
          notAfter: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000),
          fingerprint: 'FP2',
          certType: 'production',
          status: 'active',
          oib: '98765432109',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      mockRepository.getAllActiveCertificates.mockResolvedValue(certs);

      const results = await workflow.processRenewals();

      expect(results).toHaveLength(2);
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(true);
      expect(mockCA.renewCertificate).toHaveBeenCalledTimes(2);
    });

    it('should continue processing after individual failure', async () => {
      const certs: Certificate[] = [
        {
          certId: 'cert-1',
          serialNumber: '111',
          subjectDn: 'CN=Test1',
          issuer: 'Fina RDC 2015 CA',
          notBefore: new Date(),
          notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          fingerprint: 'FP1',
          certType: 'production',
          status: 'active',
          oib: '12345678901',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          certId: 'cert-2',
          serialNumber: '222',
          subjectDn: 'CN=Test2',
          issuer: 'Fina RDC 2015 CA',
          notBefore: new Date(),
          notAfter: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000),
          fingerprint: 'FP2',
          certType: 'production',
          status: 'active',
          oib: '98765432109',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      mockRepository.getAllActiveCertificates.mockResolvedValue(certs);

      // Make first renewal fail
      mockCA.renewCertificate
        .mockRejectedValueOnce(new Error('CA failure'))
        .mockResolvedValueOnce('-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----');

      const results = await workflow.processRenewals();

      expect(results).toHaveLength(2);
      expect(results[0].success).toBe(false);
      expect(results[0].error).toContain('CA failure');
      expect(results[1].success).toBe(true);
    });
  });

  describe('renewCertificate', () => {
    it('should renew certificate and distribute', async () => {
      const cert: Certificate = {
        certId: 'cert-123',
        serialNumber: '12345',
        subjectDn: 'CN=Test',
        issuer: 'Fina RDC 2015 CA',
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        fingerprint: 'FINGERPRINT',
        certType: 'production',
        status: 'active',
        oib: '12345678901',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await workflow.renewCertificate(cert);

      expect(result.success).toBe(true);
      expect(result.oldCertId).toBe('cert-123');
      expect(result.newCertId).toBeDefined();
      expect(result.newSerialNumber).toBeDefined();

      // Verify certificate was created
      expect(mockRepository.createCertificate).toHaveBeenCalled();

      // Verify old certificate was deprecated
      expect(mockRepository.updateCertificateStatus).toHaveBeenCalledWith(
        'cert-123',
        'expired'
      );

      // Verify distribution was called
      expect(mockDistribution.distributeToAll).toHaveBeenCalled();
    });

    it('should handle renewal failure gracefully', async () => {
      const cert: Certificate = {
        certId: 'cert-123',
        serialNumber: '12345',
        subjectDn: 'CN=Test',
        issuer: 'Fina RDC 2015 CA',
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        fingerprint: 'FINGERPRINT',
        certType: 'production',
        status: 'active',
        oib: '12345678901',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockCA.renewCertificate.mockRejectedValue(new Error('CA service unavailable'));

      const result = await workflow.renewCertificate(cert);

      expect(result.success).toBe(false);
      expect(result.error).toContain('CA service unavailable');
      expect(result.oldCertId).toBe('cert-123');

      // Old certificate should not be deprecated on failure
      expect(mockRepository.updateCertificateStatus).not.toHaveBeenCalled();
    });
  });

  describe('getRenewalThreshold', () => {
    it('should return configured threshold', () => {
      expect(workflow.getRenewalThreshold()).toBe(60);
    });
  });

  describe('setRenewalThreshold', () => {
    it('should update threshold', () => {
      workflow.setRenewalThreshold(90);
      expect(workflow.getRenewalThreshold()).toBe(90);
    });

    it('should reject threshold less than 1', () => {
      expect(() => workflow.setRenewalThreshold(0)).toThrow(
        'Renewal threshold must be at least 1 day'
      );
    });
  });
});

describe('createRenewalWorkflow', () => {
  it('should create workflow with mock CA', () => {
    const mockRepository = {} as any;

    const workflow = createRenewalWorkflow(mockRepository);

    expect(workflow).toBeInstanceOf(RenewalWorkflow);
  });

  it('should use custom CA if provided', () => {
    const mockRepository = {} as any;
    const mockCA = new MockCertificateAuthority();

    const workflow = createRenewalWorkflow(mockRepository, mockCA);

    expect(workflow).toBeInstanceOf(RenewalWorkflow);
  });

  it('should use environment variable for threshold', () => {
    process.env.RENEWAL_THRESHOLD_DAYS = '90';

    const mockRepository = {} as any;
    const workflow = createRenewalWorkflow(mockRepository);

    expect(workflow.getRenewalThreshold()).toBe(90);

    delete process.env.RENEWAL_THRESHOLD_DAYS;
  });
});

describe('createCertificateAuthority', () => {
  it('should create mock CA by default', () => {
    const ca = createCertificateAuthority();

    expect(ca).toBeInstanceOf(MockCertificateAuthority);
  });

  it('should create mock CA for mock type', () => {
    const ca = createCertificateAuthority('mock');

    expect(ca).toBeInstanceOf(MockCertificateAuthority);
  });

  it('should fall back to mock CA for fina type without credentials', () => {
    const ca = createCertificateAuthority('fina');

    // Should fallback to mock
    expect(ca).toBeInstanceOf(MockCertificateAuthority);
  });

  it('should throw error for unknown type', () => {
    expect(() => createCertificateAuthority('invalid' as any)).toThrow(
      'Unknown CA type: invalid'
    );
  });
});
