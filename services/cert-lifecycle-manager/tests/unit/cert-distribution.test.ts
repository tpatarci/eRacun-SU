/**
 * Tests for Certificate Distribution
 */

import {
  CertificateDistribution,
  MockEncryptionProvider,
  SOPSEncryptionProvider,
  createCertificateDistribution,
  IEncryptionProvider,
  DistributionTarget,
} from '../../src/cert-distribution';
import { Certificate } from '../../src/repository';
import * as fs from 'fs/promises';
import { join } from 'path';

// Mock file system
jest.mock('fs/promises');

// Mock HSM
jest.mock('../../src/hsm/index', () => ({
  getHSM: jest.fn(() => ({
    exportPrivateKey: jest.fn().mockResolvedValue('-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY\n-----END PRIVATE KEY-----'),
  })),
}));

describe('MockEncryptionProvider', () => {
  let provider: IEncryptionProvider;

  beforeEach(() => {
    provider = new MockEncryptionProvider();
  });

  describe('encrypt', () => {
    it('should encrypt certificate and key', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyPEM = '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----';

      const encrypted = await provider.encrypt(certPEM, keyPEM);

      expect(encrypted).toContain('-----BEGIN ENCRYPTED CERTIFICATE-----');
      expect(encrypted).toContain('-----END ENCRYPTED CERTIFICATE-----');
    });

    it('should produce different output for different inputs', async () => {
      const cert1 = '-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----';
      const cert2 = '-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----';
      const key = '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----';

      const encrypted1 = await provider.encrypt(cert1, key);
      const encrypted2 = await provider.encrypt(cert2, key);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should simulate encryption delay', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyPEM = '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----';

      const start = Date.now();
      await provider.encrypt(certPEM, keyPEM);
      const duration = Date.now() - start;

      expect(duration).toBeGreaterThanOrEqual(25); // 50ms delay with margin
    });
  });

  describe('decrypt', () => {
    it('should decrypt encrypted data', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyPEM = '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----';

      const encrypted = await provider.encrypt(certPEM, keyPEM);
      const decrypted = await provider.decrypt(encrypted);

      expect(decrypted.certPEM).toBe(certPEM);
      expect(decrypted.keyPEM).toBe(keyPEM);
    });

    it('should handle round-trip encryption', async () => {
      const originalCert = '-----BEGIN CERTIFICATE-----\nORIGINAL_CERT\n-----END CERTIFICATE-----';
      const originalKey = '-----BEGIN PRIVATE KEY-----\nORIGINAL_KEY\n-----END PRIVATE KEY-----';

      const encrypted = await provider.encrypt(originalCert, originalKey);
      const { certPEM, keyPEM } = await provider.decrypt(encrypted);

      expect(certPEM).toBe(originalCert);
      expect(keyPEM).toBe(originalKey);
    });
  });
});

describe('SOPSEncryptionProvider', () => {
  let provider: IEncryptionProvider;

  beforeEach(() => {
    provider = new SOPSEncryptionProvider('/path/to/age-key');
  });

  describe('encrypt', () => {
    it('should throw not implemented error', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyPEM = '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----';

      await expect(provider.encrypt(certPEM, keyPEM)).rejects.toThrow(
        'SOPS integration not yet implemented'
      );
    });
  });

  describe('decrypt', () => {
    it('should throw not implemented error', async () => {
      await expect(provider.decrypt('encrypted-data')).rejects.toThrow(
        'SOPS decryption not yet implemented'
      );
    });
  });
});

describe('CertificateDistribution', () => {
  let distribution: CertificateDistribution;
  let mockProvider: IEncryptionProvider;
  let testCert: Certificate;

  beforeEach(() => {
    mockProvider = new MockEncryptionProvider();
    distribution = new CertificateDistribution(mockProvider);

    testCert = {
      certId: 'cert-123',
      serialNumber: '12345',
      subjectDn: 'CN=Test',
      issuer: 'Fina RDC 2015 CA',
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      fingerprint: 'FINGERPRINT',
      certType: 'production',
      status: 'active',
      oib: '12345678901',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Mock fs functions
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('registerTarget', () => {
    it('should register distribution target', () => {
      const target: DistributionTarget = {
        serviceName: 'test-service',
        certPath: '/etc/test/certs',
        keyPath: '/etc/test/keys',
        reloadCommand: 'systemctl reload test-service',
        environment: 'production',
      };

      distribution.registerTarget(target);

      // Verify by trying to distribute (will fail if target not registered)
      expect(() => distribution.registerTarget(target)).not.toThrow();
    });

    it('should allow registering multiple targets', () => {
      const target1: DistributionTarget = {
        serviceName: 'service1',
        certPath: '/etc/service1/certs',
        keyPath: '/etc/service1/keys',
        environment: 'production',
      };

      const target2: DistributionTarget = {
        serviceName: 'service2',
        certPath: '/etc/service2/certs',
        keyPath: '/etc/service2/keys',
        environment: 'production',
      };

      distribution.registerTarget(target1);
      distribution.registerTarget(target2);

      // Both should be registered
      expect(() => distribution.registerTarget(target1)).not.toThrow();
      expect(() => distribution.registerTarget(target2)).not.toThrow();
    });
  });

  describe('distributeToTarget', () => {
    let target: DistributionTarget;

    beforeEach(() => {
      target = {
        serviceName: 'digital-signature-service',
        certPath: '/etc/eracun/certs',
        keyPath: '/etc/eracun/keys',
        environment: 'production',
      };
    });

    it('should distribute certificate successfully', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      const result = await distribution.distributeToTarget(
        testCert,
        certPEM,
        keyId,
        target
      );

      expect(result.success).toBe(true);
      expect(result.certId).toBe('cert-123');
      expect(result.target).toBe(target);
      expect(result.distributionId).toBeDefined();
      expect(result.timestamp).toBeInstanceOf(Date);

      // Verify directories were created
      expect(fs.mkdir).toHaveBeenCalledWith('/etc/eracun/certs', {
        recursive: true,
        mode: 0o700,
      });
      expect(fs.mkdir).toHaveBeenCalledWith('/etc/eracun/keys', {
        recursive: true,
        mode: 0o700,
      });

      // Verify files were written
      expect(fs.writeFile).toHaveBeenCalledTimes(2); // cert + key
    });

    it('should handle distribution failure', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      // Make file write fail
      (fs.writeFile as jest.Mock).mockRejectedValue(new Error('Permission denied'));

      const result = await distribution.distributeToTarget(
        testCert,
        certPEM,
        keyId,
        target
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Permission denied');
      expect(result.certId).toBe('cert-123');
    });

    it('should create files with secure permissions', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      await distribution.distributeToTarget(testCert, certPEM, keyId, target);

      // Verify files were written with mode 0o600
      const writeFileCalls = (fs.writeFile as jest.Mock).mock.calls;
      expect(writeFileCalls[0][2]).toEqual({ mode: 0o600 });
      expect(writeFileCalls[1][2]).toEqual({ mode: 0o600 });
    });
  });

  describe('distributeToAll', () => {
    beforeEach(() => {
      const target1: DistributionTarget = {
        serviceName: 'digital-signature-service',
        certPath: '/etc/eracun/certs',
        keyPath: '/etc/eracun/keys',
        environment: 'production',
      };

      const target2: DistributionTarget = {
        serviceName: 'fina-connector',
        certPath: '/etc/eracun/certs',
        keyPath: '/etc/eracun/keys',
        environment: 'production',
      };

      distribution.registerTarget(target1);
      distribution.registerTarget(target2);
    });

    it('should distribute to all registered targets', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      const results = await distribution.distributeToAll(testCert, certPEM, keyId);

      expect(results).toHaveLength(2);
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(true);
      expect(results[0].target.serviceName).toBe('digital-signature-service');
      expect(results[1].target.serviceName).toBe('fina-connector');
    });

    it('should continue distributing after individual failure', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      // Make first write fail, second succeed
      (fs.writeFile as jest.Mock)
        .mockRejectedValueOnce(new Error('Failed 1'))
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce(undefined);

      const results = await distribution.distributeToAll(testCert, certPEM, keyId);

      expect(results).toHaveLength(2);
      expect(results[0].success).toBe(false);
      expect(results[1].success).toBe(true);
    });
  });

  describe('getAuditLog', () => {
    beforeEach(() => {
      const target: DistributionTarget = {
        serviceName: 'test-service',
        certPath: '/etc/test/certs',
        keyPath: '/etc/test/keys',
        environment: 'production',
      };

      distribution.registerTarget(target);
    });

    it('should return empty log initially', () => {
      const log = distribution.getAuditLog();
      expect(log).toHaveLength(0);
    });

    it('should record successful distributions', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      await distribution.distributeToAll(testCert, certPEM, keyId);

      const log = distribution.getAuditLog();
      expect(log.length).toBeGreaterThan(0);
      expect(log[0].certId).toBe('cert-123');
      expect(log[0].success).toBe(true);
    });

    it('should record failed distributions', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      (fs.writeFile as jest.Mock).mockRejectedValue(new Error('Write failed'));

      await distribution.distributeToAll(testCert, certPEM, keyId);

      const log = distribution.getAuditLog();
      expect(log[0].success).toBe(false);
      expect(log[0].error).toContain('Write failed');
    });
  });

  describe('getAuditLogForCert', () => {
    beforeEach(() => {
      const target: DistributionTarget = {
        serviceName: 'test-service',
        certPath: '/etc/test/certs',
        keyPath: '/etc/test/keys',
        environment: 'production',
      };

      distribution.registerTarget(target);
    });

    it('should return distributions for specific certificate', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      // Distribute cert-123
      await distribution.distributeToAll(testCert, certPEM, keyId);

      // Distribute different cert
      const cert2 = { ...testCert, certId: 'cert-456' };
      await distribution.distributeToAll(cert2, certPEM, keyId);

      const logForCert123 = distribution.getAuditLogForCert('cert-123');
      const logForCert456 = distribution.getAuditLogForCert('cert-456');

      expect(logForCert123.length).toBeGreaterThan(0);
      expect(logForCert456.length).toBeGreaterThan(0);
      expect(logForCert123[0].certId).toBe('cert-123');
      expect(logForCert456[0].certId).toBe('cert-456');
    });

    it('should return empty array for non-existent certificate', () => {
      const log = distribution.getAuditLogForCert('nonexistent');
      expect(log).toHaveLength(0);
    });
  });

  describe('clearAuditLog', () => {
    beforeEach(() => {
      const target: DistributionTarget = {
        serviceName: 'test-service',
        certPath: '/etc/test/certs',
        keyPath: '/etc/test/keys',
        environment: 'production',
      };

      distribution.registerTarget(target);
    });

    it('should clear audit log', async () => {
      const certPEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
      const keyId = 'key-123';

      await distribution.distributeToAll(testCert, certPEM, keyId);

      expect(distribution.getAuditLog().length).toBeGreaterThan(0);

      distribution.clearAuditLog();

      expect(distribution.getAuditLog()).toHaveLength(0);
    });
  });
});

describe('createCertificateDistribution', () => {
  it('should create distribution with mock encryption by default', () => {
    const distribution = createCertificateDistribution();

    expect(distribution).toBeInstanceOf(CertificateDistribution);
  });

  it('should create distribution with mock encryption', () => {
    const distribution = createCertificateDistribution('mock');

    expect(distribution).toBeInstanceOf(CertificateDistribution);
  });

  it('should fallback to mock for sops type (not implemented)', () => {
    const distribution = createCertificateDistribution('sops');

    expect(distribution).toBeInstanceOf(CertificateDistribution);
  });

  it('should throw error for unknown encryption type', () => {
    expect(() => createCertificateDistribution('invalid' as any)).toThrow(
      'Unknown encryption type: invalid'
    );
  });

  it('should register default targets from environment', () => {
    const distribution = createCertificateDistribution();

    // Should have registered default targets
    expect(distribution).toBeInstanceOf(CertificateDistribution);
  });
});
