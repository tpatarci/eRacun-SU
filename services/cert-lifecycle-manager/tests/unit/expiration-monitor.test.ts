import { ExpirationMonitor } from '../../src/expiration-monitor';
import type { AlertHandler } from '../../src/expiration-monitor';
import type { CertificateRepository, Certificate } from '../../src/repository';
import {
  certificatesExpiring,
  certificateExpirationAlerts,
} from '../../src/observability';

describe('ExpirationMonitor', () => {
  const buildCertificate = (overrides: Partial<Certificate>): Certificate => {
    const now = new Date();
    return {
      id: overrides.id ?? Math.floor(Math.random() * 1000),
      certId: overrides.certId ?? `cert-${Math.random()}`,
      certType: overrides.certType ?? 'demo',
      issuer: overrides.issuer ?? 'FINA',
      subjectDn: overrides.subjectDn ?? 'CN=Test, O=eRacun, C=HR',
      serialNumber: overrides.serialNumber ?? `serial-${Math.random()}`,
      notBefore: overrides.notBefore ?? new Date(now.getTime() - 86400000),
      notAfter: overrides.notAfter ?? new Date(now.getTime() + 86400000),
      status: overrides.status ?? 'active',
      certPath: overrides.certPath ?? '/etc/eracun/certs/fina-demo.p12',
      passwordEncrypted: overrides.passwordEncrypted ?? 'encrypted',
      fingerprint: overrides.fingerprint ?? 'fp',
      publicKey: overrides.publicKey ?? 'pk',
      createdAt: overrides.createdAt ?? now,
      updatedAt: overrides.updatedAt ?? now,
    };
  };

  const createRepositoryMock = () => ({
    getAllActiveCertificates: jest.fn(),
    updateCertificateStatus: jest.fn().mockResolvedValue(undefined),
  });

  const createAlertHandler = () => ({
    sendAlert: jest.fn().mockResolvedValue(undefined),
  });

  beforeEach(() => {
    jest.clearAllMocks();
    certificatesExpiring.reset();
    certificateExpirationAlerts.reset();
  });

  it('classifies expiring certificates and updates metrics', async () => {
    const now = new Date();
    const repoMock = createRepositoryMock();
    const alertHandler = createAlertHandler();

    repoMock.getAllActiveCertificates.mockResolvedValue([
      buildCertificate({
        certId: 'expired',
        notAfter: new Date(now.getTime() - 2 * 86400000),
      }),
      buildCertificate({
        certId: 'one-day',
        notAfter: new Date(now.getTime() + 12 * 60 * 60 * 1000),
      }),
      buildCertificate({
        certId: 'seven-days',
        notAfter: new Date(now.getTime() + 6 * 86400000),
      }),
      buildCertificate({
        certId: 'thirty-days',
        notAfter: new Date(now.getTime() + 29 * 86400000),
      }),
      buildCertificate({
        certId: 'healthy',
        notAfter: new Date(now.getTime() + 60 * 86400000),
      }),
    ]);

    const monitor = new ExpirationMonitor(
      repoMock as unknown as CertificateRepository,
      alertHandler as AlertHandler
    );

    const result = await monitor.checkCertificateExpiration();

    expect(result.totalChecked).toBe(5);
    expect(result.expired).toBe(1);
    expect(result.expiring1Day).toBe(1);
    expect(result.expiring7Days).toBe(1);
    expect(result.expiring30Days).toBe(1);
    expect(alertHandler.sendAlert).toHaveBeenCalledTimes(4);
    expect(repoMock.updateCertificateStatus).toHaveBeenCalledWith(
      'expired',
      'expired'
    );
    expect(repoMock.updateCertificateStatus).toHaveBeenCalledWith(
      'one-day',
      'expiring_soon'
    );

    const expiringMetric = await certificatesExpiring.get();
    const urgentEntry = expiringMetric.values.find(
      (entry: any) => entry.labels.days_until_expiry === '1'
    );
    expect(urgentEntry?.value).toBe(1);

    const alertMetric = await certificateExpirationAlerts.get();
    expect(
      alertMetric.values.some(
        (entry: any) => entry.labels.severity === 'urgent'
      )
    ).toBe(true);
  });

  it('propagates repository failures to caller', async () => {
    const repoMock = createRepositoryMock();
    const alertHandler = createAlertHandler();
    repoMock.getAllActiveCertificates.mockRejectedValue(
      new Error('database offline')
    );

    const monitor = new ExpirationMonitor(
      repoMock as unknown as CertificateRepository,
      alertHandler as AlertHandler
    );

    await expect(monitor.checkCertificateExpiration()).rejects.toThrow(
      'database offline'
    );
    expect(alertHandler.sendAlert).not.toHaveBeenCalled();
  });
});
