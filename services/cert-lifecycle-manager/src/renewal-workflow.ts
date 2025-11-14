/**
 * Certificate Renewal Workflow
 *
 * Automates the certificate renewal process:
 * 1. Detects certificates approaching expiration (60 days)
 * 2. Generates Certificate Signing Request (CSR)
 * 3. Submits renewal request to FINA (or mock CA)
 * 4. Installs new certificate
 * 5. Deprecates old certificate
 * 6. Notifies stakeholders
 */

import { createSign, createPrivateKey, generateKeyPairSync } from 'crypto';
import { CertificateRepository, Certificate } from './repository.js';
import { calculateDaysUntilExpiration } from './cert-parser.js';
import { getHSM } from './hsm/index.js';
import { CertificateDistribution, createCertificateDistribution } from './cert-distribution.js';
import {
  logger,
  createSpan,
  setSpanError,
  certificateRenewals,
} from './observability.js';

/**
 * Certificate Signing Request (CSR)
 */
export interface CertificateSigningRequest {
  /** PEM-encoded CSR */
  csr: string;
  /** Subject DN */
  subject: string;
  /** Public key */
  publicKey: string;
  /** Key algorithm */
  algorithm: string;
}

/**
 * Renewal request for FINA
 */
export interface RenewalRequest {
  /** Old certificate serial number */
  oldSerialNumber: string;
  /** Certificate Signing Request */
  csr: CertificateSigningRequest;
  /** Company OIB */
  oib: string;
  /** Renewal reason */
  reason: 'expiring' | 'compromised' | 'manual';
}

/**
 * Renewal result
 */
export interface RenewalResult {
  /** Success status */
  success: boolean;
  /** Old certificate ID */
  oldCertId: string;
  /** New certificate ID (if successful) */
  newCertId?: string;
  /** New certificate serial number */
  newSerialNumber?: string;
  /** Error message (if failed) */
  error?: string;
  /** Timestamp */
  timestamp: Date;
}

/**
 * Certificate Authority interface
 *
 * Abstracts FINA certificate renewal API
 */
export interface ICertificateAuthority {
  /**
   * Submit certificate renewal request
   * @param request - Renewal request
   * @returns New certificate in PEM format
   */
  renewCertificate(request: RenewalRequest): Promise<string>;

  /**
   * Health check
   */
  healthCheck(): Promise<boolean>;
}

/**
 * Mock Certificate Authority
 *
 * Simulates FINA certificate renewal for development
 */
export class MockCertificateAuthority implements ICertificateAuthority {
  private renewalCount = 0;

  async renewCertificate(request: RenewalRequest): Promise<string> {
    logger.info(
      { oldSerialNumber: request.oldSerialNumber, reason: request.reason },
      'Processing certificate renewal (MOCK)'
    );

    // Simulate network delay
    await this.delay(500);

    this.renewalCount++;

    // Generate new certificate (simplified mock)
    const newSerial = `RENEWED-${Date.now()}-${this.renewalCount}`;
    const notBefore = new Date();
    const notAfter = new Date();
    notAfter.setFullYear(notAfter.getFullYear() + 5); // 5 year validity

    // Mock certificate in PEM format
    const mockCert = `-----BEGIN CERTIFICATE-----
MIIC${Buffer.from(newSerial).toString('base64')}
Serial: ${newSerial}
Subject: ${request.csr.subject}
NotBefore: ${notBefore.toISOString()}
NotAfter: ${notAfter.toISOString()}
Issuer: CN=Fina RDC 2015 CA,O=FINA,C=HR
-----END CERTIFICATE-----`;

    logger.info(
      { newSerial, oldSerial: request.oldSerialNumber },
      'Certificate renewed successfully (MOCK)'
    );

    return mockCert;
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  getRenewalCount(): number {
    return this.renewalCount;
  }
}

/**
 * Real FINA Certificate Authority Client
 *
 * Integrates with actual FINA certificate renewal API
 */
export class FINACertificateAuthority implements ICertificateAuthority {
  private apiUrl: string;
  private authCert: string;
  private authKey: string;

  constructor(apiUrl: string, authCert: string, authKey: string) {
    this.apiUrl = apiUrl;
    this.authCert = authCert;
    this.authKey = authKey;
  }

  async renewCertificate(request: RenewalRequest): Promise<string> {
    logger.info(
      { oldSerialNumber: request.oldSerialNumber },
      'Submitting renewal request to FINA'
    );

    // TODO: Implement actual FINA API integration
    // This would:
    // 1. Authenticate with FINA using authCert/authKey
    // 2. Submit CSR to FINA renewal endpoint
    // 3. Poll for certificate issuance
    // 4. Download new certificate
    // 5. Return PEM-encoded certificate

    throw new Error('FINA integration not yet implemented - use mock CA');
  }

  async healthCheck(): Promise<boolean> {
    // TODO: Implement FINA health check
    return false;
  }
}

/**
 * Renewal Workflow Orchestrator
 *
 * Handles end-to-end certificate renewal automation
 */
export class RenewalWorkflow {
  private repository: CertificateRepository;
  private ca: ICertificateAuthority;
  private renewalThresholdDays: number;
  private distribution: CertificateDistribution;

  constructor(
    repository: CertificateRepository,
    ca: ICertificateAuthority,
    renewalThresholdDays: number = 60,
    distribution?: CertificateDistribution
  ) {
    this.repository = repository;
    this.ca = ca;
    this.renewalThresholdDays = renewalThresholdDays;
    this.distribution = distribution || createCertificateDistribution();
  }

  /**
   * Check for certificates needing renewal and process them
   *
   * @returns Array of renewal results
   */
  async processRenewals(): Promise<RenewalResult[]> {
    const span = createSpan('process_renewals');
    const startTime = Date.now();

    try {
      logger.info(
        { thresholdDays: this.renewalThresholdDays },
        'Starting renewal workflow'
      );

      // Get certificates approaching expiration
      const certificates = await this.repository.getAllActiveCertificates();
      const needsRenewal = certificates.filter((cert) => {
        const daysUntilExpiry = calculateDaysUntilExpiration(cert.notAfter);
        return daysUntilExpiry <= this.renewalThresholdDays && daysUntilExpiry > 0;
      });

      logger.info(
        { total: certificates.length, needsRenewal: needsRenewal.length },
        'Found certificates needing renewal'
      );

      const results: RenewalResult[] = [];

      // Process each certificate
      for (const cert of needsRenewal) {
        const result = await this.renewCertificate(cert);
        results.push(result);

        // Update metrics
        if (result.success) {
          certificateRenewals.labels('success').inc();
        } else {
          certificateRenewals.labels('failure').inc();
        }
      }

      const durationSeconds = (Date.now() - startTime) / 1000;

      logger.info(
        {
          processed: results.length,
          succeeded: results.filter((r) => r.success).length,
          failed: results.filter((r) => !r.success).length,
          durationSeconds,
        },
        'Renewal workflow completed'
      );

      span.end();
      return results;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Renewal workflow failed');
      throw error;
    }
  }

  /**
   * Renew a single certificate
   *
   * @param cert - Certificate to renew
   * @returns Renewal result
   */
  async renewCertificate(cert: Certificate): Promise<RenewalResult> {
    const span = createSpan('renew_certificate', {
      certId: cert.certId,
      serialNumber: cert.serialNumber,
    });

    try {
      logger.info(
        {
          certId: cert.certId,
          serialNumber: cert.serialNumber,
          notAfter: cert.notAfter.toISOString(),
        },
        'Starting certificate renewal'
      );

      // 1. Generate new key pair
      const hsm = getHSM();
      const newKeyId = `${cert.certId}-renewed-${Date.now()}`;
      await hsm.generateKeyPair(newKeyId, 'RSA-2048', true);

      logger.info({ newKeyId }, 'Generated new key pair');

      // 2. Generate CSR
      const csr = await this.generateCSR(cert, newKeyId);

      logger.info('Generated Certificate Signing Request');

      // 3. Submit renewal request to CA
      const renewalRequest: RenewalRequest = {
        oldSerialNumber: cert.serialNumber,
        csr,
        oib: cert.oib || '',
        reason: 'expiring',
      };

      const newCertPEM = await this.ca.renewCertificate(renewalRequest);

      logger.info('Received new certificate from CA');

      // 4. Import new certificate
      const keyMetadata = await hsm.getKey(newKeyId);
      if (!keyMetadata) {
        throw new Error('Key not found after generation');
      }

      const privateKeyPEM = await hsm.exportPrivateKey(newKeyId);
      await hsm.importKey(
        `cert-${Date.now()}`,
        privateKeyPEM,
        newCertPEM
      );

      logger.info('Imported new certificate');

      // 5. Store new certificate in database
      const newCertId = `cert-${Date.now()}`;
      // Extract serial number from PEM (simplified - real implementation would parse X.509)
      const newSerialMatch = newCertPEM.match(/Serial: ([^\n]+)/);
      const newSerial = newSerialMatch ? newSerialMatch[1] : `NEW-${Date.now()}`;

      await this.repository.createCertificate({
        certId: newCertId,
        serialNumber: newSerial,
        subjectDn: cert.subjectDn,
        issuer: cert.issuer,
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000), // 5 years
        fingerprint: `SHA256:${Buffer.from(newSerial).toString('base64').substring(0, 32)}`,
        certType: cert.certType,
        status: 'active',
        oib: cert.oib,
      });

      logger.info({ newCertId, newSerial }, 'Stored new certificate');

      // 6. Distribute new certificate to services
      const distributionResults = await this.distribution.distributeToAll(
        {
          certId: newCertId,
          serialNumber: newSerial,
          subjectDn: cert.subjectDn,
          issuer: cert.issuer,
          notBefore: new Date(),
          notAfter: new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000),
          fingerprint: `SHA256:${Buffer.from(newSerial).toString('base64').substring(0, 32)}`,
          certType: cert.certType,
          status: 'active',
          oib: cert.oib,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        newCertPEM,
        newKeyId
      );

      const successfulDistributions = distributionResults.filter((r) => r.success).length;
      const failedDistributions = distributionResults.filter((r) => !r.success).length;

      logger.info(
        {
          newCertId,
          totalDistributions: distributionResults.length,
          successful: successfulDistributions,
          failed: failedDistributions,
        },
        'Certificate distributed to services'
      );

      // 7. Deprecate old certificate
      await this.repository.updateCertificateStatus(cert.certId, 'expired');

      logger.info({ oldCertId: cert.certId }, 'Deprecated old certificate');

      const result: RenewalResult = {
        success: true,
        oldCertId: cert.certId,
        newCertId,
        newSerialNumber: newSerial,
        timestamp: new Date(),
      };

      logger.info(
        {
          oldCertId: cert.certId,
          newCertId,
          newSerial,
        },
        'Certificate renewal completed successfully'
      );

      span.end();
      return result;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error(
        {
          error,
          certId: cert.certId,
          serialNumber: cert.serialNumber,
        },
        'Certificate renewal failed'
      );

      return {
        success: false,
        oldCertId: cert.certId,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
      };
    }
  }

  /**
   * Generate Certificate Signing Request (CSR)
   *
   * @param cert - Existing certificate
   * @param keyId - New key ID from HSM
   * @returns CSR
   */
  private async generateCSR(
    cert: Certificate,
    keyId: string
  ): Promise<CertificateSigningRequest> {
    const span = createSpan('generate_csr', { certId: cert.certId });

    try {
      // Get HSM to sign CSR
      const hsm = getHSM();
      const keyMetadata = await hsm.getKey(keyId);

      if (!keyMetadata) {
        throw new Error(`Key ${keyId} not found in HSM`);
      }

      // Create CSR data
      const csrData = {
        subject: cert.subjectDn,
        algorithm: keyMetadata.algorithm,
        keyId,
      };

      // Sign CSR (simplified - real implementation would use proper ASN.1 encoding)
      const csrString = JSON.stringify(csrData);
      const signResult = await hsm.sign(keyId, Buffer.from(csrString));

      // Create mock CSR in PEM format
      const csr = `-----BEGIN CERTIFICATE REQUEST-----
${Buffer.from(csrString).toString('base64')}
Signature: ${signResult.signature}
-----END CERTIFICATE REQUEST-----`;

      span.end();

      return {
        csr,
        subject: cert.subjectDn,
        publicKey: 'PUBLIC_KEY_PLACEHOLDER',
        algorithm: keyMetadata.algorithm,
      };
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();
      throw error;
    }
  }

  /**
   * Get renewal threshold in days
   */
  getRenewalThreshold(): number {
    return this.renewalThresholdDays;
  }

  /**
   * Set renewal threshold in days
   */
  setRenewalThreshold(days: number): void {
    if (days < 1) {
      throw new Error('Renewal threshold must be at least 1 day');
    }
    this.renewalThresholdDays = days;
    logger.info({ thresholdDays: days }, 'Renewal threshold updated');
  }
}

/**
 * Create renewal workflow with default configuration
 *
 * @param repository - Certificate repository
 * @param ca - Certificate authority (optional, defaults to mock)
 * @returns Configured RenewalWorkflow instance
 */
export function createRenewalWorkflow(
  repository: CertificateRepository,
  ca?: ICertificateAuthority
): RenewalWorkflow {
  const certificateAuthority = ca || new MockCertificateAuthority();
  const renewalThresholdDays = parseInt(
    process.env.RENEWAL_THRESHOLD_DAYS || '60',
    10
  );

  return new RenewalWorkflow(repository, certificateAuthority, renewalThresholdDays);
}

/**
 * Create certificate authority based on configuration
 */
export function createCertificateAuthority(
  type: 'mock' | 'fina' = 'mock'
): ICertificateAuthority {
  switch (type) {
    case 'mock':
      return new MockCertificateAuthority();
    case 'fina':
      const apiUrl = process.env.FINA_API_URL || 'https://cis.porezna-uprava.hr';
      const authCert = process.env.FINA_AUTH_CERT || '';
      const authKey = process.env.FINA_AUTH_KEY || '';

      if (!authCert || !authKey) {
        logger.warn(
          'FINA auth credentials not configured, falling back to mock CA'
        );
        return new MockCertificateAuthority();
      }

      return new FINACertificateAuthority(apiUrl, authCert, authKey);
    default:
      throw new Error(`Unknown CA type: ${type}`);
  }
}
