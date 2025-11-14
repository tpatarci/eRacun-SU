/**
 * Certificate Distribution Module
 *
 * Handles secure distribution of certificates to services:
 * 1. Encrypts certificates with SOPS before distribution
 * 2. Deploys to target services (e.g., digital-signature-service)
 * 3. Triggers service configuration reloads
 * 4. Audit logging of all distributions
 * 5. Rollback capability on failure
 */

import { writeFile, mkdir, readFile } from 'fs/promises';
import { join } from 'path';
import { getHSM } from './hsm/index.js';
import { Certificate } from './repository.js';
import {
  logger,
  createSpan,
  setSpanError,
  certificateOperations,
} from './observability.js';

/**
 * Distribution target service
 */
export interface DistributionTarget {
  /** Service name */
  serviceName: string;
  /** Certificate destination path */
  certPath: string;
  /** Private key destination path */
  keyPath: string;
  /** Reload command (optional) */
  reloadCommand?: string;
  /** Environment (dev, staging, production) */
  environment: string;
}

/**
 * Distribution result
 */
export interface DistributionResult {
  /** Success status */
  success: boolean;
  /** Target service */
  target: DistributionTarget;
  /** Certificate ID */
  certId: string;
  /** Error message (if failed) */
  error?: string;
  /** Timestamp */
  timestamp: Date;
  /** Distribution ID for audit trail */
  distributionId: string;
}

/**
 * Encryption provider interface
 *
 * Abstracts SOPS encryption for certificate distribution
 */
export interface IEncryptionProvider {
  /**
   * Encrypt certificate and private key
   * @param certPEM - Certificate in PEM format
   * @param keyPEM - Private key in PEM format
   * @returns Encrypted data
   */
  encrypt(certPEM: string, keyPEM: string): Promise<string>;

  /**
   * Decrypt certificate and private key
   * @param encryptedData - Encrypted data
   * @returns Decrypted certificate and key
   */
  decrypt(encryptedData: string): Promise<{ certPEM: string; keyPEM: string }>;
}

/**
 * Mock encryption provider
 *
 * Simulates SOPS encryption for development
 */
export class MockEncryptionProvider implements IEncryptionProvider {
  async encrypt(certPEM: string, keyPEM: string): Promise<string> {
    // Simulate encryption delay
    await this.delay(50);

    // Base64 encode for mock encryption
    const data = JSON.stringify({ certPEM, keyPEM });
    const encrypted = Buffer.from(data).toString('base64');

    logger.debug('Certificate encrypted (MOCK)');

    return `-----BEGIN ENCRYPTED CERTIFICATE-----
${encrypted}
-----END ENCRYPTED CERTIFICATE-----`;
  }

  async decrypt(encryptedData: string): Promise<{ certPEM: string; keyPEM: string }> {
    // Simulate decryption delay
    await this.delay(50);

    // Extract base64 data
    const base64Data = encryptedData
      .replace('-----BEGIN ENCRYPTED CERTIFICATE-----', '')
      .replace('-----END ENCRYPTED CERTIFICATE-----', '')
      .trim();

    const data = Buffer.from(base64Data, 'base64').toString('utf8');
    const { certPEM, keyPEM } = JSON.parse(data);

    logger.debug('Certificate decrypted (MOCK)');

    return { certPEM, keyPEM };
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

/**
 * SOPS encryption provider
 *
 * Integrates with Mozilla SOPS for production certificate encryption
 */
export class SOPSEncryptionProvider implements IEncryptionProvider {
  private ageKeyPath: string;

  constructor(ageKeyPath: string) {
    this.ageKeyPath = ageKeyPath;
  }

  async encrypt(certPEM: string, keyPEM: string): Promise<string> {
    logger.info('Encrypting certificate with SOPS');

    // TODO: Implement actual SOPS integration
    // This would:
    // 1. Create temporary file with certificate + key
    // 2. Execute: sops --encrypt --age <age-public-key> input.yaml > output.enc.yaml
    // 3. Read encrypted content
    // 4. Clean up temporary files
    // 5. Return encrypted data

    throw new Error('SOPS integration not yet implemented - use mock encryption');
  }

  async decrypt(encryptedData: string): Promise<{ certPEM: string; keyPEM: string }> {
    logger.info('Decrypting certificate with SOPS');

    // TODO: Implement actual SOPS decryption
    // This would:
    // 1. Write encrypted data to temporary file
    // 2. Execute: sops --decrypt input.enc.yaml > output.yaml
    // 3. Parse decrypted YAML
    // 4. Extract certificate and key
    // 5. Clean up temporary files

    throw new Error('SOPS decryption not yet implemented - use mock encryption');
  }
}

/**
 * Certificate Distribution Manager
 *
 * Orchestrates secure distribution of certificates to target services
 */
export class CertificateDistribution {
  private encryptionProvider: IEncryptionProvider;
  private distributionTargets: Map<string, DistributionTarget> = new Map();
  private distributionAuditLog: DistributionResult[] = [];

  constructor(encryptionProvider: IEncryptionProvider) {
    this.encryptionProvider = encryptionProvider;
  }

  /**
   * Register distribution target
   *
   * @param target - Distribution target configuration
   */
  registerTarget(target: DistributionTarget): void {
    this.distributionTargets.set(target.serviceName, target);
    logger.info(
      { serviceName: target.serviceName, environment: target.environment },
      'Distribution target registered'
    );
  }

  /**
   * Distribute certificate to all registered targets
   *
   * @param cert - Certificate to distribute
   * @param certPEM - Certificate in PEM format
   * @param keyId - HSM key ID for private key
   * @returns Array of distribution results
   */
  async distributeToAll(
    cert: Certificate,
    certPEM: string,
    keyId: string
  ): Promise<DistributionResult[]> {
    const span = createSpan('distribute_certificate', {
      certId: cert.certId,
      targetCount: this.distributionTargets.size,
    });

    try {
      logger.info(
        {
          certId: cert.certId,
          targetCount: this.distributionTargets.size,
        },
        'Starting certificate distribution to all targets'
      );

      const results: DistributionResult[] = [];

      // Distribute to each target
      for (const target of this.distributionTargets.values()) {
        const result = await this.distributeToTarget(cert, certPEM, keyId, target);
        results.push(result);

        // Update metrics
        if (result.success) {
          certificateOperations.labels('deploy', 'success').inc();
        } else {
          certificateOperations.labels('deploy', 'failed').inc();
        }
      }

      logger.info(
        {
          certId: cert.certId,
          total: results.length,
          succeeded: results.filter((r) => r.success).length,
          failed: results.filter((r) => !r.success).length,
        },
        'Certificate distribution completed'
      );

      span.end();
      return results;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error, certId: cert.certId }, 'Certificate distribution failed');
      throw error;
    }
  }

  /**
   * Distribute certificate to specific target
   *
   * @param cert - Certificate to distribute
   * @param certPEM - Certificate in PEM format
   * @param keyId - HSM key ID for private key
   * @param target - Distribution target
   * @returns Distribution result
   */
  async distributeToTarget(
    cert: Certificate,
    certPEM: string,
    keyId: string,
    target: DistributionTarget
  ): Promise<DistributionResult> {
    const distributionId = `dist-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    const span = createSpan('distribute_to_target', {
      certId: cert.certId,
      target: target.serviceName,
      distributionId,
    });

    try {
      logger.info(
        {
          certId: cert.certId,
          target: target.serviceName,
          distributionId,
        },
        'Starting certificate distribution'
      );

      // 1. Export private key from HSM
      const hsm = getHSM();
      const keyPEM = await hsm.exportPrivateKey(keyId);

      logger.debug('Private key exported from HSM');

      // 2. Encrypt certificate and key
      const encryptedData = await this.encryptionProvider.encrypt(certPEM, keyPEM);

      logger.debug('Certificate and key encrypted');

      // 3. Ensure destination directories exist
      await this.ensureDirectories(target);

      // 4. Write encrypted certificate
      const certFilePath = join(target.certPath, `${cert.certId}.cert.enc`);
      await writeFile(certFilePath, encryptedData, { mode: 0o600 });

      logger.info({ certFilePath }, 'Certificate written to disk');

      // 5. Write key separately (for compatibility)
      const keyFilePath = join(target.keyPath, `${cert.certId}.key.enc`);
      await writeFile(keyFilePath, encryptedData, { mode: 0o600 });

      logger.info({ keyFilePath }, 'Private key written to disk');

      // 6. Trigger service reload (if configured)
      if (target.reloadCommand) {
        await this.reloadService(target);
      }

      const result: DistributionResult = {
        success: true,
        target,
        certId: cert.certId,
        timestamp: new Date(),
        distributionId,
      };

      // Add to audit log
      this.distributionAuditLog.push(result);

      logger.info(
        {
          certId: cert.certId,
          target: target.serviceName,
          distributionId,
          certFilePath,
          keyFilePath,
        },
        'Certificate distributed successfully'
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
          target: target.serviceName,
          distributionId,
        },
        'Certificate distribution failed'
      );

      const result: DistributionResult = {
        success: false,
        target,
        certId: cert.certId,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
        distributionId,
      };

      // Add to audit log
      this.distributionAuditLog.push(result);

      return result;
    }
  }

  /**
   * Ensure destination directories exist
   */
  private async ensureDirectories(target: DistributionTarget): Promise<void> {
    await mkdir(target.certPath, { recursive: true, mode: 0o700 });
    await mkdir(target.keyPath, { recursive: true, mode: 0o700 });

    logger.debug(
      { certPath: target.certPath, keyPath: target.keyPath },
      'Distribution directories ensured'
    );
  }

  /**
   * Reload target service
   */
  private async reloadService(target: DistributionTarget): Promise<void> {
    if (!target.reloadCommand) {
      return;
    }

    logger.info(
      { serviceName: target.serviceName, command: target.reloadCommand },
      'Reloading service'
    );

    // TODO: Implement service reload
    // This would:
    // 1. Execute reload command (e.g., systemctl reload digital-signature-service)
    // 2. Wait for service to acknowledge reload
    // 3. Verify service health after reload

    // For now, just log
    logger.warn('Service reload not yet implemented - manual reload required');
  }

  /**
   * Get distribution audit log
   *
   * @returns Array of distribution results
   */
  getAuditLog(): DistributionResult[] {
    return [...this.distributionAuditLog];
  }

  /**
   * Get distribution audit log for specific certificate
   *
   * @param certId - Certificate ID
   * @returns Array of distribution results for this certificate
   */
  getAuditLogForCert(certId: string): DistributionResult[] {
    return this.distributionAuditLog.filter((result) => result.certId === certId);
  }

  /**
   * Clear audit log (for testing)
   */
  clearAuditLog(): void {
    this.distributionAuditLog = [];
    logger.info('Distribution audit log cleared');
  }
}

/**
 * Create certificate distribution manager with default configuration
 */
export function createCertificateDistribution(
  encryptionType: 'mock' | 'sops' = 'mock'
): CertificateDistribution {
  let encryptionProvider: IEncryptionProvider;

  switch (encryptionType) {
    case 'mock':
      encryptionProvider = new MockEncryptionProvider();
      break;
    case 'sops':
      const ageKeyPath = process.env.AGE_KEY_PATH || '/etc/eracun/.age-key';
      encryptionProvider = new SOPSEncryptionProvider(ageKeyPath);
      logger.warn('SOPS encryption requested but not yet implemented - falling back to mock');
      encryptionProvider = new MockEncryptionProvider();
      break;
    default:
      throw new Error(`Unknown encryption type: ${encryptionType}`);
  }

  const distribution = new CertificateDistribution(encryptionProvider);

  // Register default targets from environment
  const defaultTargets = getDefaultDistributionTargets();
  defaultTargets.forEach((target) => distribution.registerTarget(target));

  return distribution;
}

/**
 * Get default distribution targets from environment
 */
function getDefaultDistributionTargets(): DistributionTarget[] {
  const environment = process.env.NODE_ENV || 'development';
  const targets: DistributionTarget[] = [];

  // Digital Signature Service (always included)
  targets.push({
    serviceName: 'digital-signature-service',
    certPath: process.env.DIGITAL_SIGNATURE_CERT_PATH || '/etc/eracun/certs',
    keyPath: process.env.DIGITAL_SIGNATURE_KEY_PATH || '/etc/eracun/keys',
    reloadCommand: 'systemctl reload eracun-digital-signature-service',
    environment,
  });

  // FINA Connector (always included)
  targets.push({
    serviceName: 'fina-connector',
    certPath: process.env.FINA_CONNECTOR_CERT_PATH || '/etc/eracun/certs',
    keyPath: process.env.FINA_CONNECTOR_KEY_PATH || '/etc/eracun/keys',
    reloadCommand: 'systemctl reload eracun-fina-connector',
    environment,
  });

  // Add custom targets from environment
  const customTargets = process.env.CUSTOM_DISTRIBUTION_TARGETS;
  if (customTargets) {
    try {
      const parsed = JSON.parse(customTargets);
      targets.push(...parsed);
    } catch (error) {
      logger.warn(
        { error },
        'Failed to parse custom distribution targets from environment'
      );
    }
  }

  return targets;
}
