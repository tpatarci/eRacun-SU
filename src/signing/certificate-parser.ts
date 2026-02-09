import forge from 'node-forge';
import * as fs from 'fs/promises';
import { logger } from '../shared/logger.js';

/**
 * Certificate Information Interface
 */
export interface CertificateInfo {
  subjectDN: string;
  issuerDN: string;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  issuer: string;
  publicKey: forge.pki.rsa.PublicKey;
  certificate: forge.pki.Certificate;
}

/**
 * Parsed P12 Certificate with Private Key
 */
export interface ParsedCertificate {
  info: CertificateInfo;
  privateKey: forge.pki.rsa.PrivateKey;
  certificatePEM: string;
  privateKeyPEM: string;
}

/**
 * Certificate Parser Error
 */
export class CertificateParseError extends Error {
  constructor(message: string, public cause?: Error) {
    super(message);
    this.name = 'CertificateParseError';
  }
}

/**
 * Certificate Validation Error
 */
export class CertificateValidationError extends Error {
  constructor(message: string, public errors: string[]) {
    super(message);
    this.name = 'CertificateValidationError';
  }
}

/**
 * Load and parse PKCS#12 (.p12) certificate from filesystem
 *
 * @param certPath - Path to .p12 certificate file
 * @param password - Certificate password
 * @returns Parsed certificate with private key
 * @throws CertificateParseError if parsing fails
 */
export async function loadCertificateFromFile(
  certPath: string,
  password: string
): Promise<ParsedCertificate> {
  try {
    logger.info({ certPath }, 'Loading certificate from file');

    // Read certificate file
    const certBuffer = await fs.readFile(certPath);

    // Parse certificate
    const parsed = parseCertificate(certBuffer, password);

    logger.info({
      subjectDN: parsed.info.subjectDN,
      issuer: parsed.info.issuer,
      serialNumber: parsed.info.serialNumber,
      notBefore: parsed.info.notBefore,
      notAfter: parsed.info.notAfter,
    }, 'Certificate loaded successfully');

    return parsed;
  } catch (error) {
    logger.error({ certPath, error }, 'Failed to load certificate');
    throw new CertificateParseError(
      `Failed to load certificate from ${certPath}`,
      error as Error
    );
  }
}

/**
 * Parse PKCS#12 certificate from buffer
 *
 * @param certBuffer - Certificate buffer
 * @param password - Certificate password
 * @returns Parsed certificate
 * @throws CertificateParseError if parsing fails
 */
export function parseCertificate(
  certBuffer: Buffer,
  password: string
): ParsedCertificate {
  try {
    // Convert buffer to binary string
    const p12Der = forge.util.decode64(certBuffer.toString('base64'));

    // Parse PKCS#12
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    // Extract certificate
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certBagArray = certBags[forge.pki.oids.certBag];
    if (!certBagArray || certBagArray.length === 0) {
      throw new Error('No certificate found in PKCS#12 file');
    }

    const certBag = certBagArray[0];
    if (!certBag || !certBag.cert) {
      throw new Error('Certificate bag does not contain certificate');
    }

    const certificate = certBag.cert;

    // Extract private key
    const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const keyBagArray = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];
    if (!keyBagArray || keyBagArray.length === 0) {
      throw new Error('No private key found in PKCS#12 file');
    }

    const keyBag = keyBagArray[0];
    if (!keyBag || !keyBag.key) {
      throw new Error('Key bag does not contain private key');
    }

    const privateKey = keyBag.key as forge.pki.rsa.PrivateKey;

    // Extract certificate info
    const info = extractCertificateInfo(certificate);

    // Convert to PEM format
    const certificatePEM = forge.pki.certificateToPem(certificate);
    const privateKeyPEM = forge.pki.privateKeyToPem(privateKey);

    return {
      info,
      privateKey,
      certificatePEM,
      privateKeyPEM,
    };
  } catch (error) {
    throw new CertificateParseError(
      'Failed to parse PKCS#12 certificate',
      error as Error
    );
  }
}

/**
 * Extract certificate information
 *
 * @param certificate - forge certificate object
 * @returns Certificate information
 */
export function extractCertificateInfo(
  certificate: forge.pki.Certificate
): CertificateInfo {
  // IMPROVEMENT-019: Optimize DN extraction without intermediate array allocation
  // Use reduce to build string directly instead of mapping to array then joining
  const subjectDN = certificate.subject.attributes
    .reduce((dn, attr, index) => {
      return index === 0
        ? `${attr.shortName}=${attr.value}`
        : `${dn}, ${attr.shortName}=${attr.value}`;
    }, '');

  // Extract issuer DN (same optimization)
  const issuerDN = certificate.issuer.attributes
    .reduce((dn, attr, index) => {
      return index === 0
        ? `${attr.shortName}=${attr.value}`
        : `${dn}, ${attr.shortName}=${attr.value}`;
    }, '');

  // Extract issuer CN (Common Name)
  const issuerCN = certificate.issuer.getField('CN');
  const issuer = issuerCN ? issuerCN.value as string : 'Unknown';

  return {
    subjectDN,
    issuerDN,
    serialNumber: certificate.serialNumber,
    notBefore: certificate.validity.notBefore,
    notAfter: certificate.validity.notAfter,
    issuer,
    publicKey: certificate.publicKey as forge.pki.rsa.PublicKey,
    certificate,
  };
}

/**
 * Validate certificate against FINA requirements
 *
 * @param certInfo - Certificate information
 * @returns Array of validation errors (empty if valid)
 */
export function validateCertificate(certInfo: CertificateInfo): string[] {
  const errors: string[] = [];
  const now = new Date();

  // Check if certificate is valid (not expired, not yet valid)
  if (certInfo.notBefore > now) {
    errors.push(`Certificate not yet valid (valid from ${certInfo.notBefore.toISOString()})`);
  }

  if (certInfo.notAfter < now) {
    errors.push(`Certificate expired (expired on ${certInfo.notAfter.toISOString()})`);
  }

  // Check if certificate is issued by FINA
  // FINA certificates should be issued by "Fina RDC 2015 CA"
  const validIssuers = ['Fina RDC 2015 CA', 'FINA', 'AKD']; // Allow AKD as alternative
  const isValidIssuer = validIssuers.some((issuer) =>
    certInfo.issuer.includes(issuer) || certInfo.issuerDN.includes(issuer)
  );

  if (!isValidIssuer) {
    errors.push(
      `Certificate not issued by FINA or AKD (issuer: ${certInfo.issuer})`
    );
  }

  // Check certificate approaching expiration (30 days warning)
  const daysUntilExpiry = Math.floor(
    (certInfo.notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );

  if (daysUntilExpiry <= 30 && daysUntilExpiry > 0) {
    errors.push(
      `Certificate expiring soon (${daysUntilExpiry} days remaining)`
    );
  }

  return errors;
}

/**
 * Validate certificate and throw if invalid
 *
 * @param certInfo - Certificate information
 * @throws CertificateValidationError if certificate is invalid
 */
export function assertCertificateValid(certInfo: CertificateInfo): void {
  const errors = validateCertificate(certInfo);

  // Filter out warnings (expiring soon)
  const criticalErrors = errors.filter(
    (err) => !err.includes('expiring soon')
  );

  if (criticalErrors.length > 0) {
    logger.error({ errors: criticalErrors }, 'Certificate validation failed');

    throw new CertificateValidationError(
      'Certificate validation failed',
      criticalErrors
    );
  }

  // Log warnings
  const warnings = errors.filter((err) => err.includes('expiring soon'));
  if (warnings.length > 0) {
    logger.warn({ warnings }, 'Certificate validation warnings');
  }

  logger.info({ issuer: certInfo.issuer }, 'Certificate validated successfully');
}
