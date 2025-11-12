import forge from 'node-forge';
import { logger, certificateParseDuration, createSpan, setSpanError } from './observability';

/**
 * Certificate information extracted from X.509 .p12 certificate
 */
export interface CertificateInfo {
  subjectDn: string;
  serialNumber: string;
  issuer: string;
  notBefore: Date;
  notAfter: Date;
  fingerprint: string;
  publicKey: string;
  certType: 'production' | 'demo' | 'test';
}

/**
 * Parse X.509 .p12 certificate (PKCS#12 format)
 *
 * FINA certificates are distributed as .p12 files with password protection.
 * This function extracts certificate metadata for inventory tracking.
 *
 * @param p12Buffer - The .p12 certificate file buffer
 * @param password - The certificate password
 * @returns CertificateInfo object
 * @throws Error if parsing fails (invalid password, corrupt file, etc.)
 */
export async function parseCertificate(
  p12Buffer: Buffer,
  password: string
): Promise<CertificateInfo> {
  const span = createSpan('parse_certificate');
  const startTime = Date.now();

  try {
    logger.info('Parsing X.509 .p12 certificate');

    // Convert buffer to binary string for node-forge
    const p12Der = p12Buffer.toString('binary');
    const p12Asn1 = forge.asn1.fromDer(p12Der);

    // Parse PKCS#12 structure
    let p12: forge.pkcs12.Pkcs12Pfx;
    try {
      p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
    } catch (error) {
      logger.error({ error }, 'Failed to parse PKCS#12 - invalid password or corrupt file');
      throw new Error('Invalid certificate password or corrupt .p12 file');
    }

    // Extract certificate bags
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certBag = certBags[forge.pki.oids.certBag];

    if (!certBag || certBag.length === 0) {
      logger.error('No certificate found in .p12 file');
      throw new Error('No certificate found in .p12 file');
    }

    // Get the first certificate (FINA .p12 typically contains one certificate)
    const cert = certBag[0].cert;

    if (!cert) {
      logger.error('Certificate bag is empty');
      throw new Error('Certificate bag is empty');
    }

    // Extract subject distinguished name
    const subjectDn = cert.subject.attributes
      .map((attr) => `${attr.shortName}=${attr.value}`)
      .join(', ');

    // Extract issuer common name
    const issuerField = cert.issuer.getField('CN');
    const issuer = issuerField ? issuerField.value : 'UNKNOWN';

    // Extract serial number
    const serialNumber = cert.serialNumber;

    // Extract validity dates
    const notBefore = cert.validity.notBefore;
    const notAfter = cert.validity.notAfter;

    // Calculate SHA-256 fingerprint
    const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const md = forge.md.sha256.create();
    md.update(certDer);
    const fingerprint = md.digest().toHex().toUpperCase();

    // Extract public key (PEM format)
    const publicKey = forge.pki.publicKeyToPem(cert.publicKey);

    // Determine certificate type based on issuer or subject
    const certType = determineCertificateType(subjectDn, issuer);

    const certInfo: CertificateInfo = {
      subjectDn,
      serialNumber,
      issuer,
      notBefore,
      notAfter,
      fingerprint,
      publicKey,
      certType,
    };

    // Record parsing duration
    const durationSeconds = (Date.now() - startTime) / 1000;
    certificateParseDuration.labels('parse').observe(durationSeconds);

    logger.info(
      {
        serialNumber,
        issuer,
        notBefore: notBefore.toISOString(),
        notAfter: notAfter.toISOString(),
        certType,
        durationSeconds,
      },
      'Certificate parsed successfully'
    );

    span.end();
    return certInfo;
  } catch (error) {
    const durationSeconds = (Date.now() - startTime) / 1000;
    certificateParseDuration.labels('parse').observe(durationSeconds);

    setSpanError(span, error as Error);
    span.end();

    if (error instanceof Error) {
      logger.error({ error: error.message }, 'Certificate parsing failed');
      throw error;
    }

    throw new Error('Unknown error during certificate parsing');
  }
}

/**
 * Determine certificate type based on subject DN or issuer
 *
 * FINA production certificates: Issued by "Fina RDC 2015 CA"
 * FINA demo certificates: Issued by "Fina RDC 2015 CA" but contain "demo" or "test" in subject
 * AKD certificates: Issued by "AKD"
 *
 * @param subjectDn - Certificate subject distinguished name
 * @param issuer - Certificate issuer
 * @returns Certificate type ('production', 'demo', 'test')
 */
function determineCertificateType(
  subjectDn: string,
  issuer: string
): 'production' | 'demo' | 'test' {
  const subjectLower = subjectDn.toLowerCase();

  // Check for demo/test keywords in subject
  if (subjectLower.includes('demo') || subjectLower.includes('test')) {
    return 'demo';
  }

  // Check for test environment in issuer
  if (issuer.toLowerCase().includes('test')) {
    return 'test';
  }

  // Default to production for FINA certificates
  return 'production';
}

/**
 * Extract certificate from buffer without password (for public info only)
 *
 * This is useful for reading certificate metadata without needing the password.
 * However, PKCS#12 files are encrypted, so this will only work if the file
 * is not password-protected (rare).
 *
 * @param p12Buffer - The .p12 certificate file buffer
 * @returns Partial certificate info (what can be extracted without password)
 */
export async function extractCertificatePublicInfo(
  p12Buffer: Buffer
): Promise<Partial<CertificateInfo>> {
  try {
    // Try parsing with empty password (some test certificates)
    return await parseCertificate(p12Buffer, '');
  } catch (error) {
    // If parsing fails, return minimal info
    logger.warn('Cannot extract public info without password');
    return {
      certType: 'production',
    };
  }
}

/**
 * Calculate days until certificate expiration
 *
 * @param notAfter - Certificate expiration date
 * @returns Number of days until expiration (negative if expired)
 */
export function calculateDaysUntilExpiration(notAfter: Date): number {
  const now = new Date();
  const diffMs = notAfter.getTime() - now.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  return diffDays;
}

/**
 * Format certificate fingerprint for display
 *
 * @param fingerprint - SHA-256 fingerprint (hex string)
 * @returns Formatted fingerprint (e.g., "AB:CD:EF:...")
 */
export function formatFingerprint(fingerprint: string): string {
  return fingerprint.match(/.{1,2}/g)?.join(':') || fingerprint;
}
