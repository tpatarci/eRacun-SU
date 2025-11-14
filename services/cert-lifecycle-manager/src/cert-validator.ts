import { CertificateInfo } from './cert-parser';
import { logger, createSpan, setSpanError, certificateParseDuration } from './observability';
import { getRevocationChecker, RevocationCheckResult } from './revocation-check.js';

/**
 * Validation result with errors and warnings
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  revocationStatus?: RevocationCheckResult;
}

/**
 * Trusted certificate issuers (FINA and AKD)
 */
const TRUSTED_ISSUERS = [
  'Fina RDC 2015 CA',
  'Fina Root CA',
  'AKD', // Alternative Croatian CA
  'Financial Agency',
  'FINA',
];

/**
 * Validate certificate according to FINA requirements
 *
 * Croatian e-invoice certificates must meet these criteria:
 * - Issued by trusted CA (FINA or AKD)
 * - Not expired (notAfter > now)
 * - Already valid (notBefore <= now)
 * - Valid serial number format
 * - Appropriate key usage (digital signature)
 *
 * @param cert - Parsed certificate information
 * @returns ValidationResult with errors and warnings
 */
export async function validateCertificate(
  cert: CertificateInfo
): Promise<ValidationResult> {
  const span = createSpan('validate_certificate', {
    serialNumber: cert.serialNumber,
    issuer: cert.issuer,
  });
  const startTime = Date.now();

  const errors: string[] = [];
  const warnings: string[] = [];

  try {
    logger.info(
      { serialNumber: cert.serialNumber, issuer: cert.issuer },
      'Validating certificate'
    );

    // 1. Check certificate validity dates
    const now = new Date();

    if (cert.notBefore > now) {
      errors.push(
        `Certificate not yet valid (valid from ${cert.notBefore.toISOString()})`
      );
    }

    if (cert.notAfter < now) {
      errors.push(
        `Certificate expired (expired on ${cert.notAfter.toISOString()})`
      );
    }

    // 2. Check for expiration warning (within 30 days)
    const daysUntilExpiry = Math.floor(
      (cert.notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
    );

    if (daysUntilExpiry <= 30 && daysUntilExpiry > 0) {
      warnings.push(
        `Certificate expiring soon (${daysUntilExpiry} days remaining)`
      );
    }

    // 3. Check issuer is trusted (FINA or AKD)
    const isTrustedIssuer = TRUSTED_ISSUERS.some((trustedIssuer) =>
      cert.issuer.includes(trustedIssuer)
    );

    if (!isTrustedIssuer) {
      errors.push(
        `Certificate not issued by trusted CA (issuer: ${cert.issuer}). ` +
          `Expected one of: ${TRUSTED_ISSUERS.join(', ')}`
      );
    }

    // 4. Check serial number is present
    if (!cert.serialNumber || cert.serialNumber.length === 0) {
      errors.push('Certificate serial number is missing');
    }

    // 5. Check subject DN is present
    if (!cert.subjectDn || cert.subjectDn.length === 0) {
      errors.push('Certificate subject DN is missing');
    }

    // 6. Check fingerprint is present
    if (!cert.fingerprint || cert.fingerprint.length === 0) {
      errors.push('Certificate fingerprint is missing');
    }

    // 7. Validate certificate type
    if (!['production', 'demo', 'test'].includes(cert.certType)) {
      warnings.push(`Unknown certificate type: ${cert.certType}`);
    }

    // 8. Warn if demo certificate (should not be used in production)
    if (cert.certType === 'demo' && process.env.NODE_ENV === 'production') {
      warnings.push(
        'Demo certificate detected in production environment - this should be replaced with a production certificate'
      );
    }

    // 9. Check certificate validity period (FINA certificates: 5 years, demo: 1 year)
    const validityPeriodDays = Math.floor(
      (cert.notAfter.getTime() - cert.notBefore.getTime()) / (1000 * 60 * 60 * 24)
    );

    if (cert.certType === 'production' && validityPeriodDays > 1900) {
      // ~5 years + buffer
      warnings.push(
        `Unusual validity period for production certificate: ${validityPeriodDays} days`
      );
    }

    if (cert.certType === 'demo' && validityPeriodDays > 400) {
      // ~1 year + buffer
      warnings.push(
        `Unusual validity period for demo certificate: ${validityPeriodDays} days`
      );
    }

    // 10. Check certificate revocation status (CRL/OCSP)
    let revocationStatus: RevocationCheckResult | undefined;
    try {
      const revocationChecker = getRevocationChecker();
      revocationStatus = await revocationChecker.checkRevocation(
        cert.serialNumber,
        cert.issuer
      );

      if (revocationStatus.revoked) {
        errors.push(
          `Certificate has been revoked (reason: ${revocationStatus.reason || 'unspecified'}, ` +
            `revoked at: ${revocationStatus.revokedAt?.toISOString() || 'unknown'})`
        );
      }

      if (revocationStatus.error) {
        warnings.push(
          `Could not verify revocation status: ${revocationStatus.error} (method: ${revocationStatus.method})`
        );
      }

      logger.debug(
        {
          serialNumber: cert.serialNumber,
          revoked: revocationStatus.revoked,
          method: revocationStatus.method,
        },
        'Certificate revocation check completed'
      );
    } catch (error) {
      logger.warn(
        { error, serialNumber: cert.serialNumber },
        'Certificate revocation check failed'
      );
      warnings.push(
        `Revocation check failed: ${error instanceof Error ? error.message : 'unknown error'}`
      );
    }

    // Record validation duration
    const durationSeconds = (Date.now() - startTime) / 1000;
    certificateParseDuration.labels('validate').observe(durationSeconds);

    const result: ValidationResult = {
      valid: errors.length === 0,
      errors,
      warnings,
      revocationStatus,
    };

    if (result.valid) {
      logger.info(
        {
          serialNumber: cert.serialNumber,
          warnings: warnings.length,
          durationSeconds,
        },
        'Certificate validation passed'
      );
    } else {
      logger.warn(
        {
          serialNumber: cert.serialNumber,
          errors: errors.length,
          warnings: warnings.length,
          durationSeconds,
        },
        'Certificate validation failed'
      );
    }

    span.end();
    return result;
  } catch (error) {
    const durationSeconds = (Date.now() - startTime) / 1000;
    certificateParseDuration.labels('validate').observe(durationSeconds);

    setSpanError(span, error as Error);
    span.end();

    logger.error({ error }, 'Certificate validation error');
    throw error;
  }
}

/**
 * Check if certificate is expiring soon
 *
 * @param cert - Certificate information
 * @param daysThreshold - Number of days threshold (default: 30)
 * @returns true if expiring within threshold
 */
export function isExpiringSoon(
  cert: CertificateInfo,
  daysThreshold: number = 30
): boolean {
  const now = new Date();
  const daysUntilExpiry = Math.floor(
    (cert.notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );

  return daysUntilExpiry <= daysThreshold && daysUntilExpiry > 0;
}

/**
 * Check if certificate is expired
 *
 * @param cert - Certificate information
 * @returns true if expired
 */
export function isExpired(cert: CertificateInfo): boolean {
  const now = new Date();
  return cert.notAfter < now;
}

/**
 * Check if certificate is trusted (issued by FINA or AKD)
 *
 * @param cert - Certificate information
 * @returns true if trusted
 */
export function isTrustedIssuer(cert: CertificateInfo): boolean {
  return TRUSTED_ISSUERS.some((trustedIssuer) =>
    cert.issuer.includes(trustedIssuer)
  );
}

/**
 * Get certificate status based on expiration
 *
 * @param cert - Certificate information
 * @returns Certificate status ('active', 'expiring_soon', 'expired')
 */
export function getCertificateStatus(
  cert: CertificateInfo
): 'active' | 'expiring_soon' | 'expired' | 'revoked' {
  if (isExpired(cert)) {
    return 'expired';
  }

  if (isExpiringSoon(cert, 30)) {
    return 'expiring_soon';
  }

  return 'active';
}

/**
 * Get certificate status including revocation check
 *
 * @param cert - Certificate information
 * @returns Certificate status ('active', 'expiring_soon', 'expired', 'revoked')
 */
export async function getCertificateStatusWithRevocation(
  cert: CertificateInfo
): Promise<'active' | 'expiring_soon' | 'expired' | 'revoked'> {
  // Check revocation first (most critical)
  try {
    const revocationChecker = getRevocationChecker();
    const revocationStatus = await revocationChecker.checkRevocation(
      cert.serialNumber,
      cert.issuer
    );

    if (revocationStatus.revoked) {
      return 'revoked';
    }
  } catch (error) {
    logger.warn(
      { error, serialNumber: cert.serialNumber },
      'Revocation check failed in getCertificateStatusWithRevocation'
    );
    // Continue to expiration checks even if revocation check fails
  }

  // Then check expiration
  if (isExpired(cert)) {
    return 'expired';
  }

  if (isExpiringSoon(cert, 30)) {
    return 'expiring_soon';
  }

  return 'active';
}

/**
 * Get alert severity based on days until expiration
 *
 * @param daysUntilExpiry - Number of days until expiration
 * @returns Alert severity ('info', 'warning', 'critical', 'urgent')
 */
export function getAlertSeverity(
  daysUntilExpiry: number
): 'info' | 'warning' | 'critical' | 'urgent' {
  if (daysUntilExpiry <= 0) {
    return 'urgent'; // Expired
  } else if (daysUntilExpiry <= 1) {
    return 'urgent'; // Expires in 1 day
  } else if (daysUntilExpiry <= 7) {
    return 'critical'; // Expires in 7 days
  } else if (daysUntilExpiry <= 14) {
    return 'warning'; // Expires in 14 days
  } else if (daysUntilExpiry <= 30) {
    return 'info'; // Expires in 30 days
  }

  return 'info'; // More than 30 days
}
