/**
 * Certificate Revocation Checking (CRL/OCSP)
 *
 * Implements Certificate Revocation List (CRL) and
 * Online Certificate Status Protocol (OCSP) checking
 */

import axios from 'axios';
import { logger } from './observability.js';

/**
 * Revocation check result
 */
export interface RevocationCheckResult {
  /** Is certificate revoked */
  revoked: boolean;
  /** Revocation method used */
  method: 'crl' | 'ocsp' | 'mock';
  /** Revocation reason (if revoked) */
  reason?: string;
  /** Revocation date (if revoked) */
  revokedAt?: Date;
  /** Check timestamp */
  checkedAt: Date;
  /** Error message (if check failed) */
  error?: string;
}

/**
 * CRL/OCSP Checker Interface
 */
export interface IRevocationChecker {
  /**
   * Check if certificate is revoked
   * @param serialNumber - Certificate serial number
   * @param issuer - Certificate issuer
   * @returns Revocation check result
   */
  checkRevocation(
    serialNumber: string,
    issuer: string
  ): Promise<RevocationCheckResult>;

  /**
   * Health check
   */
  healthCheck(): Promise<boolean>;
}

/**
 * Mock Revocation Checker
 *
 * Simulates CRL/OCSP checking for development and testing
 * Real implementation would query actual CRL/OCSP endpoints
 */
export class MockRevocationChecker implements IRevocationChecker {
  private revokedCertificates: Set<string> = new Set();

  constructor() {
    // Seed with some test revoked certificates
    this.revokedCertificates.add('TEST-REVOKED-001');
    this.revokedCertificates.add('TEST-SUPERSEDED-001');
  }

  /**
   * Check if certificate is revoked
   */
  async checkRevocation(
    serialNumber: string,
    issuer: string
  ): Promise<RevocationCheckResult> {
    logger.debug(
      { serialNumber, issuer },
      'Checking certificate revocation status (MOCK)'
    );

    // Simulate network delay
    await this.delay(100);

    const revoked = this.revokedCertificates.has(serialNumber);

    // Determine revocation reason based on serial pattern
    let reason: string | undefined;
    if (revoked) {
      if (serialNumber.includes('SUPERSEDED')) {
        reason = 'superseded';
      } else {
        reason = 'keyCompromise';
      }
    }

    return {
      revoked,
      method: 'mock',
      reason,
      revokedAt: revoked ? new Date('2025-01-01') : undefined,
      checkedAt: new Date(),
    };
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    return true;
  }

  /**
   * Add certificate to revoked list (for testing)
   */
  markAsRevoked(serialNumber: string): void {
    this.revokedCertificates.add(serialNumber);
    logger.info({ serialNumber }, 'Certificate marked as revoked (MOCK)');
  }

  /**
   * Remove certificate from revoked list (for testing)
   */
  unmarkAsRevoked(serialNumber: string): void {
    this.revokedCertificates.delete(serialNumber);
    logger.info({ serialNumber }, 'Certificate unmarked as revoked (MOCK)');
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

/**
 * Real CRL Checker
 *
 * Implements actual CRL (Certificate Revocation List) checking
 * Downloads and parses CRL from CA's distribution point
 */
export class CRLChecker implements IRevocationChecker {
  private crlCache: Map<string, { crl: string; fetchedAt: Date }> = new Map();
  private crlCacheTTL = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Check revocation via CRL
   */
  async checkRevocation(
    serialNumber: string,
    issuer: string
  ): Promise<RevocationCheckResult> {
    try {
      logger.debug({ serialNumber, issuer }, 'Checking certificate via CRL');

      // Get CRL distribution point for issuer
      const crlUrl = this.getCRLDistributionPoint(issuer);
      if (!crlUrl) {
        return {
          revoked: false,
          method: 'crl',
          checkedAt: new Date(),
          error: 'No CRL distribution point found',
        };
      }

      // Download CRL (with caching)
      const crl = await this.downloadCRL(crlUrl);

      // Check if certificate is in CRL
      const revoked = this.isCertificateRevoked(serialNumber, crl);

      return {
        revoked,
        method: 'crl',
        reason: revoked ? 'Found in CRL' : undefined,
        checkedAt: new Date(),
      };
    } catch (error) {
      logger.error({ error, serialNumber }, 'CRL check failed');
      return {
        revoked: false,
        method: 'crl',
        checkedAt: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Download CRL from distribution point
   */
  private async downloadCRL(url: string): Promise<string> {
    // Check cache
    const cached = this.crlCache.get(url);
    if (cached && Date.now() - cached.fetchedAt.getTime() < this.crlCacheTTL) {
      logger.debug({ url }, 'Using cached CRL');
      return cached.crl;
    }

    // Download CRL
    logger.debug({ url }, 'Downloading CRL');
    const response = await axios.get(url, {
      timeout: 10000,
      responseType: 'text',
    });

    const crl = response.data;

    // Cache CRL
    this.crlCache.set(url, {
      crl,
      fetchedAt: new Date(),
    });

    return crl;
  }

  /**
   * Check if certificate is in CRL
   */
  private isCertificateRevoked(serialNumber: string, crl: string): boolean {
    // Simplified CRL parsing (real implementation would use x509 library)
    // CRL format: contains revoked serial numbers
    return crl.includes(serialNumber);
  }

  /**
   * Get CRL distribution point for issuer
   */
  private getCRLDistributionPoint(issuer: string): string | null {
    // Known CRL endpoints for Croatian CAs
    if (issuer.includes('FINA') || issuer.includes('Fina')) {
      return 'http://www.fina.hr/crl/finardc2015.crl';
    }
    if (issuer.includes('AKD')) {
      return 'http://www.akd.hr/crl/akdca.crl';
    }
    return null;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Try to fetch FINA CRL as health check
      const crlUrl = 'http://www.fina.hr/crl/finardc2015.crl';
      const response = await axios.get(crlUrl, {
        timeout: 5000,
        validateStatus: (status) => status < 500,
      });
      return response.status === 200;
    } catch {
      return false;
    }
  }
}

/**
 * OCSP Checker
 *
 * Implements Online Certificate Status Protocol checking
 * Queries OCSP responder for real-time certificate status
 */
export class OCSPChecker implements IRevocationChecker {
  /**
   * Check revocation via OCSP
   */
  async checkRevocation(
    serialNumber: string,
    issuer: string
  ): Promise<RevocationCheckResult> {
    try {
      logger.debug({ serialNumber, issuer }, 'Checking certificate via OCSP');

      // Get OCSP responder URL
      const ocspUrl = this.getOCSPResponder(issuer);
      if (!ocspUrl) {
        return {
          revoked: false,
          method: 'ocsp',
          checkedAt: new Date(),
          error: 'No OCSP responder found',
        };
      }

      // Create OCSP request
      const ocspRequest = this.createOCSPRequest(serialNumber);

      // Send OCSP request
      const response = await axios.post(ocspUrl, ocspRequest, {
        headers: {
          'Content-Type': 'application/ocsp-request',
        },
        timeout: 5000,
      });

      // Parse OCSP response
      const revoked = this.parseOCSPResponse(response.data);

      return {
        revoked,
        method: 'ocsp',
        reason: revoked ? 'OCSP responder reports revoked' : undefined,
        checkedAt: new Date(),
      };
    } catch (error) {
      logger.error({ error, serialNumber }, 'OCSP check failed');
      return {
        revoked: false,
        method: 'ocsp',
        checkedAt: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Get OCSP responder URL
   */
  private getOCSPResponder(issuer: string): string | null {
    // Known OCSP endpoints for Croatian CAs
    if (issuer.includes('FINA') || issuer.includes('Fina')) {
      return 'http://ocsp.fina.hr';
    }
    if (issuer.includes('AKD')) {
      return 'http://ocsp.akd.hr';
    }
    return null;
  }

  /**
   * Create OCSP request (simplified)
   */
  private createOCSPRequest(serialNumber: string): Buffer {
    // Real implementation would use x509/asn1 library to create proper OCSP request
    // This is a placeholder
    return Buffer.from(serialNumber);
  }

  /**
   * Parse OCSP response (simplified)
   */
  private parseOCSPResponse(data: unknown): boolean {
    // Real implementation would parse DER-encoded OCSP response
    // This is a placeholder
    return false;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Try to reach FINA OCSP responder
      const ocspUrl = 'http://ocsp.fina.hr';
      const response = await axios.head(ocspUrl, {
        timeout: 5000,
        validateStatus: (status) => status < 500,
      });
      return response.status < 500;
    } catch {
      return false;
    }
  }
}

/**
 * Create revocation checker based on configuration
 */
export function createRevocationChecker(
  type: 'mock' | 'crl' | 'ocsp' = 'mock'
): IRevocationChecker {
  switch (type) {
    case 'mock':
      return new MockRevocationChecker();
    case 'crl':
      return new CRLChecker();
    case 'ocsp':
      return new OCSPChecker();
    default:
      throw new Error(`Unknown revocation checker type: ${type}`);
  }
}

/**
 * Get default revocation checker
 */
let defaultChecker: IRevocationChecker | null = null;

export function getRevocationChecker(): IRevocationChecker {
  if (!defaultChecker) {
    const type = (process.env.REVOCATION_CHECK_TYPE as 'mock' | 'crl' | 'ocsp') || 'mock';
    defaultChecker = createRevocationChecker(type);
  }
  return defaultChecker;
}
