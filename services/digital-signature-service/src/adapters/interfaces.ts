/**
 * XML Digital Signature Interfaces
 *
 * Defines contracts for both real and mock implementations
 */

/**
 * Signing options
 */
export interface SigningOptions {
  /** Reference URI (default: empty for enveloped) */
  referenceUri?: string;
  /** Canonicalization algorithm */
  canonicalizationAlgorithm?: string;
  /** Signature algorithm */
  signatureAlgorithm?: string;
  /** Digest algorithm */
  digestAlgorithm?: string;
}

/**
 * Signed XML result
 */
export interface SignedXML {
  /** Signed XML document */
  xml: string;
  /** Base64-encoded signature value */
  signature: string;
  /** PEM-encoded certificate */
  certificate: string;
  /** Timestamp */
  timestamp: string;
  /** Signature algorithm used */
  algorithm: string;
}

/**
 * Verification result
 */
export interface VerificationResult {
  /** Is signature valid */
  valid: boolean;
  /** Signer information */
  signer?: string;
  /** Verification timestamp */
  timestamp?: string;
  /** Algorithm used */
  algorithm?: string;
  /** Error message (if invalid) */
  error?: string;
}

/**
 * Key pair (for mock implementation)
 */
export interface KeyPair {
  /** Private key (PEM format) */
  privateKey: string;
  /** Public key (PEM format) */
  publicKey: string;
}

/**
 * Mock certificate
 */
export interface MockCertificate {
  /** Subject DN */
  subject: string;
  /** Issuer DN */
  issuer: string;
  /** Serial number */
  serialNumber: string;
  /** Valid from */
  validFrom: Date;
  /** Valid to */
  validTo: Date;
  /** PEM-encoded certificate */
  pem: string;
}

/**
 * Interface for XML digital signature service
 * Both real and mock implementations must implement this interface
 */
export interface IXMLSigner {
  /**
   * Sign XML document
   * @param xml - XML document to sign
   * @param options - Signing options
   * @returns Signed XML with signature
   */
  signXML(xml: string, options?: SigningOptions): Promise<SignedXML>;

  /**
   * Verify XML signature
   * @param signedXML - Signed XML document
   * @returns Verification result
   */
  verifyXMLSignature(signedXML: string): Promise<VerificationResult>;

  /**
   * Get certificate information
   * @returns Certificate details
   */
  getCertificateInfo(): MockCertificate | null;
}
