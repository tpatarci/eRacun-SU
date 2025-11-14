/**
 * Digital Signature Service Adapter Interface
 * Abstracts XMLDSig signing and verification
 */

export interface IDigitalSignatureService {
  /**
   * Sign XML document with digital certificate
   */
  signXML(xml: string, certificateId: string): Promise<SignatureResult>;

  /**
   * Verify XML signature
   */
  verifySignature(signedXML: string): Promise<VerificationResult>;

  /**
   * Calculate ZKI (Zaštitni Kod Izdavatelja) for FINA
   */
  calculateZKI(data: ZKIData): Promise<string>;

  /**
   * Health check
   */
  healthCheck(): Promise<boolean>;
}

export interface SignatureResult {
  success: boolean;
  signedXML?: string;
  signature?: string;
  timestamp?: string;             // Qualified timestamp
  error?: string;
}

export interface VerificationResult {
  valid: boolean;
  certificateInfo?: CertificateInfo;
  timestamp?: string;
  error?: string;
}

export interface CertificateInfo {
  serialNumber: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  isExpired: boolean;
  isRevoked: boolean;
}

export interface ZKIData {
  oib: string;
  dateTime: string;               // DDMMYYYYHHMMSS format
  invoiceNumber: string;
  businessSpace: string;
  deviceNumber: string;
  totalAmount: number;
}

export interface ICertificateService {
  /**
   * Get certificate by ID
   */
  getCertificate(certificateId: string): Promise<Certificate | null>;

  /**
   * List all certificates
   */
  listCertificates(): Promise<Certificate[]>;

  /**
   * Check if certificate is about to expire
   */
  checkExpiry(certificateId: string): Promise<CertificateExpiryInfo>;

  /**
   * Renew certificate
   */
  renewCertificate(certificateId: string): Promise<boolean>;
}

export interface Certificate {
  id: string;
  serialNumber: string;
  type: 'FINA' | 'QUALIFIED';
  pem: string;
  validFrom: string;
  validTo: string;
  issuedBy: string;
  issuedTo: string;
}

export interface CertificateExpiryInfo {
  certificateId: string;
  expiresAt: string;
  daysRemaining: number;
  isExpired: boolean;
  shouldRenew: boolean;           // True if < 30 days remaining
}
