/**
 * FINA Client Interface
 *
 * Defines the contract for both real and mock implementations
 */

/**
 * Signed UBL Invoice with all required fiscalization data
 */
export interface SignedUBLInvoice {
  /** Supplier OIB (11 digits) */
  supplierOIB: string;
  /** Buyer OIB (11 digits) */
  buyerOIB: string;
  /** Invoice number */
  invoiceNumber: string;
  /** Issue date time (ISO 8601) */
  issueDateTime: string;
  /** Total amount */
  totalAmount: number;
  /** Line items with KPD codes */
  lineItems: Array<{
    description: string;
    quantity: number;
    unitPrice: number;
    vatRate: number;
    kpdCode: string;
  }>;
  /** ZKI (Zaštitni Kod Izdavatelja) */
  zki?: string;
  /** Digital signature (XMLDSig) */
  signature: string;
  /** X.509 certificate */
  certificate: X509Certificate;
  /** Full SOAP envelope (for real submission) */
  soapEnvelope: string;
}

/**
 * X.509 Certificate
 */
export interface X509Certificate {
  /** Serial number */
  serialNumber: string;
  /** Subject DN */
  subject: string;
  /** Issuer DN */
  issuer: string;
  /** Valid from */
  validFrom: Date;
  /** Valid to */
  validTo: Date;
  /** PEM-encoded certificate */
  pem: string;
}

/**
 * FINA submission response
 */
export interface FINAResponse {
  /** Success status */
  success: boolean;
  /** JIR (Jedinstveni Identifikator Računa) - unique invoice ID */
  jir?: string;
  /** ZKI (Zaštitni Kod Izdavatelja) - protective code */
  zki?: string;
  /** Submission timestamp */
  timestamp?: string;
  /** Message ID */
  messageId?: string;
  /** SOAP response XML */
  soapResponse?: string;
  /** Warnings (non-fatal) */
  warnings?: string[];
  /** Error (if failed) */
  error?: {
    code: string;
    message: string;
  };
}

/**
 * Status check response
 */
export interface StatusResponse {
  /** Was invoice found */
  found: boolean;
  /** Status */
  status: 'PROCESSED' | 'PENDING' | 'FAILED' | 'NOT_FOUND';
  /** JIR */
  jir?: string;
  /** Timestamp */
  timestamp?: string;
  /** Message */
  message?: string;
  /** Additional details */
  details?: {
    processed: boolean;
    archived: boolean;
    reportingComplete: boolean;
  };
}

/**
 * Certificate validation result
 */
export interface ValidationResult {
  /** Is certificate valid */
  valid: boolean;
  /** Error code (if invalid) */
  error?: string;
  /** Error details */
  details?: string;
  /** Issuer */
  issuer?: string;
  /** Subject */
  subject?: string;
  /** Valid from */
  validFrom?: Date;
  /** Valid to */
  validTo?: Date;
}

/**
 * Company information from FINA registry
 */
export interface CompanyInfo {
  /** OIB */
  oib: string;
  /** Company name */
  name: string;
  /** VAT number */
  vatNumber: string;
  /** Address */
  address: {
    street: string;
    city: string;
    postalCode: string;
    country: string;
  };
  /** Is company active */
  active: boolean;
  /** Registration date */
  registrationDate: Date;
  /** Activity codes */
  activityCodes: string[];
}

/**
 * Interface for FINA client
 * Both real and mock implementations must implement this interface
 */
export interface IFINAClient {
  /**
   * Submit invoice for fiscalization
   * @param invoice - Signed UBL invoice
   * @returns Response with JIR
   */
  submitInvoice(invoice: SignedUBLInvoice): Promise<FINAResponse>;

  /**
   * Check status of submitted invoice
   * @param jir - Jedinstveni Identifikator Računa
   * @returns Status information
   */
  checkStatus(jir: string): Promise<StatusResponse>;

  /**
   * Validate X.509 certificate
   * @param cert - Certificate to validate
   * @returns Validation result
   */
  validateCertificate(cert: X509Certificate): Promise<ValidationResult>;

  /**
   * Get company information by OIB
   * @param oib - 11-digit OIB
   * @returns Company information
   */
  getCompanyInfo(oib: string): Promise<CompanyInfo>;

  /**
   * Health check - test connection to FINA
   * @returns True if service is available
   */
  healthCheck(): Promise<boolean>;
}
