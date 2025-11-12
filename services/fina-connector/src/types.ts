/**
 * FINA Fiscalization API Types
 *
 * Based on FINA WSDL v1.9 specification
 */

/**
 * B2C Invoice (Račun) for fiscalization
 */
export interface FINAInvoice {
  /** OIB of the invoice issuer (11 digits) */
  oib: string;
  /** Date and time of issue (ISO 8601) */
  datVrijeme: string;
  /** Invoice number (sequential, unique per location/device) */
  brojRacuna: string;
  /** Business premises identifier */
  oznPoslProstora: string;
  /** Cash register/POS device identifier */
  oznNapUr: string;
  /** Total invoice amount (with 2 decimal places) */
  ukupanIznos: string;
  /** ZKI code (Zaštitni kod izdavatelja) - 32 hex characters */
  zki: string;
  /** Payment method (G=cash, K=card, C=check, T=transfer, O=other) */
  nacinPlac: 'G' | 'K' | 'C' | 'T' | 'O';
  /** Subsequent delivery flag (true if delivered after original invoice) */
  nakDost?: boolean;
  /** Paragon invoice block flag (block printing if true) */
  paragonBroj?: string;
  /** Specific purpose (label for specific use cases) */
  specNamj?: string;
  /** VAT breakdown (optional, but recommended) */
  pdv?: FINAVATBreakdown[];
  /** Non-taxable amount */
  pnp?: FINANonTaxable[];
  /** Other taxes */
  ostaliPor?: FINAOtherTaxes[];
}

/**
 * VAT breakdown
 */
export interface FINAVATBreakdown {
  /** Tax base (amount before VAT) */
  porez: string;
  /** VAT rate (25.00, 13.00, 5.00, 0.00) */
  stopa: string;
  /** VAT amount */
  iznos: string;
}

/**
 * Non-taxable amount
 */
export interface FINANonTaxable {
  /** Tax base */
  porez: string;
  /** Tax rate (0) */
  stopa: string;
  /** Amount */
  iznos: string;
}

/**
 * Other taxes (consumption tax, etc.)
 */
export interface FINAOtherTaxes {
  /** Tax name */
  naziv: string;
  /** Tax rate */
  stopa: string;
  /** Tax amount */
  iznos: string;
}

/**
 * FINA fiscalization request
 */
export interface FINAFiscalizationRequest {
  /** Invoice data */
  racun: FINAInvoice;
  /** XMLDSig signature (enveloped) */
  signature?: string;
}

/**
 * FINA fiscalization response
 */
export interface FINAFiscalizationResponse {
  /** Success flag */
  success: boolean;
  /** JIR (Jedinstveni identifikator računa) - Unique Invoice Identifier */
  jir?: string;
  /** Error details (if failure) */
  error?: FINAError;
  /** Raw SOAP response */
  rawResponse?: any;
}

/**
 * FINA error response
 */
export interface FINAError {
  /** Error code (s:001, s:002, etc.) */
  code: string;
  /** Error message */
  message: string;
  /** Stack trace (if available) */
  stack?: string;
}

/**
 * FINA echo request (health check)
 */
export interface FINAEchoRequest {
  /** Test message */
  message: string;
}

/**
 * FINA echo response
 */
export interface FINAEchoResponse {
  /** Echo message (should match request) */
  message: string;
}

/**
 * FINA provjera (validation) request - TEST ONLY
 */
export interface FINAValidationRequest {
  /** Invoice data to validate */
  racun: FINAInvoice;
}

/**
 * FINA provjera response
 */
export interface FINAValidationResponse {
  /** Validation success flag */
  success: boolean;
  /** Validation errors */
  errors?: string[];
}

/**
 * Offline queue entry (for failed submissions)
 */
export interface OfflineQueueEntry {
  /** Unique queue entry ID */
  id: string;
  /** Invoice ID (for correlation) */
  invoiceId: string;
  /** Fiscalization request */
  request: FINAFiscalizationRequest;
  /** Number of retry attempts */
  retryCount: number;
  /** Last error (if any) */
  lastError?: FINAError;
  /** Created timestamp */
  createdAt: Date;
  /** Last retry timestamp */
  lastRetryAt?: Date;
  /** Status (pending, processing, failed) */
  status: 'pending' | 'processing' | 'failed';
}

/**
 * Fiscalization message from RabbitMQ
 */
export interface FiscalizationMessage {
  /** Message ID (for idempotency) */
  messageId: string;
  /** Invoice ID */
  invoiceId: string;
  /** Invoice data */
  invoice: FINAInvoice;
  /** Request timestamp */
  timestamp: Date;
  /** Correlation ID (for tracking) */
  correlationId?: string;
}

/**
 * Fiscalization result message (to RabbitMQ)
 */
export interface FiscalizationResultMessage {
  /** Message ID (same as request) */
  messageId: string;
  /** Invoice ID */
  invoiceId: string;
  /** JIR (if successful) */
  jir?: string;
  /** Success flag */
  success: boolean;
  /** Error (if failure) */
  error?: FINAError;
  /** Processing timestamp */
  timestamp: Date;
  /** Correlation ID */
  correlationId?: string;
}
