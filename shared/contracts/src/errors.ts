/**
 * Standardized Error Codes and Error Types
 * All services must use these error codes for consistency
 */

export enum ErrorCode {
  // Validation errors (1000-1999)
  INVALID_OIB = 'ERR_1001',
  INVALID_VAT_NUMBER = 'ERR_1002',
  INVALID_KPD_CODE = 'ERR_1003',
  INVALID_VAT_RATE = 'ERR_1004',
  INVALID_XML_STRUCTURE = 'ERR_1005',
  SCHEMA_VALIDATION_FAILED = 'ERR_1006',

  // Processing errors (2000-2999)
  OCR_FAILED = 'ERR_2001',
  TRANSFORMATION_FAILED = 'ERR_2002',
  SIGNATURE_FAILED = 'ERR_2003',
  ENCRYPTION_FAILED = 'ERR_2004',

  // External service errors (3000-3999)
  FINA_UNAVAILABLE = 'ERR_3001',
  FINA_REJECTED = 'ERR_3002',
  POREZNA_UNAVAILABLE = 'ERR_3003',
  CERTIFICATE_EXPIRED = 'ERR_3004',
  CERTIFICATE_REVOKED = 'ERR_3005',

  // System errors (4000-4999)
  DATABASE_ERROR = 'ERR_4001',
  MESSAGE_BUS_ERROR = 'ERR_4002',
  STORAGE_ERROR = 'ERR_4003',
  RATE_LIMIT_EXCEEDED = 'ERR_4004',

  // Business logic errors (5000-5999)
  DUPLICATE_INVOICE = 'ERR_5001',
  INVOICE_ALREADY_PROCESSED = 'ERR_5002',
  RETENTION_PERIOD_VIOLATION = 'ERR_5003',
}

export interface StandardError {
  code: ErrorCode;
  message: string;
  details?: any;
  timestamp: string;
  service: string;
  correlationId: string;
  retryable: boolean;
  suggestedAction?: string;
}
