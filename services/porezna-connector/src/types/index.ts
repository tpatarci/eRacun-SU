/**
 * Types for Porezna Uprava (Croatian Tax Authority) Integration
 */

/**
 * Tax report submitted to Porezna Uprava
 */
export interface TaxReport {
  /** Reporting period (YYYY-MM) */
  period: string;
  /** Supplier OIB (11 digits) */
  supplierOIB: string;
  /** Total invoice amount */
  totalAmount: number;
  /** Total VAT amount */
  vatAmount: number;
  /** VAT breakdown by rate */
  vatBreakdown: VATBreakdown[];
  /** Number of invoices in period */
  invoiceCount: number;
  /** Optional notes */
  notes?: string;
}

/**
 * VAT breakdown by rate
 */
export interface VATBreakdown {
  /** VAT rate percentage (0, 5, 13, 25) */
  rate: number;
  /** Taxable base amount */
  baseAmount: number;
  /** VAT amount */
  vatAmount: number;
}

/**
 * VAT rate definition
 */
export interface VATRate {
  /** VAT rate percentage */
  rate: number;
  /** Rate category */
  category: 'STANDARD' | 'REDUCED' | 'SUPER_REDUCED' | 'EXEMPT';
  /** Description */
  description: string;
}

/**
 * VAT number validation result
 */
export interface VATValidation {
  /** Is VAT number valid */
  valid: boolean;
  /** Company name (if found) */
  companyName?: string;
  /** Registered address */
  address?: string;
  /** Is company active */
  active?: boolean;
  /** Error message (if invalid) */
  error?: string;
}

/**
 * Porezna Uprava API response
 */
export interface PoreznaResponse {
  /** Success status */
  success: boolean;
  /** Confirmation number (if successful) */
  confirmationNumber?: string;
  /** Submission timestamp */
  timestamp?: string;
  /** Next reporting date */
  nextReportingDate?: string;
  /** Status */
  status?: 'ACCEPTED' | 'REJECTED' | 'PENDING';
  /** Error code (if failed) */
  error?: string;
  /** Error details */
  details?: string;
}

/**
 * Company information from Porezna Uprava
 */
export interface CompanyInfo {
  /** OIB (11 digits) */
  oib: string;
  /** Company name */
  name: string;
  /** VAT number (HR + OIB) */
  vatNumber: string;
  /** Registered address */
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
  /** Activity codes (NACE) */
  activityCodes: string[];
}
