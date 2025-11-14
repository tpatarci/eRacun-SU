/**
 * Types for Reporting Service
 */

/**
 * Report type
 */
export type ReportType =
  | 'COMPLIANCE_SUMMARY'
  | 'FISCAL_MONTHLY'
  | 'VAT_SUMMARY'
  | 'INVOICE_VOLUME'
  | 'ERROR_ANALYSIS'
  | 'ARCHIVE_STATUS';

/**
 * Report format
 */
export type ReportFormat = 'JSON' | 'CSV' | 'XLSX' | 'PDF';

/**
 * Report request
 */
export interface ReportRequest {
  /** Report type */
  type: ReportType;
  /** Start date (ISO 8601) */
  startDate: string;
  /** End date (ISO 8601) */
  endDate: string;
  /** Output format */
  format: ReportFormat;
  /** Optional filters */
  filters?: Record<string, unknown>;
}

/**
 * Report metadata
 */
export interface ReportMetadata {
  /** Report ID */
  id: string;
  /** Report type */
  type: ReportType;
  /** Generation timestamp */
  generatedAt: string;
  /** Period covered */
  period: {
    start: string;
    end: string;
  };
  /** Number of records */
  recordCount: number;
  /** Format */
  format: ReportFormat;
}

/**
 * Compliance summary report
 */
export interface ComplianceSummaryReport {
  metadata: ReportMetadata;
  summary: {
    totalInvoices: number;
    fiscalized: number;
    pending: number;
    failed: number;
    complianceRate: number;
  };
  breakdown: {
    byStatus: Record<string, number>;
    byMonth: Array<{
      month: string;
      count: number;
      complianceRate: number;
    }>;
  };
}

/**
 * VAT summary report
 */
export interface VATSummaryReport {
  metadata: ReportMetadata;
  summary: {
    totalBase: number;
    totalVAT: number;
    totalGross: number;
  };
  breakdown: Array<{
    rate: number;
    baseAmount: number;
    vatAmount: number;
    invoiceCount: number;
  }>;
}

/**
 * Invoice volume report
 */
export interface InvoiceVolumeReport {
  metadata: ReportMetadata;
  daily: Array<{
    date: string;
    count: number;
    totalAmount: number;
  }>;
  hourly: Array<{
    hour: number;
    count: number;
  }>;
}

/**
 * Error analysis report
 */
export interface ErrorAnalysisReport {
  metadata: ReportMetadata;
  errors: Array<{
    code: string;
    message: string;
    count: number;
    lastOccurrence: string;
  }>;
  topErrors: Array<{
    code: string;
    count: number;
    percentage: number;
  }>;
}

/**
 * Archive status report
 */
export interface ArchiveStatusReport {
  metadata: ReportMetadata;
  storage: {
    totalDocuments: number;
    totalSize: number;
    oldestDocument: string;
    newestDocument: string;
  };
  retention: {
    withinRetention: number;
    nearingExpiry: number;
    expired: number;
  };
  integrity: {
    validSignatures: number;
    invalidSignatures: number;
    lastValidationRun: string;
  };
}

/**
 * Report generation result
 */
export interface ReportResult {
  /** Success status */
  success: boolean;
  /** Report metadata */
  metadata?: ReportMetadata;
  /** Report data (format-specific) */
  data?: Buffer | string | Record<string, unknown>;
  /** File path (if saved) */
  filePath?: string;
  /** Error message (if failed) */
  error?: string;
}
