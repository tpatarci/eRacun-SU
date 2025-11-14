/**
 * FINA Connector Adapter Interface
 * Abstracts Croatian Tax Authority submission
 */

import { UBLInvoice } from '@eracun/contracts';

export interface IFINAService {
  /**
   * Submit invoice to FINA for B2C fiscalization
   */
  submitInvoice(request: FINASubmissionRequest): Promise<FINASubmissionResponse>;

  /**
   * Get submission status by invoice ID
   */
  getStatus(invoiceId: string): Promise<FINAStatusResponse>;

  /**
   * Verify JIR (Jedinstveni Identifikator Računa)
   */
  verifyJIR(jir: string): Promise<boolean>;

  /**
   * Health check - verify FINA service is reachable
   */
  healthCheck(): Promise<boolean>;
}

export interface FINASubmissionRequest {
  invoice: UBLInvoice;
  signature: string;              // XMLDSig signature
  zki: string;                    // Zaštitni Kod Izdavatelja
  certificateId: string;
  priority?: 'normal' | 'high';
}

export interface FINASubmissionResponse {
  success: boolean;
  jir?: string;                   // Jedinstveni Identifikator Računa
  timestamp?: string;             // ISO 8601
  error?: FINAError;
}

export interface FINAStatusResponse {
  invoiceId: string;
  status: 'PENDING' | 'ACCEPTED' | 'REJECTED' | 'ERROR';
  jir?: string;
  submittedAt?: string;
  error?: FINAError;
}

export interface FINAError {
  code: string;
  message: string;
  details?: any;
}

export interface IPoreznaService {
  /**
   * Submit B2B invoice to Porezna
   */
  submitInvoice(invoice: UBLInvoice): Promise<PoreznaSubmissionResponse>;

  /**
   * Submit monthly e-reporting (eIzvještavanje)
   */
  submitMonthlyReport(report: MonthlyReport): Promise<PoreznaSubmissionResponse>;

  /**
   * Health check
   */
  healthCheck(): Promise<boolean>;
}

export interface PoreznaSubmissionResponse {
  success: boolean;
  confirmationNumber?: string;
  timestamp?: string;
  error?: FINAError;
}

export interface MonthlyReport {
  period: string;                 // YYYY-MM
  invoices: string[];             // Invoice IDs
  totalAmount: number;
  vatAmount: number;
}
