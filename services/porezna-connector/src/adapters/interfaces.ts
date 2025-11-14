/**
 * Porezna Uprava Client Interface
 *
 * Defines the contract for both real and mock implementations
 */

import type {
  TaxReport,
  PoreznaResponse,
  VATRate,
  VATValidation,
  CompanyInfo,
} from '../types/index.js';

/**
 * Interface for Porezna Uprava client
 * Both real and mock implementations must implement this interface
 */
export interface IPoreznaClient {
  /**
   * Submit tax report to Porezna Uprava
   * @param report - Tax report data
   * @returns Response with confirmation number
   */
  submitReport(report: TaxReport): Promise<PoreznaResponse>;

  /**
   * Get current VAT rates
   * @returns Array of VAT rates
   */
  getVATRates(): Promise<VATRate[]>;

  /**
   * Validate Croatian VAT number
   * @param vatNumber - VAT number (format: HR + 11 digits)
   * @returns Validation result
   */
  validateVATNumber(vatNumber: string): Promise<VATValidation>;

  /**
   * Get company information by OIB
   * @param oib - 11-digit OIB
   * @returns Company information
   */
  getCompanyInfo(oib: string): Promise<CompanyInfo>;

  /**
   * Health check - test connection to Porezna API
   * @returns True if service is available
   */
  healthCheck(): Promise<boolean>;
}
