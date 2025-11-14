/**
 * Real Porezna Uprava Service Client
 *
 * Production implementation that calls actual Croatian Tax Authority APIs
 */

import axios, { type AxiosInstance } from 'axios';
import type { IPoreznaClient } from './interfaces.js';
import type {
  TaxReport,
  PoreznaResponse,
  VATRate,
  VATValidation,
  CompanyInfo,
} from '../types/index.js';

export interface PoreznaClientConfig {
  /** API base URL */
  baseUrl: string;
  /** API key */
  apiKey: string;
  /** Request timeout (ms) */
  timeout: number;
}

/**
 * Real Porezna Uprava Client
 *
 * Implements actual HTTP calls to Porezna Uprava APIs
 */
export class RealPoreznaClient implements IPoreznaClient {
  private readonly client: AxiosInstance;
  private readonly config: PoreznaClientConfig;

  constructor(config: PoreznaClientConfig) {
    this.config = config;
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`,
        'User-Agent': 'eRacun/1.0',
      },
    });
  }

  /**
   * Submit tax report
   */
  async submitReport(report: TaxReport): Promise<PoreznaResponse> {
    try {
      const response = await this.client.post('/tax-reports', {
        period: report.period,
        supplierOIB: report.supplierOIB,
        totalAmount: report.totalAmount,
        vatAmount: report.vatAmount,
        vatBreakdown: report.vatBreakdown,
        invoiceCount: report.invoiceCount,
        notes: report.notes,
      });

      return {
        success: true,
        confirmationNumber: response.data.confirmationNumber,
        timestamp: response.data.timestamp,
        nextReportingDate: response.data.nextReportingDate,
        status: response.data.status,
      };
    } catch (error) {
      if (axios.isAxiosError(error) && error.response) {
        return {
          success: false,
          error: error.response.data.error || 'SUBMISSION_FAILED',
          details: error.response.data.message || error.message,
        };
      }

      throw error;
    }
  }

  /**
   * Get VAT rates
   */
  async getVATRates(): Promise<VATRate[]> {
    const response = await this.client.get('/vat-rates');
    return response.data.rates;
  }

  /**
   * Validate VAT number
   */
  async validateVATNumber(vatNumber: string): Promise<VATValidation> {
    try {
      const response = await this.client.get(`/vat-validation/${vatNumber}`);

      return {
        valid: response.data.valid,
        companyName: response.data.companyName,
        address: response.data.address,
        active: response.data.active,
      };
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        return {
          valid: false,
          error: 'VAT number not found',
        };
      }

      throw error;
    }
  }

  /**
   * Get company info
   */
  async getCompanyInfo(oib: string): Promise<CompanyInfo> {
    const response = await this.client.get(`/companies/${oib}`);
    return response.data;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.client.get('/health');
      return response.status === 200;
    } catch {
      return false;
    }
  }
}

/**
 * Create real Porezna client instance
 */
export function createRealPoreznaClient(config: PoreznaClientConfig): IPoreznaClient {
  return new RealPoreznaClient(config);
}
