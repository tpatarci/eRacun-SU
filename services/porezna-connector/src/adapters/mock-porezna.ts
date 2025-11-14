/**
 * Mock Porezna Uprava Service
 *
 * Perfect mock implementation that simulates Croatian Tax Authority APIs
 * Used for development and testing to unblock all teams
 */

import type { IPoreznaClient } from './interfaces.js';
import type {
  TaxReport,
  PoreznaResponse,
  VATRate,
  VATValidation,
  CompanyInfo,
} from '../types/index.js';

/**
 * Mock Porezna Service Implementation
 *
 * Provides realistic simulation of Porezna Uprava APIs with:
 * - Tax report submission and validation
 * - VAT number validation
 * - Company information lookup
 * - Realistic network delays
 */
export class MockPoreznaService implements IPoreznaClient {
  private submissions: Map<string, PoreznaResponse> = new Map();
  private companyRegistry: Map<string, CompanyInfo> = new Map();

  constructor() {
    this.seedTestData();
  }

  /**
   * Submit tax report to Porezna Uprava
   */
  async submitReport(report: TaxReport): Promise<PoreznaResponse> {
    // Validate report structure
    if (!this.validateReport(report)) {
      return {
        success: false,
        error: 'INVALID_REPORT_STRUCTURE',
        details: 'Report does not conform to schema',
      };
    }

    // Validate OIB
    if (!this.isValidOIB(report.supplierOIB)) {
      return {
        success: false,
        error: 'INVALID_OIB',
        details: `Invalid supplier OIB: ${report.supplierOIB}`,
      };
    }

    // Validate period format (YYYY-MM)
    if (!/^\d{4}-\d{2}$/.test(report.period)) {
      return {
        success: false,
        error: 'INVALID_PERIOD',
        details: 'Period must be in format YYYY-MM',
      };
    }

    // Validate VAT amounts
    const calculatedVAT = report.vatBreakdown.reduce(
      (sum, item) => sum + item.vatAmount,
      0
    );
    if (Math.abs(calculatedVAT - report.vatAmount) > 0.01) {
      return {
        success: false,
        error: 'VAT_MISMATCH',
        details: 'Total VAT amount does not match breakdown sum',
      };
    }

    // Simulate processing delay
    await this.simulateProcessing();

    // Generate confirmation
    const confirmationNumber = this.generateConfirmationNumber();
    const timestamp = new Date().toISOString();
    const nextReportingDate = this.calculateNextReportingDate(report.period);

    const response: PoreznaResponse = {
      success: true,
      confirmationNumber,
      timestamp,
      nextReportingDate,
      status: 'ACCEPTED',
    };

    // Store for later retrieval
    this.submissions.set(confirmationNumber, response);

    return response;
  }

  /**
   * Get current Croatian VAT rates
   */
  async getVATRates(): Promise<VATRate[]> {
    // Simulate network delay
    await this.simulateProcessing(100);

    // Return current Croatian VAT rates as of 2025
    return [
      {
        rate: 25,
        category: 'STANDARD',
        description: 'Standard VAT rate',
      },
      {
        rate: 13,
        category: 'REDUCED',
        description: 'Reduced VAT rate - tourism, hospitality',
      },
      {
        rate: 5,
        category: 'SUPER_REDUCED',
        description: 'Super reduced VAT rate - essential goods',
      },
      {
        rate: 0,
        category: 'EXEMPT',
        description: 'Exempt from VAT',
      },
    ];
  }

  /**
   * Validate Croatian VAT number
   */
  async validateVATNumber(vatNumber: string): Promise<VATValidation> {
    // Simulate network delay
    await this.simulateProcessing(150);

    // Croatian VAT number format: HR + 11 digits (OIB)
    const match = vatNumber.match(/^HR(\d{11})$/);
    if (!match) {
      return {
        valid: false,
        error: 'Invalid VAT number format. Expected: HR followed by 11 digits',
      };
    }

    const oib = match[1];
    if (!this.isValidOIB(oib)) {
      return {
        valid: false,
        error: 'Invalid OIB check digit',
      };
    }

    // Look up company in registry
    const company = this.companyRegistry.get(oib);
    if (company) {
      return {
        valid: true,
        companyName: company.name,
        address: `${company.address.street}, ${company.address.city}`,
        active: company.active,
      };
    }

    // Generate mock company for unknown OIBs (for testing)
    const mockCompany = this.generateMockCompany(oib);
    return {
      valid: true,
      companyName: mockCompany.name,
      address: `${mockCompany.address.city}, Croatia`,
      active: true,
    };
  }

  /**
   * Get company information by OIB
   */
  async getCompanyInfo(oib: string): Promise<CompanyInfo> {
    // Simulate network delay
    await this.simulateProcessing(200);

    // Validate OIB format
    if (!this.isValidOIB(oib)) {
      throw new Error(`Invalid OIB format: ${oib}`);
    }

    // Return from registry or generate mock
    const company = this.companyRegistry.get(oib);
    if (company) {
      return company;
    }

    return this.generateMockCompany(oib);
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    // Simulate network delay
    await this.simulateProcessing(50);

    // 99% uptime simulation
    return Math.random() < 0.99;
  }

  /**
   * Validate report structure
   */
  private validateReport(report: TaxReport): boolean {
    return !!(
      report.period &&
      report.supplierOIB &&
      report.totalAmount !== undefined &&
      report.vatAmount !== undefined &&
      report.vatBreakdown &&
      Array.isArray(report.vatBreakdown) &&
      report.invoiceCount !== undefined
    );
  }

  /**
   * Validate Croatian OIB (ISO 7064, MOD 11-10)
   */
  private isValidOIB(oib: string): boolean {
    // Must be 11 digits
    if (!/^\d{11}$/.test(oib)) {
      return false;
    }

    // ISO 7064, MOD 11-10 check digit validation
    let a = 10;
    for (let i = 0; i < 10; i++) {
      a = ((a + parseInt(oib[i], 10)) % 10 || 10) * 2 % 11;
    }
    return ((11 - a) % 10) === parseInt(oib[10], 10);
  }

  /**
   * Generate confirmation number
   */
  private generateConfirmationNumber(): string {
    const year = new Date().getFullYear();
    const random = Math.floor(Math.random() * 1000000);
    return `PU-${year}-${random.toString().padStart(6, '0')}`;
  }

  /**
   * Calculate next reporting date (20th of next month)
   */
  private calculateNextReportingDate(period: string): string {
    const [year, month] = period.split('-').map(Number);
    const nextMonth = new Date(year, month, 20); // month is 0-indexed
    return nextMonth.toISOString().split('T')[0];
  }

  /**
   * Generate mock company data
   */
  private generateMockCompany(oib: string): CompanyInfo {
    const cities = ['Zagreb', 'Split', 'Rijeka', 'Osijek', 'Zadar', 'Pula', 'Dubrovnik'];
    const streets = ['Ilica', 'Vukovarska', 'Frankopanska', 'Savska', 'Radnička'];

    const cityIndex = parseInt(oib.substring(0, 2), 10) % cities.length;
    const streetIndex = parseInt(oib.substring(2, 4), 10) % streets.length;
    const streetNumber = parseInt(oib.substring(4, 7), 10) % 200 + 1;

    return {
      oib,
      name: `Test Company ${oib.substring(0, 4)} d.o.o.`,
      vatNumber: `HR${oib}`,
      address: {
        street: `${streets[streetIndex]} ${streetNumber}`,
        city: cities[cityIndex],
        postalCode: `${10000 + cityIndex * 100}`,
        country: 'HR',
      },
      active: true,
      registrationDate: new Date(Date.now() - Math.random() * 10 * 365 * 24 * 60 * 60 * 1000),
      activityCodes: [
        (100000 + parseInt(oib.substring(5, 11), 10) % 900000).toString(),
      ],
    };
  }

  /**
   * Seed test data
   */
  private seedTestData(): void {
    // Seed known test OIBs with company data
    const testOIBs = [
      '12345678901', // Test company 1
      '98765432109', // Test company 2
      '11111111117', // Test company 3 (valid check digit)
    ];

    testOIBs.forEach((oib) => {
      if (this.isValidOIB(oib)) {
        this.companyRegistry.set(oib, this.generateMockCompany(oib));
      }
    });
  }

  /**
   * Simulate network delay
   */
  private simulateProcessing(baseMs: number = 200): Promise<void> {
    // Realistic network delay: baseMs + random jitter
    const delay = baseMs + Math.random() * 300;
    return new Promise((resolve) => setTimeout(resolve, delay));
  }
}

/**
 * Create mock Porezna client instance
 */
export function createMockPoreznaClient(): IPoreznaClient {
  return new MockPoreznaService();
}
