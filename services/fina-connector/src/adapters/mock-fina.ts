/**
 * Mock FINA Service
 *
 * Perfect mock implementation of Croatian Tax Authority FINA APIs
 * Used for development and testing to unblock all teams
 */

import { createHash } from 'crypto';
import type {
  IFINAClient,
  SignedUBLInvoice,
  FINAResponse,
  StatusResponse,
  ValidationResult,
  CompanyInfo,
  X509Certificate,
} from './interfaces.js';

/**
 * Mock certificate data
 */
interface MockCertificateData {
  serialNumber: string;
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
  revoked: boolean;
}

/**
 * Mock FINA Service Implementation
 *
 * Provides realistic simulation of FINA fiscalization APIs with:
 * - Invoice submission with JIR/ZKI generation
 * - Digital signature verification
 * - Certificate validation
 * - OIB validation (ISO 7064 MOD 11-10)
 * - KPD code validation (KLASUS 2025)
 * - Company registry lookup
 * - Realistic network delays
 */
export class MockFINAService implements IFINAClient {
  private readonly responses: Map<string, FINAResponse> = new Map();
  private readonly certificateStore: Map<string, MockCertificateData> = new Map();
  private readonly companyRegistry: Map<string, CompanyInfo> = new Map();
  private readonly submittedInvoices: Set<string> = new Set();

  constructor() {
    this.seedTestData();
  }

  /**
   * Submit invoice for fiscalization
   */
  async submitInvoice(invoice: SignedUBLInvoice): Promise<FINAResponse> {
    // Validate SOAP envelope structure
    if (!invoice.soapEnvelope || !invoice.soapEnvelope.includes('soap:Envelope')) {
      return this.createErrorResponse('INVALID_SOAP', 's001');
    }

    // Verify digital signature
    const signatureValid = await this.verifyXMLSignature(invoice);
    if (!signatureValid) {
      return this.createErrorResponse('INVALID_SIGNATURE', 's005');
    }

    // Validate certificate
    const certValid = await this.validateCertificate(invoice.certificate);
    if (!certValid.valid) {
      return this.createErrorResponse(
        'INVALID_CERTIFICATE',
        's006',
        certValid.details
      );
    }

    // Business validations
    const validationResult = await this.performBusinessValidations(invoice);
    if (!validationResult.valid) {
      return this.createErrorResponse(
        validationResult.error || 'VALIDATION_FAILED',
        validationResult.code || 's010'
      );
    }

    // Check for duplicate invoice
    const invoiceKey = `${invoice.supplierOIB}:${invoice.invoiceNumber}`;
    if (this.submittedInvoices.has(invoiceKey)) {
      return this.createErrorResponse('DUPLICATE_INVOICE', 's011');
    }

    // Generate JIR (Jedinstveni Identifikator Računa)
    const jir = this.generateJIR(invoice);

    // Generate ZKI (Zaštitni Kod Izdavatelja)
    const zki = await this.generateZKI(invoice);

    // Simulate network delay (100-500ms)
    await this.simulateNetworkDelay();

    // Create success response
    const response: FINAResponse = {
      success: true,
      jir,
      zki,
      timestamp: new Date().toISOString(),
      messageId: this.generateMessageId(),
      soapResponse: this.buildSOAPResponse(jir, zki),
      warnings: this.checkForWarnings(invoice),
    };

    // Store for status checking
    this.responses.set(jir, response);
    this.submittedInvoices.add(invoiceKey);

    return response;
  }

  /**
   * Check invoice status
   */
  async checkStatus(jir: string): Promise<StatusResponse> {
    // Simulate network delay
    await this.simulateNetworkDelay(100);

    const response = this.responses.get(jir);
    if (!response) {
      return {
        found: false,
        status: 'NOT_FOUND',
        message: `JIR ${jir} not found in system`,
      };
    }

    return {
      found: true,
      status: 'PROCESSED',
      jir: response.jir,
      timestamp: response.timestamp,
      details: {
        processed: true,
        archived: true,
        reportingComplete: true,
      },
    };
  }

  /**
   * Validate X.509 certificate
   */
  async validateCertificate(cert: X509Certificate): Promise<ValidationResult> {
    // Simulate processing delay
    await this.simulateNetworkDelay(50);

    // Check if certificate exists in store
    const certData = this.certificateStore.get(cert.serialNumber);
    if (!certData) {
      return {
        valid: false,
        error: 'UNKNOWN_CERTIFICATE',
        details: 'Certificate not issued by FINA',
      };
    }

    // Check expiry
    const now = new Date();
    if (now > certData.validTo) {
      return {
        valid: false,
        error: 'CERTIFICATE_EXPIRED',
        details: `Certificate expired on ${certData.validTo.toISOString()}`,
      };
    }

    if (now < certData.validFrom) {
      return {
        valid: false,
        error: 'CERTIFICATE_NOT_YET_VALID',
        details: `Certificate valid from ${certData.validFrom.toISOString()}`,
      };
    }

    // Check revocation
    if (certData.revoked) {
      return {
        valid: false,
        error: 'CERTIFICATE_REVOKED',
        details: 'Certificate has been revoked',
      };
    }

    return {
      valid: true,
      issuer: certData.issuer,
      subject: certData.subject,
      validFrom: certData.validFrom,
      validTo: certData.validTo,
    };
  }

  /**
   * Get company information by OIB
   */
  async getCompanyInfo(oib: string): Promise<CompanyInfo> {
    // Simulate network delay
    await this.simulateNetworkDelay(150);

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
    await this.simulateNetworkDelay(30);

    // 99.5% uptime simulation
    return Math.random() < 0.995;
  }

  /**
   * Perform business validations
   */
  private async performBusinessValidations(
    invoice: SignedUBLInvoice
  ): Promise<{ valid: boolean; error?: string; code?: string }> {
    const errors: string[] = [];

    // Validate supplier OIB
    if (!this.isValidOIB(invoice.supplierOIB)) {
      errors.push('Invalid supplier OIB');
    }

    // Validate buyer OIB
    if (!this.isValidOIB(invoice.buyerOIB)) {
      errors.push('Invalid buyer OIB');
    }

    // Validate VAT rates (Croatian rates: 0, 5, 13, 25)
    const validVATRates = [0, 5, 13, 25];
    for (const item of invoice.lineItems) {
      if (!validVATRates.includes(item.vatRate)) {
        errors.push(`Invalid VAT rate: ${item.vatRate}%`);
      }
    }

    // Validate KPD codes (KLASUS 2025)
    for (const item of invoice.lineItems) {
      if (!this.isValidKPDCode(item.kpdCode)) {
        errors.push(`Invalid KPD code: ${item.kpdCode}`);
      }
    }

    // Validate total amount
    if (invoice.totalAmount <= 0) {
      errors.push('Total amount must be positive');
    }

    if (errors.length > 0) {
      return {
        valid: false,
        error: errors[0],
        code: this.mapErrorToCode(errors[0]),
      };
    }

    return { valid: true };
  }

  /**
   * Verify XML digital signature (mock)
   */
  private async verifyXMLSignature(invoice: SignedUBLInvoice): Promise<boolean> {
    // Simulate signature verification delay
    await this.simulateProcessing(50);

    // Mock: 98% success rate for valid-looking signatures
    if (!invoice.signature || invoice.signature.length < 100) {
      return false;
    }

    return Math.random() < 0.98;
  }

  /**
   * Generate JIR (Jedinstveni Identifikator Računa)
   */
  private generateJIR(invoice: SignedUBLInvoice): string {
    // JIR format: 32 hexadecimal characters (uppercase)
    const hash = createHash('md5');
    hash.update(`${invoice.supplierOIB}${invoice.invoiceNumber}${Date.now()}`);
    return hash.digest('hex').toUpperCase();
  }

  /**
   * Generate ZKI (Zaštitni Kod Izdavatelja)
   */
  private async generateZKI(invoice: SignedUBLInvoice): Promise<string> {
    // ZKI = MD5(OIB + DateTime + InvoiceNumber + TotalAmount)
    const zkiSource =
      `${invoice.supplierOIB}` +
      `${invoice.issueDateTime}` +
      `${invoice.invoiceNumber}` +
      `${invoice.totalAmount.toFixed(2)}`;

    const hash = createHash('md5');
    hash.update(zkiSource);
    return hash.digest('hex').toUpperCase();
  }

  /**
   * Build SOAP response XML
   */
  private buildSOAPResponse(jir: string, zki: string): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:fis="http://www.apis-it.hr/fin/2012/types/f73">
  <soap:Body>
    <fis:RacunOdgovor>
      <fis:Zaglavlje>
        <fis:IdPoruke>${this.generateMessageId()}</fis:IdPoruke>
        <fis:DatumVrijeme>${new Date().toISOString()}</fis:DatumVrijeme>
      </fis:Zaglavlje>
      <fis:Jir>${jir}</fis:Jir>
      <fis:Zki>${zki}</fis:Zki>
    </fis:RacunOdgovor>
  </soap:Body>
</soap:Envelope>`;
  }

  /**
   * Check for warnings (non-fatal issues)
   */
  private checkForWarnings(invoice: SignedUBLInvoice): string[] {
    const warnings: string[] = [];

    // Warn about high amounts
    if (invoice.totalAmount > 1000000) {
      warnings.push('High transaction amount detected');
    }

    return warnings.length > 0 ? warnings : undefined;
  }

  /**
   * Create error response
   */
  private createErrorResponse(
    message: string,
    code: string,
    details?: string
  ): FINAResponse {
    return {
      success: false,
      error: {
        code,
        message: details || message,
      },
    };
  }

  /**
   * Validate Croatian OIB (ISO 7064 MOD 11-10)
   */
  private isValidOIB(oib: string): boolean {
    // Must be 11 digits
    if (!/^\d{11}$/.test(oib)) {
      return false;
    }

    // ISO 7064, MOD 11-10 check digit validation
    let a = 10;
    for (let i = 0; i < 10; i++) {
      a = ((a + parseInt(oib[i], 10)) % 10 || 10) * (2 % 11);
    }
    return (11 - a) % 10 === parseInt(oib[10], 10);
  }

  /**
   * Validate KPD code (KLASUS 2025)
   */
  private isValidKPDCode(code: string): boolean {
    // Must be 6 digits
    if (!/^\d{6}$/.test(code)) {
      return false;
    }

    // Check against known valid prefixes (sample)
    const validPrefixes = [
      '01', '02', '03', '10', '11', '20', '21', '22', '23', '24', '25',
      '26', '27', '28', '29', '30', '31', '32', '33', '35', '36', '37',
      '38', '39', '41', '42', '43', '45', '46', '47', '49', '50', '51',
      '52', '53', '55', '56', '58', '59', '60', '61', '62', '63', '64',
      '65', '66', '68', '69', '70', '71', '72', '73', '74', '75', '77',
      '78', '79', '80', '81', '82', '84', '85', '86', '87', '88', '90',
      '91', '92', '93', '94', '95', '96', '97', '98', '99',
    ];
    return validPrefixes.includes(code.substring(0, 2));
  }

  /**
   * Map error message to FINA error code
   */
  private mapErrorToCode(error: string): string {
    if (error.includes('OIB')) return 's007';
    if (error.includes('VAT')) return 's008';
    if (error.includes('KPD')) return 's009';
    if (error.includes('amount')) return 's012';
    return 's999';
  }

  /**
   * Generate mock company data
   */
  private generateMockCompany(oib: string): CompanyInfo {
    const cities = ['Zagreb', 'Split', 'Rijeka', 'Osijek', 'Zadar', 'Pula'];
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
        postalCode: `${10000 + cityIndex * 1000}`,
        country: 'HR',
      },
      active: true,
      registrationDate: new Date(Date.now() - Math.random() * 10 * 365 * 24 * 60 * 60 * 1000),
      activityCodes: [(100000 + parseInt(oib.substring(5, 11), 10) % 900000).toString()],
    };
  }

  /**
   * Seed test data
   */
  private seedTestData(): void {
    // Seed known test OIBs
    const testOIBs = ['12345678901', '98765432109', '11111111117'];

    testOIBs.forEach((oib) => {
      if (this.isValidOIB(oib)) {
        this.companyRegistry.set(oib, this.generateMockCompany(oib));
      }
    });

    // Seed test certificates
    this.certificateStore.set('TEST-001', {
      serialNumber: 'TEST-001',
      subject: 'CN=Test Company 1, O=Test d.o.o., C=HR',
      issuer: 'CN=FINA Demo CA, O=FINA, C=HR',
      validFrom: new Date('2024-01-01'),
      validTo: new Date('2026-12-31'),
      revoked: false,
    });

    this.certificateStore.set('TEST-002', {
      serialNumber: 'TEST-002',
      subject: 'CN=Test Company 2, O=Test d.o.o., C=HR',
      issuer: 'CN=FINA Demo CA, O=FINA, C=HR',
      validFrom: new Date('2024-01-01'),
      validTo: new Date('2026-12-31'),
      revoked: false,
    });
  }

  /**
   * Simulate network delay
   */
  private simulateNetworkDelay(baseMs: number = 100): Promise<void> {
    // Realistic network delay: baseMs + random jitter (0-400ms)
    const delay = baseMs + Math.random() * 400;
    return new Promise((resolve) => setTimeout(resolve, delay));
  }

  /**
   * Simulate processing time
   */
  private simulateProcessing(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Generate message ID (UUID v4)
   */
  private generateMessageId(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }
}

/**
 * Create mock FINA client instance
 */
export function createMockFINAClient(): IFINAClient {
  return new MockFINAService();
}
