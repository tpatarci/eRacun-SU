/**
 * Mock Validation Service
 * Simulates XSD, Schematron, KPD validation with realistic behavior
 */

import { injectable } from 'injectable';
import {
  IValidationService,
  IXSDValidatorService,
  ISchematronValidatorService,
  IKPDValidatorService,
  IOIBValidatorService,
  KPDCodeDetails
} from '@eracun/adapters';
import { ValidationResult, LayerResult, ErrorCode } from '@eracun/contracts';

@injectable()
export class MockValidationService implements IValidationService {
  async validateXSD(xml: string): Promise<LayerResult> {
    await this.simulateNetworkDelay(50, 150);

    // 90% success rate
    const passed = Math.random() > 0.1;

    return {
      passed,
      executionTime: Math.random() * 100 + 50,
      details: passed
        ? { schema: 'UBL-2.1', valid: true }
        : {
            schema: 'UBL-2.1',
            valid: false,
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                message: 'Element "cbc:ID" is missing'
              }
            ]
          }
    };
  }

  async validateSchematron(xml: string): Promise<LayerResult> {
    await this.simulateNetworkDelay(100, 200);

    // 85% success rate
    const passed = Math.random() > 0.15;

    return {
      passed,
      executionTime: Math.random() * 150 + 100,
      details: passed
        ? { rules: 'Croatian CIUS', violations: 0 }
        : {
            rules: 'Croatian CIUS',
            violations: 1,
            errors: [
              {
                code: ErrorCode.INVALID_VAT_RATE,
                message: 'VAT rate 25% expected for standard rate'
              }
            ]
          }
    };
  }

  async validateKPD(kpdCodes: string[]): Promise<LayerResult> {
    await this.simulateNetworkDelay(30, 80);

    // Check if codes are 6 digits
    const invalidCodes = kpdCodes.filter(code => !/^\d{6}$/.test(code));
    const passed = invalidCodes.length === 0;

    return {
      passed,
      executionTime: Math.random() * 50 + 30,
      details: passed
        ? { validCodes: kpdCodes.length, invalidCodes: 0 }
        : {
            validCodes: kpdCodes.length - invalidCodes.length,
            invalidCodes: invalidCodes.length,
            errors: invalidCodes.map(code => ({
              code: ErrorCode.INVALID_KPD_CODE,
              message: `Invalid KPD code: ${code}`
            }))
          }
    };
  }

  async validateSemantic(xml: string): Promise<LayerResult> {
    await this.simulateNetworkDelay(50, 100);

    // 95% success rate (semantic validation is usually more reliable)
    const passed = Math.random() > 0.05;

    return {
      passed,
      executionTime: Math.random() * 80 + 50,
      details: passed
        ? { semanticChecks: 'passed' }
        : {
            semanticChecks: 'failed',
            errors: [
              {
                code: ErrorCode.INVALID_VAT_NUMBER,
                message: 'VAT amount does not match calculated value'
              }
            ]
          }
    };
  }

  async validateFull(xml: string): Promise<ValidationResult> {
    const startTime = Date.now();

    const [xsd, schematron, kpd, semantic] = await Promise.all([
      this.validateXSD(xml),
      this.validateSchematron(xml),
      this.validateKPD(['123456']), // Mock KPD code
      this.validateSemantic(xml)
    ]);

    // AI validation (simulated)
    await this.simulateNetworkDelay(200, 400);
    const ai: LayerResult = {
      passed: Math.random() > 0.05,
      executionTime: Math.random() * 300 + 200,
      details: { anomaliesDetected: 0 }
    };

    // Consensus: majority voting
    const votes = [xsd.passed, schematron.passed, kpd.passed, semantic.passed, ai.passed];
    const passedCount = votes.filter(v => v).length;
    const consensusPassed = passedCount >= 3;

    const consensus: LayerResult = {
      passed: consensusPassed,
      executionTime: Date.now() - startTime,
      details: { votes: passedCount, required: 3, decision: consensusPassed }
    };

    const valid = xsd.passed && schematron.passed && consensusPassed;

    return {
      invoiceId: 'mock-invoice-id',
      timestamp: new Date().toISOString(),
      valid,
      confidence: passedCount / votes.length,
      layers: { xsd, schematron, kpd, semantic, ai, consensus },
      errors: valid ? [] : [
        {
          code: ErrorCode.SCHEMA_VALIDATION_FAILED,
          severity: 'CRITICAL',
          field: 'invoice',
          message: 'Validation failed'
        }
      ],
      warnings: [],
      suggestions: []
    };
  }

  private async simulateNetworkDelay(min: number = 100, max: number = 300): Promise<void> {
    const delay = Math.random() * (max - min) + min;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}

@injectable()
export class MockKPDValidatorService implements IKPDValidatorService {
  // In-memory mock KPD registry
  private mockRegistry = new Map<string, KPDCodeDetails>([
    ['123456', { code: '123456', description: 'Professional services', valid: true, category: 'Services' }],
    ['654321', { code: '654321', description: 'Computer equipment', valid: true, category: 'Goods' }],
    ['111111', { code: '111111', description: 'Consulting services', valid: true, category: 'Services' }],
  ]);

  async validateCode(kpdCode: string): Promise<boolean> {
    await this.simulateNetworkDelay(10, 30);
    return /^\d{6}$/.test(kpdCode) && this.mockRegistry.has(kpdCode);
  }

  async validateCodes(kpdCodes: string[]): Promise<LayerResult> {
    await this.simulateNetworkDelay(20, 50);

    const results = await Promise.all(kpdCodes.map(code => this.validateCode(code)));
    const invalidCount = results.filter(r => !r).length;

    return {
      passed: invalidCount === 0,
      executionTime: Math.random() * 40 + 20,
      details: {
        total: kpdCodes.length,
        valid: kpdCodes.length - invalidCount,
        invalid: invalidCount
      }
    };
  }

  async getCodeDetails(kpdCode: string): Promise<KPDCodeDetails | null> {
    await this.simulateNetworkDelay(10, 30);
    return this.mockRegistry.get(kpdCode) || null;
  }

  private async simulateNetworkDelay(min: number = 10, max: number = 50): Promise<void> {
    const delay = Math.random() * (max - min) + min;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}

@injectable()
export class MockOIBValidatorService implements IOIBValidatorService {
  async validate(oib: string): Promise<boolean> {
    // Check format: 11 digits
    if (!/^\d{11}$/.test(oib)) {
      return false;
    }

    // Validate check digit using ISO 7064, MOD 11-10 algorithm
    const digits = oib.substring(0, 10).split('').map(Number);
    const checkDigit = parseInt(oib[10], 10);
    const calculatedCheckDigit = this.calculateCheckDigitValue(digits);

    return checkDigit === calculatedCheckDigit;
  }

  calculateCheckDigit(digits: string): string {
    const digitArray = digits.split('').map(Number);
    const checkDigit = this.calculateCheckDigitValue(digitArray);
    return checkDigit.toString();
  }

  private calculateCheckDigitValue(digits: number[]): number {
    let a = 10;
    for (const digit of digits) {
      a = ((a + digit) % 10 || 10) * 2 % 11;
    }
    return (11 - a) % 10;
  }
}
