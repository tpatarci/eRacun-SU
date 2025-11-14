/**
 * Invoice Saga Tests
 */

import { InvoiceSaga } from '../../../src/sagas/invoice-saga';
import { IValidationService, IFINAService } from '@eracun/adapters';
import { UBLInvoice, ValidationResult } from '@eracun/contracts';
import { InvoiceGenerator } from '@eracun/test-fixtures';

describe('InvoiceSaga', () => {
  let saga: InvoiceSaga;
  let mockValidationService: jest.Mocked<IValidationService>;
  let mockFINAService: jest.Mocked<IFINAService>;
  let testInvoice: UBLInvoice;

  beforeEach(() => {
    // Create mocks
    mockValidationService = {
      validateFull: jest.fn(),
      validateXSD: jest.fn(),
      validateSchematron: jest.fn(),
      validateKPD: jest.fn(),
      validateSemantic: jest.fn(),
    } as any;

    mockFINAService = {
      submitInvoice: jest.fn(),
      getStatus: jest.fn(),
      verifyJIR: jest.fn(),
      healthCheck: jest.fn(),
    } as any;

    saga = new InvoiceSaga(mockValidationService, mockFINAService);

    // Generate test invoice
    testInvoice = InvoiceGenerator.generateValidInvoice();
  });

  afterEach(() => {
    saga.stop();
  });

  describe('startSaga', () => {
    it('should start saga and transition to validating state', async () => {
      const validationResult: ValidationResult = {
        invoiceId: testInvoice.id,
        timestamp: new Date().toISOString(),
        valid: true,
        confidence: 1.0,
        layers: {
          xsd: { passed: true, executionTime: 50 },
          schematron: { passed: true, executionTime: 100 },
          kpd: { passed: true, executionTime: 30 },
          semantic: { passed: true, executionTime: 80 },
          ai: { passed: true, executionTime: 200 },
          consensus: { passed: true, executionTime: 0 },
        },
        errors: [],
        warnings: [],
        suggestions: [],
      };

      mockValidationService.validateFull.mockResolvedValue(validationResult);
      mockFINAService.submitInvoice.mockResolvedValue({
        success: true,
        jir: 'TEST-JIR-123',
        timestamp: new Date().toISOString(),
      });

      await saga.startSaga(testInvoice);

      // Give time for state transitions
      await new Promise((resolve) => setTimeout(resolve, 100));

      const state = saga.getState();
      expect(['validating', 'transforming', 'submitting', 'completed']).toContain(state);
    });

    it('should call validation service', async () => {
      const validationResult: ValidationResult = {
        invoiceId: testInvoice.id,
        timestamp: new Date().toISOString(),
        valid: true,
        confidence: 1.0,
        layers: {
          xsd: { passed: true, executionTime: 50 },
          schematron: { passed: true, executionTime: 100 },
          kpd: { passed: true, executionTime: 30 },
          semantic: { passed: true, executionTime: 80 },
          ai: { passed: true, executionTime: 200 },
          consensus: { passed: true, executionTime: 0 },
        },
        errors: [],
        warnings: [],
        suggestions: [],
      };

      mockValidationService.validateFull.mockResolvedValue(validationResult);
      mockFINAService.submitInvoice.mockResolvedValue({
        success: true,
        jir: 'TEST-JIR-123',
        timestamp: new Date().toISOString(),
      });

      await saga.startSaga(testInvoice);
      await new Promise((resolve) => setTimeout(resolve, 500));

      expect(mockValidationService.validateFull).toHaveBeenCalled();
    });
  });

  describe('getState', () => {
    it('should return current state', () => {
      const state = saga.getState();
      expect(state).toBeDefined();
    });
  });

  describe('getContext', () => {
    it('should return null when not started', () => {
      const context = saga.getContext();
      expect(context).toBeNull();
    });

    it('should return context after saga starts', async () => {
      mockValidationService.validateFull.mockResolvedValue({
        invoiceId: testInvoice.id,
        timestamp: new Date().toISOString(),
        valid: true,
        confidence: 1.0,
        layers: {} as any,
        errors: [],
        warnings: [],
        suggestions: [],
      });

      await saga.startSaga(testInvoice);
      await new Promise((resolve) => setTimeout(resolve, 100));

      const context = saga.getContext();
      expect(context).not.toBeNull();
      expect(context?.invoiceId).toBe(testInvoice.id);
    });
  });

  describe('stop', () => {
    it('should stop saga without errors', () => {
      expect(() => saga.stop()).not.toThrow();
    });
  });
});
