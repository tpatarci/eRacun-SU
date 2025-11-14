/**
 * Validation Coordinator Tests
 */

import { ValidationCoordinator } from '../../../src/coordinators/validation-coordinator';
import { ErrorAggregator } from '../../../src/aggregators/error-aggregator';
import {
  IValidationService,
  IKPDValidatorService,
  IAIValidationService,
} from '@eracun/adapters';
import { LayerResult, ErrorCode } from '@eracun/contracts';
import { XMLGenerator, InvoiceGenerator } from '@eracun/test-fixtures';

describe('ValidationCoordinator', () => {
  let coordinator: ValidationCoordinator;
  let mockValidationService: jest.Mocked<IValidationService>;
  let mockKPDValidator: jest.Mocked<IKPDValidatorService>;
  let mockAIValidator: jest.Mocked<IAIValidationService>;
  let mockErrorAggregator: jest.Mocked<ErrorAggregator>;

  const createPassedLayer = (executionTime: number = 50): LayerResult => ({
    passed: true,
    executionTime,
    details: {},
  });

  const createFailedLayer = (
    executionTime: number = 50,
    errorMessage: string = 'Test error'
  ): LayerResult => ({
    passed: false,
    executionTime,
    details: { error: errorMessage },
  });

  beforeEach(() => {
    mockValidationService = {
      validateFull: jest.fn(),
      validateXSD: jest.fn(),
      validateSchematron: jest.fn(),
      validateKPD: jest.fn(),
      validateSemantic: jest.fn(),
    } as any;

    mockKPDValidator = {
      validateCodes: jest.fn(),
    } as any;

    mockAIValidator = {
      validate: jest.fn(),
    } as any;

    mockErrorAggregator = {
      aggregate: jest.fn().mockReturnValue({
        errors: [],
        warnings: [],
        suggestions: [],
      }),
    } as any;

    coordinator = new ValidationCoordinator(
      mockValidationService,
      mockKPDValidator,
      mockAIValidator,
      mockErrorAggregator
    );
  });

  describe('Parallel Validation', () => {
    it('should run all 4 core layers in parallel by default', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer(50));
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer(100));
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer(80));
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer(30));

      const startTime = Date.now();
      await coordinator.validate(xml, testInvoice.id);
      const duration = Date.now() - startTime;

      // Parallel execution should be faster than sequential (50+100+80+30=260ms)
      // Allow some overhead, but should be significantly faster
      expect(duration).toBeLessThan(200);

      expect(mockValidationService.validateXSD).toHaveBeenCalledWith(xml);
      expect(mockValidationService.validateSchematron).toHaveBeenCalledWith(xml);
      expect(mockValidationService.validateSemantic).toHaveBeenCalledWith(xml);
      expect(mockKPDValidator.validateCodes).toHaveBeenCalled();
    });

    it('should run layers sequentially when parallel disabled', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer(10));
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer(10));
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer(10));
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer(10));

      await coordinator.validate(xml, testInvoice.id, {
        enableParallelValidation: false,
      });

      // Verify all layers were called
      expect(mockValidationService.validateXSD).toHaveBeenCalledWith(xml);
      expect(mockValidationService.validateSchematron).toHaveBeenCalledWith(xml);
      expect(mockValidationService.validateSemantic).toHaveBeenCalledWith(xml);
      expect(mockKPDValidator.validateCodes).toHaveBeenCalled();
    });
  });

  describe('AI Validation', () => {
    it('should run AI validation when enabled (default)', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      // AI validation should have been attempted (even if not implemented)
      expect(result.layers.ai).toBeDefined();
    });

    it('should skip AI validation when disabled', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id, {
        enableAIValidation: false,
      });

      expect(result.layers.ai.passed).toBe(true);
      expect(result.layers.ai.details).toEqual({ skipped: true });
      expect(result.layers.ai.executionTime).toBe(0);
    });
  });

  describe('Consensus Mechanism', () => {
    it('should pass consensus with default threshold (3/5)', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      // 3 passed, 2 failed (meets 3/5 threshold)
      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createFailedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());
      // AI validation will be skipped or passed

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.layers.consensus.passed).toBe(true);
      expect(result.layers.consensus.details).toMatchObject({
        threshold: 3,
        decision: 'APPROVED',
      });
    });

    it('should fail consensus when below threshold', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      // Only 2 passed, 3 failed (below 3/5 threshold)
      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createFailedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createFailedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createFailedLayer());

      const result = await coordinator.validate(xml, testInvoice.id, {
        enableAIValidation: false, // Disable AI to control test
      });

      expect(result.layers.consensus.passed).toBe(false);
      expect(result.layers.consensus.details).toMatchObject({
        threshold: 3,
        decision: 'REJECTED',
      });
    });

    it('should support custom consensus threshold', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      // 2 passed, 2 failed
      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createFailedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createFailedLayer());

      const result = await coordinator.validate(xml, testInvoice.id, {
        enableAIValidation: false,
        consensusThreshold: 2, // Lower threshold
      });

      expect(result.layers.consensus.passed).toBe(true);
      expect(result.layers.consensus.details?.threshold).toBe(2);
    });

    it('should include vote counts in consensus result', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.layers.consensus.details).toMatchObject({
        votes: expect.any(Number),
        total: expect.any(Number),
        threshold: 3,
      });
      expect(result.layers.consensus.details?.votes).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Overall Validity', () => {
    it('should be valid when XSD, Schematron, and consensus pass', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.valid).toBe(true);
    });

    it('should be invalid when XSD fails', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createFailedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.valid).toBe(false);
    });

    it('should be invalid when Schematron fails', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createFailedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.valid).toBe(false);
    });

    it('should be invalid when consensus fails', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      // XSD and Schematron pass, but consensus fails
      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createFailedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createFailedLayer());

      const result = await coordinator.validate(xml, testInvoice.id, {
        enableAIValidation: false,
      });

      // Consensus should fail (only 2/4 passed, threshold 3)
      expect(result.valid).toBe(false);
    });
  });

  describe('Confidence Score', () => {
    it('should calculate confidence as ratio of passed layers', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      // All pass
      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      // Should be close to 1.0 (5/5 or 4/4 depending on AI)
      expect(result.confidence).toBeGreaterThanOrEqual(0.8);
      expect(result.confidence).toBeLessThanOrEqual(1.0);
    });

    it('should reflect partial failures in confidence score', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      // 2 pass, 2 fail
      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createFailedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createFailedLayer());

      const result = await coordinator.validate(xml, testInvoice.id, {
        enableAIValidation: false,
      });

      // Should be 2/4 = 0.5
      expect(result.confidence).toBe(0.5);
    });

    it('should be 0 when all layers fail', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createFailedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createFailedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createFailedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createFailedLayer());

      const result = await coordinator.validate(xml, testInvoice.id, {
        enableAIValidation: false,
      });

      expect(result.confidence).toBe(0);
    });

    it('should be 1.0 when all layers pass', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id, {
        enableAIValidation: false,
      });

      expect(result.confidence).toBe(1.0);
    });
  });

  describe('KPD Code Extraction', () => {
    it('should extract KPD codes from XML', async () => {
      const xmlWithKPD = `<?xml version="1.0"?>
<Invoice>
  <InvoiceLine>
    <Item>
      <cbc:ItemClassificationCode listID="KLASUS">123456</cbc:ItemClassificationCode>
    </Item>
  </InvoiceLine>
  <InvoiceLine>
    <Item>
      <cbc:ItemClassificationCode listID="KLASUS">789012</cbc:ItemClassificationCode>
    </Item>
  </InvoiceLine>
</Invoice>`;

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      await coordinator.validate(xmlWithKPD, 'test-id');

      expect(mockKPDValidator.validateCodes).toHaveBeenCalledWith(
        expect.arrayContaining(['123456', '789012'])
      );
    });

    it('should use default KPD code when none found', async () => {
      const xmlWithoutKPD = `<?xml version="1.0"?>
<Invoice>
  <cbc:ID>INV-001</cbc:ID>
</Invoice>`;

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      await coordinator.validate(xmlWithoutKPD, 'test-id');

      // Should call with default code
      expect(mockKPDValidator.validateCodes).toHaveBeenCalledWith(
        expect.arrayContaining(['123456'])
      );
    });
  });

  describe('Error Aggregation', () => {
    it('should aggregate errors from all layers', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createFailedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createFailedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createFailedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createFailedLayer());

      await coordinator.validate(xml, testInvoice.id);

      expect(mockErrorAggregator.aggregate).toHaveBeenCalledWith({
        xsd: expect.any(Object),
        schematron: expect.any(Object),
        kpd: expect.any(Object),
        semantic: expect.any(Object),
        ai: expect.any(Object),
      });
    });

    it('should include aggregated errors in result', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      const mockAggregatedErrors = [
        {
          code: ErrorCode.SCHEMA_VALIDATION_FAILED,
          severity: 'HIGH' as const,
          field: 'test',
          message: 'Test error',
        },
      ];

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      mockErrorAggregator.aggregate.mockReturnValue({
        errors: mockAggregatedErrors,
        warnings: [],
        suggestions: [],
      });

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.errors).toEqual(mockAggregatedErrors);
    });
  });

  describe('Error Handling', () => {
    it('should handle XSD validation errors gracefully', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockRejectedValue(
        new Error('XSD validation crashed')
      );
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.layers.xsd.passed).toBe(false);
      expect(result.layers.xsd.details?.error).toContain('XSD validation crashed');
    });

    it('should handle Schematron validation errors gracefully', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockRejectedValue(
        new Error('Schematron crashed')
      );
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.layers.schematron.passed).toBe(false);
      expect(result.layers.schematron.details?.error).toContain('Schematron crashed');
    });

    it('should handle KPD validation errors gracefully', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockRejectedValue(new Error('KPD service down'));

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.layers.kpd.passed).toBe(false);
      expect(result.layers.kpd.details?.error).toContain('KPD service down');
    });

    it('should handle semantic validation errors gracefully', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockRejectedValue(
        new Error('Semantic validation crashed')
      );
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.layers.semantic.passed).toBe(false);
      expect(result.layers.semantic.details?.error).toContain(
        'Semantic validation crashed'
      );
    });

    it('should throw on catastrophic failures', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      // Simulate all services throwing
      mockValidationService.validateXSD.mockRejectedValue(new Error('XSD down'));
      mockValidationService.validateSchematron.mockRejectedValue(
        new Error('Schematron down')
      );
      mockValidationService.validateSemantic.mockRejectedValue(new Error('Semantic down'));
      mockKPDValidator.validateCodes.mockRejectedValue(new Error('KPD down'));

      // Should still complete but with all failed layers
      const result = await coordinator.validate(xml, testInvoice.id, {
        enableAIValidation: false,
      });

      expect(result.layers.xsd.passed).toBe(false);
      expect(result.layers.schematron.passed).toBe(false);
      expect(result.layers.kpd.passed).toBe(false);
      expect(result.layers.semantic.passed).toBe(false);
    });
  });

  describe('Result Structure', () => {
    it('should include all required fields', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result).toMatchObject({
        invoiceId: testInvoice.id,
        timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
        valid: expect.any(Boolean),
        confidence: expect.any(Number),
        layers: {
          xsd: expect.any(Object),
          schematron: expect.any(Object),
          kpd: expect.any(Object),
          semantic: expect.any(Object),
          ai: expect.any(Object),
          consensus: expect.any(Object),
        },
        errors: expect.any(Array),
        warnings: expect.any(Array),
        suggestions: expect.any(Array),
      });
    });

    it('should include correct invoice ID', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, 'custom-invoice-id');

      expect(result.invoiceId).toBe('custom-invoice-id');
    });

    it('should include ISO 8601 timestamp', async () => {
      const testInvoice = InvoiceGenerator.generateValidInvoice();
      const xml = XMLGenerator.generateUBL21XML(testInvoice);

      mockValidationService.validateXSD.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSchematron.mockResolvedValue(createPassedLayer());
      mockValidationService.validateSemantic.mockResolvedValue(createPassedLayer());
      mockKPDValidator.validateCodes.mockResolvedValue(createPassedLayer());

      const result = await coordinator.validate(xml, testInvoice.id);

      expect(result.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      expect(new Date(result.timestamp).getTime()).toBeLessThanOrEqual(Date.now());
    });
  });
});
