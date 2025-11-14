/**
 * Error Aggregator Tests
 */

import { ErrorAggregator } from '../../../src/aggregators/error-aggregator';
import { LayerResult, ErrorCode } from '@eracun/contracts';

describe('ErrorAggregator', () => {
  let aggregator: ErrorAggregator;

  beforeEach(() => {
    aggregator = new ErrorAggregator();
  });

  describe('Error Extraction', () => {
    it('should extract errors from failed layer with errors array', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'HIGH' as const,
                field: 'supplier.vatNumber',
                message: 'Invalid VAT format',
                suggestion: 'Use HR followed by 11 digits',
              },
            ],
          },
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toMatchObject({
        code: ErrorCode.SCHEMA_VALIDATION_FAILED,
        severity: 'HIGH',
        field: 'supplier.vatNumber',
        message: expect.stringContaining('[XSD]'),
        suggestion: 'Use HR followed by 11 digits',
      });
    });

    it('should extract single error message from failed layer', () => {
      const layers = {
        xsd: { passed: true, executionTime: 50 } as LayerResult,
        schematron: {
          passed: false,
          executionTime: 100,
          details: {
            error: 'Schematron validation failed',
          },
        } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toMatchObject({
        code: ErrorCode.SCHEMA_VALIDATION_FAILED,
        severity: 'HIGH',
        field: 'unknown',
        message: '[Schematron] Schematron validation failed',
      });
    });

    it('should extract errors from multiple layers', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'HIGH' as const,
                field: 'supplier.vatNumber',
                message: 'Invalid VAT format',
              },
            ],
          },
        } as LayerResult,
        schematron: {
          passed: false,
          executionTime: 100,
          details: {
            error: 'Business rule violation',
          },
        } as LayerResult,
        kpd: {
          passed: false,
          executionTime: 30,
          details: {
            errors: [
              {
                code: ErrorCode.INVALID_KPD_CODE,
                severity: 'CRITICAL' as const,
                field: 'lineItems[0].kpdCode',
                message: 'KPD code not found in registry',
              },
            ],
          },
        } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(3);
      expect(result.errors.some((e) => e.message.includes('[XSD]'))).toBe(true);
      expect(result.errors.some((e) => e.message.includes('[Schematron]'))).toBe(true);
      expect(result.errors.some((e) => e.message.includes('[KPD]'))).toBe(true);
    });

    it('should not extract errors from passed layers', () => {
      const layers = {
        xsd: { passed: true, executionTime: 50 } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(0);
    });

    it('should handle AI layer errors', () => {
      const layers = {
        xsd: { passed: true, executionTime: 50 } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: {
          passed: false,
          executionTime: 200,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'MEDIUM' as const,
                field: 'amounts.gross',
                message: 'Anomaly detected in amount',
                suggestion: 'Verify calculation',
              },
            ],
          },
        } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].message).toContain('[AI]');
    });
  });

  describe('Error Deduplication', () => {
    it('should deduplicate errors with same code and field', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'HIGH' as const,
                field: 'supplier.vatNumber',
                message: 'Invalid format',
              },
            ],
          },
        } as LayerResult,
        schematron: {
          passed: false,
          executionTime: 100,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'HIGH' as const,
                field: 'supplier.vatNumber',
                message: 'Different message but same code/field',
              },
            ],
          },
        } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      // Should only have 1 error (deduplicated)
      expect(result.errors).toHaveLength(1);
    });

    it('should not deduplicate errors with different codes', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'HIGH' as const,
                field: 'supplier.vatNumber',
                message: 'Error 1',
              },
              {
                code: ErrorCode.INVALID_OIB,
                severity: 'HIGH' as const,
                field: 'supplier.vatNumber',
                message: 'Error 2',
              },
            ],
          },
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(2);
    });

    it('should not deduplicate errors with different fields', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'HIGH' as const,
                field: 'supplier.vatNumber',
                message: 'Error 1',
              },
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'HIGH' as const,
                field: 'buyer.vatNumber',
                message: 'Error 2',
              },
            ],
          },
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(2);
    });
  });

  describe('Severity Sorting', () => {
    it('should sort errors by severity (CRITICAL > HIGH > MEDIUM)', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'MEDIUM' as const,
                field: 'field1',
                message: 'Medium error',
              },
              {
                code: ErrorCode.INVALID_KPD_CODE,
                severity: 'CRITICAL' as const,
                field: 'field2',
                message: 'Critical error',
              },
              {
                code: ErrorCode.INVALID_OIB,
                severity: 'HIGH' as const,
                field: 'field3',
                message: 'High error',
              },
            ],
          },
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(3);
      expect(result.errors[0].severity).toBe('CRITICAL');
      expect(result.errors[1].severity).toBe('HIGH');
      expect(result.errors[2].severity).toBe('MEDIUM');
    });

    it('should maintain order for same severity', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [
              {
                code: ErrorCode.SCHEMA_VALIDATION_FAILED,
                severity: 'HIGH' as const,
                field: 'field1',
                message: 'Error A',
              },
              {
                code: ErrorCode.INVALID_OIB,
                severity: 'HIGH' as const,
                field: 'field2',
                message: 'Error B',
              },
            ],
          },
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(2);
      expect(result.errors[0].severity).toBe('HIGH');
      expect(result.errors[1].severity).toBe('HIGH');
    });
  });

  describe('Edge Cases', () => {
    it('should handle layer with no details', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(0);
    });

    it('should handle empty errors array', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [],
          },
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(0);
    });

    it('should provide default values for missing error properties', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: {
            errors: [
              {
                // Missing code, severity, field
                message: 'Some error',
              } as any,
            ],
          },
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].code).toBe(ErrorCode.SCHEMA_VALIDATION_FAILED);
      expect(result.errors[0].severity).toBe('HIGH');
      expect(result.errors[0].field).toBe('unknown');
    });

    it('should return empty warnings and suggestions', () => {
      const layers = {
        xsd: { passed: true, executionTime: 50 } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);

      expect(result.warnings).toEqual([]);
      expect(result.suggestions).toEqual([]);
    });
  });

  describe('Layer Name Prefixes', () => {
    it('should prefix XSD errors with [XSD]', () => {
      const layers = {
        xsd: {
          passed: false,
          executionTime: 50,
          details: { error: 'Test error' },
        } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);
      expect(result.errors[0].message).toMatch(/^\[XSD\]/);
    });

    it('should prefix Schematron errors with [Schematron]', () => {
      const layers = {
        xsd: { passed: true, executionTime: 50 } as LayerResult,
        schematron: {
          passed: false,
          executionTime: 100,
          details: { error: 'Test error' },
        } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);
      expect(result.errors[0].message).toMatch(/^\[Schematron\]/);
    });

    it('should prefix KPD errors with [KPD]', () => {
      const layers = {
        xsd: { passed: true, executionTime: 50 } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: {
          passed: false,
          executionTime: 30,
          details: { error: 'Test error' },
        } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);
      expect(result.errors[0].message).toMatch(/^\[KPD\]/);
    });

    it('should prefix Semantic errors with [Semantic]', () => {
      const layers = {
        xsd: { passed: true, executionTime: 50 } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: {
          passed: false,
          executionTime: 80,
          details: { error: 'Test error' },
        } as LayerResult,
        ai: { passed: true, executionTime: 200 } as LayerResult,
      };

      const result = aggregator.aggregate(layers);
      expect(result.errors[0].message).toMatch(/^\[Semantic\]/);
    });

    it('should prefix AI errors with [AI]', () => {
      const layers = {
        xsd: { passed: true, executionTime: 50 } as LayerResult,
        schematron: { passed: true, executionTime: 100 } as LayerResult,
        kpd: { passed: true, executionTime: 30 } as LayerResult,
        semantic: { passed: true, executionTime: 80 } as LayerResult,
        ai: {
          passed: false,
          executionTime: 200,
          details: { error: 'Test error' },
        } as LayerResult,
      };

      const result = aggregator.aggregate(layers);
      expect(result.errors[0].message).toMatch(/^\[AI\]/);
    });
  });
});
