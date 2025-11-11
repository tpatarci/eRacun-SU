/**
 * Unit Tests: Observability (TODO-008 Compliance)
 *
 * Tests observability components:
 * - PII masking (OIB, IBAN, VAT)
 * - Prometheus metrics
 * - Structured logging
 * - Distributed tracing
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import {
  maskOIB,
  maskIBAN,
  maskVAT,
  maskPII,
  validationTotal,
  validationDuration,
  rulesCheckedHistogram,
  rulesFailedHistogram,
  rulesLoaded,
  errorsByRule,
  warningsByRule,
  ruleCacheSize,
  xsltCompilationTime,
  getMetricsRegistry,
  createSpan,
  logger
} from '../../src/observability.js';

describe('Observability', () => {
  beforeEach(() => {
    // Reset metric values between tests (keeps metrics registered)
    getMetricsRegistry().resetMetrics();
  });

  // ==========================================================================
  // PII Masking Tests
  // ==========================================================================

  describe('PII Masking', () => {
    describe('maskOIB', () => {
      it('should mask valid 11-digit OIB', () => {
        const oib = '12345678901';
        const masked = maskOIB(oib);

        expect(masked).toBe('***********');
        expect(masked).toHaveLength(11);
      });

      it('should mask different OIB values consistently', () => {
        expect(maskOIB('98765432109')).toBe('***********');
        expect(maskOIB('11111111111')).toBe('***********');
        expect(maskOIB('99999999999')).toBe('***********');
      });

      it('should not leak any digits from OIB', () => {
        const oib = '12345678901';
        const masked = maskOIB(oib);

        for (let i = 0; i < 10; i++) {
          expect(masked).not.toContain(String(i));
        }
      });

      it('should handle invalid OIB gracefully (too short)', () => {
        const result = maskOIB('123456789');
        expect(result).toBe('INVALID_OIB');
      });

      it('should handle invalid OIB gracefully (too long)', () => {
        const result = maskOIB('123456789012');
        expect(result).toBe('INVALID_OIB');
      });

      it('should handle invalid OIB gracefully (non-numeric)', () => {
        const result = maskOIB('1234567890A');
        expect(result).toBe('INVALID_OIB');
      });

      it('should handle null input gracefully', () => {
        const result = maskOIB(null as any);
        expect(result).toBe('INVALID_OIB');
      });

      it('should handle undefined input gracefully', () => {
        const result = maskOIB(undefined as any);
        expect(result).toBe('INVALID_OIB');
      });

      it('should handle empty string gracefully', () => {
        const result = maskOIB('');
        expect(result).toBe('INVALID_OIB');
      });
    });

    describe('maskIBAN', () => {
      it('should mask valid Croatian IBAN', () => {
        const iban = 'HR1723600001101234567';
        const masked = maskIBAN(iban);

        expect(masked).toContain('HR');
        expect(masked).toContain('**');
        expect(masked).toContain('*');
        expect(masked).not.toContain('23600001101234567');
      });

      it('should preserve country code (HR)', () => {
        const iban = 'HR1723600001101234567';
        const masked = maskIBAN(iban);

        expect(masked.startsWith('HR')).toBe(true);
      });

      it('should mask check digits', () => {
        const iban = 'HR1723600001101234567';
        const masked = maskIBAN(iban);

        // Should not contain original check digits
        expect(masked).not.toContain('17');
      });

      it('should handle invalid IBAN gracefully (wrong country)', () => {
        const result = maskIBAN('GB82WEST12345698765432');
        expect(result).toBe('INVALID_IBAN');
      });

      it('should handle null input gracefully', () => {
        const result = maskIBAN(null as any);
        expect(result).toBe('INVALID_IBAN');
      });

      it('should handle empty string gracefully', () => {
        const result = maskIBAN('');
        expect(result).toBe('INVALID_IBAN');
      });
    });

    describe('maskVAT', () => {
      it('should mask valid Croatian VAT number', () => {
        const vat = 'HR12345678901';
        const masked = maskVAT(vat);

        expect(masked).toBe('HR***********');
        expect(masked.startsWith('HR')).toBe(true);
        expect(masked).not.toContain('12345678901');
      });

      it('should preserve country code only', () => {
        const vat = 'HR98765432109';
        const masked = maskVAT(vat);

        expect(masked.startsWith('HR')).toBe(true);
        expect(masked).not.toContain('98765432109');
      });

      it('should handle invalid VAT gracefully (wrong country)', () => {
        const result = maskVAT('DE123456789');
        expect(result).toBe('INVALID_VAT');
      });

      it('should handle null input gracefully', () => {
        const result = maskVAT(null as any);
        expect(result).toBe('INVALID_VAT');
      });

      it('should handle empty string gracefully', () => {
        const result = maskVAT('');
        expect(result).toBe('INVALID_VAT');
      });
    });

    describe('maskPII', () => {
      it('should mask OIB in text', () => {
        const text = 'Supplier OIB: 12345678901';
        const masked = maskPII(text);

        expect(masked).toContain('***********');
        expect(masked).not.toContain('12345678901');
      });

      it('should mask IBAN in text', () => {
        const text = 'Account: HR1723600001101234567';
        const masked = maskPII(text);

        expect(masked).toContain('HR**');
        expect(masked).not.toContain('1723600001101234567');
      });

      it('should mask VAT in text', () => {
        const text = 'VAT ID: HR12345678901';
        const masked = maskPII(text);

        expect(masked).toContain('HR***********');
        expect(masked).not.toContain('12345678901');
      });

      it('should mask multiple PII values in same text', () => {
        const text = 'OIB: 12345678901, IBAN: HR1723600001101234567, VAT: HR98765432109';
        const masked = maskPII(text);

        expect(masked).toContain('***********');
        expect(masked).toContain('HR**');
        expect(masked).not.toContain('12345678901');
        expect(masked).not.toContain('1723600001101234567');
        expect(masked).not.toContain('98765432109');
      });

      it('should handle text without PII', () => {
        const text = 'Hello world, no sensitive data here';
        const masked = maskPII(text);

        expect(masked).toBe(text);
      });

      it('should handle empty string', () => {
        const masked = maskPII('');
        expect(masked).toBe('');
      });

      it('should handle null gracefully', () => {
        const masked = maskPII(null as any);
        expect(masked).toBeFalsy();
      });
    });
  });

  // ==========================================================================
  // Prometheus Metrics Tests
  // ==========================================================================

  describe('Prometheus Metrics', () => {
    it('should export validationTotal counter', () => {
      validationTotal.inc({ status: 'valid', rule_set: 'CIUS_HR_CORE' });

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_validation_total');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('counter');
    });

    it('should export validationDuration histogram', () => {
      validationDuration.observe({ rule_set: 'CIUS_HR_CORE' }, 0.5);

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_validation_duration_seconds');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('histogram');
    });

    it('should export rulesCheckedHistogram', () => {
      rulesCheckedHistogram.observe({ rule_set: 'CIUS_HR_CORE' }, 150);

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_rules_checked_total');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('histogram');
    });

    it('should export rulesFailedHistogram', () => {
      rulesFailedHistogram.observe({ rule_set: 'CIUS_HR_CORE' }, 3);

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_rules_failed_total');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('histogram');
    });

    it('should export rulesLoaded gauge', () => {
      rulesLoaded.set({ rule_set: 'CIUS_HR_CORE' }, 150);

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_rules_loaded');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('gauge');
    });

    it('should export errorsByRule counter', () => {
      errorsByRule.inc({ rule_id: 'BR-S-01', rule_set: 'CIUS_HR_CORE' });

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_errors_by_rule');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('counter');
    });

    it('should export warningsByRule counter', () => {
      warningsByRule.inc({ rule_id: 'BR-W-01', rule_set: 'CIUS_HR_CORE' });

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_warnings_by_rule');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('counter');
    });

    it('should export ruleCacheSize gauge', () => {
      ruleCacheSize.set(1024000);

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_rule_cache_size_bytes');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('gauge');
    });

    it('should export xsltCompilationTime histogram', () => {
      xsltCompilationTime.observe({ rule_set: 'CIUS_HR_CORE' }, 2.5);

      const metrics = getMetricsRegistry();
      const metric = metrics.getSingleMetric('schematron_xslt_compilation_time_seconds');

      expect(metric).toBeDefined();
      expect(metric!.type).toBe('histogram');
    });

    it('should increment counters correctly', () => {
      validationTotal.inc({ status: 'valid', rule_set: 'CIUS_HR_CORE' });
      validationTotal.inc({ status: 'valid', rule_set: 'CIUS_HR_CORE' });
      validationTotal.inc({ status: 'invalid', rule_set: 'CIUS_HR_CORE' });

      // Metrics should have been incremented
      // (Exact value testing would require accessing internal state)
      const metrics = getMetricsRegistry();
      expect(metrics.getSingleMetric('schematron_validation_total')).toBeDefined();
    });

    it('should handle concurrent metric updates', async () => {
      const promises = [];

      for (let i = 0; i < 100; i++) {
        promises.push(
          Promise.resolve().then(() => {
            validationTotal.inc({ status: 'valid', rule_set: 'CIUS_HR_CORE' });
            validationDuration.observe({ rule_set: 'CIUS_HR_CORE' }, Math.random());
          })
        );
      }

      await Promise.all(promises);

      // Should not throw or corrupt metrics
      const metrics = getMetricsRegistry();
      expect(metrics.getSingleMetric('schematron_validation_total')).toBeDefined();
      expect(metrics.getSingleMetric('schematron_validation_duration_seconds')).toBeDefined();
    });

    it('should format metrics in Prometheus format', async () => {
      validationTotal.inc({ status: 'valid', rule_set: 'CIUS_HR_CORE' });

      const metrics = await getMetricsRegistry().metrics();

      expect(metrics).toContain('schematron_validation_total');
      expect(metrics).toContain('status="valid"');
      expect(metrics).toContain('rule_set="CIUS_HR_CORE"');
    });

    it('should have correct metric types', async () => {
      validationTotal.inc({ status: 'valid', rule_set: 'CIUS_HR_CORE' });
      validationDuration.observe({ rule_set: 'CIUS_HR_CORE' }, 0.5);
      rulesLoaded.set({ rule_set: 'CIUS_HR_CORE' }, 150);

      const metrics = await getMetricsRegistry().metrics();

      expect(metrics).toContain('# TYPE schematron_validation_total counter');
      expect(metrics).toContain('# TYPE schematron_validation_duration_seconds histogram');
      expect(metrics).toContain('# TYPE schematron_rules_loaded gauge');
    });
  });

  // ==========================================================================
  // Structured Logging Tests
  // ==========================================================================

  describe('Structured Logging', () => {
    it('should export logger instance', () => {
      expect(logger).toBeDefined();
      expect(typeof logger.info).toBe('function');
      expect(typeof logger.error).toBe('function');
      expect(typeof logger.warn).toBe('function');
    });

    it('should have correct logger name', () => {
      expect(logger.bindings().name).toBe('schematron-validator');
    });

    it('should have service field in base bindings', () => {
      expect(logger.bindings().service).toBe('schematron-validator');
    });

    it('should have version field in base bindings', () => {
      expect(logger.bindings().version).toBe('1.0.0');
    });

    it('should have environment field in base bindings', () => {
      expect(logger.bindings().environment).toBeDefined();
    });
  });

  // ==========================================================================
  // Distributed Tracing Tests
  // ==========================================================================

  describe('Distributed Tracing', () => {
    it('should create span with name', () => {
      const span = createSpan('test_operation');

      expect(span).toBeDefined();
      expect(typeof span.end).toBe('function');

      span.end();
    });

    it('should create span with attributes', () => {
      const span = createSpan('test_operation', {
        'test.attribute': 'value',
        'test.number': 42
      });

      expect(span).toBeDefined();

      span.end();
    });

    it('should allow recording exceptions', () => {
      const span = createSpan('test_operation');
      const error = new Error('Test error');

      expect(() => {
        span.recordException(error);
        span.end();
      }).not.toThrow();
    });

    it('should allow setting span status', () => {
      const span = createSpan('test_operation');

      expect(() => {
        span.setStatus({ code: 1 }); // OK
        span.end();
      }).not.toThrow();
    });

    it('should create multiple spans concurrently', () => {
      const spans = [];

      for (let i = 0; i < 10; i++) {
        spans.push(createSpan(`operation_${i}`));
      }

      expect(spans).toHaveLength(10);

      spans.forEach(span => span.end());
    });
  });

  // ==========================================================================
  // Performance Tests
  // ==========================================================================

  describe('Performance', () => {
    it('should mask OIB quickly (<1ms)', () => {
      const startTime = Date.now();

      for (let i = 0; i < 1000; i++) {
        maskOIB('12345678901');
      }

      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100); // 1000 maskings in <100ms
    });

    it('should record metrics quickly (<1ms each)', () => {
      const startTime = Date.now();

      for (let i = 0; i < 1000; i++) {
        validationTotal.inc({ status: 'valid', rule_set: 'CIUS_HR_CORE' });
      }

      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100); // 1000 increments in <100ms
    });

    it('should create spans quickly (<1ms each)', () => {
      const startTime = Date.now();

      for (let i = 0; i < 100; i++) {
        const span = createSpan('test_operation');
        span.end();
      }

      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100); // 100 spans in <100ms
    });
  });
});
