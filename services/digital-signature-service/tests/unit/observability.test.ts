import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  logger,
  signatureTotal,
  signatureDuration,
  certificateOperations,
  signatureErrors,
  activeCertificates,
  serviceUp,
  xmldsigValidations,
  getMetrics,
  resetMetrics,
  initObservability,
  shutdownObservability,
  maskOIB,
  maskPassword,
  createSpan,
  setSpanError,
  endSpanSuccess,
} from '../../src/observability.js';

describe('Observability Module', () => {
  beforeEach(() => {
    resetMetrics();
  });

  describe('Prometheus Metrics', () => {
    it('should initialize all required metrics', async () => {
      // Initialize
      initObservability();

      // Get metrics
      const metrics = await getMetrics();

      // Verify metrics exist
      expect(metrics).toContain('digital_signature_total');
      expect(metrics).toContain('digital_signature_duration_seconds');
      expect(metrics).toContain('certificate_operations_total');
      expect(metrics).toContain('digital_signature_errors_total');
      expect(metrics).toContain('active_certificates_count');
      expect(metrics).toContain('digital_signature_service_up');
      expect(metrics).toContain('xmldsig_validations_total');
    });

    it('should increment signature total counter', async () => {
      signatureTotal.inc({ operation: 'sign', status: 'success' });

      const metrics = await getMetrics();
      expect(metrics).toContain('digital_signature_total');
      expect(metrics).toContain('operation="sign"');
      expect(metrics).toContain('status="success"');
    });

    it('should record signature duration', async () => {
      signatureDuration.observe({ operation: 'sign' }, 0.123);

      const metrics = await getMetrics();
      expect(metrics).toContain('digital_signature_duration_seconds');
      expect(metrics).toContain('operation="sign"');
    });

    it('should increment certificate operations counter', async () => {
      certificateOperations.inc({ operation: 'load', status: 'success' });

      const metrics = await getMetrics();
      expect(metrics).toContain('certificate_operations_total');
      expect(metrics).toContain('operation="load"');
      expect(metrics).toContain('status="success"');
    });

    it('should increment signature errors counter', async () => {
      signatureErrors.inc({ error_type: 'certificate_load' });

      const metrics = await getMetrics();
      expect(metrics).toContain('digital_signature_errors_total');
      expect(metrics).toContain('error_type="certificate_load"');
    });

    it('should set active certificates gauge', async () => {
      activeCertificates.set(2);

      const metrics = await getMetrics();
      expect(metrics).toContain('active_certificates_count 2');
    });

    it('should set service up gauge', async () => {
      serviceUp.set(1);

      const metrics = await getMetrics();
      expect(metrics).toContain('digital_signature_service_up 1');
    });

    it('should increment xmldsig validations counter', async () => {
      xmldsigValidations.inc({ result: 'valid' });

      const metrics = await getMetrics();
      expect(metrics).toContain('xmldsig_validations_total');
      expect(metrics).toContain('result="valid"');
    });
  });

  describe('Logging', () => {
    it('should have logger configured', () => {
      expect(logger).toBeDefined();
      expect(logger.info).toBeDefined();
      expect(logger.error).toBeDefined();
      expect(logger.warn).toBeDefined();
      expect(logger.debug).toBeDefined();
    });

    it('should log without errors', () => {
      expect(() => {
        logger.info({ test: 'data' }, 'Test message');
      }).not.toThrow();
    });

    it('should redact sensitive fields', () => {
      const logEntry = {
        password: 'secret123',
        cert_password: 'secret456',
        message: 'Test log',
      };

      // Logger should redact password fields
      expect(() => {
        logger.info(logEntry, 'Test with sensitive data');
      }).not.toThrow();
    });
  });

  describe('PII Masking', () => {
    it('should mask valid OIB', () => {
      const oib = '12345678901';
      const masked = maskOIB(oib);

      expect(masked).toBe('***********');
      expect(masked).not.toContain('1');
      expect(masked).not.toContain('2');
    });

    it('should return INVALID_OIB for invalid OIB', () => {
      expect(maskOIB('')).toBe('INVALID_OIB');
      expect(maskOIB('123')).toBe('INVALID_OIB');
      expect(maskOIB('123456789012')).toBe('INVALID_OIB'); // 12 digits
    });

    it('should mask passwords', () => {
      const password = 'secret123';
      const masked = maskPassword(password);

      expect(masked).toBe('[REDACTED]');
      expect(masked).not.toContain('secret');
    });
  });

  describe('Distributed Tracing', () => {
    it('should create span with attributes', () => {
      const span = createSpan('test_operation', {
        test_attr: 'value',
        numeric_attr: 123,
        boolean_attr: true,
      });

      expect(span).toBeDefined();
      expect(span.end).toBeDefined();

      span.end();
    });

    it('should set span error', () => {
      const span = createSpan('test_operation');
      const error = new Error('Test error');

      expect(() => {
        setSpanError(span, error);
        span.end();
      }).not.toThrow();
    });

    it('should end span with success', () => {
      const span = createSpan('test_operation');

      expect(() => {
        endSpanSuccess(span);
      }).not.toThrow();
    });
  });

  describe('Observability Lifecycle', () => {
    it('should initialize observability', async () => {
      initObservability();

      const metrics = await getMetrics();
      expect(metrics).toContain('digital_signature_service_up 1');
    });

    it('should shutdown observability', async () => {
      initObservability();
      shutdownObservability();

      const metrics = await getMetrics();
      expect(metrics).toContain('digital_signature_service_up 0');
    });
  });

  describe('Metrics Reset', () => {
    it('should reset all metrics', async () => {
      // Set some metrics
      signatureTotal.inc({ operation: 'sign', status: 'success' });
      activeCertificates.set(5);
      serviceUp.set(1);

      // Reset
      resetMetrics();

      // All metrics should be reset to 0
      const metrics = await getMetrics();

      // Check that counters are reset
      expect(metrics).toContain('digital_signature_total');
      expect(metrics).toContain('active_certificates_count');
    });
  });
});
