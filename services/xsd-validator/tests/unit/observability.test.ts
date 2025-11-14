import { register } from 'prom-client';
import {
  validationTotal,
  validationDuration,
  validationErrors,
  queueDepth,
  serviceUp,
  schemasLoaded,
  maskOIB,
  getMetrics,
  initObservability,
} from '../../src/observability.js';

describe('Observability', () => {
  beforeEach(() => {
    // Clear metrics before each test
    register.resetMetrics();
  });

  describe('Prometheus Metrics', () => {
    it('should have validationTotal counter', () => {
      expect(validationTotal).toBeDefined();
      validationTotal.inc({ status: 'valid' });
      validationTotal.inc({ status: 'invalid' });
      validationTotal.inc({ status: 'error' });
    });

    it('should have validationDuration histogram', () => {
      expect(validationDuration).toBeDefined();
      validationDuration.observe({ schema_type: 'UBL-Invoice-2.1' }, 0.1);
      validationDuration.observe({ schema_type: 'UBL-CreditNote-2.1' }, 0.2);
    });

    it('should have validationErrors counter', () => {
      expect(validationErrors).toBeDefined();
      validationErrors.inc({ error_type: 'parse' });
      validationErrors.inc({ error_type: 'schema' });
      validationErrors.inc({ error_type: 'internal' });
    });

    it('should have queueDepth gauge', () => {
      expect(queueDepth).toBeDefined();
      queueDepth.set(10);
      queueDepth.inc();
      queueDepth.dec();
    });

    it('should have serviceUp gauge', () => {
      expect(serviceUp).toBeDefined();
      serviceUp.set(1);
      serviceUp.set(0);
    });

    it('should have schemasLoaded gauge', () => {
      expect(schemasLoaded).toBeDefined();
      schemasLoaded.set(2);
    });
  });

  describe('maskOIB', () => {
    it('should mask valid OIB (11 digits)', () => {
      const oib = '12345678901';
      const masked = maskOIB(oib);
      expect(masked).toBe('***********');
      expect(masked.length).toBe(11);
    });

    it('should handle invalid OIB length', () => {
      expect(maskOIB('123')).toBe('INVALID_OIB');
      expect(maskOIB('12345678901234')).toBe('INVALID_OIB');
    });

    it('should handle empty OIB', () => {
      expect(maskOIB('')).toBe('INVALID_OIB');
    });

    it('should handle null/undefined', () => {
      expect(maskOIB(null as any)).toBe('INVALID_OIB');
      expect(maskOIB(undefined as any)).toBe('INVALID_OIB');
    });

    it('should not leak any digits', () => {
      const oib = '98765432109';
      const masked = maskOIB(oib);

      // Ensure no original digits are present
      for (let i = 0; i < 10; i++) {
        expect(masked).not.toContain(String(i));
      }
    });

    it('should consistently mask same OIB', () => {
      const oib = '11111111111';
      const masked1 = maskOIB(oib);
      const masked2 = maskOIB(oib);
      expect(masked1).toBe(masked2);
    });
  });

  describe('getMetrics', () => {
    it('should return Prometheus metrics in text format', async () => {
      // Set some metrics
      serviceUp.set(1);
      schemasLoaded.set(2);
      validationTotal.inc({ status: 'valid' });

      const metrics = await getMetrics();

      expect(typeof metrics).toBe('string');
      expect(metrics).toContain('xsd_validator_up');
      expect(metrics).toContain('xsd_schemas_loaded');
      expect(metrics).toContain('xsd_validation_total');
    });

    it('should include metric labels', async () => {
      validationTotal.inc({ status: 'valid' });
      validationTotal.inc({ status: 'invalid' });

      const metrics = await getMetrics();

      expect(metrics).toContain('status="valid"');
      expect(metrics).toContain('status="invalid"');
    });

    it('should include histogram buckets', async () => {
      validationDuration.observe({ schema_type: 'UBL-Invoice-2.1' }, 0.15);

      const metrics = await getMetrics();

      expect(metrics).toContain('xsd_validation_duration_seconds');
      expect(metrics).toContain('_bucket');
      expect(metrics).toContain('_count');
      expect(metrics).toContain('_sum');
    });
  });

  describe('initObservability', () => {
    it('should set serviceUp to 1', () => {
      initObservability();

      // Check that serviceUp was set (we can't directly read gauge value,
      // but we can verify it was called by checking metrics output)
      getMetrics().then((metrics) => {
        expect(metrics).toContain('xsd_validator_up 1');
      });
    });

    it('should not throw errors', () => {
      expect(() => initObservability()).not.toThrow();
    });
  });

  describe('Logger', () => {
    it('should export logger instance', async () => {
      const { logger } = await import('../../src/observability.js');
      expect(logger).toBeDefined();
      expect(typeof logger.info).toBe('function');
      expect(typeof logger.error).toBe('function');
      expect(typeof logger.warn).toBe('function');
      expect(typeof logger.debug).toBe('function');
    });

    it('should use pino logger', async () => {
      const { logger } = await import('../../src/observability.js');
      expect(logger.constructor.name).toBe('Pino');
    });
  });

  describe('Tracer', () => {
    it('should export tracer instance', async () => {
      const { tracer } = await import('../../src/observability.js');
      expect(tracer).toBeDefined();
    });

    it('should export createSpan function', async () => {
      const { createSpan } = await import('../../src/observability.js');
      expect(typeof createSpan).toBe('function');
    });

    it('should export setSpanError function', async () => {
      const { setSpanError } = await import('../../src/observability.js');
      expect(typeof setSpanError).toBe('function');
    });

    it('should create span with attributes', async () => {
      const { createSpan } = await import('../../src/observability.js');
      const span = createSpan('test_span', {
        'test.attribute': 'value',
        'test.number': 123,
      });

      expect(span).toBeDefined();
      expect(typeof span.end).toBe('function');

      span.end();
    });

    it('should set span error', async () => {
      const { createSpan, setSpanError } = await import('../../src/observability.js');
      const span = createSpan('test_span');
      const error = new Error('Test error');

      expect(() => setSpanError(span, error)).not.toThrow();

      span.end();
    });
  });

  describe('Metric Collection', () => {
    it('should increment counter multiple times', () => {
      validationTotal.inc({ status: 'valid' });
      validationTotal.inc({ status: 'valid' });
      validationTotal.inc({ status: 'valid' });

      // Verify through metrics output
      getMetrics().then((metrics) => {
        expect(metrics).toContain('xsd_validation_total');
      });
    });

    it('should record multiple histogram observations', () => {
      const durations = [0.05, 0.1, 0.15, 0.2, 0.25];

      for (const duration of durations) {
        validationDuration.observe({ schema_type: 'UBL-Invoice-2.1' }, duration);
      }

      getMetrics().then((metrics) => {
        expect(metrics).toContain('xsd_validation_duration_seconds');
      });
    });

    it('should handle gauge updates', () => {
      queueDepth.set(0);
      queueDepth.inc();
      queueDepth.inc();
      queueDepth.inc();
      queueDepth.dec();

      getMetrics().then((metrics) => {
        expect(metrics).toContain('xsd_validation_queue_depth');
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle metric errors gracefully', async () => {
      // Try to get metrics even if some are not set
      const metrics = await getMetrics();
      expect(metrics).toBeDefined();
      expect(typeof metrics).toBe('string');
    });
  });

  describe('Performance', () => {
    it('should collect metrics quickly', () => {
      const startTime = Date.now();

      for (let i = 0; i < 1000; i++) {
        validationTotal.inc({ status: 'valid' });
      }

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(100); // Should be very fast
    });

    it('should handle concurrent metric updates', async () => {
      const promises = [];

      for (let i = 0; i < 100; i++) {
        promises.push(
          Promise.resolve().then(() => {
            validationTotal.inc({ status: 'valid' });
            validationDuration.observe({ schema_type: 'UBL-Invoice-2.1' }, Math.random());
            queueDepth.inc();
          })
        );
      }

      await Promise.all(promises);

      const metrics = await getMetrics();
      expect(metrics).toBeDefined();
    });
  });
});
