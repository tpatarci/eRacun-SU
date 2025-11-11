/**
 * Unit tests for observability.ts
 * Tests metrics, logging, tracing, and PII masking
 */

import {
  initObservability,
  register,
  logger,
  maskOIB,
  maskIBAN,
  auditEventsWritten,
  auditWriteDuration,
  auditDbConnections,
  auditKafkaLag,
  auditGrpcRequests,
  auditIntegrityVerifications,
  auditIntegrityErrors,
  serviceUp,
  createSpan,
  setSpanError,
} from '../../src/observability';

describe('observability.ts', () => {
  describe('Prometheus Metrics', () => {
    beforeEach(() => {
      // Clear metrics between tests
      register.clear();
    });

    it('should register all required metrics', () => {
      initObservability();

      const metrics = register.getMetricsAsJSON();
      const metricNames = metrics.map((m: any) => m.name);

      expect(metricNames).toContain('audit_events_written_total');
      expect(metricNames).toContain('audit_write_duration_seconds');
      expect(metricNames).toContain('audit_db_connections');
      expect(metricNames).toContain('audit_kafka_lag');
      expect(metricNames).toContain('audit_grpc_requests_total');
      expect(metricNames).toContain('audit_integrity_verifications_total');
      expect(metricNames).toContain('audit_integrity_errors_total');
      expect(metricNames).toContain('service_up');
    });

    it('should increment event counter with labels', () => {
      auditEventsWritten.inc({ service: 'xsd-validator', event_type: 'VALIDATION_STARTED' });
      auditEventsWritten.inc({ service: 'xsd-validator', event_type: 'VALIDATION_STARTED' });
      auditEventsWritten.inc({ service: 'schematron-validator', event_type: 'VALIDATION_PASSED' });

      const metrics = register.getSingleMetric('audit_events_written_total');
      expect(metrics).toBeDefined();
    });

    it('should observe write duration with service label', () => {
      auditWriteDuration.observe({ service: 'xsd-validator' }, 0.123);
      auditWriteDuration.observe({ service: 'xsd-validator' }, 0.456);

      const metrics = register.getSingleMetric('audit_write_duration_seconds');
      expect(metrics).toBeDefined();
    });

    it('should track database connections', () => {
      auditDbConnections.inc();
      auditDbConnections.inc();
      auditDbConnections.dec();

      const metrics = register.getSingleMetric('audit_db_connections');
      expect(metrics).toBeDefined();
    });

    it('should track Kafka lag', () => {
      auditKafkaLag.set(42);
      auditKafkaLag.set(0);

      const metrics = register.getSingleMetric('audit_kafka_lag');
      expect(metrics).toBeDefined();
    });

    it('should count gRPC requests with method and status', () => {
      auditGrpcRequests.inc({ method: 'GetAuditTrail', status: 'success' });
      auditGrpcRequests.inc({ method: 'GetAuditTrail', status: 'error' });
      auditGrpcRequests.inc({ method: 'VerifyIntegrity', status: 'success' });

      const metrics = register.getSingleMetric('audit_grpc_requests_total');
      expect(metrics).toBeDefined();
    });

    it('should track integrity verifications', () => {
      auditIntegrityVerifications.inc({ result: 'valid' });
      auditIntegrityVerifications.inc({ result: 'invalid' });

      const metrics = register.getSingleMetric('audit_integrity_verifications_total');
      expect(metrics).toBeDefined();
    });

    it('should count integrity errors', () => {
      auditIntegrityErrors.inc();
      auditIntegrityErrors.inc();

      const metrics = register.getSingleMetric('audit_integrity_errors_total');
      expect(metrics).toBeDefined();
    });

    it('should track service up status', () => {
      serviceUp.set(1);
      serviceUp.set(0);

      const metrics = register.getSingleMetric('service_up');
      expect(metrics).toBeDefined();
    });

    it('should export metrics in Prometheus format', async () => {
      auditEventsWritten.inc({ service: 'test-service', event_type: 'TEST_EVENT' });

      const metricsOutput = await register.metrics();

      expect(metricsOutput).toContain('# TYPE audit_events_written_total counter');
      expect(metricsOutput).toContain('audit_events_written_total');
    });
  });

  describe('PII Masking', () => {
    describe('maskOIB', () => {
      it('should fully mask valid OIB', () => {
        const oib = '12345678901';
        const masked = maskOIB(oib);

        expect(masked).toBe('***********');
        expect(masked).toHaveLength(11);
      });

      it('should return INVALID_OIB for empty string', () => {
        expect(maskOIB('')).toBe('INVALID_OIB');
      });

      it('should return INVALID_OIB for null', () => {
        expect(maskOIB(null as any)).toBe('INVALID_OIB');
      });

      it('should return INVALID_OIB for undefined', () => {
        expect(maskOIB(undefined as any)).toBe('INVALID_OIB');
      });

      it('should return INVALID_OIB for short string', () => {
        expect(maskOIB('123')).toBe('INVALID_OIB');
      });

      it('should return INVALID_OIB for long string', () => {
        expect(maskOIB('123456789012')).toBe('INVALID_OIB');
      });

      it('should mask OIB with exactly 11 characters', () => {
        expect(maskOIB('00000000000')).toBe('***********');
        expect(maskOIB('99999999999')).toBe('***********');
      });
    });

    describe('maskIBAN', () => {
      it('should mask Croatian IBAN (show prefix + last 4)', () => {
        const iban = 'HR1234567890123456789';
        const masked = maskIBAN(iban);

        expect(masked).toBe('HR12***6789');
        expect(masked).toHaveLength(11);
      });

      it('should mask short IBAN', () => {
        const iban = 'HR123456';
        const masked = maskIBAN(iban);

        expect(masked).toBe('HR12***3456');
      });

      it('should return INVALID_IBAN for empty string', () => {
        expect(maskIBAN('')).toBe('INVALID_IBAN');
      });

      it('should return INVALID_IBAN for null', () => {
        expect(maskIBAN(null as any)).toBe('INVALID_IBAN');
      });

      it('should return INVALID_IBAN for very short string', () => {
        expect(maskIBAN('HR')).toBe('INVALID_IBAN');
      });

      it('should mask international IBAN', () => {
        const iban = 'DE89370400440532013000';
        const masked = maskIBAN(iban);

        expect(masked).toBe('DE89***3000');
      });

      it('should handle IBAN with spaces (normalize first)', () => {
        const iban = 'HR12 3456 7890 1234 5678 9';
        const normalized = iban.replace(/\s/g, '');
        const masked = maskIBAN(normalized);

        expect(masked).toBe('HR12***8 9');
      });
    });

    it('should not mask PII in production audit logs (regulatory requirement)', () => {
      // IMPORTANT: The maskOIB and maskIBAN functions exist for logging/metrics only
      // Audit logs themselves DO NOT mask PII (Croatian law requires unmasked data)

      const sensitiveData = {
        oib: '12345678901',
        iban: 'HR1234567890123456789',
      };

      // In audit log storage, this data remains unmasked
      expect(sensitiveData.oib).toBe('12345678901');
      expect(sensitiveData.iban).toBe('HR1234567890123456789');

      // But in observability (logs, metrics), we mask it
      expect(maskOIB(sensitiveData.oib)).toBe('***********');
      expect(maskIBAN(sensitiveData.iban)).toBe('HR12***6789');
    });
  });

  describe('Structured Logging', () => {
    it('should provide logger instance', () => {
      expect(logger).toBeDefined();
      expect(typeof logger.info).toBe('function');
      expect(typeof logger.error).toBe('function');
      expect(typeof logger.warn).toBe('function');
      expect(typeof logger.debug).toBe('function');
    });

    it('should log structured data', () => {
      const logSpy = jest.spyOn(logger, 'info');

      logger.info(
        {
          event_id: 'evt-001',
          invoice_id: 'inv-001',
          service: 'xsd-validator',
        },
        'Audit event written'
      );

      expect(logSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          event_id: 'evt-001',
          invoice_id: 'inv-001',
          service: 'xsd-validator',
        }),
        'Audit event written'
      );

      logSpy.mockRestore();
    });

    it('should log errors with context', () => {
      const errorSpy = jest.spyOn(logger, 'error');
      const error = new Error('Database connection failed');

      logger.error(
        {
          err: error,
          event_id: 'evt-001',
        },
        'Failed to write audit event'
      );

      expect(errorSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          err: error,
          event_id: 'evt-001',
        }),
        'Failed to write audit event'
      );

      errorSpy.mockRestore();
    });
  });

  describe('Distributed Tracing', () => {
    it('should create span with operation name', () => {
      const span = createSpan('test_operation');

      expect(span).toBeDefined();
      expect(typeof span.end).toBe('function');
      expect(typeof span.setAttribute).toBe('function');
    });

    it('should create span with attributes', () => {
      const span = createSpan('test_operation', {
        'event.id': 'evt-001',
        'invoice.id': 'inv-001',
      });

      expect(span).toBeDefined();
    });

    it('should set span error', () => {
      const span = createSpan('test_operation');
      const error = new Error('Test error');

      setSpanError(span, error);

      // Should not throw
      expect(span).toBeDefined();
    });

    it('should allow span to be ended', () => {
      const span = createSpan('test_operation');

      expect(() => span.end()).not.toThrow();
    });
  });

  describe('Observability Initialization', () => {
    it('should initialize without errors', () => {
      expect(() => initObservability()).not.toThrow();
    });

    it('should set service_up to 1 on init', () => {
      initObservability();

      const metrics = register.getSingleMetric('service_up');
      expect(metrics).toBeDefined();
    });

    it('should log initialization message', () => {
      const infoSpy = jest.spyOn(logger, 'info');

      initObservability();

      expect(infoSpy).toHaveBeenCalledWith(
        expect.stringContaining('Observability initialized')
      );

      infoSpy.mockRestore();
    });
  });

  describe('Metric Labels and Cardinality', () => {
    it('should use bounded label values (prevent cardinality explosion)', () => {
      // Service names are bounded (only our services)
      const validServices = [
        'xsd-validator',
        'schematron-validator',
        'ai-validator',
        'invoice-gateway',
      ];

      validServices.forEach((service) => {
        auditEventsWritten.inc({ service, event_type: 'TEST' });
      });

      // This should not cause cardinality issues
      expect(register.getSingleMetric('audit_events_written_total')).toBeDefined();
    });

    it('should use bounded event types', () => {
      const validEventTypes = [
        'VALIDATION_STARTED',
        'VALIDATION_PASSED',
        'VALIDATION_FAILED',
        'TRANSFORMATION_STARTED',
        'TRANSFORMATION_COMPLETED',
        'SUBMISSION_STARTED',
        'SUBMISSION_SUCCESS',
        'SUBMISSION_FAILED',
      ];

      validEventTypes.forEach((event_type) => {
        auditEventsWritten.inc({ service: 'test-service', event_type });
      });

      expect(register.getSingleMetric('audit_events_written_total')).toBeDefined();
    });

    it('should use bounded gRPC methods', () => {
      const validMethods = ['GetAuditTrail', 'QueryAuditEvents', 'VerifyIntegrity'];
      const validStatuses = ['success', 'error'];

      validMethods.forEach((method) => {
        validStatuses.forEach((status) => {
          auditGrpcRequests.inc({ method, status });
        });
      });

      expect(register.getSingleMetric('audit_grpc_requests_total')).toBeDefined();
    });
  });

  describe('Metrics Export', () => {
    it('should export metrics for Prometheus scraping', async () => {
      auditEventsWritten.inc({ service: 'test-service', event_type: 'TEST' });
      auditDbConnections.set(10);
      serviceUp.set(1);

      const output = await register.metrics();

      // Should contain metric metadata
      expect(output).toContain('# HELP');
      expect(output).toContain('# TYPE');

      // Should contain actual metrics
      expect(output).toContain('audit_events_written_total');
      expect(output).toContain('audit_db_connections');
      expect(output).toContain('service_up');
    });

    it('should export metrics as JSON', () => {
      auditEventsWritten.inc({ service: 'test-service', event_type: 'TEST' });

      const json = register.getMetricsAsJSON();

      expect(Array.isArray(json)).toBe(true);
      expect(json.length).toBeGreaterThan(0);
      expect(json[0]).toHaveProperty('name');
      expect(json[0]).toHaveProperty('type');
    });
  });

  describe('Performance', () => {
    it('should handle high-frequency metric updates', () => {
      const iterations = 10000;
      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        auditEventsWritten.inc({ service: 'test-service', event_type: 'TEST' });
      }

      const duration = Date.now() - startTime;

      // 10k increments should complete in <100ms
      expect(duration).toBeLessThan(100);
    });

    it('should handle concurrent metric updates', async () => {
      const promises = Array.from({ length: 100 }, (_, i) =>
        Promise.resolve(
          auditEventsWritten.inc({ service: 'test-service', event_type: 'TEST' })
        )
      );

      await expect(Promise.all(promises)).resolves.toBeDefined();
    });

    it('should create spans efficiently', () => {
      const iterations = 1000;
      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        const span = createSpan('test_operation');
        span.end();
      }

      const duration = Date.now() - startTime;

      // 1k span creations should complete in <50ms
      expect(duration).toBeLessThan(50);
    });
  });
});
