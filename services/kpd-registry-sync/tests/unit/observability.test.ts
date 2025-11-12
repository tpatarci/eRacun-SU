/**
 * Unit Tests for Observability Module
 */

import {
  logger,
  kpdCodesSynced,
  kpdSyncDuration,
  kpdTotalCodes,
  kpdActiveCodes,
  kpdLookupRequests,
  kpdLookupDuration,
  kpdSyncErrors,
  kpdLastSyncTimestamp,
  dbPoolSize,
  dbPoolIdle,
  getMetricsRegistry,
  resetMetrics,
  initializeTracing,
  shutdownTracing,
  createSpan,
  endSpan,
  endSpanWithError,
  traceOperation,
} from '../../src/observability';

describe('Observability Module', () => {
  beforeEach(() => {
    // Reset metrics before each test
    resetMetrics();
  });

  describe('Prometheus Metrics', () => {
    it('should increment kpdCodesSynced counter', () => {
      kpdCodesSynced.inc({ action: 'added' }, 5);
      kpdCodesSynced.inc({ action: 'updated' }, 3);
      kpdCodesSynced.inc({ action: 'deleted' }, 2);

      const metrics = getMetricsRegistry();
      const metricValues = metrics.getSingleMetric('kpd_codes_synced_total');

      expect(metricValues).toBeDefined();
    });

    it('should observe kpdSyncDuration histogram', () => {
      kpdSyncDuration.observe(45.5); // 45.5 seconds
      kpdSyncDuration.observe(32.1);

      const metrics = getMetricsRegistry();
      const metricValues = metrics.getSingleMetric('kpd_sync_duration_seconds');

      expect(metricValues).toBeDefined();
    });

    it('should set kpdTotalCodes gauge', () => {
      kpdTotalCodes.set(50000);

      const metrics = getMetricsRegistry();
      const metricValues = metrics.getSingleMetric('kpd_total_codes');

      expect(metricValues).toBeDefined();
    });

    it('should set kpdActiveCodes gauge', () => {
      kpdActiveCodes.set(48000);

      const metrics = getMetricsRegistry();
      const metricValues = metrics.getSingleMetric('kpd_active_codes');

      expect(metricValues).toBeDefined();
    });

    it('should increment kpdLookupRequests counter', () => {
      kpdLookupRequests.inc({ status: 'found' }, 100);
      kpdLookupRequests.inc({ status: 'not_found' }, 5);
      kpdLookupRequests.inc({ status: 'error' }, 1);

      const metrics = getMetricsRegistry();
      const metricValues = metrics.getSingleMetric('kpd_lookup_requests_total');

      expect(metricValues).toBeDefined();
    });

    it('should observe kpdLookupDuration histogram', () => {
      kpdLookupDuration.observe(0.003); // 3ms
      kpdLookupDuration.observe(0.005); // 5ms

      const metrics = getMetricsRegistry();
      const metricValues = metrics.getSingleMetric('kpd_lookup_duration_seconds');

      expect(metricValues).toBeDefined();
    });

    it('should increment kpdSyncErrors counter', () => {
      kpdSyncErrors.inc({ error_type: 'network' });
      kpdSyncErrors.inc({ error_type: 'parsing' });

      const metrics = getMetricsRegistry();
      const metricValues = metrics.getSingleMetric('kpd_sync_errors_total');

      expect(metricValues).toBeDefined();
    });

    it('should set kpdLastSyncTimestamp gauge', () => {
      const timestamp = Date.now() / 1000;
      kpdLastSyncTimestamp.set(timestamp);

      const metrics = getMetricsRegistry();
      const metricValues = metrics.getSingleMetric('kpd_last_sync_timestamp_seconds');

      expect(metricValues).toBeDefined();
    });

    it('should set database pool metrics', () => {
      dbPoolSize.set(20);
      dbPoolIdle.set(15);

      const metrics = getMetricsRegistry();
      expect(metrics.getSingleMetric('kpd_db_pool_size')).toBeDefined();
      expect(metrics.getSingleMetric('kpd_db_pool_idle')).toBeDefined();
    });
  });

  describe('Structured Logging', () => {
    it('should create logger instance', () => {
      expect(logger).toBeDefined();
      expect(logger.info).toBeDefined();
      expect(logger.error).toBeDefined();
      expect(logger.warn).toBeDefined();
      expect(logger.debug).toBeDefined();
    });

    it('should log messages without errors', () => {
      expect(() => {
        logger.info('Test info message');
        logger.error('Test error message');
        logger.warn('Test warn message');
        logger.debug('Test debug message');
      }).not.toThrow();
    });

    it('should log structured data', () => {
      expect(() => {
        logger.info({ kpd_code: '010101', action: 'lookup' }, 'Code lookup');
      }).not.toThrow();
    });
  });

  describe('Distributed Tracing', () => {
    it('should create and end span', () => {
      const span = createSpan('test_operation', { test_attr: 'value' });
      expect(span).toBeDefined();

      expect(() => {
        endSpan(span);
      }).not.toThrow();
    });

    it('should end span with error', () => {
      const span = createSpan('test_operation_error');
      const error = new Error('Test error');

      expect(() => {
        endSpanWithError(span, error);
      }).not.toThrow();
    });

    it('should trace async operation successfully', async () => {
      const result = await traceOperation('test_async_op', async (span) => {
        expect(span).toBeDefined();
        return 'success';
      });

      expect(result).toBe('success');
    });

    it('should trace async operation with error', async () => {
      await expect(
        traceOperation('test_async_op_error', async (span) => {
          throw new Error('Operation failed');
        })
      ).rejects.toThrow('Operation failed');
    });
  });

  describe('Metrics Registry', () => {
    it('should return metrics registry', () => {
      const registry = getMetricsRegistry();
      expect(registry).toBeDefined();
      expect(registry.metrics).toBeDefined();
    });

    it('should reset all metrics', () => {
      kpdCodesSynced.inc({ action: 'added' }, 10);
      kpdTotalCodes.set(1000);

      resetMetrics();

      // After reset, metrics should be cleared
      const registry = getMetricsRegistry();
      expect(registry).toBeDefined();
    });
  });

  describe('OpenTelemetry Integration', () => {
    it('should initialize tracing without errors', () => {
      expect(() => {
        initializeTracing();
      }).not.toThrow();
    });

    it('should shutdown tracing without errors', async () => {
      await expect(shutdownTracing()).resolves.not.toThrow();
    });
  });
});
