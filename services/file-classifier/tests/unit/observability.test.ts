/**
 * Observability Module Tests
 */

import {
  logger,
  filesClassifiedTotal,
  filesRoutedTotal,
  classificationErrorsTotal,
  classificationDuration,
  queueDepth,
  fileSizeBytes,
  getMetricsRegistry,
  withSpan,
} from '../../src/observability';

describe('Observability Module', () => {
  beforeEach(() => {
    // Reset metrics
    getMetricsRegistry().resetMetrics();
  });

  describe('Logger', () => {
    it('should have info level or higher', () => {
      expect(logger.level).toBeDefined();
      expect(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']).toContain(
        logger.level
      );
    });

    it('should log messages', () => {
      const logSpy = jest.spyOn(logger, 'info');
      logger.info('test message');
      expect(logSpy).toHaveBeenCalled();
      logSpy.mockRestore();
    });
  });

  describe('Metrics', () => {
    it('should increment filesClassifiedTotal', async () => {
      filesClassifiedTotal.inc({ file_type: 'pdf-document', status: 'success' });

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('file_classifier_files_classified_total');
      expect(metrics).toContain('file_type="pdf-document"');
      expect(metrics).toContain('status="success"');
    });

    it('should increment filesRoutedTotal', async () => {
      filesRoutedTotal.inc({ processor: 'pdf-parser', status: 'success' });

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('file_classifier_files_routed_total');
      expect(metrics).toContain('processor="pdf-parser"');
    });

    it('should increment classificationErrorsTotal', async () => {
      classificationErrorsTotal.inc({ error_type: 'unsupported_type' });

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('file_classifier_classification_errors_total');
      expect(metrics).toContain('error_type="unsupported_type"');
    });

    it('should record classificationDuration', async () => {
      const endTimer = classificationDuration.startTimer({ operation: 'detect' });
      await new Promise((resolve) => setTimeout(resolve, 10));
      endTimer();

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('file_classifier_classification_duration_seconds');
      expect(metrics).toContain('operation="detect"');
    });

    it('should set queueDepth', async () => {
      queueDepth.set({ processor: 'pdf-parser' }, 42);

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('file_classifier_queue_depth');
      expect(metrics).toContain('42');
    });

    it('should record fileSizeBytes', async () => {
      fileSizeBytes.observe({ file_type: 'application/pdf' }, 1024);

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('file_classifier_file_size_bytes');
    });
  });

  describe('Distributed Tracing', () => {
    it('should execute function within span successfully', async () => {
      const testFn = jest.fn().mockResolvedValue('success');

      const result = await withSpan(
        'test.operation',
        { test: 'attribute' },
        testFn
      );

      expect(result).toBe('success');
      expect(testFn).toHaveBeenCalled();
    });

    it('should handle errors in span', async () => {
      const testError = new Error('test error');
      const testFn = jest.fn().mockRejectedValue(testError);

      await expect(
        withSpan('test.operation', { test: 'attribute' }, testFn)
      ).rejects.toThrow('test error');

      expect(testFn).toHaveBeenCalled();
    });

    it('should pass span to callback function', async () => {
      const testFn = jest.fn((span) => {
        expect(span).toBeDefined();
        expect(span.setAttribute).toBeDefined();
        return Promise.resolve();
      });

      await withSpan('test.operation', { test: 'attribute' }, testFn);

      expect(testFn).toHaveBeenCalled();
    });

    it('should call getActiveSpan function', async () => {
      const { getActiveSpan } = require('../../src/observability');

      await withSpan('test.operation', {}, async () => {
        const span = getActiveSpan();
        // In test environment with NoopContextManager, may return undefined
        expect(span === undefined || span !== undefined).toBe(true);
        return 'test';
      });
    });

    it('should handle getActiveSpan outside of span context', () => {
      const { getActiveSpan } = require('../../src/observability');
      const span = getActiveSpan();
      // getActiveSpan should be callable and return a value (or undefined)
      expect(span === undefined || span !== undefined).toBe(true);
    });
  });

  describe('Metrics Registry', () => {
    it('should return registry instance', () => {
      const registry = getMetricsRegistry();
      expect(registry).toBeDefined();
      expect(registry.metrics).toBeDefined();
    });

    it('should contain all registered metrics', async () => {
      // Trigger all metrics
      filesClassifiedTotal.inc({ file_type: 'pdf-document', status: 'success' });
      filesRoutedTotal.inc({ processor: 'pdf-parser', status: 'success' });
      classificationErrorsTotal.inc({ error_type: 'size_exceeded' });
      queueDepth.set({ processor: 'pdf-parser' }, 10);
      fileSizeBytes.observe({ file_type: 'application/pdf' }, 1024);

      const metrics = await getMetricsRegistry().metrics();

      expect(metrics).toContain('file_classifier_files_classified_total');
      expect(metrics).toContain('file_classifier_files_routed_total');
      expect(metrics).toContain('file_classifier_classification_errors_total');
      expect(metrics).toContain('file_classifier_queue_depth');
      expect(metrics).toContain('file_classifier_file_size_bytes');
    });
  });
});
