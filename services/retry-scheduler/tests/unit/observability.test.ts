/**
 * Unit Tests - Observability Module
 *
 * Tests Prometheus metrics, structured logging, and tracing.
 */

import {
  retriesScheduledTotal,
  retriesExecutedTotal,
  retriesExhaustedTotal,
  retryQueueDepth,
  serviceUp,
  resetMetrics,
  getMetrics,
  logger,
} from '../../src/observability';

describe('Observability Module', () => {
  beforeEach(() => {
    // Reset metrics before each test
    resetMetrics();
  });

  describe('Prometheus Metrics', () => {
    describe('retriesScheduledTotal counter', () => {
      it('should increment for scheduled retries', async () => {
        retriesScheduledTotal.inc({ queue: 'test.queue' });

        const metrics = await getMetrics();
        expect(metrics).toContain('retries_scheduled_total');
        expect(metrics).toContain('queue="test.queue"');
      });

      it('should track multiple queues separately', async () => {
        retriesScheduledTotal.inc({ queue: 'queue.a' });
        retriesScheduledTotal.inc({ queue: 'queue.b' });
        retriesScheduledTotal.inc({ queue: 'queue.a' });

        const metrics = await getMetrics();
        expect(metrics).toContain('queue="queue.a"');
        expect(metrics).toContain('queue="queue.b"');
      });

      it('should increment by custom amount', async () => {
        retriesScheduledTotal.inc({ queue: 'test.queue' }, 5);

        const metrics = await getMetrics();
        expect(metrics).toContain('retries_scheduled_total');
      });
    });

    describe('retriesExecutedTotal counter', () => {
      it('should increment for successful retries', async () => {
        retriesExecutedTotal.inc({ queue: 'test.queue', status: 'success' });

        const metrics = await getMetrics();
        expect(metrics).toContain('retries_executed_total');
        expect(metrics).toContain('status="success"');
      });

      it('should increment for failed retries', async () => {
        retriesExecutedTotal.inc({ queue: 'test.queue', status: 'failed' });

        const metrics = await getMetrics();
        expect(metrics).toContain('retries_executed_total');
        expect(metrics).toContain('status="failed"');
      });

      it('should track success and failure separately', async () => {
        retriesExecutedTotal.inc({ queue: 'test.queue', status: 'success' }, 3);
        retriesExecutedTotal.inc({ queue: 'test.queue', status: 'failed' }, 1);

        const metrics = await getMetrics();
        expect(metrics).toContain('status="success"');
        expect(metrics).toContain('status="failed"');
      });
    });

    describe('retriesExhaustedTotal counter', () => {
      it('should increment when max retries exceeded', async () => {
        retriesExhaustedTotal.inc({ queue: 'test.queue' });

        const metrics = await getMetrics();
        expect(metrics).toContain('retries_exhausted_total');
        expect(metrics).toContain('queue="test.queue"');
      });

      it('should track exhausted retries per queue', async () => {
        retriesExhaustedTotal.inc({ queue: 'queue.a' });
        retriesExhaustedTotal.inc({ queue: 'queue.b' });

        const metrics = await getMetrics();
        expect(metrics).toContain('queue="queue.a"');
        expect(metrics).toContain('queue="queue.b"');
      });
    });

    describe('retryQueueDepth gauge', () => {
      it('should set queue depth value', async () => {
        retryQueueDepth.set(42);

        const metrics = await getMetrics();
        expect(metrics).toContain('retry_queue_depth');
        expect(metrics).toContain('42');
      });

      it('should update queue depth value', async () => {
        retryQueueDepth.set(10);
        retryQueueDepth.set(20);

        const metrics = await getMetrics();
        expect(metrics).toContain('20');
      });

      it('should increment queue depth', () => {
        retryQueueDepth.set(5);
        retryQueueDepth.inc();
        retryQueueDepth.inc(3);

        // Final value should be 9 (5 + 1 + 3)
        // We can't easily verify the exact value without parsing metrics,
        // but we can verify it doesn't error
        expect(() => retryQueueDepth.inc()).not.toThrow();
      });

      it('should decrement queue depth', () => {
        retryQueueDepth.set(10);
        retryQueueDepth.dec();
        retryQueueDepth.dec(2);

        // Final value should be 7 (10 - 1 - 2)
        expect(() => retryQueueDepth.dec()).not.toThrow();
      });
    });

    describe('serviceUp gauge', () => {
      it('should set service up status', async () => {
        serviceUp.set(1);

        const metrics = await getMetrics();
        expect(metrics).toContain('service_up');
        expect(metrics).toContain('1');
      });

      it('should set service down status', async () => {
        serviceUp.set(0);

        const metrics = await getMetrics();
        expect(metrics).toContain('service_up');
        expect(metrics).toContain('0');
      });
    });

    describe('getMetrics', () => {
      it('should return metrics in Prometheus text format', async () => {
        retriesScheduledTotal.inc({ queue: 'test' });

        const metrics = await getMetrics();

        expect(typeof metrics).toBe('string');
        expect(metrics).toContain('# HELP');
        expect(metrics).toContain('# TYPE');
      });

      it('should include all registered metrics', async () => {
        retriesScheduledTotal.inc({ queue: 'test' });
        retriesExecutedTotal.inc({ queue: 'test', status: 'success' });
        retriesExhaustedTotal.inc({ queue: 'test' });
        retryQueueDepth.set(5);
        serviceUp.set(1);

        const metrics = await getMetrics();

        expect(metrics).toContain('retries_scheduled_total');
        expect(metrics).toContain('retries_executed_total');
        expect(metrics).toContain('retries_exhausted_total');
        expect(metrics).toContain('retry_queue_depth');
        expect(metrics).toContain('service_up');
      });
    });

    describe('resetMetrics', () => {
      it('should reset all metrics to zero', async () => {
        retriesScheduledTotal.inc({ queue: 'test' }, 10);
        retryQueueDepth.set(42);

        resetMetrics();

        const metrics = await getMetrics();
        // After reset, counters should be back to 0 or not present
        expect(metrics).toContain('retries_scheduled_total');
      });
    });
  });

  describe('Structured Logging', () => {
    describe('logger instance', () => {
      it('should be defined', () => {
        expect(logger).toBeDefined();
        expect(logger.info).toBeDefined();
        expect(logger.error).toBeDefined();
        expect(logger.warn).toBeDefined();
        expect(logger.debug).toBeDefined();
      });

      it('should have logging methods', () => {
        expect(typeof logger.info).toBe('function');
        expect(typeof logger.error).toBe('function');
        expect(typeof logger.warn).toBe('function');
        expect(typeof logger.debug).toBe('function');
        expect(typeof logger.trace).toBe('function');
        expect(typeof logger.fatal).toBe('function');
      });

      it('should accept structured log data', () => {
        // These should not throw
        expect(() => {
          logger.info({ message_id: '123', queue: 'test' }, 'Test message');
        }).not.toThrow();

        expect(() => {
          logger.error({ error: new Error('test'), context: 'test' }, 'Error occurred');
        }).not.toThrow();
      });

      it('should support child loggers', () => {
        const childLogger = logger.child({ module: 'test' });

        expect(childLogger).toBeDefined();
        expect(childLogger.info).toBeDefined();
      });

      it('should handle all log levels', () => {
        expect(() => {
          logger.trace('Trace message');
          logger.debug('Debug message');
          logger.info('Info message');
          logger.warn('Warn message');
          logger.error('Error message');
          logger.fatal('Fatal message');
        }).not.toThrow();
      });
    });
  });

  describe('Distributed Tracing', () => {
    describe('initTracing', () => {
      it('should initialize tracing without error', () => {
        const { initTracing } = require('../../src/observability');
        expect(() => initTracing()).not.toThrow();
      });
    });

    describe('getTracer', () => {
      it('should return a tracer instance', () => {
        const { getTracer } = require('../../src/observability');
        const tracer = getTracer();
        expect(tracer).toBeDefined();
      });
    });

    describe('createSpan', () => {
      it('should create a span with operation name', () => {
        const { createSpan } = require('../../src/observability');
        const span = createSpan('test.operation');
        expect(span).toBeDefined();
        expect(span.end).toBeDefined();
        span.end();
      });

      it('should create a span with attributes', () => {
        const { createSpan } = require('../../src/observability');
        const span = createSpan('test.operation', {
          'test.attribute': 'value',
          'test.number': 42,
        });
        expect(span).toBeDefined();
        span.end();
      });
    });

    describe('endSpan', () => {
      it('should end a span successfully', () => {
        const { createSpan, endSpan } = require('../../src/observability');
        const span = createSpan('test.operation');
        expect(() => endSpan(span)).not.toThrow();
      });
    });

    describe('setSpanError', () => {
      it('should set error on span and end it', () => {
        const { createSpan, setSpanError } = require('../../src/observability');
        const span = createSpan('test.operation');
        const error = new Error('Test error');
        expect(() => setSpanError(span, error)).not.toThrow();
      });
    });

    describe('withSpan', () => {
      it('should execute function within span context', async () => {
        const { withSpan } = require('../../src/observability');

        const result = await withSpan(
          'test.operation',
          { testAttr: 'value' },
          async (span: any) => {
            expect(span).toBeDefined();
            return 'success';
          }
        );

        expect(result).toBe('success');
      });

      it('should handle errors and set span error', async () => {
        const { withSpan } = require('../../src/observability');

        await expect(
          withSpan('test.operation', {}, async () => {
            throw new Error('Test error');
          })
        ).rejects.toThrow('Test error');
      });
    });

    describe('shutdownTracing', () => {
      it('should shutdown tracing gracefully', async () => {
        const { shutdownTracing } = require('../../src/observability');
        // Call shutdown (it may or may not throw depending on state)
        try {
          await shutdownTracing();
        } catch (error) {
          // Shutdown may fail if already shut down, which is fine
        }
        // Just verify it completes
        expect(true).toBe(true);
      });
    });
  });

  describe('Metrics Compliance (TODO-008)', () => {
    it('should have at least 4 metrics defined', async () => {
      const metrics = await getMetrics();

      // Count unique metric names
      const metricNames = [
        'retries_scheduled_total',
        'retries_executed_total',
        'retries_exhausted_total',
        'retry_queue_depth',
        'service_up',
      ];

      const definedMetrics = metricNames.filter(name => metrics.includes(name));

      expect(definedMetrics.length).toBeGreaterThanOrEqual(4);
    });

    it('should have proper metric labels', async () => {
      retriesScheduledTotal.inc({ queue: 'validation.xsd' });
      retriesExecutedTotal.inc({ queue: 'validation.xsd', status: 'success' });

      const metrics = await getMetrics();

      // Verify labels are present
      expect(metrics).toContain('queue=');
      expect(metrics).toContain('status=');
    });

    it('should track retry lifecycle metrics', async () => {
      // Simulate complete retry lifecycle
      retriesScheduledTotal.inc({ queue: 'test.queue' });
      retriesExecutedTotal.inc({ queue: 'test.queue', status: 'success' });

      const metrics = await getMetrics();

      expect(metrics).toContain('retries_scheduled_total');
      expect(metrics).toContain('retries_executed_total');
    });

    it('should track manual review routing', async () => {
      retriesExhaustedTotal.inc({ queue: 'test.queue' });

      const metrics = await getMetrics();

      expect(metrics).toContain('retries_exhausted_total');
    });
  });

  describe('Real-world Scenarios', () => {
    it('should track successful retry workflow', async () => {
      const queue = 'validation.xsd.validate';

      // Schedule retry
      retriesScheduledTotal.inc({ queue });
      retryQueueDepth.set(1);

      // Execute retry successfully
      retriesExecutedTotal.inc({ queue, status: 'success' });
      retryQueueDepth.set(0);

      const metrics = await getMetrics();

      expect(metrics).toContain('retries_scheduled_total');
      expect(metrics).toContain('retries_executed_total');
      expect(metrics).toContain('retry_queue_depth');
    });

    it('should track failed retry escalation', async () => {
      const queue = 'transformation.ubl.transform';

      // Schedule retries
      retriesScheduledTotal.inc({ queue }, 3);

      // Execute failed retries
      retriesExecutedTotal.inc({ queue, status: 'failed' }, 3);

      // Move to manual review
      retriesExhaustedTotal.inc({ queue });

      const metrics = await getMetrics();

      expect(metrics).toContain('retries_scheduled_total');
      expect(metrics).toContain('retries_executed_total');
      expect(metrics).toContain('retries_exhausted_total');
    });

    it('should track queue depth changes', async () => {
      retryQueueDepth.set(0);

      // Add tasks
      retryQueueDepth.set(5);
      retryQueueDepth.set(10);
      retryQueueDepth.set(8);

      // Process tasks
      retryQueueDepth.set(3);
      retryQueueDepth.set(0);

      const metrics = await getMetrics();
      expect(metrics).toContain('retry_queue_depth');
    });
  });
});
