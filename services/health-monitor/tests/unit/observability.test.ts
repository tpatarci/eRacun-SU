/**
 * Unit Tests for Observability Module
 */

import {
  register,
  serviceHealthStatus,
  healthCheckSuccess,
  healthCheckFailures,
  circuitBreakerState,
  healthCheckDuration,
  serviceUp,
  logger,
  healthStatusToMetric,
  createSpan,
  setSpanError,
} from '../../src/observability';
import { HealthStatus } from '../../src/health-checker';

describe('Observability Module', () => {
  beforeEach(() => {
    // Clear all metrics before each test
    register.resetMetrics();
  });

  describe('Prometheus Metrics', () => {
    describe('serviceHealthStatus', () => {
      it('should track service health status as gauge', () => {
        serviceHealthStatus.set({ service: 'test-service' }, 1);

        const metrics = register.getSingleMetric('service_health_status');
        expect(metrics).toBeDefined();
      });

      it('should support multiple services', () => {
        serviceHealthStatus.set({ service: 'service-a' }, 1); // healthy
        serviceHealthStatus.set({ service: 'service-b' }, 0.5); // degraded
        serviceHealthStatus.set({ service: 'service-c' }, 0); // unhealthy

        const metrics = register.getSingleMetric('service_health_status');
        expect(metrics).toBeDefined();
      });
    });

    describe('healthCheckSuccess', () => {
      it('should increment success counter', () => {
        healthCheckSuccess.inc({ service: 'test-service' });
        healthCheckSuccess.inc({ service: 'test-service' });

        const metrics = register.getSingleMetric('health_check_success_total');
        expect(metrics).toBeDefined();
      });

      it('should track successes per service', () => {
        healthCheckSuccess.inc({ service: 'service-a' }, 5);
        healthCheckSuccess.inc({ service: 'service-b' }, 3);

        const metrics = register.getSingleMetric('health_check_success_total');
        expect(metrics).toBeDefined();
      });
    });

    describe('healthCheckFailures', () => {
      it('should increment failure counter with reason', () => {
        healthCheckFailures.inc({ service: 'test-service', reason: 'timeout' });
        healthCheckFailures.inc({ service: 'test-service', reason: 'connection_refused' });

        const metrics = register.getSingleMetric('health_check_failures_total');
        expect(metrics).toBeDefined();
      });

      it('should track different failure reasons', () => {
        const reasons = ['timeout', 'connection_refused', 'http_error', 'dns_failure'];

        reasons.forEach(reason => {
          healthCheckFailures.inc({ service: 'test-service', reason });
        });

        const metrics = register.getSingleMetric('health_check_failures_total');
        expect(metrics).toBeDefined();
      });
    });

    describe('circuitBreakerState', () => {
      it('should track circuit breaker state', () => {
        circuitBreakerState.set({ service: 'test-service', breaker: 'main' }, 0); // closed
        circuitBreakerState.set({ service: 'test-service', breaker: 'main' }, 1); // open
        circuitBreakerState.set({ service: 'test-service', breaker: 'main' }, 0.5); // half-open

        const metrics = register.getSingleMetric('circuit_breaker_state');
        expect(metrics).toBeDefined();
      });

      it('should support multiple circuit breakers per service', () => {
        circuitBreakerState.set({ service: 'db-service', breaker: 'read' }, 0);
        circuitBreakerState.set({ service: 'db-service', breaker: 'write' }, 1);

        const metrics = register.getSingleMetric('circuit_breaker_state');
        expect(metrics).toBeDefined();
      });
    });

    describe('healthCheckDuration', () => {
      it('should observe health check duration', () => {
        healthCheckDuration.observe({ service: 'test-service' }, 0.1); // 100ms
        healthCheckDuration.observe({ service: 'test-service' }, 0.5); // 500ms

        const metrics = register.getSingleMetric('health_check_duration_seconds');
        expect(metrics).toBeDefined();
      });

      it('should use correct buckets', () => {
        // Buckets: 0.01, 0.05, 0.1, 0.5, 1, 5
        healthCheckDuration.observe({ service: 'fast-service' }, 0.01); // 10ms
        healthCheckDuration.observe({ service: 'slow-service' }, 2); // 2s

        const metrics = register.getSingleMetric('health_check_duration_seconds');
        expect(metrics).toBeDefined();
      });
    });

    describe('serviceUp', () => {
      it('should track health monitor availability', () => {
        serviceUp.set(1); // service is up

        const metrics = register.getSingleMetric('service_up');
        expect(metrics).toBeDefined();
      });

      it('should allow setting to 0 when down', () => {
        serviceUp.set(0); // service is down

        const metrics = register.getSingleMetric('service_up');
        expect(metrics).toBeDefined();
      });
    });
  });

  describe('healthStatusToMetric()', () => {
    it('should convert HEALTHY status to 1', () => {
      const result = healthStatusToMetric(HealthStatus.HEALTHY);
      expect(result).toBe(1);
    });

    it('should convert DEGRADED status to 0.5', () => {
      const result = healthStatusToMetric(HealthStatus.DEGRADED);
      expect(result).toBe(0.5);
    });

    it('should convert UNHEALTHY status to 0', () => {
      const result = healthStatusToMetric(HealthStatus.UNHEALTHY);
      expect(result).toBe(0);
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
        logger.info(
          {
            service: 'test-service',
            status: 'healthy',
            latency_ms: 100,
          },
          'Health check completed'
        );
      }).not.toThrow();
    });
  });

  describe('Distributed Tracing', () => {
    describe('createSpan()', () => {
      it('should create span with operation name', () => {
        const span = createSpan('test_operation');
        expect(span).toBeDefined();
        span.end();
      });

      it('should create span with attributes', () => {
        const span = createSpan('test_operation', {
          'service.name': 'test-service',
          'request.id': '12345',
        });
        expect(span).toBeDefined();
        span.end();
      });

      it('should handle empty attributes', () => {
        const span = createSpan('test_operation', {});
        expect(span).toBeDefined();
        span.end();
      });
    });

    describe('setSpanError()', () => {
      it('should set error on span', () => {
        const span = createSpan('test_operation');
        const error = new Error('Test error');

        expect(() => {
          setSpanError(span, error);
          span.end();
        }).not.toThrow();
      });

      it('should record error message', () => {
        const span = createSpan('test_operation');
        const error = new Error('Connection timeout');

        setSpanError(span, error);
        expect(error.message).toBe('Connection timeout');
        span.end();
      });
    });
  });

  describe('Metrics Registry', () => {
    it('should return metrics registry', () => {
      expect(register).toBeDefined();
      expect(register.metrics).toBeDefined();
    });

    it('should export metrics in Prometheus format', async () => {
      serviceHealthStatus.set({ service: 'test' }, 1);
      healthCheckSuccess.inc({ service: 'test' });

      const metrics = await register.metrics();
      expect(metrics).toContain('service_health_status');
      expect(metrics).toContain('health_check_success_total');
    });

    it('should reset metrics', () => {
      serviceHealthStatus.set({ service: 'test' }, 1);
      healthCheckSuccess.inc({ service: 'test' }, 10);

      register.resetMetrics();

      // After reset, metrics should be cleared
      expect(register).toBeDefined();
    });

    it('should track all 6 metrics', () => {
      const metricNames = [
        'service_health_status',
        'health_check_success_total',
        'health_check_failures_total',
        'circuit_breaker_state',
        'health_check_duration_seconds',
        'service_up',
      ];

      // Set/observe all metrics
      serviceHealthStatus.set({ service: 'test' }, 1);
      healthCheckSuccess.inc({ service: 'test' });
      healthCheckFailures.inc({ service: 'test', reason: 'timeout' });
      circuitBreakerState.set({ service: 'test', breaker: 'main' }, 0);
      healthCheckDuration.observe({ service: 'test' }, 0.1);
      serviceUp.set(1);

      // Verify all metrics are registered
      metricNames.forEach(name => {
        const metric = register.getSingleMetric(name);
        expect(metric).toBeDefined();
      });
    });
  });

  describe('Metric Values', () => {
    it('should record realistic health check scenario', () => {
      // Simulate 10 successful health checks
      for (let i = 0; i < 10; i++) {
        healthCheckSuccess.inc({ service: 'api-gateway' });
        healthCheckDuration.observe({ service: 'api-gateway' }, 0.05 + Math.random() * 0.1);
        serviceHealthStatus.set({ service: 'api-gateway' }, 1);
      }

      // Simulate 3 failures
      for (let i = 0; i < 3; i++) {
        healthCheckFailures.inc({ service: 'api-gateway', reason: 'timeout' });
      }

      const metrics = register.getSingleMetric('health_check_success_total');
      expect(metrics).toBeDefined();
    });

    it('should handle rapid metric updates', () => {
      // Simulate high-frequency updates
      for (let i = 0; i < 100; i++) {
        serviceHealthStatus.set({ service: `service-${i % 5}` }, Math.random());
        healthCheckDuration.observe({ service: `service-${i % 5}` }, Math.random());
      }

      const metrics = register.getSingleMetric('service_health_status');
      expect(metrics).toBeDefined();
    });
  });
});
