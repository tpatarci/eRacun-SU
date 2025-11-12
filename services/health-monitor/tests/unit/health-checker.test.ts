/**
 * Unit Tests for Health Checker Module
 */

import axios from 'axios';
import {
  checkServiceHealth,
  HealthStatus,
  getFailureCount,
  getSuccessCount,
  getLastKnownStatus,
} from '../../src/health-checker';
import { Service } from '../../src/service-registry';
import * as observability from '../../src/observability';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock observability
jest.mock('../../src/observability', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    error: jest.fn(),
  },
  createSpan: jest.fn(() => ({
    end: jest.fn(),
    setAttribute: jest.fn(),
  })),
  setSpanError: jest.fn(),
  healthCheckSuccess: {
    inc: jest.fn(),
  },
  healthCheckFailures: {
    inc: jest.fn(),
  },
  healthCheckDuration: {
    observe: jest.fn(),
  },
  serviceHealthStatus: {
    set: jest.fn(),
  },
  healthStatusToMetric: jest.fn((status) => {
    if (status === 'healthy') return 1;
    if (status === 'degraded') return 0.5;
    return 0;
  }),
}));

describe('Health Checker Module', () => {
  const mockService: Service = {
    name: 'test-service',
    health_url: 'http://localhost:8080/health',
    ready_url: 'http://localhost:8080/ready',
    critical: true,
    poll_interval_ms: 10000,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('checkServiceHealth()', () => {
    describe('Successful Health Checks', () => {
      it('should return HEALTHY for 200 OK response', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: {
            status: 'healthy',
            checks: {
              database: { status: 'healthy' },
            },
            uptime_seconds: 3600,
            version: '1.0.0',
          },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.service_name).toBe('test-service');
        expect(result.status).toBe(HealthStatus.HEALTHY);
        expect(result.uptime_seconds).toBe(3600);
        expect(result.version).toBe('1.0.0');
        expect(result.latency_ms).toBeGreaterThan(0);
        expect(mockedAxios.get).toHaveBeenCalledWith(mockService.health_url, expect.any(Object));
      });

      it('should track metrics on successful check', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: { status: 'healthy' },
        });

        await checkServiceHealth(mockService);

        expect(observability.healthCheckSuccess.inc).toHaveBeenCalledWith({
          service: 'test-service',
        });
        expect(observability.healthCheckDuration.observe).toHaveBeenCalled();
        expect(observability.serviceHealthStatus.set).toHaveBeenCalled();
      });

      it('should parse health data correctly', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: {
            status: 'healthy',
            checks: {
              database: { status: 'healthy', latency_ms: 5 },
              message_queue: { status: 'healthy', latency_ms: 3 },
            },
          },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.checks.database).toBeDefined();
        expect(result.checks.database?.status).toBe('healthy');
        expect(result.checks.message_queue).toBeDefined();
      });
    });

    describe('Degraded Health Status', () => {
      it('should return DEGRADED for status="degraded" response', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: {
            status: 'degraded',
            checks: {
              circuit_breaker: { status: 'open' },
            },
          },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.DEGRADED);
      });

      it('should return DEGRADED for 429 status code', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 429,
          data: { message: 'Rate limited' },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.DEGRADED);
      });

      it('should return DEGRADED when circuit breaker is open', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: {
            status: 'healthy',
            checks: {
              circuit_breaker: { status: 'open', failure_rate: 0.5 },
            },
          },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.DEGRADED);
      });
    });

    describe('Unhealthy Status', () => {
      it('should return UNHEALTHY for 503 status code', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 503,
          data: { status: 'unhealthy' },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
      });

      it('should return UNHEALTHY for 500 status code', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 500,
          data: { error: 'Internal server error' },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
      });

      it('should return UNHEALTHY when database is unhealthy', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: {
            status: 'healthy',
            checks: {
              database: { status: 'unhealthy' },
            },
          },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
      });

      it('should return UNHEALTHY when message queue is unhealthy', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: {
            status: 'healthy',
            checks: {
              message_queue: { status: 'unhealthy' },
            },
          },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
      });
    });

    describe('Error Handling', () => {
      it('should handle connection refused error', async () => {
        const error: any = new Error('Connection refused');
        error.isAxiosError = true;
        error.code = 'ECONNREFUSED';
        mockedAxios.get.mockRejectedValue(error);

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
        expect(result.error).toBe('Connection refused');
        expect(observability.healthCheckFailures.inc).toHaveBeenCalledWith({
          service: 'test-service',
          reason: 'connection_refused',
        });
      });

      it('should handle timeout error', async () => {
        const error: any = new Error('Timeout');
        error.isAxiosError = true;
        error.code = 'ETIMEDOUT';
        mockedAxios.get.mockRejectedValue(error);

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
        expect(observability.healthCheckFailures.inc).toHaveBeenCalledWith({
          service: 'test-service',
          reason: 'timeout',
        });
      });

      it('should handle DNS failure error', async () => {
        const error: any = new Error('DNS failure');
        error.isAxiosError = true;
        error.code = 'ENOTFOUND';
        mockedAxios.get.mockRejectedValue(error);

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
        expect(observability.healthCheckFailures.inc).toHaveBeenCalledWith({
          service: 'test-service',
          reason: 'dns_failure',
        });
      });

      it('should handle unknown errors', async () => {
        const error = new Error('Unknown error');
        mockedAxios.get.mockRejectedValue(error);

        const result = await checkServiceHealth(mockService);

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
        expect(result.error).toBe('Unknown error');
      });

      it('should record error span', async () => {
        const error = new Error('Test error');
        mockedAxios.get.mockRejectedValue(error);

        await checkServiceHealth(mockService);

        expect(observability.setSpanError).toHaveBeenCalled();
      });
    });

    describe('Status Change Detection', () => {
      it('should log status change from HEALTHY to UNHEALTHY', async () => {
        // First check - healthy
        mockedAxios.get.mockResolvedValueOnce({
          status: 200,
          data: { status: 'healthy' },
        });
        await checkServiceHealth(mockService);

        // Second check - unhealthy
        mockedAxios.get.mockRejectedValueOnce(new Error('Connection failed'));
        await checkServiceHealth(mockService);

        expect(observability.logger.warn).toHaveBeenCalledWith(
          expect.objectContaining({
            service: 'test-service',
            previous_status: HealthStatus.HEALTHY,
            new_status: HealthStatus.UNHEALTHY,
          }),
          'Service became unhealthy'
        );
      });

      it('should log status change from UNHEALTHY to HEALTHY', async () => {
        // First check - unhealthy
        mockedAxios.get.mockRejectedValueOnce(new Error('Error'));
        await checkServiceHealth(mockService);

        // Second check - healthy
        mockedAxios.get.mockResolvedValueOnce({
          status: 200,
          data: { status: 'healthy' },
        });
        await checkServiceHealth(mockService);

        expect(observability.logger.info).toHaveBeenCalledWith(
          expect.objectContaining({
            service: 'test-service',
            previous_status: HealthStatus.UNHEALTHY,
            new_status: HealthStatus.HEALTHY,
          }),
          'Service health status changed'
        );
      });
    });

    describe('Latency Tracking', () => {
      it('should track request latency', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: { status: 'healthy' },
        });

        const result = await checkServiceHealth(mockService);

        expect(result.latency_ms).toBeGreaterThan(0);
        expect(result.latency_ms).toBeLessThan(1000); // Reasonable upper bound
      });

      it('should track latency even on failure', async () => {
        mockedAxios.get.mockRejectedValue(new Error('Error'));

        const result = await checkServiceHealth(mockService);

        expect(result.latency_ms).toBeGreaterThan(0);
      });
    });
  });

  describe('Counter Functions', () => {
    beforeEach(() => {
      // Reset counters by checking a service multiple times
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'healthy' },
      });
    });

    describe('getFailureCount()', () => {
      it('should return 0 for service with no failures', () => {
        const count = getFailureCount('new-service');
        expect(count).toBe(0);
      });

      it('should track consecutive failures', async () => {
        mockedAxios.get.mockRejectedValue(new Error('Error'));

        await checkServiceHealth(mockService);
        expect(getFailureCount('test-service')).toBe(1);

        await checkServiceHealth(mockService);
        expect(getFailureCount('test-service')).toBe(2);

        await checkServiceHealth(mockService);
        expect(getFailureCount('test-service')).toBe(3);
      });

      it('should reset failure count on successful check', async () => {
        // 2 failures
        mockedAxios.get.mockRejectedValueOnce(new Error('Error'));
        await checkServiceHealth(mockService);
        mockedAxios.get.mockRejectedValueOnce(new Error('Error'));
        await checkServiceHealth(mockService);

        expect(getFailureCount('test-service')).toBe(2);

        // Success - should reset
        mockedAxios.get.mockResolvedValueOnce({
          status: 200,
          data: { status: 'healthy' },
        });
        await checkServiceHealth(mockService);

        expect(getFailureCount('test-service')).toBe(0);
      });
    });

    describe('getSuccessCount()', () => {
      it('should return 0 for service with no successes', () => {
        const count = getSuccessCount('new-service');
        expect(count).toBe(0);
      });

      it('should track consecutive successes', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: { status: 'healthy' },
        });

        await checkServiceHealth(mockService);
        expect(getSuccessCount('test-service')).toBe(1);

        await checkServiceHealth(mockService);
        expect(getSuccessCount('test-service')).toBe(2);
      });

      it('should reset success count on failure', async () => {
        // 2 successes
        mockedAxios.get.mockResolvedValueOnce({
          status: 200,
          data: { status: 'healthy' },
        });
        await checkServiceHealth(mockService);
        mockedAxios.get.mockResolvedValueOnce({
          status: 200,
          data: { status: 'healthy' },
        });
        await checkServiceHealth(mockService);

        expect(getSuccessCount('test-service')).toBe(2);

        // Failure - should reset
        mockedAxios.get.mockRejectedValueOnce(new Error('Error'));
        await checkServiceHealth(mockService);

        expect(getSuccessCount('test-service')).toBe(0);
      });
    });

    describe('getLastKnownStatus()', () => {
      it('should return undefined for unchecked service', () => {
        const status = getLastKnownStatus('unknown-service');
        expect(status).toBeUndefined();
      });

      it('should track last known status', async () => {
        mockedAxios.get.mockResolvedValue({
          status: 200,
          data: { status: 'healthy' },
        });

        await checkServiceHealth(mockService);

        const status = getLastKnownStatus('test-service');
        expect(status).toBe(HealthStatus.HEALTHY);
      });

      it('should update on status change', async () => {
        // Healthy
        mockedAxios.get.mockResolvedValueOnce({
          status: 200,
          data: { status: 'healthy' },
        });
        await checkServiceHealth(mockService);
        expect(getLastKnownStatus('test-service')).toBe(HealthStatus.HEALTHY);

        // Degraded
        mockedAxios.get.mockResolvedValueOnce({
          status: 200,
          data: { status: 'degraded' },
        });
        await checkServiceHealth(mockService);
        expect(getLastKnownStatus('test-service')).toBe(HealthStatus.DEGRADED);

        // Unhealthy
        mockedAxios.get.mockRejectedValueOnce(new Error('Error'));
        await checkServiceHealth(mockService);
        expect(getLastKnownStatus('test-service')).toBe(HealthStatus.UNHEALTHY);
      });
    });
  });

  describe('Failure Threshold Logic', () => {
    it('should log warning after exceeding failure threshold', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Error'));

      // Trigger 3 failures (default threshold)
      await checkServiceHealth(mockService);
      await checkServiceHealth(mockService);
      await checkServiceHealth(mockService);

      expect(observability.logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          service: 'test-service',
          consecutive_failures: 3,
          threshold: 3,
        }),
        'Service exceeded failure threshold'
      );
    });

    it('should log recovery after success threshold', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'healthy' },
      });

      // Trigger 2 successes (threshold for recovery)
      await checkServiceHealth(mockService);
      await checkServiceHealth(mockService);

      expect(observability.logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({
          service: 'test-service',
          consecutive_successes: 2,
        }),
        'Service recovered'
      );
    });
  });
});
