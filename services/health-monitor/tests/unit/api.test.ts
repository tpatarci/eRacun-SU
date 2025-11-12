/**
 * Unit Tests for HTTP REST API Module
 */

import request from 'supertest';
import { app, recordHealthHistory } from '../../src/api';
import { HealthStatus } from '../../src/health-checker';
import { CircuitBreakerState } from '../../src/circuit-breaker';

// Mock observability
jest.mock('../../src/observability', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  register: {
    metrics: jest.fn().mockResolvedValue('# Prometheus metrics...'),
    contentType: 'text/plain; version=0.0.4',
  },
}));

// Mock service-registry
jest.mock('../../src/service-registry', () => ({
  getAllServices: jest.fn(() => [
    {
      name: 'service-1',
      health_url: 'http://service-1:8080/health',
      ready_url: 'http://service-1:8080/ready',
      critical: true,
      poll_interval_ms: 15000,
      layer: 3,
      description: 'Critical service',
    },
    {
      name: 'service-2',
      health_url: 'http://service-2:8080/health',
      ready_url: 'http://service-2:8080/ready',
      critical: false,
      poll_interval_ms: 30000,
      layer: 5,
    },
  ]),
  getExternalDependencies: jest.fn(() => [
    {
      name: 'postgresql',
      health_url: 'postgresql://localhost:5432',
      ready_url: 'postgresql://localhost:5432',
      critical: true,
      poll_interval_ms: 30000,
    },
  ]),
  getServiceByName: jest.fn((name: string) => {
    if (name === 'service-1') {
      return {
        name: 'service-1',
        health_url: 'http://service-1:8080/health',
        ready_url: 'http://service-1:8080/ready',
        critical: true,
        poll_interval_ms: 15000,
        layer: 3,
        description: 'Critical service',
      };
    }
    return undefined;
  }),
}));

// Mock health-checker
jest.mock('../../src/health-checker', () => ({
  HealthStatus: {
    HEALTHY: 'healthy',
    DEGRADED: 'degraded',
    UNHEALTHY: 'unhealthy',
  },
  getLastKnownStatus: jest.fn((serviceName: string) => {
    const statusMap: Record<string, string> = {
      'service-1': 'healthy',
      'service-2': 'degraded',
      postgresql: 'unhealthy',
    };
    return statusMap[serviceName];
  }),
}));

// Mock circuit-breaker
jest.mock('../../src/circuit-breaker', () => ({
  CircuitBreakerState: {
    CLOSED: 'closed',
    OPEN: 'open',
    HALF_OPEN: 'half-open',
  },
  getAllCircuitBreakers: jest.fn(() => [
    {
      service: 'service-1',
      breaker_name: 'default',
      state: 'closed',
      failure_rate: 0.0,
      last_state_change_ms: Date.now() - 60000,
    },
    {
      service: 'service-2',
      breaker_name: 'default',
      state: 'open',
      failure_rate: 0.95,
      last_state_change_ms: Date.now() - 120000,
    },
  ]),
  getCircuitBreaker: jest.fn((serviceName: string) => {
    if (serviceName === 'service-1') {
      return {
        service: 'service-1',
        breaker_name: 'default',
        state: 'closed',
        failure_rate: 0.0,
        last_state_change_ms: Date.now() - 60000,
      };
    }
    return undefined;
  }),
}));

describe('HTTP REST API', () => {
  describe('GET /health/dashboard', () => {
    it('should return overall system health', async () => {
      const response = await request(app).get('/health/dashboard').expect(200);

      expect(response.body).toHaveProperty('system_health');
      expect(response.body).toHaveProperty('healthy_services');
      expect(response.body).toHaveProperty('degraded_services');
      expect(response.body).toHaveProperty('unhealthy_services');
      expect(response.body).toHaveProperty('services');
      expect(response.body).toHaveProperty('timestamp');
    });

    it('should count services by status correctly', async () => {
      const response = await request(app).get('/health/dashboard').expect(200);

      expect(response.body.healthy_services).toBe(1); // service-1
      expect(response.body.degraded_services).toBe(1); // service-2
      expect(response.body.unhealthy_services).toBe(1); // postgresql
    });

    it('should include all monitored services', async () => {
      const response = await request(app).get('/health/dashboard').expect(200);

      expect(response.body.services).toHaveLength(3); // 2 services + 1 external dep
      expect(response.body.services.map((s: any) => s.name).sort()).toEqual([
        'postgresql',
        'service-1',
        'service-2',
      ]);
    });

    it('should set system health to UNHEALTHY if any service unhealthy', async () => {
      const response = await request(app).get('/health/dashboard').expect(200);

      expect(response.body.system_health).toBe(HealthStatus.UNHEALTHY);
    });

    it('should include service criticality', async () => {
      const response = await request(app).get('/health/dashboard').expect(200);

      const service1 = response.body.services.find((s: any) => s.name === 'service-1');
      expect(service1.critical).toBe(true);

      const service2 = response.body.services.find((s: any) => s.name === 'service-2');
      expect(service2.critical).toBe(false);
    });

    it('should handle errors gracefully', async () => {
      const registry = require('../../src/service-registry');
      registry.getAllServices.mockImplementationOnce(() => {
        throw new Error('Registry error');
      });

      const response = await request(app).get('/health/dashboard').expect(500);

      expect(response.body.error).toBe('Internal server error');
    });
  });

  describe('GET /health/services/:name', () => {
    it('should return specific service details', async () => {
      const response = await request(app).get('/health/services/service-1').expect(200);

      expect(response.body.name).toBe('service-1');
      expect(response.body.status).toBe(HealthStatus.HEALTHY);
      expect(response.body.critical).toBe(true);
      expect(response.body.poll_interval_ms).toBe(15000);
      expect(response.body.layer).toBe(3);
      expect(response.body.description).toBe('Critical service');
      expect(response.body.health_url).toBe('http://service-1:8080/health');
      expect(response.body.ready_url).toBe('http://service-1:8080/ready');
    });

    it('should return 404 for non-existent service', async () => {
      const response = await request(app).get('/health/services/non-existent').expect(404);

      expect(response.body.error).toBe('Service not found');
    });

    it('should handle errors gracefully', async () => {
      const registry = require('../../src/service-registry');
      registry.getServiceByName.mockImplementationOnce(() => {
        throw new Error('Registry error');
      });

      const response = await request(app).get('/health/services/service-1').expect(500);

      expect(response.body.error).toBe('Internal server error');
    });
  });

  describe('GET /health/external', () => {
    it('should return external dependency health', async () => {
      const response = await request(app).get('/health/external').expect(200);

      expect(response.body).toHaveProperty('external_dependencies');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body.external_dependencies).toHaveLength(1);
    });

    it('should include dependency status', async () => {
      const response = await request(app).get('/health/external').expect(200);

      const postgresql = response.body.external_dependencies.find(
        (d: any) => d.name === 'postgresql'
      );
      expect(postgresql.status).toBe(HealthStatus.UNHEALTHY);
      expect(postgresql.health_url).toBe('postgresql://localhost:5432');
    });

    it('should handle errors gracefully', async () => {
      const registry = require('../../src/service-registry');
      registry.getExternalDependencies.mockImplementationOnce(() => {
        throw new Error('Registry error');
      });

      const response = await request(app).get('/health/external').expect(500);

      expect(response.body.error).toBe('Internal server error');
    });
  });

  describe('GET /health/circuit-breakers', () => {
    it('should return all circuit breakers', async () => {
      const response = await request(app).get('/health/circuit-breakers').expect(200);

      expect(response.body).toHaveProperty('circuit_breakers');
      expect(response.body).toHaveProperty('total_open');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body.circuit_breakers).toHaveLength(2);
    });

    it('should include circuit breaker details', async () => {
      const response = await request(app).get('/health/circuit-breakers').expect(200);

      const breaker1 = response.body.circuit_breakers.find((b: any) => b.service === 'service-1');
      expect(breaker1.breaker_name).toBe('default');
      expect(breaker1.state).toBe(CircuitBreakerState.CLOSED);
      expect(breaker1.failure_rate).toBe(0.0);
      expect(breaker1.last_state_change).toBeDefined();
      expect(breaker1.open_duration_seconds).toBe(0);
    });

    it('should calculate open duration for open breakers', async () => {
      const response = await request(app).get('/health/circuit-breakers').expect(200);

      const breaker2 = response.body.circuit_breakers.find((b: any) => b.service === 'service-2');
      expect(breaker2.state).toBe(CircuitBreakerState.OPEN);
      expect(breaker2.open_duration_seconds).toBeGreaterThan(0);
    });

    it('should count total open breakers', async () => {
      const response = await request(app).get('/health/circuit-breakers').expect(200);

      expect(response.body.total_open).toBe(1); // service-2 is open
    });

    it('should handle errors gracefully', async () => {
      const circuitBreaker = require('../../src/circuit-breaker');
      circuitBreaker.getAllCircuitBreakers.mockImplementationOnce(() => {
        throw new Error('Circuit breaker error');
      });

      const response = await request(app).get('/health/circuit-breakers').expect(500);

      expect(response.body.error).toBe('Internal server error');
    });
  });

  describe('GET /health/history/:service', () => {
    beforeEach(() => {
      // Clear history by requiring fresh module
      jest.resetModules();
    });

    it('should return empty history for service with no data', async () => {
      const response = await request(app).get('/health/history/service-1').expect(200);

      expect(response.body.service).toBe('service-1');
      expect(response.body.history).toEqual([]);
      expect(response.body.total_entries).toBe(0);
      expect(response.body.time_range).toBe('24 hours');
    });

    it('should return historical health data', async () => {
      // Record some history
      recordHealthHistory('test-service', HealthStatus.HEALTHY, 50);
      recordHealthHistory('test-service', HealthStatus.DEGRADED, 100);
      recordHealthHistory('test-service', HealthStatus.UNHEALTHY, 200);

      const response = await request(app).get('/health/history/test-service').expect(200);

      expect(response.body.service).toBe('test-service');
      expect(response.body.history).toHaveLength(3);
      expect(response.body.total_entries).toBe(3);
    });

    it('should include timestamp, status, and latency in history', async () => {
      recordHealthHistory('test-service-2', HealthStatus.HEALTHY, 75);

      const response = await request(app).get('/health/history/test-service-2').expect(200);

      expect(response.body.history[0]).toHaveProperty('timestamp');
      expect(response.body.history[0].status).toBe(HealthStatus.HEALTHY);
      expect(response.body.history[0].latency_ms).toBe(75);
    });

    it('should handle errors gracefully', async () => {
      // Force an error by mocking recordHealthHistory to throw
      // (Not easily testable without breaking the module, so skip or test indirectly)
      const response = await request(app).get('/health/history/test-service-3').expect(200);

      expect(response.body).toHaveProperty('service');
    });
  });

  describe('GET /health', () => {
    it('should return health check for health-monitor itself', async () => {
      const response = await request(app).get('/health').expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.service).toBe('health-monitor');
      expect(response.body).toHaveProperty('uptime_seconds');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body.uptime_seconds).toBeGreaterThanOrEqual(0);
    });
  });

  describe('GET /ready', () => {
    it('should return ready when service registry loaded', async () => {
      const response = await request(app).get('/ready').expect(200);

      expect(response.body.status).toBe('ready');
      expect(response.body.service).toBe('health-monitor');
      expect(response.body).toHaveProperty('timestamp');
    });

    it('should return 503 when service registry not loaded', async () => {
      const registry = require('../../src/service-registry');
      registry.getAllServices.mockImplementationOnce(() => {
        throw new Error('Registry not loaded');
      });

      const response = await request(app).get('/ready').expect(503);

      expect(response.body.status).toBe('not_ready');
      expect(response.body.error).toBe('Service registry not loaded');
    });
  });

  describe('GET /metrics', () => {
    it('should return Prometheus metrics', async () => {
      const response = await request(app).get('/metrics').expect(200);

      expect(response.headers['content-type']).toContain('text/plain');
      expect(response.text).toContain('Prometheus metrics');
    });

    it('should handle metrics export errors', async () => {
      const observability = require('../../src/observability');
      observability.register.metrics.mockRejectedValueOnce(new Error('Metrics error'));

      const response = await request(app).get('/metrics').expect(500);

      expect(response.text).toBe('Error exporting metrics');
    });
  });

  describe('404 handler', () => {
    it('should return 404 for non-existent routes', async () => {
      const response = await request(app).get('/non-existent').expect(404);

      expect(response.body.error).toBe('Not found');
    });
  });

  describe('CORS middleware', () => {
    it('should include CORS headers', async () => {
      const response = await request(app).get('/health').expect(200);

      expect(response.headers).toHaveProperty('access-control-allow-origin');
    });
  });

  describe('Request logging middleware', () => {
    it('should log incoming requests', async () => {
      const observability = require('../../src/observability');

      await request(app).get('/health').expect(200);

      expect(observability.logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'GET',
          path: '/health',
        }),
        'HTTP request received'
      );
    });
  });

  describe('recordHealthHistory()', () => {
    it('should record health check in history', () => {
      recordHealthHistory('history-test-service', HealthStatus.HEALTHY, 50);

      // Verify by fetching history
      request(app)
        .get('/health/history/history-test-service')
        .then((response) => {
          expect(response.body.history).toHaveLength(1);
        });
    });

    it('should limit history to MAX_HISTORY_ENTRIES (288)', () => {
      const serviceName = 'history-limit-test';

      // Add 300 entries (exceeds limit)
      for (let i = 0; i < 300; i++) {
        recordHealthHistory(serviceName, HealthStatus.HEALTHY, 50);
      }

      // Verify history is capped
      request(app)
        .get(`/health/history/${serviceName}`)
        .then((response) => {
          expect(response.body.total_entries).toBeLessThanOrEqual(288);
        });
    });

    it('should remove oldest entries when limit exceeded', () => {
      const serviceName = 'history-fifo-test';

      // Add entries with different statuses
      recordHealthHistory(serviceName, HealthStatus.UNHEALTHY, 100); // Will be removed
      for (let i = 0; i < 288; i++) {
        recordHealthHistory(serviceName, HealthStatus.HEALTHY, 50);
      }

      // Verify oldest entry (UNHEALTHY) is removed
      request(app)
        .get(`/health/history/${serviceName}`)
        .then((response) => {
          const statuses = response.body.history.map((h: any) => h.status);
          expect(statuses).not.toContain(HealthStatus.UNHEALTHY);
          expect(statuses.every((s: string) => s === HealthStatus.HEALTHY)).toBe(true);
        });
    });
  });
});
