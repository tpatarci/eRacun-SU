/**
 * Unit Tests for Circuit Breaker Module
 */

import {
  CircuitBreakerState,
  CircuitBreakerInfo,
  monitorCircuitBreakers,
  getAllCircuitBreakers,
  getOpenCircuitBreakers,
  getCircuitBreaker,
  requiresP0Alert,
  requiresP1Alert,
  getCircuitBreakersRequiringAlerts,
  resetCircuitBreakers,
} from '../../src/circuit-breaker';
import { HealthCheckResult, HealthStatus } from '../../src/health-checker';

// Mock observability module
jest.mock('../../src/observability', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  circuitBreakerState: {
    set: jest.fn(),
  },
  circuitBreakerStateToMetric: jest.fn((state: string) => {
    switch (state) {
      case CircuitBreakerState.CLOSED:
        return 0;
      case CircuitBreakerState.HALF_OPEN:
        return 0.5;
      case CircuitBreakerState.OPEN:
        return 1;
      default:
        return 0;
    }
  }),
}));

describe('Circuit Breaker Module', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetCircuitBreakers();
  });

  describe('monitorCircuitBreakers()', () => {
    it('should extract circuit breaker from health result', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
        checks: {
          circuit_breaker: {
            status: 'closed',
            failure_rate: 0.0,
          },
        },
      };

      const breakers = monitorCircuitBreakers(healthResult);

      expect(breakers).toHaveLength(1);
      expect(breakers[0].service).toBe('test-service');
      expect(breakers[0].breaker_name).toBe('default');
      expect(breakers[0].state).toBe(CircuitBreakerState.CLOSED);
      expect(breakers[0].failure_rate).toBe(0.0);
    });

    it('should return empty array if no circuit breaker data', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
        checks: {},
      };

      const breakers = monitorCircuitBreakers(healthResult);

      expect(breakers).toHaveLength(0);
    });

    it('should track circuit breaker state changes', () => {
      const observability = require('../../src/observability');
      const timestamp1 = Date.now();
      const timestamp2 = timestamp1 + 10000;

      // First call - CLOSED
      const healthResult1: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp1,
        latency_ms: 50,
        checks: {
          circuit_breaker: {
            status: 'closed',
            failure_rate: 0.0,
          },
        },
      };

      monitorCircuitBreakers(healthResult1);

      // Second call - OPEN (state change)
      const healthResult2: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.DEGRADED,
        timestamp_ms: timestamp2,
        latency_ms: 100,
        checks: {
          circuit_breaker: {
            status: 'open',
            failure_rate: 0.8,
          },
        },
      };

      monitorCircuitBreakers(healthResult2);

      expect(observability.logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          service: 'test-service',
          previous_state: CircuitBreakerState.CLOSED,
          new_state: CircuitBreakerState.OPEN,
        }),
        'Circuit breaker state changed'
      );
    });

    it('should update last_state_change_ms on state change', () => {
      const timestamp1 = Date.now();
      const timestamp2 = timestamp1 + 10000;

      // First call - CLOSED
      const healthResult1: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp1,
        latency_ms: 50,
        checks: {
          circuit_breaker: {
            status: 'closed',
          },
        },
      };

      monitorCircuitBreakers(healthResult1);
      const breaker1 = getCircuitBreaker('test-service');
      expect(breaker1?.last_state_change_ms).toBe(timestamp1);

      // Second call - OPEN (state change)
      const healthResult2: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.DEGRADED,
        timestamp_ms: timestamp2,
        latency_ms: 100,
        checks: {
          circuit_breaker: {
            status: 'open',
          },
        },
      };

      monitorCircuitBreakers(healthResult2);
      const breaker2 = getCircuitBreaker('test-service');
      expect(breaker2?.last_state_change_ms).toBe(timestamp2);
    });

    it('should preserve last_state_change_ms when state unchanged', () => {
      const timestamp1 = Date.now();
      const timestamp2 = timestamp1 + 10000;

      // First call - CLOSED
      const healthResult1: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp1,
        latency_ms: 50,
        checks: {
          circuit_breaker: {
            status: 'closed',
          },
        },
      };

      monitorCircuitBreakers(healthResult1);

      // Second call - Still CLOSED (no state change)
      const healthResult2: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp2,
        latency_ms: 45,
        checks: {
          circuit_breaker: {
            status: 'closed',
          },
        },
      };

      monitorCircuitBreakers(healthResult2);
      const breaker = getCircuitBreaker('test-service');
      expect(breaker?.last_state_change_ms).toBe(timestamp1); // Original timestamp
    });

    it('should update Prometheus metric', () => {
      const observability = require('../../src/observability');
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
        checks: {
          circuit_breaker: {
            status: 'closed',
          },
        },
      };

      monitorCircuitBreakers(healthResult);

      expect(observability.circuitBreakerState.set).toHaveBeenCalledWith(
        { service: 'test-service', breaker: 'default' },
        0 // CLOSED = 0
      );
    });

    it('should handle all circuit breaker states', () => {
      const states = [
        { input: 'closed', expected: CircuitBreakerState.CLOSED },
        { input: 'open', expected: CircuitBreakerState.OPEN },
        { input: 'half-open', expected: CircuitBreakerState.HALF_OPEN },
        { input: 'CLOSED', expected: CircuitBreakerState.CLOSED },
        { input: 'OPEN', expected: CircuitBreakerState.OPEN },
        { input: 'HALF_OPEN', expected: CircuitBreakerState.HALF_OPEN },
        { input: 'halfopen', expected: CircuitBreakerState.HALF_OPEN },
      ];

      states.forEach(({ input, expected }) => {
        resetCircuitBreakers();

        const healthResult: HealthCheckResult = {
          service_name: 'test-service',
          status: HealthStatus.HEALTHY,
          timestamp_ms: Date.now(),
          latency_ms: 50,
          checks: {
            circuit_breaker: {
              status: input,
            },
          },
        };

        const breakers = monitorCircuitBreakers(healthResult);
        expect(breakers[0].state).toBe(expected);
      });
    });

    it('should default to closed for unknown state', () => {
      const observability = require('../../src/observability');
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
        checks: {
          circuit_breaker: {
            status: 'unknown_state',
          },
        },
      };

      const breakers = monitorCircuitBreakers(healthResult);

      expect(breakers[0].state).toBe(CircuitBreakerState.CLOSED);
      expect(observability.logger.warn).toHaveBeenCalledWith(
        { state: 'unknown_state' },
        'Unknown circuit breaker state, defaulting to closed'
      );
    });

    it('should handle missing status field', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
        checks: {
          circuit_breaker: {
            status: '', // Empty status field
          },
        },
      };

      const breakers = monitorCircuitBreakers(healthResult);

      expect(breakers[0].state).toBe(CircuitBreakerState.CLOSED);
    });
  });

  describe('getAllCircuitBreakers()', () => {
    it('should return all tracked circuit breakers', () => {
      const timestamp = Date.now();

      // Add multiple circuit breakers
      monitorCircuitBreakers({
        service_name: 'service-1',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp,
        latency_ms: 50,
        checks: {
          circuit_breaker: { status: 'closed' },
        },
      });

      monitorCircuitBreakers({
        service_name: 'service-2',
        status: HealthStatus.DEGRADED,
        timestamp_ms: timestamp,
        latency_ms: 100,
        checks: {
          circuit_breaker: { status: 'open' },
        },
      });

      const allBreakers = getAllCircuitBreakers();

      expect(allBreakers).toHaveLength(2);
      expect(allBreakers.map((b) => b.service)).toEqual(['service-1', 'service-2']);
    });

    it('should return empty array when no breakers tracked', () => {
      const allBreakers = getAllCircuitBreakers();
      expect(allBreakers).toHaveLength(0);
    });
  });

  describe('getOpenCircuitBreakers()', () => {
    it('should return only open circuit breakers', () => {
      const timestamp = Date.now();

      // Add multiple circuit breakers with different states
      monitorCircuitBreakers({
        service_name: 'service-1',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp,
        latency_ms: 50,
        checks: {
          circuit_breaker: { status: 'closed' },
        },
      });

      monitorCircuitBreakers({
        service_name: 'service-2',
        status: HealthStatus.DEGRADED,
        timestamp_ms: timestamp,
        latency_ms: 100,
        checks: {
          circuit_breaker: { status: 'open' },
        },
      });

      monitorCircuitBreakers({
        service_name: 'service-3',
        status: HealthStatus.DEGRADED,
        timestamp_ms: timestamp,
        latency_ms: 80,
        checks: {
          circuit_breaker: { status: 'half-open' },
        },
      });

      monitorCircuitBreakers({
        service_name: 'service-4',
        status: HealthStatus.UNHEALTHY,
        timestamp_ms: timestamp,
        latency_ms: 200,
        checks: {
          circuit_breaker: { status: 'open' },
        },
      });

      const openBreakers = getOpenCircuitBreakers();

      expect(openBreakers).toHaveLength(2);
      expect(openBreakers.map((b) => b.service).sort()).toEqual(['service-2', 'service-4']);
      expect(openBreakers.every((b) => b.state === CircuitBreakerState.OPEN)).toBe(true);
    });

    it('should return empty array when no open breakers', () => {
      const timestamp = Date.now();

      monitorCircuitBreakers({
        service_name: 'service-1',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp,
        latency_ms: 50,
        checks: {
          circuit_breaker: { status: 'closed' },
        },
      });

      const openBreakers = getOpenCircuitBreakers();
      expect(openBreakers).toHaveLength(0);
    });
  });

  describe('getCircuitBreaker()', () => {
    it('should get circuit breaker by service name', () => {
      const timestamp = Date.now();

      monitorCircuitBreakers({
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp,
        latency_ms: 50,
        checks: {
          circuit_breaker: { status: 'closed', failure_rate: 0.05 },
        },
      });

      const breaker = getCircuitBreaker('test-service');

      expect(breaker).toBeDefined();
      expect(breaker?.service).toBe('test-service');
      expect(breaker?.breaker_name).toBe('default');
      expect(breaker?.state).toBe(CircuitBreakerState.CLOSED);
      expect(breaker?.failure_rate).toBe(0.05);
    });

    it('should return undefined for non-existent service', () => {
      const breaker = getCircuitBreaker('non-existent-service');
      expect(breaker).toBeUndefined();
    });

    it('should support custom breaker name', () => {
      // Note: Current implementation only uses 'default', but tests the parameter
      const breaker = getCircuitBreaker('test-service', 'custom-breaker');
      expect(breaker).toBeUndefined(); // Won't exist since only 'default' is used
    });
  });

  describe('requiresP0Alert()', () => {
    it('should return true for circuit open >5 minutes', () => {
      const sixMinutesAgo = Date.now() - 6 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.OPEN,
        last_state_change_ms: sixMinutesAgo,
      };

      expect(requiresP0Alert(breaker)).toBe(true);
    });

    it('should return false for circuit open <5 minutes', () => {
      const fourMinutesAgo = Date.now() - 4 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.OPEN,
        last_state_change_ms: fourMinutesAgo,
      };

      expect(requiresP0Alert(breaker)).toBe(false);
    });

    it('should return false for closed circuit', () => {
      const sixMinutesAgo = Date.now() - 6 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.CLOSED,
        last_state_change_ms: sixMinutesAgo,
      };

      expect(requiresP0Alert(breaker)).toBe(false);
    });

    it('should return false for half-open circuit', () => {
      const sixMinutesAgo = Date.now() - 6 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.HALF_OPEN,
        last_state_change_ms: sixMinutesAgo,
      };

      expect(requiresP0Alert(breaker)).toBe(false);
    });
  });

  describe('requiresP1Alert()', () => {
    it('should return true for circuit just opened (<1 minute)', () => {
      const thirtySecondsAgo = Date.now() - 30 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.OPEN,
        last_state_change_ms: thirtySecondsAgo,
      };

      expect(requiresP1Alert(breaker)).toBe(true);
    });

    it('should return false for circuit open >1 minute', () => {
      const twoMinutesAgo = Date.now() - 2 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.OPEN,
        last_state_change_ms: twoMinutesAgo,
      };

      expect(requiresP1Alert(breaker)).toBe(false);
    });

    it('should return false for closed circuit', () => {
      const thirtySecondsAgo = Date.now() - 30 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.CLOSED,
        last_state_change_ms: thirtySecondsAgo,
      };

      expect(requiresP1Alert(breaker)).toBe(false);
    });

    it('should return false for half-open circuit', () => {
      const thirtySecondsAgo = Date.now() - 30 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.HALF_OPEN,
        last_state_change_ms: thirtySecondsAgo,
      };

      expect(requiresP1Alert(breaker)).toBe(false);
    });
  });

  describe('getCircuitBreakersRequiringAlerts()', () => {
    it('should categorize breakers into P0 and P1 alerts', () => {
      const now = Date.now();
      const timestamp = now;

      // Add breaker that requires P1 alert (just opened)
      monitorCircuitBreakers({
        service_name: 'service-p1',
        status: HealthStatus.DEGRADED,
        timestamp_ms: timestamp,
        latency_ms: 100,
        checks: {
          circuit_breaker: { status: 'open' },
        },
      });

      // Add breaker that requires P0 alert (open >5 minutes)
      // Need to manually set to simulate old timestamp
      const sixMinutesAgo = now - 6 * 60 * 1000;
      monitorCircuitBreakers({
        service_name: 'service-p0',
        status: HealthStatus.UNHEALTHY,
        timestamp_ms: sixMinutesAgo,
        latency_ms: 200,
        checks: {
          circuit_breaker: { status: 'open' },
        },
      });

      // Manually adjust timestamp for P0 breaker (simulate old open)
      const p0Breaker = getCircuitBreaker('service-p0');
      if (p0Breaker) {
        p0Breaker.last_state_change_ms = sixMinutesAgo;
      }

      const alerts = getCircuitBreakersRequiringAlerts();

      expect(alerts.p1_alerts).toHaveLength(1);
      expect(alerts.p1_alerts[0].service).toBe('service-p1');

      expect(alerts.p0_alerts).toHaveLength(1);
      expect(alerts.p0_alerts[0].service).toBe('service-p0');
    });

    it('should return empty arrays when no alerts required', () => {
      const timestamp = Date.now();

      // Add closed breaker
      monitorCircuitBreakers({
        service_name: 'service-1',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp,
        latency_ms: 50,
        checks: {
          circuit_breaker: { status: 'closed' },
        },
      });

      const alerts = getCircuitBreakersRequiringAlerts();

      expect(alerts.p0_alerts).toHaveLength(0);
      expect(alerts.p1_alerts).toHaveLength(0);
    });
  });

  describe('resetCircuitBreakers()', () => {
    it('should clear all tracked circuit breakers', () => {
      const timestamp = Date.now();

      // Add circuit breakers
      monitorCircuitBreakers({
        service_name: 'service-1',
        status: HealthStatus.HEALTHY,
        timestamp_ms: timestamp,
        latency_ms: 50,
        checks: {
          circuit_breaker: { status: 'closed' },
        },
      });

      monitorCircuitBreakers({
        service_name: 'service-2',
        status: HealthStatus.DEGRADED,
        timestamp_ms: timestamp,
        latency_ms: 100,
        checks: {
          circuit_breaker: { status: 'open' },
        },
      });

      expect(getAllCircuitBreakers()).toHaveLength(2);

      resetCircuitBreakers();

      expect(getAllCircuitBreakers()).toHaveLength(0);
      expect(getCircuitBreaker('service-1')).toBeUndefined();
      expect(getCircuitBreaker('service-2')).toBeUndefined();
    });
  });
});
