/**
 * Unit Tests for Alerting Module
 */

import axios from 'axios';
import { Kafka, Producer } from 'kafkajs';
import {
  AlertSeverity,
  Alert,
  publishHealthEvent,
  sendAlert,
  checkHealthAlert,
  checkCircuitBreakerAlert,
  disconnectKafka,
} from '../../src/alerting';
import { HealthStatus, HealthCheckResult } from '../../src/health-checker';
import { CircuitBreakerState, CircuitBreakerInfo } from '../../src/circuit-breaker';
import { Service } from '../../src/service-registry';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock kafkajs
jest.mock('kafkajs');
const MockedKafka = Kafka as jest.MockedClass<typeof Kafka>;

// Mock observability
jest.mock('../../src/observability', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  createSpan: jest.fn(() => ({
    end: jest.fn(),
    setAttribute: jest.fn(),
  })),
  setSpanError: jest.fn(),
}));

describe('Alerting Module', () => {
  let mockProducer: jest.Mocked<Producer>;

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup Kafka mock
    mockProducer = {
      connect: jest.fn().mockResolvedValue(undefined),
      send: jest.fn().mockResolvedValue(undefined),
      disconnect: jest.fn().mockResolvedValue(undefined),
    } as any;

    MockedKafka.mockImplementation(() => ({
      producer: jest.fn().mockReturnValue(mockProducer),
    } as any));
  });

  describe('publishHealthEvent()', () => {
    it('should publish health event to Kafka', async () => {
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
        checks: {
          database: { status: 'healthy' },
        },
      };

      await publishHealthEvent(healthResult);

      expect(mockProducer.connect).toHaveBeenCalled();
      expect(mockProducer.send).toHaveBeenCalledWith({
        topic: 'system-health',
        messages: [
          {
            key: 'test-service',
            value: expect.stringContaining('test-service'),
          },
        ],
      });
    });

    it('should include health check metadata in event', async () => {
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.DEGRADED,
        timestamp_ms: Date.now(),
        latency_ms: 150,
        checks: {
          database: { status: 'healthy' },
          cache: { status: 'degraded' },
        },
      };

      await publishHealthEvent(healthResult);

      const sendCall = mockProducer.send.mock.calls[0][0];
      const messageValue = JSON.parse(sendCall.messages[0].value);

      expect(messageValue.service_name).toBe('test-service');
      expect(messageValue.status).toBe(HealthStatus.DEGRADED);
      expect(messageValue.metadata.latency_ms).toBe(150);
      expect(messageValue.metadata.checks).toEqual(healthResult.checks);
    });

    it('should include error message in event', async () => {
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.UNHEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 200,
        error: 'Connection refused',
      };

      await publishHealthEvent(healthResult);

      const sendCall = mockProducer.send.mock.calls[0][0];
      const messageValue = JSON.parse(sendCall.messages[0].value);

      expect(messageValue.reason).toBe('Connection refused');
    });

    it('should use default reason if no error', async () => {
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
      };

      await publishHealthEvent(healthResult);

      const sendCall = mockProducer.send.mock.calls[0][0];
      const messageValue = JSON.parse(sendCall.messages[0].value);

      expect(messageValue.reason).toBe('Health check completed');
    });

    it('should handle Kafka publish errors', async () => {
      const observability = require('../../src/observability');
      mockProducer.send.mockRejectedValue(new Error('Kafka unavailable'));

      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
      };

      await publishHealthEvent(healthResult);

      expect(observability.logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          err: expect.any(Error),
          service: 'test-service',
        }),
        'Failed to publish health event to Kafka'
      );
    });

    it('should reuse existing Kafka producer', async () => {
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
      };

      // First call
      await publishHealthEvent(healthResult);
      expect(mockProducer.connect).toHaveBeenCalledTimes(1);

      // Second call - should reuse producer
      await publishHealthEvent(healthResult);
      expect(mockProducer.connect).toHaveBeenCalledTimes(1);
    });

    it('should create and end span for tracing', async () => {
      const observability = require('../../src/observability');
      const mockSpan = { end: jest.fn(), setAttribute: jest.fn() };
      observability.createSpan.mockReturnValue(mockSpan);

      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
      };

      await publishHealthEvent(healthResult);

      expect(observability.createSpan).toHaveBeenCalledWith('publish_health_event', {
        'service.name': 'test-service',
        'health.status': HealthStatus.HEALTHY,
      });
      expect(mockSpan.end).toHaveBeenCalled();
    });
  });

  describe('sendAlert()', () => {
    it('should send alert to notification service', async () => {
      mockedAxios.post.mockResolvedValue({ status: 200, data: {} });

      const alert: Alert = {
        severity: AlertSeverity.P0,
        service: 'test-service',
        message: 'CRITICAL: test-service is UNHEALTHY',
        timestamp_ms: Date.now(),
        metadata: { error: 'Connection refused' },
      };

      await sendAlert(alert);

      expect(mockedAxios.post).toHaveBeenCalledWith(
        'http://notification-service:8080/notifications',
        expect.objectContaining({
          severity: AlertSeverity.P0,
          service: 'test-service',
          message: 'CRITICAL: test-service is UNHEALTHY',
        }),
        { timeout: 5000 }
      );
    });

    it('should convert timestamp to ISO string', async () => {
      mockedAxios.post.mockResolvedValue({ status: 200, data: {} });

      const timestamp = Date.now();
      const alert: Alert = {
        severity: AlertSeverity.P1,
        service: 'test-service',
        message: 'WARNING: test-service is DEGRADED',
        timestamp_ms: timestamp,
      };

      await sendAlert(alert);

      const postCall = mockedAxios.post.mock.calls[0][1];
      expect(postCall.timestamp).toBe(new Date(timestamp).toISOString());
    });

    it('should include metadata in alert', async () => {
      mockedAxios.post.mockResolvedValue({ status: 200, data: {} });

      const alert: Alert = {
        severity: AlertSeverity.P0,
        service: 'test-service',
        message: 'CRITICAL alert',
        timestamp_ms: Date.now(),
        metadata: {
          error: 'Database connection failed',
          latency_ms: 5000,
        },
      };

      await sendAlert(alert);

      const postCall = mockedAxios.post.mock.calls[0][1];
      expect(postCall.metadata).toEqual(alert.metadata);
    });

    it('should handle notification service errors', async () => {
      const observability = require('../../src/observability');
      mockedAxios.post.mockRejectedValue(new Error('Service unavailable'));

      const alert: Alert = {
        severity: AlertSeverity.P0,
        service: 'test-service',
        message: 'CRITICAL alert',
        timestamp_ms: Date.now(),
      };

      await sendAlert(alert);

      expect(observability.logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          err: expect.any(Error),
          alert,
        }),
        'Failed to send alert to notification service'
      );
    });

    it('should create and end span for tracing', async () => {
      const observability = require('../../src/observability');
      const mockSpan = { end: jest.fn(), setAttribute: jest.fn() };
      observability.createSpan.mockReturnValue(mockSpan);
      mockedAxios.post.mockResolvedValue({ status: 200, data: {} });

      const alert: Alert = {
        severity: AlertSeverity.P0,
        service: 'test-service',
        message: 'CRITICAL alert',
        timestamp_ms: Date.now(),
      };

      await sendAlert(alert);

      expect(observability.createSpan).toHaveBeenCalledWith('send_alert', {
        'alert.severity': AlertSeverity.P0,
        'alert.service': 'test-service',
      });
      expect(mockSpan.end).toHaveBeenCalled();
    });
  });

  describe('checkHealthAlert()', () => {
    const criticalService: Service = {
      name: 'critical-service',
      health_url: 'http://critical-service:8080/health',
      ready_url: 'http://critical-service:8080/ready',
      critical: true,
      poll_interval_ms: 15000,
    };

    const nonCriticalService: Service = {
      name: 'non-critical-service',
      health_url: 'http://non-critical-service:8080/health',
      ready_url: 'http://non-critical-service:8080/ready',
      critical: false,
      poll_interval_ms: 30000,
    };

    it('should return null if status unchanged', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'critical-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
      };

      const alert = checkHealthAlert(criticalService, healthResult, HealthStatus.HEALTHY);

      expect(alert).toBeNull();
    });

    it('should return P0 alert for critical service becoming unhealthy', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'critical-service',
        status: HealthStatus.UNHEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 200,
        error: 'Connection refused',
      };

      const alert = checkHealthAlert(criticalService, healthResult, HealthStatus.HEALTHY);

      expect(alert).not.toBeNull();
      expect(alert?.severity).toBe(AlertSeverity.P0);
      expect(alert?.service).toBe('critical-service');
      expect(alert?.message).toContain('CRITICAL');
      expect(alert?.message).toContain('UNHEALTHY');
      expect(alert?.metadata?.error).toBe('Connection refused');
    });

    it('should return P1 alert for critical service becoming degraded', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'critical-service',
        status: HealthStatus.DEGRADED,
        timestamp_ms: Date.now(),
        latency_ms: 150,
      };

      const alert = checkHealthAlert(criticalService, healthResult, HealthStatus.HEALTHY);

      expect(alert).not.toBeNull();
      expect(alert?.severity).toBe(AlertSeverity.P1);
      expect(alert?.service).toBe('critical-service');
      expect(alert?.message).toContain('WARNING');
      expect(alert?.message).toContain('DEGRADED');
    });

    it('should return P2 alert for non-critical service becoming unhealthy', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'non-critical-service',
        status: HealthStatus.UNHEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 200,
        error: 'Timeout',
      };

      const alert = checkHealthAlert(nonCriticalService, healthResult, HealthStatus.HEALTHY);

      expect(alert).not.toBeNull();
      expect(alert?.severity).toBe(AlertSeverity.P2);
      expect(alert?.service).toBe('non-critical-service');
      expect(alert?.message).toContain('Non-critical service affected');
    });

    it('should return null for non-critical service becoming degraded', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'non-critical-service',
        status: HealthStatus.DEGRADED,
        timestamp_ms: Date.now(),
        latency_ms: 150,
      };

      const alert = checkHealthAlert(nonCriticalService, healthResult, HealthStatus.HEALTHY);

      expect(alert).toBeNull();
    });

    it('should return null when status changes to healthy', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'critical-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
      };

      const alert = checkHealthAlert(criticalService, healthResult, HealthStatus.UNHEALTHY);

      expect(alert).toBeNull();
    });

    it('should include previous status in alert metadata', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'critical-service',
        status: HealthStatus.UNHEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 200,
      };

      const alert = checkHealthAlert(criticalService, healthResult, HealthStatus.DEGRADED);

      expect(alert?.metadata?.previous_status).toBe(HealthStatus.DEGRADED);
      expect(alert?.metadata?.current_status).toBe(HealthStatus.UNHEALTHY);
    });

    it('should handle undefined previous status', () => {
      const healthResult: HealthCheckResult = {
        service_name: 'critical-service',
        status: HealthStatus.UNHEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 200,
      };

      const alert = checkHealthAlert(criticalService, healthResult, undefined);

      expect(alert).not.toBeNull();
      expect(alert?.severity).toBe(AlertSeverity.P0);
      expect(alert?.metadata?.previous_status).toBeUndefined();
    });
  });

  describe('checkCircuitBreakerAlert()', () => {
    it('should return P0 alert for circuit open >5 minutes', () => {
      const sixMinutesAgo = Date.now() - 6 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.OPEN,
        failure_rate: 0.95,
        last_state_change_ms: sixMinutesAgo,
      };

      const alert = checkCircuitBreakerAlert(breaker);

      expect(alert).not.toBeNull();
      expect(alert?.severity).toBe(AlertSeverity.P0);
      expect(alert?.service).toBe('test-service');
      expect(alert?.message).toContain('CRITICAL');
      expect(alert?.message).toContain('6 minutes');
      expect(alert?.metadata?.open_duration_ms).toBeGreaterThan(5 * 60 * 1000);
    });

    it('should return P1 alert for circuit just opened (<1 minute)', () => {
      const thirtySecondsAgo = Date.now() - 30 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.OPEN,
        failure_rate: 0.8,
        last_state_change_ms: thirtySecondsAgo,
      };

      const alert = checkCircuitBreakerAlert(breaker);

      expect(alert).not.toBeNull();
      expect(alert?.severity).toBe(AlertSeverity.P1);
      expect(alert?.service).toBe('test-service');
      expect(alert?.message).toContain('WARNING');
      expect(alert?.message).toContain('now OPEN');
    });

    it('should return null for circuit open between 1-5 minutes', () => {
      const threeMinutesAgo = Date.now() - 3 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.OPEN,
        failure_rate: 0.8,
        last_state_change_ms: threeMinutesAgo,
      };

      const alert = checkCircuitBreakerAlert(breaker);

      expect(alert).toBeNull();
    });

    it('should return null for closed circuit', () => {
      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.CLOSED,
        failure_rate: 0.0,
        last_state_change_ms: Date.now(),
      };

      const alert = checkCircuitBreakerAlert(breaker);

      expect(alert).toBeNull();
    });

    it('should return null for half-open circuit', () => {
      const sixMinutesAgo = Date.now() - 6 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'default',
        state: CircuitBreakerState.HALF_OPEN,
        failure_rate: 0.5,
        last_state_change_ms: sixMinutesAgo,
      };

      const alert = checkCircuitBreakerAlert(breaker);

      expect(alert).toBeNull();
    });

    it('should include breaker metadata in alert', () => {
      const sixMinutesAgo = Date.now() - 6 * 60 * 1000;

      const breaker: CircuitBreakerInfo = {
        service: 'test-service',
        breaker_name: 'custom-breaker',
        state: CircuitBreakerState.OPEN,
        failure_rate: 0.95,
        last_state_change_ms: sixMinutesAgo,
      };

      const alert = checkCircuitBreakerAlert(breaker);

      expect(alert?.metadata?.breaker_name).toBe('custom-breaker');
      expect(alert?.metadata?.state).toBe(CircuitBreakerState.OPEN);
      expect(alert?.metadata?.failure_rate).toBe(0.95);
    });
  });

  describe('disconnectKafka()', () => {
    it('should disconnect Kafka producer', async () => {
      // First establish connection
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
      };

      await publishHealthEvent(healthResult);

      // Then disconnect
      await disconnectKafka();

      expect(mockProducer.disconnect).toHaveBeenCalled();
    });

    it('should handle disconnect when producer not initialized', async () => {
      await expect(disconnectKafka()).resolves.not.toThrow();
    });

    it('should allow reconnection after disconnect', async () => {
      // First connection
      const healthResult: HealthCheckResult = {
        service_name: 'test-service',
        status: HealthStatus.HEALTHY,
        timestamp_ms: Date.now(),
        latency_ms: 50,
      };

      await publishHealthEvent(healthResult);
      expect(mockProducer.connect).toHaveBeenCalledTimes(1);

      // Disconnect
      await disconnectKafka();

      // Reconnect
      await publishHealthEvent(healthResult);
      expect(mockProducer.connect).toHaveBeenCalledTimes(2);
    });
  });
});
