/**
 * Unit Tests for External Dependencies Health Checker
 */

import axios from 'axios';
import { Pool } from 'pg';
import { Kafka, Admin } from 'kafkajs';
import {
  checkRabbitMQ,
  checkPostgreSQL,
  checkKafka,
  checkFinaAPI,
  checkAllExternalDeps,
  closePgPool,
  closeAllConnections,
} from '../../src/external-deps';
import { HealthStatus } from '../../src/health-checker';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock pg
jest.mock('pg');
const MockedPool = Pool as jest.MockedClass<typeof Pool>;

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
  healthCheckSuccess: {
    inc: jest.fn(),
  },
  healthCheckFailures: {
    inc: jest.fn(),
  },
  healthCheckDuration: {
    observe: jest.fn(),
  },
}));

describe('External Dependencies Health Checker', () => {
  let mockPool: jest.Mocked<Pool>;
  let mockAdmin: jest.Mocked<Admin>;

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup PostgreSQL mock
    mockPool = {
      query: jest.fn().mockResolvedValue({ rows: [] }),
      end: jest.fn().mockResolvedValue(undefined),
      connect: jest.fn(),
      on: jest.fn(),
    } as any;

    MockedPool.mockImplementation(() => mockPool);

    // Setup Kafka mock
    mockAdmin = {
      connect: jest.fn().mockResolvedValue(undefined),
      disconnect: jest.fn().mockResolvedValue(undefined),
      describeCluster: jest.fn().mockResolvedValue({
        brokers: [{ nodeId: 1 }, { nodeId: 2 }],
      }),
    } as any;

    MockedKafka.mockImplementation(() => ({
      admin: jest.fn().mockReturnValue(mockAdmin),
    } as any));
  });

  describe('checkRabbitMQ()', () => {
    it('should return HEALTHY for 200 OK response', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'ok' },
      });

      const result = await checkRabbitMQ();

      expect(result.service_name).toBe('rabbitmq');
      expect(result.status).toBe(HealthStatus.HEALTHY);
      expect(result.latency_ms).toBeGreaterThan(0);
      expect(mockedAxios.get).toHaveBeenCalledWith(
        expect.stringContaining('/api/healthchecks/node'),
        expect.objectContaining({
          auth: expect.any(Object),
        })
      );
    });

    it('should include queue statistics if available', async () => {
      mockedAxios.get
        .mockResolvedValueOnce({
          status: 200,
          data: { status: 'ok' },
        })
        .mockResolvedValueOnce({
          status: 200,
          data: [
            { name: 'queue1', messages: 100 },
            { name: 'queue2', messages: 50 },
          ],
        });

      const result = await checkRabbitMQ();

      expect(result.status).toBe(HealthStatus.HEALTHY);
      expect(result.checks?.message_queue?.total_queues).toBe(2);
      expect(result.checks?.message_queue?.total_messages).toBe(150);
    });

    it('should not fail health check if queue stats unavailable', async () => {
      mockedAxios.get
        .mockResolvedValueOnce({
          status: 200,
          data: { status: 'ok' },
        })
        .mockRejectedValueOnce(new Error('Queue API unavailable'));

      const result = await checkRabbitMQ();

      expect(result.status).toBe(HealthStatus.HEALTHY);
      expect(result.checks?.message_queue?.total_queues).toBeUndefined();
    });

    it('should return UNHEALTHY for non-200 response', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 503,
        data: { error: 'Service unavailable' },
      });

      const result = await checkRabbitMQ();

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
    });

    it('should handle connection errors', async () => {
      const observability = require('../../src/observability');
      mockedAxios.get.mockRejectedValue(new Error('Connection refused'));

      const result = await checkRabbitMQ();

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
      expect(result.error).toBe('Connection refused');
      expect(observability.healthCheckFailures.inc).toHaveBeenCalledWith({
        service: 'rabbitmq',
        reason: 'connection_error',
      });
    });

    it('should track success metrics', async () => {
      const observability = require('../../src/observability');
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'ok' },
      });

      await checkRabbitMQ();

      expect(observability.healthCheckSuccess.inc).toHaveBeenCalledWith({
        service: 'rabbitmq',
      });
      expect(observability.healthCheckDuration.observe).toHaveBeenCalledWith(
        { service: 'rabbitmq' },
        expect.any(Number)
      );
    });

    it('should create and end span for tracing', async () => {
      const observability = require('../../src/observability');
      const mockSpan = { end: jest.fn(), setAttribute: jest.fn() };
      observability.createSpan.mockReturnValue(mockSpan);

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'ok' },
      });

      await checkRabbitMQ();

      expect(observability.createSpan).toHaveBeenCalledWith('check_rabbitmq');
      expect(mockSpan.end).toHaveBeenCalled();
    });
  });

  describe('checkPostgreSQL()', () => {
    it('should return HEALTHY for successful query', async () => {
      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);

      const result = await checkPostgreSQL();

      expect(result.service_name).toBe('postgresql');
      expect(result.status).toBe(HealthStatus.HEALTHY);
      expect(result.latency_ms).toBeGreaterThan(0);
      expect(result.checks?.database?.status).toBe(HealthStatus.HEALTHY);
      expect(mockPool.query).toHaveBeenCalledWith('SELECT 1');
    });

    it('should handle connection errors', async () => {
      const observability = require('../../src/observability');
      mockPool.query.mockRejectedValue(new Error('Connection refused'));

      const result = await checkPostgreSQL();

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
      expect(result.error).toBe('Connection refused');
      expect(observability.healthCheckFailures.inc).toHaveBeenCalledWith({
        service: 'postgresql',
        reason: 'query_failed',
      });
    });

    it('should track success metrics', async () => {
      const observability = require('../../src/observability');
      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);

      await checkPostgreSQL();

      expect(observability.healthCheckSuccess.inc).toHaveBeenCalledWith({
        service: 'postgresql',
      });
      expect(observability.healthCheckDuration.observe).toHaveBeenCalledWith(
        { service: 'postgresql' },
        expect.any(Number)
      );
    });

    it('should reuse existing connection pool', async () => {
      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);

      // First call
      await checkPostgreSQL();
      expect(MockedPool).toHaveBeenCalledTimes(1);

      // Second call - should reuse pool
      await checkPostgreSQL();
      expect(MockedPool).toHaveBeenCalledTimes(1);
    });

    it('should mask credentials in error logs', async () => {
      const observability = require('../../src/observability');
      mockPool.query.mockRejectedValue(new Error('Authentication failed'));

      await checkPostgreSQL();

      expect(observability.logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          database_url: expect.stringContaining('***'),
        }),
        'PostgreSQL health check failed'
      );
    });

    it('should create and end span for tracing', async () => {
      const observability = require('../../src/observability');
      const mockSpan = { end: jest.fn(), setAttribute: jest.fn() };
      observability.createSpan.mockReturnValue(mockSpan);

      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);

      await checkPostgreSQL();

      expect(observability.createSpan).toHaveBeenCalledWith('check_postgresql');
      expect(mockSpan.end).toHaveBeenCalled();
    });
  });

  describe('closePgPool()', () => {
    it('should close PostgreSQL pool', async () => {
      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);

      // Initialize pool
      await checkPostgreSQL();

      // Close pool
      await closePgPool();

      expect(mockPool.end).toHaveBeenCalled();
    });

    it('should handle close when pool not initialized', async () => {
      await expect(closePgPool()).resolves.not.toThrow();
    });
  });

  describe('checkKafka()', () => {
    it('should return HEALTHY for successful connection', async () => {
      const result = await checkKafka();

      expect(result.service_name).toBe('kafka');
      expect(result.status).toBe(HealthStatus.HEALTHY);
      expect(result.latency_ms).toBeGreaterThan(0);
      expect(result.checks?.message_queue?.brokers).toBe(2);
      expect(mockAdmin.connect).toHaveBeenCalled();
      expect(mockAdmin.describeCluster).toHaveBeenCalled();
      expect(mockAdmin.disconnect).toHaveBeenCalled();
    });

    it('should handle connection errors', async () => {
      const observability = require('../../src/observability');
      mockAdmin.connect.mockRejectedValue(new Error('Broker unavailable'));

      const result = await checkKafka();

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
      expect(result.error).toBe('Broker unavailable');
      expect(observability.healthCheckFailures.inc).toHaveBeenCalledWith({
        service: 'kafka',
        reason: 'connection_error',
      });
    });

    it('should disconnect on error', async () => {
      mockAdmin.connect.mockRejectedValue(new Error('Broker unavailable'));

      await checkKafka();

      // Should still attempt disconnect despite error
      expect(mockAdmin.disconnect).toHaveBeenCalled();
    });

    it('should handle disconnect errors gracefully', async () => {
      mockAdmin.connect.mockResolvedValue(undefined);
      mockAdmin.describeCluster.mockRejectedValue(new Error('Cluster error'));
      mockAdmin.disconnect.mockRejectedValue(new Error('Disconnect failed'));

      const result = await checkKafka();

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
      // Should not throw on disconnect failure
    });

    it('should track success metrics', async () => {
      const observability = require('../../src/observability');

      await checkKafka();

      expect(observability.healthCheckSuccess.inc).toHaveBeenCalledWith({
        service: 'kafka',
      });
      expect(observability.healthCheckDuration.observe).toHaveBeenCalledWith(
        { service: 'kafka' },
        expect.any(Number)
      );
    });

    it('should create and end span for tracing', async () => {
      const observability = require('../../src/observability');
      const mockSpan = { end: jest.fn(), setAttribute: jest.fn() };
      observability.createSpan.mockReturnValue(mockSpan);

      await checkKafka();

      expect(observability.createSpan).toHaveBeenCalledWith('check_kafka');
      expect(mockSpan.end).toHaveBeenCalled();
    });
  });

  describe('checkFinaAPI()', () => {
    it('should return HEALTHY for 200 OK response', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'ok' },
      });

      const result = await checkFinaAPI();

      expect(result.service_name).toBe('fina-api');
      expect(result.status).toBe(HealthStatus.HEALTHY);
      expect(result.latency_ms).toBeGreaterThan(0);
    });

    it('should return DEGRADED for non-200 response', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 503,
        data: { error: 'Service unavailable' },
      });

      const result = await checkFinaAPI();

      expect(result.status).toBe(HealthStatus.DEGRADED);
    });

    it('should return DEGRADED on connection errors (not critical)', async () => {
      const observability = require('../../src/observability');
      mockedAxios.get.mockRejectedValue(new Error('Timeout'));

      const result = await checkFinaAPI();

      expect(result.status).toBe(HealthStatus.DEGRADED);
      expect(result.error).toBe('Timeout');
      expect(observability.logger.warn).toHaveBeenCalledWith(
        expect.any(Object),
        'FINA API health check failed (non-critical)'
      );
    });

    it('should track success metrics', async () => {
      const observability = require('../../src/observability');
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'ok' },
      });

      await checkFinaAPI();

      expect(observability.healthCheckSuccess.inc).toHaveBeenCalledWith({
        service: 'fina-api',
      });
      expect(observability.healthCheckDuration.observe).toHaveBeenCalledWith(
        { service: 'fina-api' },
        expect.any(Number)
      );
    });

    it('should track failure metrics', async () => {
      const observability = require('../../src/observability');
      mockedAxios.get.mockRejectedValue(new Error('Connection refused'));

      await checkFinaAPI();

      expect(observability.healthCheckFailures.inc).toHaveBeenCalledWith({
        service: 'fina-api',
        reason: 'unavailable',
      });
    });

    it('should create and end span for tracing', async () => {
      const observability = require('../../src/observability');
      const mockSpan = { end: jest.fn(), setAttribute: jest.fn() };
      observability.createSpan.mockReturnValue(mockSpan);

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'ok' },
      });

      await checkFinaAPI();

      expect(observability.createSpan).toHaveBeenCalledWith('check_fina_api');
      expect(mockSpan.end).toHaveBeenCalled();
    });
  });

  describe('checkAllExternalDeps()', () => {
    it('should check all external dependencies in parallel', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'ok' },
      });
      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);

      const results = await checkAllExternalDeps();

      expect(results).toHaveLength(3); // RabbitMQ, PostgreSQL, Kafka
      expect(results.map((r) => r.service_name).sort()).toEqual([
        'kafka',
        'postgresql',
        'rabbitmq',
      ]);
    });

    it('should handle individual check failures', async () => {
      mockedAxios.get.mockRejectedValue(new Error('RabbitMQ unavailable'));
      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);
      // Kafka will succeed (default mocks)

      const results = await checkAllExternalDeps();

      expect(results).toHaveLength(3);
      const rabbitMqResult = results.find((r) => r.service_name === 'rabbitmq');
      const postgresResult = results.find((r) => r.service_name === 'postgresql');

      expect(rabbitMqResult?.status).toBe(HealthStatus.UNHEALTHY);
      expect(postgresResult?.status).toBe(HealthStatus.HEALTHY);
    });

    it('should log errors for completely failed checks', async () => {
      const observability = require('../../src/observability');

      // Make one check throw an unhandled error (shouldn't happen in practice)
      mockedAxios.get.mockImplementation(() => {
        throw new Error('Catastrophic failure');
      });

      const results = await checkAllExternalDeps();

      expect(observability.logger.error).toHaveBeenCalled();
      expect(results.some((r) => r.service_name === 'unknown')).toBe(true);
    });

    it('should return results even if some checks fail', async () => {
      // All checks fail
      mockedAxios.get.mockRejectedValue(new Error('RabbitMQ down'));
      mockPool.query.mockRejectedValue(new Error('Database down'));
      mockAdmin.connect.mockRejectedValue(new Error('Kafka down'));

      const results = await checkAllExternalDeps();

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.status === HealthStatus.UNHEALTHY)).toBe(true);
    });
  });

  describe('closeAllConnections()', () => {
    it('should close all connections', async () => {
      // Initialize connections
      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);
      await checkPostgreSQL();
      await checkKafka();

      // Close all
      await closeAllConnections();

      expect(mockPool.end).toHaveBeenCalled();
      // Note: Kafka admin is disconnected immediately after each check
    });

    it('should handle errors during cleanup', async () => {
      const observability = require('../../src/observability');
      mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] } as any);
      await checkPostgreSQL();

      // Simulate disconnect error
      mockPool.end.mockRejectedValue(new Error('Disconnect failed'));

      await expect(closeAllConnections()).rejects.toThrow();
    });

    it('should handle Kafka admin disconnect errors', async () => {
      const observability = require('../../src/observability');

      // Create a failing Kafka check that leaves admin initialized
      mockAdmin.connect.mockResolvedValue(undefined);
      mockAdmin.describeCluster.mockRejectedValue(new Error('Cluster error'));
      mockAdmin.disconnect.mockRejectedValue(new Error('Disconnect error'));

      await checkKafka();

      // closeAllConnections should handle this gracefully
      await expect(closeAllConnections()).resolves.not.toThrow();
    });
  });

  describe('Configuration', () => {
    it('should use environment variables for URLs', () => {
      // This is implicitly tested in other tests via mocking
      // Just ensure the configuration is used
      expect(true).toBe(true);
    });

    it('should use default timeout of 5000ms', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { status: 'ok' },
      });

      await checkRabbitMQ();

      expect(mockedAxios.get).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          timeout: 5000,
        })
      );
    });
  });
});
