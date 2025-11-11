/**
 * External Dependencies Health Checker
 *
 * Checks health of external dependencies:
 * - RabbitMQ (management API)
 * - PostgreSQL (connection + query)
 * - Kafka (broker metadata)
 * - FINA API (optional ping)
 */

import axios from 'axios';
import { Pool } from 'pg';
import { Kafka, Admin } from 'kafkajs';
import * as amqp from 'amqplib';
import {
  logger,
  createSpan,
  setSpanError,
  healthCheckSuccess,
  healthCheckFailures,
  healthCheckDuration,
} from './observability';
import { HealthStatus, HealthCheckResult } from './health-checker';

// =============================================
// Configuration
// =============================================

const RABBITMQ_MANAGEMENT_URL = process.env.RABBITMQ_MANAGEMENT_URL || 'http://rabbitmq:15672';
const RABBITMQ_USER = process.env.RABBITMQ_USER || 'guest';
const RABBITMQ_PASS = process.env.RABBITMQ_PASS || 'guest';

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost:5432/eracun';

const KAFKA_BROKERS = (process.env.KAFKA_BROKERS || 'localhost:9092').split(',');

const FINA_API_URL = process.env.FINA_API_URL || 'https://cistest.apis-it.hr:8449';

const TIMEOUT_MS = 5000;

// =============================================
// RabbitMQ Health Check
// =============================================

/**
 * Check RabbitMQ health via management API
 * @returns HealthCheckResult
 */
export async function checkRabbitMQ(): Promise<HealthCheckResult> {
  const span = createSpan('check_rabbitmq');
  const startTime = Date.now();

  try {
    // Check node health
    const response = await axios.get(`${RABBITMQ_MANAGEMENT_URL}/api/healthchecks/node`, {
      timeout: TIMEOUT_MS,
      auth: {
        username: RABBITMQ_USER,
        password: RABBITMQ_PASS,
      },
      validateStatus: (status) => status >= 200 && status < 600,
    });

    const latency_ms = Date.now() - startTime;

    const status = response.status === 200 ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY;

    // Get queue statistics (optional)
    let queueStats = {};
    try {
      const queuesResponse = await axios.get(`${RABBITMQ_MANAGEMENT_URL}/api/queues`, {
        timeout: 2000,
        auth: {
          username: RABBITMQ_USER,
          password: RABBITMQ_PASS,
        },
      });

      const queues = queuesResponse.data || [];
      const totalMessages = queues.reduce((sum: number, q: any) => sum + (q.messages || 0), 0);
      queueStats = {
        total_queues: queues.length,
        total_messages: totalMessages,
      };
    } catch {
      // Queue stats optional - don't fail health check
    }

    healthCheckSuccess.inc({ service: 'rabbitmq' });
    healthCheckDuration.observe({ service: 'rabbitmq' }, latency_ms / 1000);

    span.end();

    return {
      service_name: 'rabbitmq',
      status,
      checks: {
        message_queue: {
          status: status,
          latency_ms,
          ...queueStats,
        },
      },
      timestamp_ms: Date.now(),
      latency_ms,
    };
  } catch (error) {
    const latency_ms = Date.now() - startTime;

    healthCheckFailures.inc({ service: 'rabbitmq', reason: 'connection_error' });

    setSpanError(span, error as Error);
    span.end();

    logger.error(
      {
        err: error,
        url: RABBITMQ_MANAGEMENT_URL,
      },
      'RabbitMQ health check failed'
    );

    return {
      service_name: 'rabbitmq',
      status: HealthStatus.UNHEALTHY,
      checks: {},
      timestamp_ms: Date.now(),
      latency_ms,
      error: (error as Error).message,
    };
  }
}

// =============================================
// PostgreSQL Health Check
// =============================================

let pgPool: Pool | null = null;

/**
 * Initialize PostgreSQL connection pool
 */
function initPgPool(): Pool {
  if (!pgPool) {
    pgPool = new Pool({
      connectionString: DATABASE_URL,
      max: 5, // Small pool for health checks only
      connectionTimeoutMillis: TIMEOUT_MS,
    });
  }
  return pgPool;
}

/**
 * Check PostgreSQL health
 * @returns HealthCheckResult
 */
export async function checkPostgreSQL(): Promise<HealthCheckResult> {
  const span = createSpan('check_postgresql');
  const startTime = Date.now();

  try {
    const pool = initPgPool();

    // Simple SELECT 1 query
    await pool.query('SELECT 1');

    const latency_ms = Date.now() - startTime;

    healthCheckSuccess.inc({ service: 'postgresql' });
    healthCheckDuration.observe({ service: 'postgresql' }, latency_ms / 1000);

    span.end();

    return {
      service_name: 'postgresql',
      status: HealthStatus.HEALTHY,
      checks: {
        database: {
          status: HealthStatus.HEALTHY,
          latency_ms,
        },
      },
      timestamp_ms: Date.now(),
      latency_ms,
    };
  } catch (error) {
    const latency_ms = Date.now() - startTime;

    healthCheckFailures.inc({ service: 'postgresql', reason: 'query_failed' });

    setSpanError(span, error as Error);
    span.end();

    logger.error(
      {
        err: error,
        database_url: DATABASE_URL.replace(/:\/\/.*@/, '://***@'), // Mask credentials
      },
      'PostgreSQL health check failed'
    );

    return {
      service_name: 'postgresql',
      status: HealthStatus.UNHEALTHY,
      checks: {},
      timestamp_ms: Date.now(),
      latency_ms,
      error: (error as Error).message,
    };
  }
}

/**
 * Close PostgreSQL pool (for cleanup)
 */
export async function closePgPool(): Promise<void> {
  if (pgPool) {
    await pgPool.end();
    pgPool = null;
  }
}

// =============================================
// Kafka Health Check
// =============================================

let kafkaAdmin: Admin | null = null;

/**
 * Initialize Kafka admin client
 */
function initKafkaAdmin(): Admin {
  if (!kafkaAdmin) {
    const kafka = new Kafka({
      clientId: 'health-monitor',
      brokers: KAFKA_BROKERS,
      requestTimeout: TIMEOUT_MS,
    });
    kafkaAdmin = kafka.admin();
  }
  return kafkaAdmin;
}

/**
 * Check Kafka health
 * @returns HealthCheckResult
 */
export async function checkKafka(): Promise<HealthCheckResult> {
  const span = createSpan('check_kafka');
  const startTime = Date.now();

  try {
    const admin = initKafkaAdmin();

    // Connect and fetch broker metadata
    await admin.connect();
    const cluster = await admin.describeCluster();

    const latency_ms = Date.now() - startTime;

    // Disconnect after check
    await admin.disconnect();
    kafkaAdmin = null;

    healthCheckSuccess.inc({ service: 'kafka' });
    healthCheckDuration.observe({ service: 'kafka' }, latency_ms / 1000);

    span.end();

    return {
      service_name: 'kafka',
      status: HealthStatus.HEALTHY,
      checks: {
        message_queue: {
          status: HealthStatus.HEALTHY,
          latency_ms,
          brokers: cluster.brokers.length,
        },
      },
      timestamp_ms: Date.now(),
      latency_ms,
    };
  } catch (error) {
    const latency_ms = Date.now() - startTime;

    healthCheckFailures.inc({ service: 'kafka', reason: 'connection_error' });

    setSpanError(span, error as Error);
    span.end();

    logger.error(
      {
        err: error,
        brokers: KAFKA_BROKERS,
      },
      'Kafka health check failed'
    );

    // Try to disconnect on error
    if (kafkaAdmin) {
      try {
        await kafkaAdmin.disconnect();
      } catch {
        // Ignore disconnect errors
      }
      kafkaAdmin = null;
    }

    return {
      service_name: 'kafka',
      status: HealthStatus.UNHEALTHY,
      checks: {},
      timestamp_ms: Date.now(),
      latency_ms,
      error: (error as Error).message,
    };
  }
}

// =============================================
// FINA API Health Check (Optional)
// =============================================

/**
 * Check FINA API health (optional)
 * @returns HealthCheckResult
 */
export async function checkFinaAPI(): Promise<HealthCheckResult> {
  const span = createSpan('check_fina_api');
  const startTime = Date.now();

  try {
    // Try to ping FINA health endpoint (if available)
    // Note: FINA may not have a dedicated health endpoint
    const response = await axios.get(`${FINA_API_URL}/health`, {
      timeout: TIMEOUT_MS,
      validateStatus: (status) => status >= 200 && status < 600,
    });

    const latency_ms = Date.now() - startTime;

    const status = response.status === 200 ? HealthStatus.HEALTHY : HealthStatus.DEGRADED;

    healthCheckSuccess.inc({ service: 'fina-api' });
    healthCheckDuration.observe({ service: 'fina-api' }, latency_ms / 1000);

    span.end();

    return {
      service_name: 'fina-api',
      status,
      checks: {},
      timestamp_ms: Date.now(),
      latency_ms,
    };
  } catch (error) {
    const latency_ms = Date.now() - startTime;

    // FINA API being unavailable is not critical (we mark as degraded, not unhealthy)
    healthCheckFailures.inc({ service: 'fina-api', reason: 'unavailable' });

    setSpanError(span, error as Error);
    span.end();

    logger.warn(
      {
        err: error,
        url: FINA_API_URL,
      },
      'FINA API health check failed (non-critical)'
    );

    return {
      service_name: 'fina-api',
      status: HealthStatus.DEGRADED, // Not critical, mark as degraded
      checks: {},
      timestamp_ms: Date.now(),
      latency_ms,
      error: (error as Error).message,
    };
  }
}

// =============================================
// Check All External Dependencies
// =============================================

/**
 * Check all external dependencies
 * @returns Array of HealthCheckResults
 */
export async function checkAllExternalDeps(): Promise<HealthCheckResult[]> {
  const results = await Promise.allSettled([
    checkRabbitMQ(),
    checkPostgreSQL(),
    checkKafka(),
    // checkFinaAPI(), // Optional - uncomment if FINA has health endpoint
  ]);

  return results.map((result) => {
    if (result.status === 'fulfilled') {
      return result.value;
    } else {
      logger.error({ err: result.reason }, 'External dependency check failed');
      return {
        service_name: 'unknown',
        status: HealthStatus.UNHEALTHY,
        checks: {},
        timestamp_ms: Date.now(),
        latency_ms: 0,
        error: result.reason.message,
      };
    }
  });
}

// =============================================
// Cleanup
// =============================================

/**
 * Close all external connections (for graceful shutdown)
 */
export async function closeAllConnections(): Promise<void> {
  await closePgPool();

  if (kafkaAdmin) {
    try {
      await kafkaAdmin.disconnect();
      kafkaAdmin = null;
    } catch (error) {
      logger.error({ err: error }, 'Failed to disconnect Kafka admin');
    }
  }
}
