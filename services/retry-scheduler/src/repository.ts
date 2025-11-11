/**
 * PostgreSQL Repository
 *
 * Handles persistent retry queue storage in PostgreSQL.
 * Features:
 * - Connection pooling
 * - Retry task CRUD operations
 * - Query for due retries
 */

import { Pool, PoolClient } from 'pg';
import { logger, retryQueueDepth } from './observability';

// =============================================================================
// TYPES
// =============================================================================

export interface RetryTask {
  id?: number;
  message_id: string;
  original_payload: Buffer;
  original_queue: string;
  error_reason?: string;
  retry_count: number;
  max_retries: number;
  next_retry_at: Date;
  created_at?: Date;
  status: 'pending' | 'retried' | 'failed';
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const POSTGRES_HOST = process.env.POSTGRES_HOST || 'localhost';
const POSTGRES_PORT = parseInt(process.env.POSTGRES_PORT || '5432', 10);
const POSTGRES_DB = process.env.POSTGRES_DB || 'eracun';
const POSTGRES_USER = process.env.POSTGRES_USER || 'eracun';
const POSTGRES_PASSWORD = process.env.POSTGRES_PASSWORD || '';
const POSTGRES_POOL_MIN = parseInt(process.env.POSTGRES_POOL_MIN || '10', 10);
const POSTGRES_POOL_MAX = parseInt(process.env.POSTGRES_POOL_MAX || '50', 10);

// =============================================================================
// CONNECTION POOL
// =============================================================================

let pool: Pool | null = null;

export function initPool(): Pool {
  if (pool) {
    logger.warn('PostgreSQL pool already initialized');
    return pool;
  }

  pool = new Pool({
    host: POSTGRES_HOST,
    port: POSTGRES_PORT,
    database: POSTGRES_DB,
    user: POSTGRES_USER,
    password: POSTGRES_PASSWORD,
    min: POSTGRES_POOL_MIN,
    max: POSTGRES_POOL_MAX,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  pool.on('error', (err) => {
    logger.error({ error: err }, 'PostgreSQL pool error');
  });

  logger.info(
    {
      host: POSTGRES_HOST,
      port: POSTGRES_PORT,
      database: POSTGRES_DB,
      pool_min: POSTGRES_POOL_MIN,
      pool_max: POSTGRES_POOL_MAX,
    },
    'PostgreSQL connection pool initialized'
  );

  return pool;
}

export function getPool(): Pool {
  if (!pool) {
    return initPool();
  }
  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    logger.info('PostgreSQL connection pool closed');
  }
}

// =============================================================================
// SCHEMA INITIALIZATION
// =============================================================================

export async function createSchema(): Promise<void> {
  const client = await getPool().connect();

  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS retry_queue (
        id BIGSERIAL PRIMARY KEY,
        message_id UUID UNIQUE NOT NULL,
        original_payload BYTEA NOT NULL,
        original_queue VARCHAR(255) NOT NULL,
        error_reason TEXT,
        retry_count INT NOT NULL DEFAULT 0,
        max_retries INT NOT NULL DEFAULT 3,
        next_retry_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        status VARCHAR(50) DEFAULT 'pending',

        CONSTRAINT retry_queue_status_check CHECK (status IN ('pending', 'retried', 'failed'))
      );

      -- Index for polling due retries
      CREATE INDEX IF NOT EXISTS idx_retry_next_retry
        ON retry_queue(next_retry_at, status)
        WHERE status = 'pending';

      -- Index for message_id lookups
      CREATE INDEX IF NOT EXISTS idx_retry_message_id
        ON retry_queue(message_id);
    `);

    logger.info('retry_queue table schema verified/created');
  } catch (error) {
    logger.error({ error }, 'Failed to create retry_queue schema');
    throw error;
  } finally {
    client.release();
  }
}

// =============================================================================
// REPOSITORY FUNCTIONS
// =============================================================================

export async function saveRetryTask(task: RetryTask): Promise<void> {
  const pool = getPool();

  try {
    await pool.query(
      `INSERT INTO retry_queue
       (message_id, original_payload, original_queue, error_reason, retry_count, max_retries, next_retry_at, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
       ON CONFLICT (message_id) DO UPDATE
         SET original_payload = EXCLUDED.original_payload,
             original_queue = EXCLUDED.original_queue,
             error_reason = EXCLUDED.error_reason,
             retry_count = EXCLUDED.retry_count,
             max_retries = EXCLUDED.max_retries,
             next_retry_at = EXCLUDED.next_retry_at,
             status = 'pending'`,
      [
        task.message_id,
        task.original_payload,
        task.original_queue,
        task.error_reason || null,
        task.retry_count,
        task.max_retries,
        task.next_retry_at,
      ]
    );

    // Update queue depth metric
    await updateQueueDepthMetric();

    logger.info(
      {
        message_id: task.message_id,
        original_queue: task.original_queue,
        retry_count: task.retry_count,
        next_retry_at: task.next_retry_at,
        operation: 'upsert',
      },
      'Retry task persisted'
    );
  } catch (error) {
    logger.error({ error, message_id: task.message_id }, 'Failed to save retry task');
    throw error;
  }
}

export async function getDueRetryTasks(limit = 100): Promise<RetryTask[]> {
  const pool = getPool();

  try {
    const result = await pool.query(
      `SELECT * FROM retry_queue
       WHERE next_retry_at <= NOW() AND status = 'pending'
       ORDER BY next_retry_at ASC
       LIMIT $1`,
      [limit]
    );

    return result.rows as RetryTask[];
  } catch (error) {
    logger.error({ error }, 'Failed to get due retry tasks');
    throw error;
  }
}

export async function updateRetryTask(task: RetryTask): Promise<void> {
  const pool = getPool();

  try {
    await pool.query(
      `UPDATE retry_queue
       SET retry_count = $1, status = $2
       WHERE message_id = $3`,
      [task.retry_count, task.status, task.message_id]
    );

    logger.debug(
      {
        message_id: task.message_id,
        retry_count: task.retry_count,
        status: task.status,
      },
      'Retry task updated'
    );
  } catch (error) {
    logger.error({ error, message_id: task.message_id }, 'Failed to update retry task');
    throw error;
  }
}

export async function markRetrySuccess(messageId: string): Promise<void> {
  const pool = getPool();

  try {
    await pool.query(
      `UPDATE retry_queue SET status = 'retried' WHERE message_id = $1`,
      [messageId]
    );

    // Update queue depth metric
    await updateQueueDepthMetric();

    logger.info({ message_id: messageId }, 'Retry marked as successful');
  } catch (error) {
    logger.error({ error, message_id: messageId }, 'Failed to mark retry success');
    throw error;
  }
}

export async function markRetryFailed(messageId: string): Promise<void> {
  const pool = getPool();

  try {
    await pool.query(
      `UPDATE retry_queue SET status = 'failed' WHERE message_id = $1`,
      [messageId]
    );

    // Update queue depth metric
    await updateQueueDepthMetric();

    logger.info({ message_id: messageId }, 'Retry marked as failed (max retries exceeded)');
  } catch (error) {
    logger.error({ error, message_id: messageId }, 'Failed to mark retry failed');
    throw error;
  }
}

export async function updateQueueDepthMetric(): Promise<void> {
  try {
    const pool = getPool();
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM retry_queue WHERE status = 'pending'`
    );
    const depth = parseInt(result.rows[0].count, 10);
    retryQueueDepth.set(depth);
  } catch (error) {
    logger.error({ error }, 'Failed to update queue depth metric');
  }
}

export async function healthCheck(): Promise<boolean> {
  try {
    const pool = getPool();
    const result = await pool.query('SELECT 1 as health');
    return result.rows[0].health === 1;
  } catch (error) {
    logger.error({ error }, 'PostgreSQL health check failed');
    return false;
  }
}

export default {
  initPool,
  getPool,
  closePool,
  createSchema,
  saveRetryTask,
  getDueRetryTasks,
  updateRetryTask,
  markRetrySuccess,
  markRetryFailed,
  updateQueueDepthMetric,
  healthCheck,
};
