/**
 * PostgreSQL Repository
 *
 * Handles notification audit trail storage in PostgreSQL.
 * Features:
 * - Connection pooling (min: 10, max: 50)
 * - Audit trail for all sent notifications
 * - Notification status tracking (pending/sent/failed)
 * - Error message logging for failed notifications
 */

import { Pool, PoolClient } from 'pg';
import { logger } from './observability';

// =============================================================================
// TYPES
// =============================================================================

export enum NotificationType {
  EMAIL = 'email',
  SMS = 'sms',
  WEBHOOK = 'webhook',
}

export enum NotificationPriority {
  LOW = 'low',
  NORMAL = 'normal',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export enum NotificationStatus {
  PENDING = 'pending',
  SENT = 'sent',
  FAILED = 'failed',
}

export interface Notification {
  notification_id: string;          // UUID
  type: NotificationType;
  priority: NotificationPriority;
  recipients: string[];             // Email addresses or phone numbers
  subject?: string;                 // Email subject or SMS title
  body: string;                     // Message content
  webhook_url?: string;             // For webhook notifications
  status: NotificationStatus;
  sent_at?: Date;
  error_message?: string;
  created_at: Date;
}

export interface SaveNotificationParams {
  notification_id: string;
  type: NotificationType;
  priority: NotificationPriority;
  recipients: string[];
  subject?: string;
  body: string;
  webhook_url?: string;
}

export interface UpdateNotificationStatusParams {
  notification_id: string;
  status: NotificationStatus;
  sent_at?: Date;
  error_message?: string;
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

/**
 * Initialize PostgreSQL connection pool
 */
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

  // Handle pool errors
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

/**
 * Get connection pool (initialize if not exists)
 */
export function getPool(): Pool {
  if (!pool) {
    return initPool();
  }
  return pool;
}

/**
 * Close connection pool (for graceful shutdown)
 */
export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    logger.info('PostgreSQL connection pool closed');
  }
}

// =============================================================================
// DATABASE SCHEMA INITIALIZATION
// =============================================================================

/**
 * Create notification_log table if not exists
 *
 * Schema:
 * - id: BIGSERIAL PRIMARY KEY
 * - notification_id: UUID (unique identifier)
 * - type: VARCHAR(50) (email/sms/webhook)
 * - priority: VARCHAR(50) (low/normal/high/critical)
 * - recipients: TEXT[] (array of email addresses or phone numbers)
 * - subject: TEXT (email subject or SMS title)
 * - body: TEXT (message content)
 * - webhook_url: TEXT (for webhook notifications)
 * - status: VARCHAR(50) (pending/sent/failed)
 * - sent_at: TIMESTAMP (when notification was sent)
 * - error_message: TEXT (error details for failed notifications)
 * - created_at: TIMESTAMP (when record was created)
 */
export async function createSchema(): Promise<void> {
  const client = await getPool().connect();

  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS notification_log (
        id BIGSERIAL PRIMARY KEY,
        notification_id UUID NOT NULL UNIQUE,
        type VARCHAR(50) NOT NULL,
        priority VARCHAR(50) NOT NULL,
        recipients TEXT[] NOT NULL,
        subject TEXT,
        body TEXT NOT NULL,
        webhook_url TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        sent_at TIMESTAMP,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT NOW(),

        -- Indexes for common queries
        CONSTRAINT notification_log_type_check CHECK (type IN ('email', 'sms', 'webhook')),
        CONSTRAINT notification_log_priority_check CHECK (priority IN ('low', 'normal', 'high', 'critical')),
        CONSTRAINT notification_log_status_check CHECK (status IN ('pending', 'sent', 'failed'))
      );

      -- Index for notification_id lookups
      CREATE INDEX IF NOT EXISTS idx_notification_log_notification_id
        ON notification_log(notification_id);

      -- Index for status queries
      CREATE INDEX IF NOT EXISTS idx_notification_log_status
        ON notification_log(status);

      -- Index for type and created_at queries (for metrics)
      CREATE INDEX IF NOT EXISTS idx_notification_log_type_created_at
        ON notification_log(type, created_at DESC);
    `);

    logger.info('notification_log table schema verified/created');
  } catch (error) {
    logger.error({ error }, 'Failed to create notification_log schema');
    throw error;
  } finally {
    client.release();
  }
}

// =============================================================================
// REPOSITORY FUNCTIONS
// =============================================================================

/**
 * Save notification to database (audit trail)
 *
 * @param params - Notification parameters
 * @returns Notification ID
 */
export async function saveNotification(params: SaveNotificationParams): Promise<string> {
  const pool = getPool();

  try {
    const result = await pool.query(
      `INSERT INTO notification_log
       (notification_id, type, priority, recipients, subject, body, webhook_url, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
       RETURNING notification_id`,
      [
        params.notification_id,
        params.type,
        params.priority,
        params.recipients,
        params.subject || null,
        params.body,
        params.webhook_url || null,
      ]
    );

    const notificationId = result.rows[0].notification_id;

    logger.info(
      {
        notification_id: notificationId,
        type: params.type,
        priority: params.priority,
        recipients_count: params.recipients.length,
      },
      'Notification saved to database'
    );

    return notificationId;
  } catch (error) {
    logger.error(
      { error, notification_id: params.notification_id },
      'Failed to save notification'
    );
    throw error;
  }
}

/**
 * Update notification status
 *
 * @param params - Status update parameters
 */
export async function updateNotificationStatus(params: UpdateNotificationStatusParams): Promise<void> {
  const pool = getPool();

  try {
    await pool.query(
      `UPDATE notification_log
       SET status = $1, sent_at = $2, error_message = $3
       WHERE notification_id = $4`,
      [
        params.status,
        params.sent_at || null,
        params.error_message || null,
        params.notification_id,
      ]
    );

    logger.info(
      {
        notification_id: params.notification_id,
        status: params.status,
        has_error: !!params.error_message,
      },
      'Notification status updated'
    );
  } catch (error) {
    logger.error(
      { error, notification_id: params.notification_id },
      'Failed to update notification status'
    );
    throw error;
  }
}

/**
 * Get notification by ID
 *
 * @param notificationId - Notification UUID
 * @returns Notification or null if not found
 */
export async function getNotification(notificationId: string): Promise<Notification | null> {
  const pool = getPool();

  try {
    const result = await pool.query(
      `SELECT * FROM notification_log WHERE notification_id = $1`,
      [notificationId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return result.rows[0] as Notification;
  } catch (error) {
    logger.error({ error, notification_id: notificationId }, 'Failed to get notification');
    throw error;
  }
}

/**
 * Get notifications by status
 *
 * @param status - Notification status
 * @param limit - Maximum number of results
 * @returns Array of notifications
 */
export async function getNotificationsByStatus(
  status: NotificationStatus,
  limit = 100
): Promise<Notification[]> {
  const pool = getPool();

  try {
    const result = await pool.query(
      `SELECT * FROM notification_log
       WHERE status = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [status, limit]
    );

    return result.rows as Notification[];
  } catch (error) {
    logger.error({ error, status }, 'Failed to get notifications by status');
    throw error;
  }
}

/**
 * Get failed notifications for retry
 *
 * @param limit - Maximum number of results
 * @returns Array of failed notifications
 */
export async function getFailedNotifications(limit = 10): Promise<Notification[]> {
  return getNotificationsByStatus(NotificationStatus.FAILED, limit);
}

/**
 * Health check - verify database connection
 *
 * @returns true if connection is healthy
 */
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

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  initPool,
  getPool,
  closePool,
  createSchema,
  saveNotification,
  updateNotificationStatus,
  getNotification,
  getNotificationsByStatus,
  getFailedNotifications,
  healthCheck,
};
