import { Pool, PoolClient } from 'pg';
import {
  logger,
  offlineQueueDepth,
  offlineQueueMaxAge,
  createSpan,
  setSpanError,
  endSpanSuccess,
} from './observability.js';
import type {
  OfflineQueueEntry,
  FINAFiscalizationRequest,
  FINAError,
} from './types.js';
import { randomUUID } from 'crypto';

/**
 * IMPROVEMENT-028: Safe JSON stringify with circular reference protection
 * Prevents "Converting circular structure to JSON" errors
 */
function safeStringify(obj: any): string {
  const seen = new WeakSet();

  return JSON.stringify(obj, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[Circular Reference]'; // Replace circular references with placeholder
      }
      seen.add(value);
    }
    return value;
  });
}

/**
 * Offline Queue Configuration
 */
export interface OfflineQueueConfig {
  /** PostgreSQL connection pool */
  pool: Pool;
  /** Max age for queue entries (milliseconds) - default 48 hours */
  maxAge: number;
  /** Max retry attempts per entry */
  maxRetries: number;
  /** Batch size for processing */
  batchSize: number;
}

/**
 * Offline Queue Manager
 *
 * Manages failed fiscalization requests in PostgreSQL queue.
 * Provides 48-hour grace period for offline submission per Croatian regulations.
 */
export class OfflineQueueManager {
  private config: OfflineQueueConfig;

  constructor(config: OfflineQueueConfig) {
    this.config = config;
  }

  /**
   * Initialize database schema
   */
  async initialize(): Promise<void> {
    const span = createSpan('initialize_offline_queue');

    try {
      logger.info('Initializing offline queue database schema');

      await this.config.pool.query(`
        CREATE TABLE IF NOT EXISTS offline_queue (
          id UUID PRIMARY KEY,
          invoice_id VARCHAR(255) NOT NULL,
          request JSONB NOT NULL,
          retry_count INTEGER DEFAULT 0,
          last_error JSONB,
          status VARCHAR(50) DEFAULT 'pending',
          created_at TIMESTAMPTZ DEFAULT NOW(),
          last_retry_at TIMESTAMPTZ,
          CONSTRAINT status_check CHECK (status IN ('pending', 'processing', 'failed'))
        )
      `);

      await this.config.pool.query(`
        CREATE INDEX IF NOT EXISTS idx_offline_queue_status
        ON offline_queue(status)
      `);

      await this.config.pool.query(`
        CREATE INDEX IF NOT EXISTS idx_offline_queue_created_at
        ON offline_queue(created_at)
      `);

      await this.config.pool.query(`
        CREATE INDEX IF NOT EXISTS idx_offline_queue_invoice_id
        ON offline_queue(invoice_id)
      `);

      endSpanSuccess(span);
      logger.info('Offline queue database schema initialized');
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to initialize offline queue schema');
      throw error;
    }
  }

  /**
   * Add failed request to offline queue
   *
   * @param request - Fiscalization request
   * @param invoiceId - Invoice ID
   * @param error - Error details
   * @returns Queue entry ID
   */
  async enqueue(
    request: FINAFiscalizationRequest,
    invoiceId: string,
    error?: FINAError
  ): Promise<string> {
    const span = createSpan('enqueue_offline', {
      invoice_id: invoiceId,
    });

    try {
      const id = randomUUID();

      logger.info({
        id,
        invoiceId,
        invoiceNumber: request.racun.brojRacuna,
      }, 'Adding invoice to offline queue');

      await this.config.pool.query(
        `INSERT INTO offline_queue
         (id, invoice_id, request, retry_count, last_error, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [
          id,
          invoiceId,
          safeStringify(request), // IMPROVEMENT-028: Use safe stringify
          0,
          error ? safeStringify(error) : null, // IMPROVEMENT-028: Use safe stringify
          'pending',
        ]
      );

      // Update queue depth metric
      await this.updateMetrics();

      endSpanSuccess(span);

      logger.info({
        id,
        invoiceId,
      }, 'Invoice added to offline queue');

      return id;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({
        invoiceId,
        error,
      }, 'Failed to enqueue offline request');

      throw error;
    }
  }

  /**
   * Get next batch of pending entries for processing
   *
   * @returns Array of queue entries
   */
  async getNextBatch(): Promise<OfflineQueueEntry[]> {
    const span = createSpan('get_next_batch');

    try {
      const result = await this.config.pool.query<any>(
        `SELECT id, invoice_id, request, retry_count, last_error,
                status, created_at, last_retry_at
         FROM offline_queue
         WHERE status = 'pending'
           AND retry_count < $1
           AND created_at > NOW() - INTERVAL '48 hours'
         ORDER BY created_at ASC
         LIMIT $2`,
        [this.config.maxRetries, this.config.batchSize]
      );

      const entries: OfflineQueueEntry[] = result.rows.map(row => ({
        id: row.id,
        invoiceId: row.invoice_id,
        request: row.request,
        retryCount: row.retry_count,
        lastError: row.last_error,
        createdAt: row.created_at,
        lastRetryAt: row.last_retry_at,
        status: row.status,
      }));

      endSpanSuccess(span);

      logger.debug({
        count: entries.length,
      }, 'Retrieved next batch from offline queue');

      return entries;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to get next batch from offline queue');
      throw error;
    }
  }

  /**
   * Mark entry as processing
   *
   * @param id - Queue entry ID
   */
  async markProcessing(id: string): Promise<void> {
    try {
      await this.config.pool.query(
        `UPDATE offline_queue
         SET status = 'processing',
             last_retry_at = NOW()
         WHERE id = $1`,
        [id]
      );

      logger.debug({ id }, 'Marked offline queue entry as processing');
    } catch (error) {
      logger.error({ id, error }, 'Failed to mark entry as processing');
      throw error;
    }
  }

  /**
   * IMPROVEMENT-026: Mark multiple entries as processing in a single query
   * Prevents N+1 query problem when processing batches
   *
   * @param ids - Array of queue entry IDs
   */
  async batchMarkProcessing(ids: string[]): Promise<void> {
    if (ids.length === 0) {
      return;
    }

    try {
      // Use ANY for array matching in WHERE clause
      await this.config.pool.query(
        `UPDATE offline_queue
         SET status = 'processing',
             last_retry_at = NOW()
         WHERE id = ANY($1)`,
        [ids]
      );

      logger.debug({ count: ids.length }, 'Marked offline queue entries as processing');
    } catch (error) {
      logger.error({ count: ids.length, error }, 'Failed to mark entries as processing');
      throw error;
    }
  }

  /**
   * Remove successfully processed entry
   *
   * @param id - Queue entry ID
   */
  async remove(id: string): Promise<void> {
    const span = createSpan('remove_offline_entry', { entry_id: id });

    try {
      await this.config.pool.query(
        `DELETE FROM offline_queue WHERE id = $1`,
        [id]
      );

      // Update queue depth metric
      await this.updateMetrics();

      endSpanSuccess(span);

      logger.info({ id }, 'Removed entry from offline queue');
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ id, error }, 'Failed to remove entry from offline queue');
      throw error;
    }
  }

  /**
   * IMPROVEMENT-026: Remove multiple successfully processed entries in a single query
   * Prevents N+1 query problem when cleaning up processed batches
   *
   * @param ids - Array of queue entry IDs
   */
  async batchRemove(ids: string[]): Promise<void> {
    const span = createSpan('batch_remove_offline_entries', {
      count: ids.length,
    });

    if (ids.length === 0) {
      endSpanSuccess(span);
      return;
    }

    try {
      // Use ANY for array matching in WHERE clause
      const result = await this.config.pool.query(
        `DELETE FROM offline_queue WHERE id = ANY($1)`,
        [ids]
      );

      logger.info({
        count: ids.length,
        deleted: result.rowCount,
      }, 'Removed entries from offline queue');

      // Update queue depth metric
      await this.updateMetrics();

      endSpanSuccess(span);
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ count: ids.length, error }, 'Failed to remove entries from offline queue');
      throw error;
    }
  }

  /**
   * Update entry after failed retry
   *
   * @param id - Queue entry ID
   * @param error - Error details
   */
  async updateRetry(id: string, error: FINAError): Promise<void> {
    const span = createSpan('update_retry', { entry_id: id });

    try {
      await this.config.pool.query(
        `UPDATE offline_queue
         SET retry_count = retry_count + 1,
             last_error = $2,
             status = CASE
               WHEN retry_count + 1 >= $3 THEN 'failed'
               ELSE 'pending'
             END,
             last_retry_at = NOW()
         WHERE id = $1`,
        [id, safeStringify(error), this.config.maxRetries] // IMPROVEMENT-028: Use safe stringify
      );

      endSpanSuccess(span);

      logger.debug({ id }, 'Updated offline queue entry after retry');
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ id, error }, 'Failed to update retry for offline entry');
      throw error;
    }
  }

  /**
   * Get queue statistics
   *
   * IMPROVEMENT-044: Safe array access with bounds checking
   * @returns Queue stats
   */
  async getStats(): Promise<{
    pending: number;
    processing: number;
    failed: number;
    oldestEntryAge: number | null;
  }> {
    try {
      const result = await this.config.pool.query<any>(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'pending') as pending,
          COUNT(*) FILTER (WHERE status = 'processing') as processing,
          COUNT(*) FILTER (WHERE status = 'failed') as failed,
          EXTRACT(EPOCH FROM (NOW() - MIN(created_at))) as oldest_age
        FROM offline_queue
      `);

      // IMPROVEMENT-044: Check array has elements before accessing
      const row = result.rows?.[0];
      if (!row) {
        logger.warn('No rows returned from offline queue stats query');
        return {
          pending: 0,
          processing: 0,
          failed: 0,
          oldestEntryAge: null,
        };
      }

      return {
        pending: parseInt(row.pending || 0) || 0,
        processing: parseInt(row.processing || 0) || 0,
        failed: parseInt(row.failed || 0) || 0,
        oldestEntryAge: row.oldest_age ? parseFloat(row.oldest_age) : null,
      };
    } catch (error) {
      logger.error({ error }, 'Failed to get offline queue stats');
      throw error;
    }
  }

  /**
   * Clean up expired entries (older than 48 hours)
   *
   * @returns Number of entries removed
   */
  async cleanupExpired(): Promise<number> {
    const span = createSpan('cleanup_expired_entries');

    try {
      logger.info('Cleaning up expired offline queue entries');

      const result = await this.config.pool.query(
        `DELETE FROM offline_queue
         WHERE created_at < NOW() - INTERVAL '48 hours'
         RETURNING id`,
      );

      const removedCount = result.rowCount || 0;

      // Update queue depth metric
      await this.updateMetrics();

      endSpanSuccess(span);

      logger.info({
        removedCount,
      }, 'Cleaned up expired offline queue entries');

      return removedCount;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to cleanup expired entries');
      throw error;
    }
  }

  /**
   * Update Prometheus metrics
   */
  private async updateMetrics(): Promise<void> {
    try {
      const stats = await this.getStats();

      offlineQueueDepth.set(stats.pending + stats.processing);

      if (stats.oldestEntryAge !== null) {
        offlineQueueMaxAge.set(stats.oldestEntryAge);
      }
    } catch (error) {
      logger.error({ error }, 'Failed to update offline queue metrics');
      // Don't throw - metrics update failure shouldn't break queue operations
    }
  }
}

/**
 * Create offline queue manager
 */
export function createOfflineQueueManager(
  config: OfflineQueueConfig
): OfflineQueueManager {
  return new OfflineQueueManager(config);
}
