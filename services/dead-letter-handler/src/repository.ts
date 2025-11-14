/**
 * Manual Review Repository
 *
 * PostgreSQL persistence for errors requiring manual review
 *
 * Schema:
 * - manual_review_errors: Error details and status
 *
 * See: README.md §3.2 for schema definition
 */

import { Pool, PoolClient } from 'pg';
import { ManualReviewError, ErrorStats, ErrorClassification } from './types';
import { createLogger } from './utils/logger';

const logger = createLogger('repository');

export class ManualReviewRepository {
  private pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

    logger.info('Repository initialized', { database: connectionString.split('@')[1] });
  }

  /**
   * Create new manual review error
   *
   * @param error - Error details
   */
  async createManualReviewError(error: ManualReviewError): Promise<void> {
    logger.info('Creating manual review error', {
      errorId: error.error_id,
      classification: error.error_classification,
    });

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      await client.query(
        `INSERT INTO manual_review_errors (
          error_id, invoice_id, service_name, error_classification,
          original_message, original_queue, error_reason, error_stack,
          retry_count, status, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
        [
          error.error_id,
          error.invoice_id,
          error.service_name,
          error.error_classification,
          error.original_message,
          error.original_queue,
          error.error_reason,
          error.error_stack,
          error.retry_count,
          error.status,
        ]
      );

      await client.query('COMMIT');
      logger.info('Manual review error created', { errorId: error.error_id });
    } catch (err) {
      await client.query('ROLLBACK');
      logger.error('Failed to create manual review error', { error: err });
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Get manual review error by ID
   *
   * @param errorId - Error ID
   * @returns Error or null if not found
   */
  async getError(errorId: string): Promise<ManualReviewError | null> {
    const result = await this.pool.query(
      `SELECT
        id, error_id, invoice_id, service_name, error_classification,
        original_message, original_queue, error_reason, error_stack,
        retry_count, status, created_at, resolved_at, resolved_by
      FROM manual_review_errors
      WHERE error_id = $1`,
      [errorId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRowToError(result.rows[0]);
  }

  /**
   * List all pending errors
   *
   * @param limit - Maximum number of results
   * @param offset - Offset for pagination
   * @returns Array of errors
   */
  async listErrors(limit = 100, offset = 0): Promise<ManualReviewError[]> {
    const result = await this.pool.query(
      `SELECT
        id, error_id, invoice_id, service_name, error_classification,
        original_message, original_queue, error_reason, error_stack,
        retry_count, status, created_at, resolved_at, resolved_by
      FROM manual_review_errors
      ORDER BY created_at DESC
      LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return result.rows.map((row) => this.mapRowToError(row));
  }

  /**
   * List errors by status
   *
   * @param status - Error status
   * @param limit - Maximum number of results
   * @param offset - Offset for pagination
   * @returns Array of errors
   */
  async listByStatus(
    status: 'pending' | 'in_review' | 'resolved',
    limit = 100,
    offset = 0
  ): Promise<ManualReviewError[]> {
    const result = await this.pool.query(
      `SELECT
        id, error_id, invoice_id, service_name, error_classification,
        original_message, original_queue, error_reason, error_stack,
        retry_count, status, created_at, resolved_at, resolved_by
      FROM manual_review_errors
      WHERE status = $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3`,
      [status, limit, offset]
    );

    return result.rows.map((row) => this.mapRowToError(row));
  }

  /**
   * Mark error as resolved
   *
   * @param errorId - Error ID
   * @param resolvedBy - Who resolved it (user/admin)
   */
  async resolveError(errorId: string, resolvedBy: string): Promise<void> {
    logger.info('Resolving error', { errorId, resolvedBy });

    const result = await this.pool.query(
      `UPDATE manual_review_errors
       SET status = 'resolved', resolved_at = NOW(), resolved_by = $1
       WHERE error_id = $2`,
      [resolvedBy, errorId]
    );

    if (result.rowCount === 0) {
      throw new Error(`Error not found: ${errorId}`);
    }

    logger.info('Error resolved', { errorId });
  }

  /**
   * Mark error as in review
   *
   * @param errorId - Error ID
   */
  async markInReview(errorId: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE manual_review_errors
       SET status = 'in_review'
       WHERE error_id = $1`,
      [errorId]
    );

    if (result.rowCount === 0) {
      throw new Error(`Error not found: ${errorId}`);
    }

    logger.info('Error marked as in review', { errorId });
  }

  /**
   * Get error statistics
   *
   * @returns Error statistics by classification, service, and status
   */
  async getStats(): Promise<ErrorStats> {
    const [totalResult, classificationResult, serviceResult, statusResult] = await Promise.all([
      // Total errors
      this.pool.query('SELECT COUNT(*) as count FROM manual_review_errors'),

      // By classification
      this.pool.query(
        `SELECT error_classification, COUNT(*) as count
         FROM manual_review_errors
         GROUP BY error_classification`
      ),

      // By service
      this.pool.query(
        `SELECT service_name, COUNT(*) as count
         FROM manual_review_errors
         GROUP BY service_name
         ORDER BY count DESC
         LIMIT 20`
      ),

      // By status
      this.pool.query(
        `SELECT status, COUNT(*) as count
         FROM manual_review_errors
         GROUP BY status`
      ),
    ]);

    const totalErrors = parseInt(totalResult.rows[0].count, 10);

    const byClassification: Record<ErrorClassification, number> = {
      [ErrorClassification.TRANSIENT]: 0,
      [ErrorClassification.BUSINESS]: 0,
      [ErrorClassification.TECHNICAL]: 0,
      [ErrorClassification.UNKNOWN]: 0,
    };

    classificationResult.rows.forEach((row) => {
      byClassification[row.error_classification as ErrorClassification] = parseInt(row.count, 10);
    });

    const byService: Record<string, number> = {};
    serviceResult.rows.forEach((row) => {
      byService[row.service_name] = parseInt(row.count, 10);
    });

    const byStatus: Record<string, number> = {};
    let pendingCount = 0;
    let resolvedCount = 0;

    statusResult.rows.forEach((row) => {
      const count = parseInt(row.count, 10);
      byStatus[row.status] = count;

      if (row.status === 'pending') pendingCount = count;
      if (row.status === 'resolved') resolvedCount = count;
    });

    return {
      total_errors: totalErrors,
      by_classification: byClassification,
      by_service: byService,
      by_status: byStatus,
      pending_count: pendingCount,
      resolved_count: resolvedCount,
    };
  }

  /**
   * Delete old resolved errors (cleanup)
   *
   * @param daysOld - Delete errors resolved more than this many days ago
   * @returns Number of deleted errors
   */
  async cleanupOldErrors(daysOld = 90): Promise<number> {
    logger.info('Cleaning up old errors', { daysOld });

    const result = await this.pool.query(
      `DELETE FROM manual_review_errors
       WHERE status = 'resolved'
       AND resolved_at < NOW() - INTERVAL '${daysOld} days'`
    );

    const deletedCount = result.rowCount || 0;
    logger.info('Old errors cleaned up', { deletedCount });

    return deletedCount;
  }

  /**
   * Map database row to ManualReviewError
   */
  private mapRowToError(row: any): ManualReviewError {
    return {
      id: row.id,
      error_id: row.error_id,
      invoice_id: row.invoice_id,
      service_name: row.service_name,
      error_classification: row.error_classification,
      original_message: row.original_message,
      original_queue: row.original_queue,
      error_reason: row.error_reason,
      error_stack: row.error_stack,
      retry_count: row.retry_count,
      status: row.status,
      created_at: row.created_at,
      resolved_at: row.resolved_at,
      resolved_by: row.resolved_by,
    };
  }

  /**
   * Close connection pool
   */
  async close(): Promise<void> {
    await this.pool.end();
    logger.info('Repository connection pool closed');
  }
}

/**
 * Mock repository for development/testing
 */
export class MockManualReviewRepository extends ManualReviewRepository {
  private errors = new Map<string, ManualReviewError>();

  constructor() {
    // Pass dummy connection string - won't be used
    super('postgresql://mock:mock@localhost:5432/mock');
  }

  async createManualReviewError(error: ManualReviewError): Promise<void> {
    this.errors.set(error.error_id, {
      ...error,
      id: this.errors.size + 1,
      created_at: new Date(),
    });
  }

  async getError(errorId: string): Promise<ManualReviewError | null> {
    return this.errors.get(errorId) || null;
  }

  async listErrors(limit = 100, offset = 0): Promise<ManualReviewError[]> {
    const allErrors = Array.from(this.errors.values());
    return allErrors.slice(offset, offset + limit);
  }

  async listByStatus(
    status: 'pending' | 'in_review' | 'resolved',
    limit = 100,
    offset = 0
  ): Promise<ManualReviewError[]> {
    const filtered = Array.from(this.errors.values()).filter((e) => e.status === status);
    return filtered.slice(offset, offset + limit);
  }

  async resolveError(errorId: string, resolvedBy: string): Promise<void> {
    const error = this.errors.get(errorId);
    if (!error) {
      throw new Error(`Error not found: ${errorId}`);
    }
    error.status = 'resolved';
    error.resolved_at = new Date();
    error.resolved_by = resolvedBy;
  }

  async markInReview(errorId: string): Promise<void> {
    const error = this.errors.get(errorId);
    if (!error) {
      throw new Error(`Error not found: ${errorId}`);
    }
    error.status = 'in_review';
  }

  async getStats(): Promise<ErrorStats> {
    const allErrors = Array.from(this.errors.values());

    const byClassification: Record<ErrorClassification, number> = {
      [ErrorClassification.TRANSIENT]: 0,
      [ErrorClassification.BUSINESS]: 0,
      [ErrorClassification.TECHNICAL]: 0,
      [ErrorClassification.UNKNOWN]: 0,
    };

    const byService: Record<string, number> = {};
    const byStatus: Record<string, number> = {};
    let pendingCount = 0;
    let resolvedCount = 0;

    allErrors.forEach((error) => {
      byClassification[error.error_classification]++;

      byService[error.service_name] = (byService[error.service_name] || 0) + 1;

      byStatus[error.status] = (byStatus[error.status] || 0) + 1;

      if (error.status === 'pending') pendingCount++;
      if (error.status === 'resolved') resolvedCount++;
    });

    return {
      total_errors: allErrors.length,
      by_classification: byClassification,
      by_service: byService,
      by_status: byStatus,
      pending_count: pendingCount,
      resolved_count: resolvedCount,
    };
  }

  async cleanupOldErrors(daysOld = 90): Promise<number> {
    const now = Date.now();
    const cutoff = now - daysOld * 24 * 60 * 60 * 1000;

    let deletedCount = 0;
    for (const [errorId, error] of this.errors.entries()) {
      if (error.status === 'resolved' && error.resolved_at && error.resolved_at.getTime() < cutoff) {
        this.errors.delete(errorId);
        deletedCount++;
      }
    }

    return deletedCount;
  }

  async close(): Promise<void> {
    this.errors.clear();
  }
}
