/**
 * PostgreSQL Repository for KPD Codes
 *
 * Provides CRUD operations for the local KPD code cache.
 *
 * Security:
 * - Uses prepared statements (SQL injection prevention)
 * - Connection pooling (performance)
 * - Query timeouts (prevent hanging queries)
 *
 * Performance:
 * - Indexes on kpd_code and parent_code
 * - Connection pool (min: 10, max: 50)
 * - Query timeout: 10 seconds
 */

import { Pool, PoolClient, QueryResult } from 'pg';
import { logger, dbPoolSize, dbPoolIdle, kpdTotalCodes, kpdActiveCodes } from './observability';

// ============================================================================
// Type Definitions
// ============================================================================

export interface KPDCode {
  id?: bigint;
  kpd_code: string;
  description: string;
  level: number;
  parent_code: string | null;
  active: boolean;
  effective_from: Date;
  effective_to: Date | null;
  created_at?: Date;
  updated_at?: Date;
}

export interface SyncStatistics {
  total_codes: number;
  active_codes: number;
  inactive_codes: number;
}

// ============================================================================
// Database Connection Pool
// ============================================================================

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost:5432/eracun';
const POOL_MIN = parseInt(process.env.DATABASE_POOL_MIN || '10', 10);
const POOL_MAX = parseInt(process.env.DATABASE_POOL_MAX || '50', 10);
const QUERY_TIMEOUT = parseInt(process.env.DB_QUERY_TIMEOUT_MS || '10000', 10);

let pool: Pool | null = null;

/**
 * Initialize database connection pool
 */
export function initializePool(): Pool {
  if (pool) {
    return pool;
  }

  pool = new Pool({
    connectionString: DATABASE_URL,
    min: POOL_MIN,
    max: POOL_MAX,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    statement_timeout: QUERY_TIMEOUT,
  });

  pool.on('connect', () => {
    logger.debug('New database connection established');
    updatePoolMetrics();
  });

  pool.on('error', (err) => {
    logger.error({ err }, 'Unexpected database pool error');
  });

  logger.info(
    { pool_min: POOL_MIN, pool_max: POOL_MAX, query_timeout_ms: QUERY_TIMEOUT },
    'Database pool initialized'
  );

  return pool;
}

/**
 * Get database pool (initialize if needed)
 */
export function getPool(): Pool {
  if (!pool) {
    return initializePool();
  }
  return pool;
}

/**
 * Update pool metrics for Prometheus
 */
async function updatePoolMetrics(): Promise<void> {
  if (!pool) return;

  dbPoolSize.set(pool.totalCount);
  dbPoolIdle.set(pool.idleCount);
}

/**
 * Close database pool (graceful shutdown)
 */
export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    logger.info('Database pool closed');
    pool = null;
  }
}

/**
 * Health check - verify database connectivity
 */
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const pool = getPool();
    const result = await pool.query('SELECT 1 AS health');
    return result.rows.length === 1 && result.rows[0].health === 1;
  } catch (error) {
    logger.error({ err: error }, 'Database health check failed');
    return false;
  }
}

// ============================================================================
// Database Schema Initialization
// ============================================================================

/**
 * Create kpd_codes table if not exists
 */
export async function initializeSchema(): Promise<void> {
  const pool = getPool();

  const createTableSQL = `
    CREATE TABLE IF NOT EXISTS kpd_codes (
      id BIGSERIAL PRIMARY KEY,
      kpd_code VARCHAR(10) NOT NULL UNIQUE,
      description TEXT NOT NULL,
      level INT NOT NULL,
      parent_code VARCHAR(10),
      active BOOLEAN DEFAULT true,
      effective_from DATE NOT NULL,
      effective_to DATE,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_kpd_code ON kpd_codes(kpd_code, active);
    CREATE INDEX IF NOT EXISTS idx_kpd_parent ON kpd_codes(parent_code);
    CREATE INDEX IF NOT EXISTS idx_kpd_active ON kpd_codes(active);
    CREATE INDEX IF NOT EXISTS idx_kpd_description ON kpd_codes USING GIN(to_tsvector('english', description));
  `;

  try {
    await pool.query(createTableSQL);
    logger.info('Database schema initialized');
  } catch (error) {
    logger.error({ err: error }, 'Failed to initialize database schema');
    throw error;
  }
}

// ============================================================================
// CRUD Operations
// ============================================================================

/**
 * Insert a new KPD code
 */
export async function insertKPDCode(code: KPDCode): Promise<void> {
  const pool = getPool();

  const query = `
    INSERT INTO kpd_codes
      (kpd_code, description, level, parent_code, active, effective_from, effective_to)
    VALUES
      ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT (kpd_code) DO UPDATE
      SET description = EXCLUDED.description,
          level = EXCLUDED.level,
          parent_code = EXCLUDED.parent_code,
          active = EXCLUDED.active,
          effective_from = EXCLUDED.effective_from,
          effective_to = EXCLUDED.effective_to,
          updated_at = NOW()
  `;

  try {
    await pool.query(query, [
      code.kpd_code,
      code.description,
      code.level,
      code.parent_code,
      code.active,
      code.effective_from,
      code.effective_to,
    ]);

    logger.debug({ kpd_code: code.kpd_code }, 'KPD code inserted/updated');
    await updateCacheMetrics();
  } catch (error) {
    logger.error({ err: error, kpd_code: code.kpd_code }, 'Failed to insert KPD code');
    throw error;
  }
}

/**
 * Update an existing KPD code
 */
export async function updateKPDCode(code: KPDCode): Promise<void> {
  const pool = getPool();

  const query = `
    UPDATE kpd_codes
    SET description = $2,
        level = $3,
        parent_code = $4,
        active = $5,
        effective_from = $6,
        effective_to = $7,
        updated_at = NOW()
    WHERE kpd_code = $1
  `;

  try {
    const result = await pool.query(query, [
      code.kpd_code,
      code.description,
      code.level,
      code.parent_code,
      code.active,
      code.effective_from,
      code.effective_to,
    ]);

    if (result.rowCount === 0) {
      logger.warn({ kpd_code: code.kpd_code }, 'KPD code not found for update (inserting instead)');
      await insertKPDCode(code);
    } else {
      logger.debug({ kpd_code: code.kpd_code }, 'KPD code updated');
      await updateCacheMetrics();
    }
  } catch (error) {
    logger.error({ err: error, kpd_code: code.kpd_code }, 'Failed to update KPD code');
    throw error;
  }
}

/**
 * Soft delete a KPD code (set active = false)
 */
export async function softDeleteKPDCode(kpdCode: string): Promise<void> {
  const pool = getPool();

  const query = `
    UPDATE kpd_codes
    SET active = false,
        effective_to = NOW(),
        updated_at = NOW()
    WHERE kpd_code = $1
  `;

  try {
    const result = await pool.query(query, [kpdCode]);

    if (result.rowCount === 0) {
      logger.warn({ kpd_code: kpdCode }, 'KPD code not found for soft delete');
    } else {
      logger.debug({ kpd_code: kpdCode }, 'KPD code soft deleted');
      await updateCacheMetrics();
    }
  } catch (error) {
    logger.error({ err: error, kpd_code: kpdCode }, 'Failed to soft delete KPD code');
    throw error;
  }
}

/**
 * Get all KPD codes
 */
export async function getAllKPDCodes(): Promise<KPDCode[]> {
  const pool = getPool();

  const query = `
    SELECT id, kpd_code, description, level, parent_code, active, effective_from, effective_to, created_at, updated_at
    FROM kpd_codes
    ORDER BY kpd_code
  `;

  try {
    const result = await pool.query(query);
    return result.rows;
  } catch (error) {
    logger.error({ err: error }, 'Failed to get all KPD codes');
    throw error;
  }
}

/**
 * Get a single KPD code by code
 */
export async function getKPDCode(kpdCode: string): Promise<KPDCode | null> {
  const pool = getPool();

  const query = `
    SELECT id, kpd_code, description, level, parent_code, active, effective_from, effective_to, created_at, updated_at
    FROM kpd_codes
    WHERE kpd_code = $1
  `;

  try {
    const result = await pool.query(query, [kpdCode]);
    return result.rows.length > 0 ? result.rows[0] : null;
  } catch (error) {
    logger.error({ err: error, kpd_code: kpdCode }, 'Failed to get KPD code');
    throw error;
  }
}

/**
 * Get active KPD codes only
 */
export async function getActiveKPDCodes(): Promise<KPDCode[]> {
  const pool = getPool();

  const query = `
    SELECT id, kpd_code, description, level, parent_code, active, effective_from, effective_to, created_at, updated_at
    FROM kpd_codes
    WHERE active = true
    ORDER BY kpd_code
  `;

  try {
    const result = await pool.query(query);
    return result.rows;
  } catch (error) {
    logger.error({ err: error }, 'Failed to get active KPD codes');
    throw error;
  }
}

/**
 * Search KPD codes by description (full-text search)
 */
export async function searchKPDCodes(query: string, limit: number = 100): Promise<KPDCode[]> {
  const pool = getPool();

  const searchQuery = `
    SELECT id, kpd_code, description, level, parent_code, active, effective_from, effective_to, created_at, updated_at
    FROM kpd_codes
    WHERE to_tsvector('english', description) @@ plainto_tsquery('english', $1)
       OR description ILIKE $2
    ORDER BY kpd_code
    LIMIT $3
  `;

  try {
    const result = await pool.query(searchQuery, [query, `%${query}%`, limit]);
    logger.debug({ query, result_count: result.rows.length }, 'KPD code search performed');
    return result.rows;
  } catch (error) {
    logger.error({ err: error, query }, 'Failed to search KPD codes');
    throw error;
  }
}

/**
 * Get KPD codes with pagination
 */
export async function getKPDCodesPaginated(page: number = 1, pageSize: number = 100): Promise<{ codes: KPDCode[], total: number }> {
  const pool = getPool();

  const offset = (page - 1) * pageSize;

  const countQuery = 'SELECT COUNT(*) AS total FROM kpd_codes';
  const dataQuery = `
    SELECT id, kpd_code, description, level, parent_code, active, effective_from, effective_to, created_at, updated_at
    FROM kpd_codes
    ORDER BY kpd_code
    LIMIT $1 OFFSET $2
  `;

  try {
    const [countResult, dataResult] = await Promise.all([
      pool.query(countQuery),
      pool.query(dataQuery, [pageSize, offset]),
    ]);

    const total = parseInt(countResult.rows[0].total, 10);

    return {
      codes: dataResult.rows,
      total,
    };
  } catch (error) {
    logger.error({ err: error, page, pageSize }, 'Failed to get paginated KPD codes');
    throw error;
  }
}

/**
 * Get sync statistics
 */
export async function getSyncStatistics(): Promise<SyncStatistics> {
  const pool = getPool();

  const query = `
    SELECT
      COUNT(*) AS total_codes,
      SUM(CASE WHEN active = true THEN 1 ELSE 0 END) AS active_codes,
      SUM(CASE WHEN active = false THEN 1 ELSE 0 END) AS inactive_codes
    FROM kpd_codes
  `;

  try {
    const result = await pool.query(query);
    const stats = {
      total_codes: parseInt(result.rows[0].total_codes, 10),
      active_codes: parseInt(result.rows[0].active_codes, 10),
      inactive_codes: parseInt(result.rows[0].inactive_codes, 10),
    };

    return stats;
  } catch (error) {
    logger.error({ err: error }, 'Failed to get sync statistics');
    throw error;
  }
}

/**
 * Update cache metrics in Prometheus
 */
async function updateCacheMetrics(): Promise<void> {
  try {
    const stats = await getSyncStatistics();
    kpdTotalCodes.set(stats.total_codes);
    kpdActiveCodes.set(stats.active_codes);
  } catch (error) {
    logger.error({ err: error }, 'Failed to update cache metrics');
  }
}

/**
 * Bulk insert KPD codes (for initial sync)
 */
export async function bulkInsertKPDCodes(codes: KPDCode[]): Promise<void> {
  const pool = getPool();
  const client: PoolClient = await pool.connect();

  try {
    await client.query('BEGIN');

    for (const code of codes) {
      const query = `
        INSERT INTO kpd_codes
          (kpd_code, description, level, parent_code, active, effective_from, effective_to)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (kpd_code) DO UPDATE
          SET description = EXCLUDED.description,
              level = EXCLUDED.level,
              parent_code = EXCLUDED.parent_code,
              active = EXCLUDED.active,
              effective_from = EXCLUDED.effective_from,
              effective_to = EXCLUDED.effective_to,
              updated_at = NOW()
      `;

      await client.query(query, [
        code.kpd_code,
        code.description,
        code.level,
        code.parent_code,
        code.active,
        code.effective_from,
        code.effective_to,
      ]);
    }

    await client.query('COMMIT');
    logger.info({ count: codes.length }, 'Bulk insert completed');
    await updateCacheMetrics();
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error({ err: error, count: codes.length }, 'Bulk insert failed (rolled back)');
    throw error;
  } finally {
    client.release();
  }
}
