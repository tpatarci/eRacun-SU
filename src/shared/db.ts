import { Pool, PoolClient, QueryResult } from 'pg';
import { logger } from './logger.js';

let pool: Pool | null = null;

export function initDb(databaseUrl: string): void {
  if (pool) {
    throw new Error('Database already initialized');
  }
  pool = new Pool({
    connectionString: databaseUrl,
    max: 10,
  });

  pool.on('error', (err) => {
    logger.error({ err }, 'Unexpected PostgreSQL pool error');
  });
}

export async function query(text: string, params?: unknown[]): Promise<QueryResult> {
  if (!pool) throw new Error('Database not initialized. Call initDb() first.');
  return pool.query(text, params);
}

/**
 * Execute a query with automatic user_id filtering.
 * The user_id is prepended to params as $1, so queries should include
 * a WHERE clause like "WHERE user_id = $1" or "AND user_id = $1".
 */
export async function userQuery(
  userId: string,
  text: string,
  params?: unknown[]
): Promise<QueryResult> {
  if (!pool) throw new Error('Database not initialized. Call initDb() first.');
  const allParams = [userId, ...(params || [])];
  logger.debug({ userId, query: text }, 'Executing user-scoped query');
  return pool.query(text, allParams);
}

export async function getClient(): Promise<PoolClient> {
  if (!pool) throw new Error('Database not initialized. Call initDb() first.');
  return pool.connect();
}

export function getPool(): Pool {
  if (!pool) throw new Error('Database not initialized. Call initDb() first.');
  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
