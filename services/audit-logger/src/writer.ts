import { Pool, PoolClient } from 'pg';
import crypto from 'crypto';
import {
  logger,
  auditEventsWritten,
  auditWriteDuration,
  auditDbConnections,
  createSpan,
  setSpanError,
} from './observability';

/**
 * Audit Event Interface (matches Kafka schema)
 */
export interface AuditEvent {
  event_id: string;              // UUID v4
  invoice_id: string;            // Invoice being processed
  service_name: string;          // Producer service
  event_type: string;            // Event category
  timestamp_ms: number;          // Unix timestamp
  user_id?: string;              // Authenticated user (optional)
  request_id: string;            // Trace ID
  metadata: Record<string, any>; // Event-specific data
  previous_hash?: string;        // Hash of previous event (for chaining)
  event_hash?: string;           // SHA-256 of this event (computed if not provided)
}

/**
 * PostgreSQL connection pool
 * Configuration via environment variables
 */
let pool: Pool | null = null;

export function initPool(): Pool {
  if (pool) {
    return pool;
  }

  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    min: parseInt(process.env.DATABASE_POOL_MIN || '10'),
    max: parseInt(process.env.DATABASE_POOL_MAX || '50'),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  // Monitor connection pool size
  pool.on('connect', () => {
    auditDbConnections.inc();
  });

  pool.on('remove', () => {
    auditDbConnections.dec();
  });

  pool.on('error', (err) => {
    logger.error({ err }, 'PostgreSQL pool error');
  });

  logger.info('PostgreSQL connection pool initialized');

  return pool;
}

/**
 * Get PostgreSQL pool (lazy initialization)
 */
export function getPool(): Pool {
  if (!pool) {
    return initPool();
  }
  return pool;
}

/**
 * Calculate SHA-256 hash for audit event
 * Used for hash chain integrity
 */
export function calculateEventHash(event: AuditEvent): string {
  // Concatenate critical fields for hashing
  const data = [
    event.event_id,
    event.invoice_id,
    event.service_name,
    event.event_type,
    event.timestamp_ms.toString(),
    event.request_id,
    JSON.stringify(event.metadata),
    event.previous_hash || '',
  ].join('|');

  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

/**
 * Get the hash of the last written audit event
 * Used to link new events in the hash chain
 */
export async function getLastEventHash(): Promise<string | null> {
  const span = createSpan('get_last_event_hash');

  try {
    const pool = getPool();
    const result = await pool.query(
      `SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1`
    );

    span.end();

    if (result.rows.length === 0) {
      logger.debug('No previous audit events found (first event)');
      return null;
    }

    return result.rows[0].event_hash as string;
  } catch (error) {
    setSpanError(span, error as Error);
    span.end();
    logger.error({ err: error }, 'Failed to get last event hash');
    throw error;
  }
}

/**
 * Write audit event to PostgreSQL (append-only)
 *
 * CRITICAL: This function performs INSERT ONLY (never UPDATE or DELETE)
 * Immutability enforced at database level (see README.md for table schema)
 */
export async function writeAuditEvent(event: AuditEvent): Promise<void> {
  const span = createSpan('write_audit_event', {
    'event.id': event.event_id,
    'event.type': event.event_type,
    'event.service': event.service_name,
  });

  const startTime = Date.now();

  // CRITICAL: Use transaction with SELECT FOR UPDATE to prevent race conditions
  // Without this, concurrent writes can create forked chains (both read same previous_hash)
  const pool = getPool();
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Lock the last event row to serialize hash chain writes
    // This prevents two concurrent writers from reading the same previous_hash
    const result = await client.query(
      `SELECT event_hash FROM audit_events
       ORDER BY id DESC LIMIT 1
       FOR UPDATE`
    );
    const previousHash = result.rows[0]?.event_hash || null;

    // Calculate event hash if not provided
    const eventHash = event.event_hash || calculateEventHash({
      ...event,
      previous_hash: previousHash || undefined
    });

    // Write to database (INSERT only - immutable)
    await client.query(
      `INSERT INTO audit_events
       (event_id, invoice_id, service_name, event_type, timestamp_ms,
        user_id, request_id, metadata, previous_hash, event_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        event.event_id,
        event.invoice_id,
        event.service_name,
        event.event_type,
        event.timestamp_ms,
        event.user_id || null,
        event.request_id,
        JSON.stringify(event.metadata),
        previousHash,
        eventHash,
      ]
    );

    await client.query('COMMIT');

    // Metrics
    const duration = (Date.now() - startTime) / 1000;
    auditWriteDuration.observe({ service: event.service_name }, duration);
    auditEventsWritten.inc({ service: event.service_name, event_type: event.event_type });

    span.end();

    logger.debug({
      event_id: event.event_id,
      invoice_id: event.invoice_id,
      service: event.service_name,
      event_type: event.event_type,
      duration_ms: duration * 1000,
    }, 'Audit event written');

  } catch (error) {
    // Rollback transaction on error
    await client.query('ROLLBACK');

    setSpanError(span, error as Error);
    span.end();

    logger.error({
      err: error,
      event_id: event.event_id,
      invoice_id: event.invoice_id,
      service: event.service_name,
      event_type: event.event_type,
    }, 'Failed to write audit event');

    throw error;
  } finally {
    // Always release client back to pool
    client.release();
  }
}

/**
 * Query audit events by invoice ID
 */
export async function getAuditTrail(invoiceId: string): Promise<AuditEvent[]> {
  const span = createSpan('get_audit_trail', {
    'invoice.id': invoiceId,
  });

  try {
    const pool = getPool();
    const result = await pool.query(
      `SELECT event_id, invoice_id, service_name, event_type, timestamp_ms,
              user_id, request_id, metadata, previous_hash, event_hash
       FROM audit_events
       WHERE invoice_id = $1
       ORDER BY timestamp_ms ASC`,
      [invoiceId]
    );

    span.setAttribute('events.count', result.rows.length);
    span.end();

    return result.rows.map(row => ({
      event_id: row.event_id,
      invoice_id: row.invoice_id,
      service_name: row.service_name,
      event_type: row.event_type,
      timestamp_ms: parseInt(row.timestamp_ms),
      user_id: row.user_id,
      request_id: row.request_id,
      metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata,
      previous_hash: row.previous_hash,
      event_hash: row.event_hash,
    }));

  } catch (error) {
    setSpanError(span, error as Error);
    span.end();
    logger.error({ err: error, invoice_id: invoiceId }, 'Failed to get audit trail');
    throw error;
  }
}

/**
 * Query audit events with filters
 */
export interface AuditQueryFilters {
  service_name?: string;
  event_type?: string;
  start_timestamp_ms?: number;
  end_timestamp_ms?: number;
  limit?: number;
  offset?: number;
}

export async function queryAuditEvents(filters: AuditQueryFilters): Promise<{ events: AuditEvent[]; total: number }> {
  const span = createSpan('query_audit_events');

  try {
    const pool = getPool();
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    // Build WHERE clause
    if (filters.service_name) {
      conditions.push(`service_name = $${paramIndex++}`);
      params.push(filters.service_name);
    }
    if (filters.event_type) {
      conditions.push(`event_type = $${paramIndex++}`);
      params.push(filters.event_type);
    }
    if (filters.start_timestamp_ms) {
      conditions.push(`timestamp_ms >= $${paramIndex++}`);
      params.push(filters.start_timestamp_ms);
    }
    if (filters.end_timestamp_ms) {
      conditions.push(`timestamp_ms <= $${paramIndex++}`);
      params.push(filters.end_timestamp_ms);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Count query
    const countResult = await pool.query(`SELECT COUNT(*) FROM audit_events ${whereClause}`, params);
    const total = parseInt(countResult.rows[0].count);

    // Data query with pagination
    const limit = filters.limit || 100;
    const offset = filters.offset || 0;
    params.push(limit, offset);

    const dataResult = await pool.query(
      `SELECT event_id, invoice_id, service_name, event_type, timestamp_ms,
              user_id, request_id, metadata, previous_hash, event_hash
       FROM audit_events ${whereClause}
       ORDER BY timestamp_ms DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      params
    );

    span.setAttribute('events.count', dataResult.rows.length);
    span.setAttribute('events.total', total);
    span.end();

    const events = dataResult.rows.map(row => ({
      event_id: row.event_id,
      invoice_id: row.invoice_id,
      service_name: row.service_name,
      event_type: row.event_type,
      timestamp_ms: parseInt(row.timestamp_ms),
      user_id: row.user_id,
      request_id: row.request_id,
      metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata,
      previous_hash: row.previous_hash,
      event_hash: row.event_hash,
    }));

    return { events, total };

  } catch (error) {
    setSpanError(span, error as Error);
    span.end();
    logger.error({ err: error, filters }, 'Failed to query audit events');
    throw error;
  }
}

/**
 * Close database connection pool
 */
export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    logger.info('PostgreSQL connection pool closed');
  }
}
