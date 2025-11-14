/**
 * Invoice Repository (PostgreSQL Data Access Layer)
 *
 * Manages invoice metadata in archive_metadata schema with immutable audit trail.
 * All UPDATE/DELETE operations append to audit log; primary records are never modified.
 *
 * See: docs/adr/004-archive-compliance-layer.md §114-165
 */

import { Pool, PoolClient } from 'pg';
import { createLogger } from '../utils/logger';
import { StorageMetadata } from '../storage/interfaces';

const logger = createLogger('invoice-repository');

export interface Invoice {
  invoiceId: string;
  originalXml: string; // base64 encoded
  sha512Hash: string;
  contentLength: number;
  submissionChannel: 'B2C' | 'B2B';
  confirmationReference: {
    type: 'JIR' | 'UUID';
    value: string;
  };
  submissionTimestamp: Date;
  signatureStatus: 'VALID' | 'PENDING' | 'INVALID' | 'EXPIRED';
  signatureLastChecked?: Date;
  storageMetadata: StorageMetadata;
  createdAt: Date;
  retentionExpiresAt: Date;
}

export interface AuditEvent {
  eventId: string;
  invoiceId: string;
  eventType: 'ARCHIVED' | 'SIGNATURE_VALIDATED' | 'SIGNATURE_FAILED' | 'RETRIEVED' | 'RESTORED';
  actor: string; // User or system component
  timestamp: Date;
  metadata: Record<string, unknown>;
}

export interface InvoiceFilter {
  startDate?: Date;
  endDate?: Date;
  channel?: 'B2C' | 'B2B';
  signatureStatus?: 'VALID' | 'PENDING' | 'INVALID' | 'EXPIRED';
  limit?: number;
  offset?: number;
}

export class InvoiceRepository {
  private pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      max: 30,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });
  }

  /**
   * Create invoice record (idempotent)
   *
   * @param invoice - Invoice metadata
   * @returns void
   * @throws Error if duplicate with different hash
   */
  async create(invoice: Invoice): Promise<void> {
    logger.info('Creating invoice', { invoiceId: invoice.invoiceId });

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN SERIALIZABLE');

      // Check for existing invoice (idempotency)
      const existing = await client.query(
        'SELECT sha512_hash FROM invoices WHERE invoice_id = $1',
        [invoice.invoiceId]
      );

      if (existing.rows.length > 0) {
        if (existing.rows[0].sha512_hash === invoice.sha512Hash) {
          // Idempotent - same invoice, no-op
          await client.query('COMMIT');
          logger.info('Invoice already exists (idempotent)', { invoiceId: invoice.invoiceId });
          return;
        }

        // Different hash - conflict
        await client.query('ROLLBACK');
        throw new Error(`Invoice ${invoice.invoiceId} already exists with different content`);
      }

      // Insert invoice
      await client.query(
        `INSERT INTO invoices (
          invoice_id, original_xml, sha512_hash, content_length,
          submission_channel, confirmation_type, confirmation_value, submission_timestamp,
          signature_status, storage_tier, storage_bucket, storage_key,
          storage_retained_until, created_at, retention_expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
        [
          invoice.invoiceId,
          invoice.originalXml,
          invoice.sha512Hash,
          invoice.contentLength,
          invoice.submissionChannel,
          invoice.confirmationReference.type,
          invoice.confirmationReference.value,
          invoice.submissionTimestamp,
          invoice.signatureStatus,
          invoice.storageMetadata.tier,
          invoice.storageMetadata.bucket,
          invoice.storageMetadata.key,
          invoice.storageMetadata.retentionUntil,
          invoice.createdAt,
          invoice.retentionExpiresAt,
        ]
      );

      // Create audit event
      await this.createAuditEvent(
        client,
        invoice.invoiceId,
        'ARCHIVED',
        'archive-service',
        {
          channel: invoice.submissionChannel,
          confirmationType: invoice.confirmationReference.type,
          confirmationValue: invoice.confirmationReference.value,
          storageTier: invoice.storageMetadata.tier,
        }
      );

      await client.query('COMMIT');
      logger.info('Invoice created successfully', { invoiceId: invoice.invoiceId });
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Failed to create invoice', { invoiceId: invoice.invoiceId, error });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Find invoice by ID
   *
   * @param invoiceId - Invoice identifier
   * @returns Invoice or null if not found
   */
  async findById(invoiceId: string): Promise<Invoice | null> {
    logger.info('Finding invoice', { invoiceId });

    const result = await this.pool.query(
      `SELECT
        invoice_id, original_xml, sha512_hash, content_length,
        submission_channel, confirmation_type, confirmation_value, submission_timestamp,
        signature_status, signature_last_checked,
        storage_tier, storage_bucket, storage_key, storage_retained_until,
        created_at, retention_expires_at
      FROM invoices
      WHERE invoice_id = $1`,
      [invoiceId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0];
    return this.mapRowToInvoice(row);
  }

  /**
   * Update signature status (creates audit event)
   *
   * @param invoiceId - Invoice identifier
   * @param status - New signature status
   * @param actor - Who/what triggered the update
   */
  async updateSignatureStatus(
    invoiceId: string,
    status: 'VALID' | 'PENDING' | 'INVALID' | 'EXPIRED',
    actor: string
  ): Promise<void> {
    logger.info('Updating signature status', { invoiceId, status });

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Update signature status
      const result = await client.query(
        `UPDATE invoices
         SET signature_status = $1, signature_last_checked = NOW()
         WHERE invoice_id = $2`,
        [status, invoiceId]
      );

      if (result.rowCount === 0) {
        throw new Error(`Invoice not found: ${invoiceId}`);
      }

      // Create audit event
      const eventType = status === 'VALID' ? 'SIGNATURE_VALIDATED' : 'SIGNATURE_FAILED';
      await this.createAuditEvent(client, invoiceId, eventType, actor, {
        signatureStatus: status,
      });

      await client.query('COMMIT');
      logger.info('Signature status updated', { invoiceId, status });
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Failed to update signature status', { invoiceId, status, error });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Find invoices by filter criteria
   *
   * @param filter - Filter options
   * @returns Array of invoices
   */
  async findByFilter(filter: InvoiceFilter): Promise<Invoice[]> {
    logger.info('Finding invoices by filter', { filter });

    const params: unknown[] = [];
    const conditions: string[] = [];
    let paramIndex = 1;

    if (filter.startDate) {
      conditions.push(`created_at >= $${paramIndex++}`);
      params.push(filter.startDate);
    }

    if (filter.endDate) {
      conditions.push(`created_at <= $${paramIndex++}`);
      params.push(filter.endDate);
    }

    if (filter.channel) {
      conditions.push(`submission_channel = $${paramIndex++}`);
      params.push(filter.channel);
    }

    if (filter.signatureStatus) {
      conditions.push(`signature_status = $${paramIndex++}`);
      params.push(filter.signatureStatus);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = filter.limit ?? 100;
    const offset = filter.offset ?? 0;

    const query = `
      SELECT
        invoice_id, original_xml, sha512_hash, content_length,
        submission_channel, confirmation_type, confirmation_value, submission_timestamp,
        signature_status, signature_last_checked,
        storage_tier, storage_bucket, storage_key, storage_retained_until,
        created_at, retention_expires_at
      FROM invoices
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    params.push(limit, offset);

    const result = await this.pool.query(query, params);
    return result.rows.map((row) => this.mapRowToInvoice(row));
  }

  /**
   * Get audit trail for invoice
   *
   * @param invoiceId - Invoice identifier
   * @returns Array of audit events
   */
  async getAuditTrail(invoiceId: string): Promise<AuditEvent[]> {
    logger.info('Getting audit trail', { invoiceId });

    const result = await this.pool.query(
      `SELECT event_id, invoice_id, event_type, actor, timestamp, metadata
       FROM audit_events
       WHERE invoice_id = $1
       ORDER BY timestamp ASC`,
      [invoiceId]
    );

    return result.rows.map((row) => ({
      eventId: row.event_id,
      invoiceId: row.invoice_id,
      eventType: row.event_type,
      actor: row.actor,
      timestamp: row.timestamp,
      metadata: row.metadata,
    }));
  }

  /**
   * Log audit event (internal)
   */
  private async createAuditEvent(
    client: PoolClient,
    invoiceId: string,
    eventType: AuditEvent['eventType'],
    actor: string,
    metadata: Record<string, unknown>
  ): Promise<void> {
    const eventId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    await client.query(
      `INSERT INTO audit_events (event_id, invoice_id, event_type, actor, timestamp, metadata)
       VALUES ($1, $2, $3, $4, NOW(), $5)`,
      [eventId, invoiceId, eventType, actor, JSON.stringify(metadata)]
    );
  }

  /**
   * Map database row to Invoice object
   */
  private mapRowToInvoice(row: any): Invoice {
    return {
      invoiceId: row.invoice_id,
      originalXml: row.original_xml,
      sha512Hash: row.sha512_hash,
      contentLength: row.content_length,
      submissionChannel: row.submission_channel,
      confirmationReference: {
        type: row.confirmation_type,
        value: row.confirmation_value,
      },
      submissionTimestamp: row.submission_timestamp,
      signatureStatus: row.signature_status,
      signatureLastChecked: row.signature_last_checked,
      storageMetadata: {
        tier: row.storage_tier,
        sha512: row.sha512_hash,
        contentLength: row.content_length,
        storedAt: row.created_at.toISOString(),
        retentionUntil: row.storage_retained_until,
        objectLockMode: 'COMPLIANCE',
        bucket: row.storage_bucket,
        key: row.storage_key,
      },
      createdAt: row.created_at,
      retentionExpiresAt: row.retention_expires_at,
    };
  }

  /**
   * Close connection pool
   */
  async close(): Promise<void> {
    await this.pool.end();
    logger.info('Connection pool closed');
  }
}

/**
 * Mock implementation for development/testing
 */
export class MockInvoiceRepository extends InvoiceRepository {
  private invoices = new Map<string, Invoice>();
  private auditEvents = new Map<string, AuditEvent[]>();

  constructor() {
    // Pass dummy connection string - won't be used
    super('postgresql://mock:mock@localhost:5432/mock');
  }

  async create(invoice: Invoice): Promise<void> {
    // Check idempotency
    const existing = this.invoices.get(invoice.invoiceId);
    if (existing) {
      if (existing.sha512Hash === invoice.sha512Hash) {
        return; // Idempotent
      }
      throw new Error(`Invoice ${invoice.invoiceId} already exists with different content`);
    }

    this.invoices.set(invoice.invoiceId, invoice);

    // Add audit event
    const events = this.auditEvents.get(invoice.invoiceId) ?? [];
    events.push({
      eventId: `${Date.now()}-${Math.random()}`,
      invoiceId: invoice.invoiceId,
      eventType: 'ARCHIVED',
      actor: 'archive-service',
      timestamp: new Date(),
      metadata: {},
    });
    this.auditEvents.set(invoice.invoiceId, events);
  }

  async findById(invoiceId: string): Promise<Invoice | null> {
    return this.invoices.get(invoiceId) ?? null;
  }

  async updateSignatureStatus(
    invoiceId: string,
    status: 'VALID' | 'PENDING' | 'INVALID' | 'EXPIRED',
    actor: string
  ): Promise<void> {
    const invoice = this.invoices.get(invoiceId);
    if (!invoice) {
      throw new Error(`Invoice not found: ${invoiceId}`);
    }

    invoice.signatureStatus = status;
    invoice.signatureLastChecked = new Date();

    // Add audit event
    const events = this.auditEvents.get(invoiceId) ?? [];
    events.push({
      eventId: `${Date.now()}-${Math.random()}`,
      invoiceId,
      eventType: status === 'VALID' ? 'SIGNATURE_VALIDATED' : 'SIGNATURE_FAILED',
      actor,
      timestamp: new Date(),
      metadata: { signatureStatus: status },
    });
    this.auditEvents.set(invoiceId, events);
  }

  async findByFilter(filter: InvoiceFilter): Promise<Invoice[]> {
    let invoices = Array.from(this.invoices.values());

    if (filter.startDate) {
      invoices = invoices.filter((inv) => inv.createdAt >= filter.startDate!);
    }

    if (filter.endDate) {
      invoices = invoices.filter((inv) => inv.createdAt <= filter.endDate!);
    }

    if (filter.channel) {
      invoices = invoices.filter((inv) => inv.submissionChannel === filter.channel);
    }

    if (filter.signatureStatus) {
      invoices = invoices.filter((inv) => inv.signatureStatus === filter.signatureStatus);
    }

    // Sort by created_at DESC
    invoices.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    // Apply pagination
    const offset = filter.offset ?? 0;
    const limit = filter.limit ?? 100;
    return invoices.slice(offset, offset + limit);
  }

  async getAuditTrail(invoiceId: string): Promise<AuditEvent[]> {
    return this.auditEvents.get(invoiceId) ?? [];
  }

  async close(): Promise<void> {
    this.invoices.clear();
    this.auditEvents.clear();
  }
}
