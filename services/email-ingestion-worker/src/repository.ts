/**
 * Repository Module
 *
 * PostgreSQL repository for email processing state tracking.
 * - Track processed emails to prevent duplicates
 * - Store email and attachment metadata
 * - Query processing history
 */

import { Pool, PoolConfig } from 'pg';
import { logger, withSpan } from './observability';

/**
 * Processed email record
 */
export interface ProcessedEmail {
  id: number;
  uid: number;
  messageId: string;
  subject: string;
  from: string;
  to: string[];
  date: Date;
  attachmentCount: number;
  processedAt: Date;
  status: 'success' | 'error';
  errorMessage?: string;
}

/**
 * Processed attachment record
 */
export interface ProcessedAttachment {
  id: number;
  emailId: number;
  attachmentId: string;
  filename: string;
  contentType: string;
  size: number;
  checksum: string;
  publishedAt: Date;
}

/**
 * Email Repository
 */
export class EmailRepository {
  private pool: Pool;

  constructor(poolConfig: PoolConfig) {
    this.pool = new Pool(poolConfig);

    // Handle pool errors
    this.pool.on('error', (err) => {
      logger.error({ err }, 'Unexpected database pool error');
    });
  }

  /**
   * Initialize database schema
   */
  async initialize(): Promise<void> {
    return withSpan('repository.initialize', {}, async () => {
      logger.info('Initializing database schema');

      const client = await this.pool.connect();

      try {
        await client.query('BEGIN');

        // Create processed_emails table
        await client.query(`
          CREATE TABLE IF NOT EXISTS processed_emails (
            id SERIAL PRIMARY KEY,
            uid INTEGER NOT NULL,
            message_id VARCHAR(255) NOT NULL UNIQUE,
            subject TEXT,
            "from" VARCHAR(255),
            "to" TEXT[],
            date TIMESTAMP NOT NULL,
            attachment_count INTEGER DEFAULT 0,
            processed_at TIMESTAMP NOT NULL DEFAULT NOW(),
            status VARCHAR(50) NOT NULL DEFAULT 'success',
            error_message TEXT,
            CONSTRAINT unique_uid UNIQUE(uid)
          )
        `);

        // Create processed_attachments table
        await client.query(`
          CREATE TABLE IF NOT EXISTS processed_attachments (
            id SERIAL PRIMARY KEY,
            email_id INTEGER NOT NULL REFERENCES processed_emails(id) ON DELETE CASCADE,
            attachment_id VARCHAR(255) NOT NULL UNIQUE,
            filename VARCHAR(500),
            content_type VARCHAR(100),
            size INTEGER,
            checksum VARCHAR(64),
            published_at TIMESTAMP NOT NULL DEFAULT NOW()
          )
        `);

        // Create indexes
        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_processed_emails_message_id
          ON processed_emails(message_id)
        `);

        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_processed_emails_processed_at
          ON processed_emails(processed_at DESC)
        `);

        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_processed_attachments_email_id
          ON processed_attachments(email_id)
        `);

        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_processed_attachments_checksum
          ON processed_attachments(checksum)
        `);

        await client.query('COMMIT');

        logger.info('Database schema initialized successfully');
      } catch (err) {
        await client.query('ROLLBACK');
        logger.error({ err }, 'Failed to initialize database schema');
        throw err;
      } finally {
        client.release();
      }
    });
  }

  /**
   * Check if email has been processed
   */
  async isEmailProcessed(uid: number): Promise<boolean> {
    const result = await this.pool.query(
      'SELECT 1 FROM processed_emails WHERE uid = $1',
      [uid]
    );
    return result.rowCount !== null && result.rowCount > 0;
  }

  /**
   * Check if email message ID has been processed
   */
  async isMessageIdProcessed(messageId: string): Promise<boolean> {
    const result = await this.pool.query(
      'SELECT 1 FROM processed_emails WHERE message_id = $1',
      [messageId]
    );
    return result.rowCount !== null && result.rowCount > 0;
  }

  /**
   * Save processed email
   */
  async saveProcessedEmail(
    uid: number,
    messageId: string,
    subject: string,
    from: string,
    to: string[],
    date: Date,
    attachmentCount: number,
    status: 'success' | 'error' = 'success',
    errorMessage?: string
  ): Promise<number> {
    return withSpan(
      'repository.saveProcessedEmail',
      { uid, messageId },
      async () => {
        logger.debug({ uid, messageId }, 'Saving processed email');

        try {
          const result = await this.pool.query(
            `INSERT INTO processed_emails
             (uid, message_id, subject, "from", "to", date, attachment_count, status, error_message)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (message_id) DO UPDATE
             SET processed_at = NOW(),
                 status = EXCLUDED.status,
                 error_message = EXCLUDED.error_message
             RETURNING id`,
            [uid, messageId, subject, from, to, date, attachmentCount, status, errorMessage]
          );

          const emailId = result.rows[0].id;
          logger.info({ emailId, uid, messageId }, 'Processed email saved');
          return emailId;
        } catch (err) {
          logger.error({ err, uid, messageId }, 'Failed to save processed email');
          throw err;
        }
      }
    );
  }

  /**
   * Save processed attachment
   */
  async saveProcessedAttachment(
    emailId: number,
    attachmentId: string,
    filename: string,
    contentType: string,
    size: number,
    checksum: string
  ): Promise<void> {
    return withSpan(
      'repository.saveProcessedAttachment',
      { emailId, attachmentId },
      async () => {
        logger.debug({ emailId, attachmentId }, 'Saving processed attachment');

        try {
          await this.pool.query(
            `INSERT INTO processed_attachments
             (email_id, attachment_id, filename, content_type, size, checksum)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (attachment_id) DO NOTHING`,
            [emailId, attachmentId, filename, contentType, size, checksum]
          );

          logger.info({ emailId, attachmentId, filename }, 'Processed attachment saved');
        } catch (err) {
          logger.error({ err, emailId, attachmentId }, 'Failed to save processed attachment');
          throw err;
        }
      }
    );
  }

  /**
   * Get processed email by UID
   */
  async getProcessedEmailByUid(uid: number): Promise<ProcessedEmail | null> {
    const result = await this.pool.query(
      'SELECT * FROM processed_emails WHERE uid = $1',
      [uid]
    );

    if (result.rowCount === 0) {
      return null;
    }

    return this.mapToProcessedEmail(result.rows[0]);
  }

  /**
   * Get recent processed emails
   */
  async getRecentProcessedEmails(limit = 100): Promise<ProcessedEmail[]> {
    const result = await this.pool.query(
      'SELECT * FROM processed_emails ORDER BY processed_at DESC LIMIT $1',
      [limit]
    );

    return result.rows.map((row) => this.mapToProcessedEmail(row));
  }

  /**
   * Get attachments for email
   */
  async getAttachmentsForEmail(emailId: number): Promise<ProcessedAttachment[]> {
    const result = await this.pool.query(
      'SELECT * FROM processed_attachments WHERE email_id = $1',
      [emailId]
    );

    return result.rows.map((row) => this.mapToProcessedAttachment(row));
  }

  /**
   * Get processing statistics
   */
  async getStatistics(): Promise<{
    totalEmails: number;
    totalAttachments: number;
    successfulEmails: number;
    failedEmails: number;
  }> {
    const emailStats = await this.pool.query(`
      SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'success') as successful,
        COUNT(*) FILTER (WHERE status = 'error') as failed
      FROM processed_emails
    `);

    const attachmentStats = await this.pool.query(
      'SELECT COUNT(*) as total FROM processed_attachments'
    );

    return {
      totalEmails: parseInt(emailStats.rows[0].total, 10),
      successfulEmails: parseInt(emailStats.rows[0].successful, 10),
      failedEmails: parseInt(emailStats.rows[0].failed, 10),
      totalAttachments: parseInt(attachmentStats.rows[0].total, 10),
    };
  }

  /**
   * Close database connection pool
   */
  async close(): Promise<void> {
    logger.info('Closing database connection pool');
    await this.pool.end();
  }

  /**
   * Map database row to ProcessedEmail
   */
  private mapToProcessedEmail(row: any): ProcessedEmail {
    return {
      id: row.id,
      uid: row.uid,
      messageId: row.message_id,
      subject: row.subject,
      from: row.from,
      to: row.to,
      date: row.date,
      attachmentCount: row.attachment_count,
      processedAt: row.processed_at,
      status: row.status,
      errorMessage: row.error_message,
    };
  }

  /**
   * Map database row to ProcessedAttachment
   */
  private mapToProcessedAttachment(row: any): ProcessedAttachment {
    return {
      id: row.id,
      emailId: row.email_id,
      attachmentId: row.attachment_id,
      filename: row.filename,
      contentType: row.content_type,
      size: row.size,
      checksum: row.checksum,
      publishedAt: row.published_at,
    };
  }
}

/**
 * Create email repository from environment variables
 */
export function createEmailRepositoryFromEnv(): EmailRepository {
  const config: PoolConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    database: process.env.DB_NAME || 'eracun',
    user: process.env.DB_USER || 'eracun',
    password: process.env.DB_PASSWORD || '',
    max: parseInt(process.env.DB_POOL_MAX || '10', 10),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  };

  logger.info(
    {
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
    },
    'Creating email repository'
  );

  return new EmailRepository(config);
}
