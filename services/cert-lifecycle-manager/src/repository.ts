import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import { CertificateInfo } from './cert-parser';
import { logger, databaseConnected, activeCertificates, createSpan, setSpanError } from './observability';

/**
 * Certificate database record
 */
export interface Certificate {
  id: number;
  certId: string;
  certType: 'production' | 'demo' | 'test';
  issuer: string;
  subjectDn: string;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  status: 'active' | 'expiring_soon' | 'expired' | 'revoked';
  certPath: string | null;
  passwordEncrypted: string | null;
  fingerprint: string;
  publicKey: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Certificate Repository
 *
 * Manages certificate inventory in PostgreSQL database.
 * Implements connection pooling and transaction support.
 */
export class CertificateRepository {
  private pool: Pool;

  constructor(databaseUrl?: string) {
    const connectionString = databaseUrl || process.env.DATABASE_URL;

    if (!connectionString) {
      throw new Error('DATABASE_URL environment variable is required');
    }

    this.pool = new Pool({
      connectionString,
      min: 10,
      max: 50,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });

    // Listen for pool errors
    this.pool.on('error', (err) => {
      logger.error({ error: err }, 'Unexpected database pool error');
      databaseConnected.set(0);
    });

    // Listen for pool connect
    this.pool.on('connect', () => {
      databaseConnected.set(1);
    });

    logger.info('Certificate repository initialized');
  }

  /**
   * Initialize database schema
   *
   * Creates certificates table if it doesn't exist.
   * Should be called on service startup.
   */
  async initializeSchema(): Promise<void> {
    const span = createSpan('initialize_schema');

    try {
      logger.info('Initializing database schema');

      const client = await this.pool.connect();

      try {
        await client.query('BEGIN');

        // Create certificates table
        await client.query(`
          CREATE TABLE IF NOT EXISTS certificates (
            id BIGSERIAL PRIMARY KEY,
            cert_id UUID UNIQUE NOT NULL,
            cert_type VARCHAR(50) NOT NULL,
            issuer VARCHAR(100) NOT NULL,
            subject_dn TEXT NOT NULL,
            serial_number VARCHAR(100) NOT NULL,
            not_before TIMESTAMP NOT NULL,
            not_after TIMESTAMP NOT NULL,
            status VARCHAR(50) NOT NULL,
            cert_path VARCHAR(255),
            password_encrypted TEXT,
            fingerprint VARCHAR(100) NOT NULL,
            public_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
          );
        `);

        // Create indexes
        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_cert_expiration
          ON certificates(not_after, status);
        `);

        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_cert_status
          ON certificates(status);
        `);

        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_cert_serial_number
          ON certificates(serial_number);
        `);

        await client.query('COMMIT');

        logger.info('Database schema initialized successfully');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to initialize database schema');
      throw error;
    }
  }

  /**
   * Save certificate to database
   *
   * @param certInfo - Parsed certificate information
   * @param certPath - File path where certificate is stored
   * @param passwordEncrypted - Encrypted certificate password
   * @returns Saved certificate record
   */
  async saveCertificate(
    certInfo: CertificateInfo,
    certPath: string,
    passwordEncrypted: string
  ): Promise<Certificate> {
    const span = createSpan('save_certificate', {
      serialNumber: certInfo.serialNumber,
    });

    try {
      logger.info(
        { serialNumber: certInfo.serialNumber },
        'Saving certificate to database'
      );

      const certId = uuidv4();
      const now = new Date();

      // Determine initial status
      const status = this.calculateStatus(certInfo.notAfter);

      const result = await this.pool.query<Certificate>(
        `
        INSERT INTO certificates (
          cert_id, cert_type, issuer, subject_dn, serial_number,
          not_before, not_after, status, cert_path, password_encrypted,
          fingerprint, public_key, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING *
        `,
        [
          certId,
          certInfo.certType,
          certInfo.issuer,
          certInfo.subjectDn,
          certInfo.serialNumber,
          certInfo.notBefore,
          certInfo.notAfter,
          status,
          certPath,
          passwordEncrypted,
          certInfo.fingerprint,
          certInfo.publicKey,
          now,
          now,
        ]
      );

      const cert = this.mapRowToCertificate(result.rows[0]);

      // Update metrics
      this.updateActiveCertificatesMetric();

      logger.info(
        {
          certId,
          serialNumber: cert.serialNumber,
          status: cert.status,
        },
        'Certificate saved successfully'
      );

      span.end();
      return cert;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to save certificate');
      throw error;
    }
  }

  /**
   * Get certificate by ID
   *
   * @param certId - Certificate UUID
   * @returns Certificate record or null if not found
   */
  async getCertificate(certId: string): Promise<Certificate | null> {
    const span = createSpan('get_certificate', { certId });

    try {
      const result = await this.pool.query<Certificate>(
        'SELECT * FROM certificates WHERE cert_id = $1',
        [certId]
      );

      if (result.rows.length === 0) {
        logger.warn({ certId }, 'Certificate not found');
        span.end();
        return null;
      }

      const cert = this.mapRowToCertificate(result.rows[0]);

      span.end();
      return cert;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error, certId }, 'Failed to get certificate');
      throw error;
    }
  }

  /**
   * Get all certificates
   *
   * @returns Array of all certificates
   */
  async getAllCertificates(): Promise<Certificate[]> {
    const span = createSpan('get_all_certificates');

    try {
      const result = await this.pool.query<Certificate>(
        'SELECT * FROM certificates ORDER BY created_at DESC'
      );

      const certs = result.rows.map((row) => this.mapRowToCertificate(row));

      logger.info({ count: certs.length }, 'Retrieved all certificates');

      span.end();
      return certs;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to get all certificates');
      throw error;
    }
  }

  /**
   * Get all active certificates
   *
   * @returns Array of active certificates
   */
  async getAllActiveCertificates(): Promise<Certificate[]> {
    const span = createSpan('get_active_certificates');

    try {
      const result = await this.pool.query<Certificate>(
        `SELECT * FROM certificates
         WHERE status IN ('active', 'expiring_soon')
         ORDER BY not_after ASC`
      );

      const certs = result.rows.map((row) => this.mapRowToCertificate(row));

      logger.info({ count: certs.length }, 'Retrieved active certificates');

      span.end();
      return certs;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to get active certificates');
      throw error;
    }
  }

  /**
   * Get certificates expiring within threshold
   *
   * @param daysThreshold - Number of days threshold
   * @returns Array of expiring certificates
   */
  async getExpiringCertificates(daysThreshold: number): Promise<Certificate[]> {
    const span = createSpan('get_expiring_certificates', { daysThreshold });

    try {
      const thresholdDate = new Date();
      thresholdDate.setDate(thresholdDate.getDate() + daysThreshold);

      const result = await this.pool.query<Certificate>(
        `SELECT * FROM certificates
         WHERE status IN ('active', 'expiring_soon')
         AND not_after <= $1
         ORDER BY not_after ASC`,
        [thresholdDate]
      );

      const certs = result.rows.map((row) => this.mapRowToCertificate(row));

      logger.info(
        { count: certs.length, daysThreshold },
        'Retrieved expiring certificates'
      );

      span.end();
      return certs;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to get expiring certificates');
      throw error;
    }
  }

  /**
   * Update certificate status
   *
   * @param certId - Certificate UUID
   * @param status - New status
   */
  async updateCertificateStatus(
    certId: string,
    status: 'active' | 'expiring_soon' | 'expired' | 'revoked'
  ): Promise<void> {
    const span = createSpan('update_certificate_status', { certId, status });

    try {
      const result = await this.pool.query(
        `UPDATE certificates
         SET status = $1, updated_at = NOW()
         WHERE cert_id = $2`,
        [status, certId]
      );

      if (result.rowCount === 0) {
        throw new Error(`Certificate not found: ${certId}`);
      }

      // Update metrics
      this.updateActiveCertificatesMetric();

      logger.info({ certId, status }, 'Certificate status updated');

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error, certId, status }, 'Failed to update certificate status');
      throw error;
    }
  }

  /**
   * Delete certificate (mark as revoked)
   *
   * @param certId - Certificate UUID
   */
  async revokeCertificate(certId: string): Promise<void> {
    await this.updateCertificateStatus(certId, 'revoked');
  }

  /**
   * Check database connection health
   *
   * @returns true if connected
   */
  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.pool.query('SELECT 1');
      databaseConnected.set(1);
      return result.rowCount === 1;
    } catch (error) {
      logger.error({ error }, 'Database health check failed');
      databaseConnected.set(0);
      return false;
    }
  }

  /**
   * Close database connection pool
   */
  async close(): Promise<void> {
    await this.pool.end();
    databaseConnected.set(0);
    logger.info('Database connection pool closed');
  }

  /**
   * Calculate certificate status based on expiration date
   *
   * @param notAfter - Certificate expiration date
   * @returns Certificate status
   */
  private calculateStatus(
    notAfter: Date
  ): 'active' | 'expiring_soon' | 'expired' {
    const now = new Date();
    const daysUntilExpiry = Math.floor(
      (notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
    );

    if (daysUntilExpiry < 0) {
      return 'expired';
    } else if (daysUntilExpiry <= 30) {
      return 'expiring_soon';
    } else {
      return 'active';
    }
  }

  /**
   * Update active certificates metric
   */
  private async updateActiveCertificatesMetric(): Promise<void> {
    try {
      const result = await this.pool.query<{ cert_type: string; count: string }>(
        `SELECT cert_type, COUNT(*) as count
         FROM certificates
         WHERE status IN ('active', 'expiring_soon')
         GROUP BY cert_type`
      );

      // Reset all labels
      activeCertificates.reset();

      // Set counts by type
      for (const row of result.rows) {
        activeCertificates.labels(row.cert_type).set(parseInt(row.count, 10));
      }
    } catch (error) {
      logger.error({ error }, 'Failed to update active certificates metric');
    }
  }

  /**
   * Map database row to Certificate object
   */
  private mapRowToCertificate(row: any): Certificate {
    return {
      id: row.id,
      certId: row.cert_id,
      certType: row.cert_type,
      issuer: row.issuer,
      subjectDn: row.subject_dn,
      serialNumber: row.serial_number,
      notBefore: new Date(row.not_before),
      notAfter: new Date(row.not_after),
      status: row.status,
      certPath: row.cert_path,
      passwordEncrypted: row.password_encrypted,
      fingerprint: row.fingerprint,
      publicKey: row.public_key,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }
}
