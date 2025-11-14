import { Pool, PoolConfig, QueryResult } from 'pg';
import pino from 'pino';

export type InvoiceStatus =
  | 'QUEUED'
  | 'PROCESSING'
  | 'VALIDATING'
  | 'VALIDATED'
  | 'COMPLETED'
  | 'FAILED';

export interface InvoiceRecord {
  id: string;
  idempotencyKey: string;
  invoiceNumber: string;
  supplierOIB: string;
  buyerOIB: string;
  totalAmount: number;
  currency: string;
  status: InvoiceStatus;
  createdAt: Date;
  updatedAt: Date | null;
}

export interface CreateInvoiceRecordInput {
  id: string;
  idempotencyKey: string;
  invoiceNumber: string;
  supplierOIB: string;
  buyerOIB: string;
  totalAmount: number;
  currency: string;
  status: InvoiceStatus;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface InvoiceRepository {
  saveInvoice(data: CreateInvoiceRecordInput): Promise<InvoiceRecord>;
  findById(id: string): Promise<InvoiceRecord | null>;
  findByIdempotencyKey(idempotencyKey: string): Promise<InvoiceRecord | null>;
  updateStatus(id: string, status: InvoiceStatus): Promise<void>;
  close(): Promise<void>;
}

export interface InvoiceRepositoryOptions {
  connectionString?: string;
  poolConfig?: PoolConfig;
}

export class PostgresInvoiceRepository implements InvoiceRepository {
  private readonly pool: Pool;
  private readonly logger = pino({ name: 'invoice-repository' });

  constructor(options: InvoiceRepositoryOptions = {}) {
    const connectionString = options.connectionString || process.env.DATABASE_URL;

    if (!connectionString) {
      throw new Error('DATABASE_URL environment variable is required');
    }

    const poolOptions: PoolConfig = {
      connectionString,
      max: parseInt(process.env.DATABASE_POOL_SIZE || '20', 10),
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
      ...options.poolConfig,
    };

    this.pool = new Pool(poolOptions);
  }

  async saveInvoice(data: CreateInvoiceRecordInput): Promise<InvoiceRecord> {
    const createdAt = data.createdAt || new Date();
    const updatedAt = data.updatedAt || createdAt;

    try {
      const result = await this.pool.query(
        `INSERT INTO invoices (
          id,
          idempotency_key,
          invoice_number,
          supplier_oib,
          buyer_oib,
          total_amount,
          currency,
          status,
          created_at,
          updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        RETURNING *`,
        [
          data.id,
          data.idempotencyKey,
          data.invoiceNumber,
          data.supplierOIB,
          data.buyerOIB,
          data.totalAmount,
          data.currency,
          data.status,
          createdAt,
          updatedAt,
        ]
      );

      return this.mapRow(result);
    } catch (error: any) {
      if (this.isUniqueViolation(error)) {
        this.logger.warn(
          {
            id: data.id,
            idempotencyKey: data.idempotencyKey,
          },
          'Duplicate invoice detected via unique constraint'
        );

        const existing = await this.findByIdempotencyKey(data.idempotencyKey);
        if (existing) {
          return existing;
        }
      }

      this.logger.error({ error, invoiceId: data.id }, 'Failed to persist invoice metadata');
      throw error;
    }
  }

  async findById(id: string): Promise<InvoiceRecord | null> {
    const result = await this.pool.query('SELECT * FROM invoices WHERE id = $1', [id]);
    return result.rows[0] ? this.mapRow(result) : null;
  }

  async findByIdempotencyKey(idempotencyKey: string): Promise<InvoiceRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM invoices WHERE idempotency_key = $1',
      [idempotencyKey]
    );
    return result.rows[0] ? this.mapRow(result) : null;
  }

  async updateStatus(id: string, status: InvoiceStatus): Promise<void> {
    await this.pool.query(
      'UPDATE invoices SET status = $1, updated_at = $2 WHERE id = $3',
      [status, new Date(), id]
    );
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  private mapRow(result: QueryResult): InvoiceRecord {
    const row = result.rows[0];
    return {
      id: row.id,
      idempotencyKey: row.idempotency_key,
      invoiceNumber: row.invoice_number,
      supplierOIB: row.supplier_oib,
      buyerOIB: row.buyer_oib,
      totalAmount: Number(row.total_amount),
      currency: row.currency,
      status: row.status,
      createdAt: new Date(row.created_at),
      updatedAt: row.updated_at ? new Date(row.updated_at) : null,
    };
  }

  private isUniqueViolation(error: any): boolean {
    return error && typeof error === 'object' && error.code === '23505';
  }
}
