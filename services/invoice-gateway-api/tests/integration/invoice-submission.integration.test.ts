/**
 * Integration Tests for Invoice Submission Pipeline
 * Uses Testcontainers to spin up real PostgreSQL instance
 */

import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { InvoiceGenerator, XMLGenerator } from '@eracun/test-fixtures';
import { v4 as uuidv4 } from 'uuid';

describe('Invoice Submission Integration Tests', () => {
  let postgresContainer: StartedPostgreSqlContainer;
  let connectionString: string;

  // Setup PostgreSQL container before all tests
  beforeAll(async () => {
    console.log('Starting PostgreSQL container...');
    postgresContainer = await new PostgreSqlContainer('postgres:15-alpine')
      .withDatabase('eracun_test')
      .withUsername('testuser')
      .withPassword('testpass')
      .withExposedPorts(5432)
      .start();

    connectionString = postgresContainer.getConnectionUri();
    console.log(`PostgreSQL started at: ${connectionString}`);

    // Initialize database schema
    await initializeSchema(connectionString);
  }, 60000); // 60 second timeout for container startup

  // Cleanup after all tests
  afterAll(async () => {
    if (postgresContainer) {
      console.log('Stopping PostgreSQL container...');
      await postgresContainer.stop();
    }
  }, 30000);

  describe('Database Persistence', () => {
    it('should persist invoice metadata to database', async () => {
      const invoice = InvoiceGenerator.generateValidInvoice();
      const invoiceId = uuidv4();
      const idempotencyKey = uuidv4();

      // Simulate invoice submission
      await saveInvoiceMetadata(connectionString, {
        id: invoiceId,
        idempotencyKey,
        invoiceNumber: invoice.invoiceNumber,
        supplierOIB: invoice.oib.supplier,
        buyerOIB: invoice.oib.buyer,
        totalAmount: invoice.amounts.gross,
        currency: invoice.amounts.currency,
        status: 'QUEUED',
        createdAt: new Date(),
      });

      // Verify data was persisted
      const retrieved = await getInvoiceMetadata(connectionString, invoiceId);

      expect(retrieved).toBeDefined();
      expect(retrieved.id).toBe(invoiceId);
      expect(retrieved.invoiceNumber).toBe(invoice.invoiceNumber);
      expect(retrieved.supplierOIB).toBe(invoice.oib.supplier);
      expect(retrieved.status).toBe('QUEUED');
    });

    it('should enforce unique constraint on idempotency keys', async () => {
      const invoice = InvoiceGenerator.generateValidInvoice();
      const idempotencyKey = uuidv4();

      // First submission
      await saveInvoiceMetadata(connectionString, {
        id: uuidv4(),
        idempotencyKey,
        invoiceNumber: invoice.invoiceNumber,
        supplierOIB: invoice.oib.supplier,
        buyerOIB: invoice.oib.buyer,
        totalAmount: invoice.amounts.gross,
        currency: invoice.amounts.currency,
        status: 'QUEUED',
        createdAt: new Date(),
      });

      // Second submission with same idempotency key should fail
      await expect(
        saveInvoiceMetadata(connectionString, {
          id: uuidv4(),
          idempotencyKey, // Same key
          invoiceNumber: 'INV-DIFFERENT',
          supplierOIB: invoice.oib.supplier,
          buyerOIB: invoice.oib.buyer,
          totalAmount: 5000,
          currency: 'EUR',
          status: 'QUEUED',
          createdAt: new Date(),
        })
      ).rejects.toThrow();
    });

    it('should query invoices by status', async () => {
      const invoice1 = InvoiceGenerator.generateValidInvoice();
      const invoice2 = InvoiceGenerator.generateValidInvoice();

      const id1 = uuidv4();
      const id2 = uuidv4();

      // Save invoices with different statuses
      await saveInvoiceMetadata(connectionString, {
        id: id1,
        idempotencyKey: uuidv4(),
        invoiceNumber: invoice1.invoiceNumber,
        supplierOIB: invoice1.oib.supplier,
        buyerOIB: invoice1.oib.buyer,
        totalAmount: invoice1.amounts.gross,
        currency: invoice1.amounts.currency,
        status: 'QUEUED',
        createdAt: new Date(),
      });

      await saveInvoiceMetadata(connectionString, {
        id: id2,
        idempotencyKey: uuidv4(),
        invoiceNumber: invoice2.invoiceNumber,
        supplierOIB: invoice2.oib.supplier,
        buyerOIB: invoice2.oib.buyer,
        totalAmount: invoice2.amounts.gross,
        currency: invoice2.amounts.currency,
        status: 'VALIDATING',
        createdAt: new Date(),
      });

      // Query by status
      const queuedInvoices = await getInvoicesByStatus(connectionString, 'QUEUED');
      const validatingInvoices = await getInvoicesByStatus(connectionString, 'VALIDATING');

      expect(queuedInvoices.some((inv) => inv.id === id1)).toBe(true);
      expect(validatingInvoices.some((inv) => inv.id === id2)).toBe(true);
    });

    it('should update invoice status', async () => {
      const invoice = InvoiceGenerator.generateValidInvoice();
      const invoiceId = uuidv4();

      await saveInvoiceMetadata(connectionString, {
        id: invoiceId,
        idempotencyKey: uuidv4(),
        invoiceNumber: invoice.invoiceNumber,
        supplierOIB: invoice.oib.supplier,
        buyerOIB: invoice.oib.buyer,
        totalAmount: invoice.amounts.gross,
        currency: invoice.amounts.currency,
        status: 'QUEUED',
        createdAt: new Date(),
      });

      // Update status
      await updateInvoiceStatus(connectionString, invoiceId, 'VALIDATED');

      // Verify update
      const updated = await getInvoiceMetadata(connectionString, invoiceId);
      expect(updated.status).toBe('VALIDATED');
    });
  });

  describe('Transaction Handling', () => {
    it('should rollback on transaction failure', async () => {
      const invoice = InvoiceGenerator.generateValidInvoice();
      const invoiceId = uuidv4();

      // Attempt transaction that should fail
      try {
        await executeInTransaction(connectionString, async (client) => {
          await client.query(
            'INSERT INTO invoices (id, idempotency_key, invoice_number, supplier_oib, buyer_oib, total_amount, currency, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [
              invoiceId,
              uuidv4(),
              invoice.invoiceNumber,
              invoice.oib.supplier,
              invoice.oib.buyer,
              invoice.amounts.gross,
              invoice.amounts.currency,
              'QUEUED',
              new Date(),
            ]
          );

          // Force an error
          throw new Error('Simulated error');
        });
      } catch (error) {
        // Expected to fail
      }

      // Verify rollback - invoice should not exist
      const retrieved = await getInvoiceMetadata(connectionString, invoiceId);
      expect(retrieved).toBeNull();
    });
  });

  describe('Performance', () => {
    it('should handle bulk inserts efficiently', async () => {
      const startTime = Date.now();
      const numInvoices = 100;

      const promises = [];
      for (let i = 0; i < numInvoices; i++) {
        const invoice = InvoiceGenerator.generateValidInvoice();
        promises.push(
          saveInvoiceMetadata(connectionString, {
            id: uuidv4(),
            idempotencyKey: uuidv4(),
            invoiceNumber: `${invoice.invoiceNumber}-${i}`,
            supplierOIB: invoice.oib.supplier,
            buyerOIB: invoice.oib.buyer,
            totalAmount: invoice.amounts.gross,
            currency: invoice.amounts.currency,
            status: 'QUEUED',
            createdAt: new Date(),
          })
        );
      }

      await Promise.all(promises);

      const duration = Date.now() - startTime;
      console.log(`Inserted ${numInvoices} invoices in ${duration}ms`);

      // Should complete in reasonable time (< 5 seconds)
      expect(duration).toBeLessThan(5000);
    });
  });
});

// Helper functions for database operations
async function initializeSchema(connectionUri: string): Promise<void> {
  const { Client } = require('pg');
  const client = new Client({ connectionString: connectionUri });

  try {
    await client.connect();

    await client.query(`
      CREATE TABLE IF NOT EXISTS invoices (
        id UUID PRIMARY KEY,
        idempotency_key UUID UNIQUE NOT NULL,
        invoice_number VARCHAR(255) NOT NULL,
        supplier_oib VARCHAR(11) NOT NULL,
        buyer_oib VARCHAR(11) NOT NULL,
        total_amount DECIMAL(15, 2) NOT NULL,
        currency VARCHAR(3) NOT NULL,
        status VARCHAR(50) NOT NULL,
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_invoices_created_at ON invoices(created_at DESC)
    `);
  } finally {
    await client.end();
  }
}

async function saveInvoiceMetadata(
  connectionUri: string,
  data: any
): Promise<void> {
  const { Client } = require('pg');
  const client = new Client({ connectionString: connectionUri });

  try {
    await client.connect();

    await client.query(
      `INSERT INTO invoices (id, idempotency_key, invoice_number, supplier_oib, buyer_oib, total_amount, currency, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        data.id,
        data.idempotencyKey,
        data.invoiceNumber,
        data.supplierOIB,
        data.buyerOIB,
        data.totalAmount,
        data.currency,
        data.status,
        data.createdAt,
      ]
    );
  } finally {
    await client.end();
  }
}

async function getInvoiceMetadata(
  connectionUri: string,
  id: string
): Promise<any> {
  const { Client } = require('pg');
  const client = new Client({ connectionString: connectionUri });

  try {
    await client.connect();

    const result = await client.query('SELECT * FROM invoices WHERE id = $1', [
      id,
    ]);

    return result.rows[0] || null;
  } finally {
    await client.end();
  }
}

async function getInvoicesByStatus(
  connectionUri: string,
  status: string
): Promise<any[]> {
  const { Client } = require('pg');
  const client = new Client({ connectionString: connectionUri });

  try {
    await client.connect();

    const result = await client.query(
      'SELECT * FROM invoices WHERE status = $1',
      [status]
    );

    return result.rows;
  } finally {
    await client.end();
  }
}

async function updateInvoiceStatus(
  connectionUri: string,
  id: string,
  status: string
): Promise<void> {
  const { Client } = require('pg');
  const client = new Client({ connectionString: connectionUri });

  try {
    await client.connect();

    await client.query(
      'UPDATE invoices SET status = $1, updated_at = $2 WHERE id = $3',
      [status, new Date(), id]
    );
  } finally {
    await client.end();
  }
}

async function executeInTransaction(
  connectionUri: string,
  callback: (client: any) => Promise<void>
): Promise<void> {
  const { Client } = require('pg');
  const client = new Client({ connectionString: connectionUri });

  try {
    await client.connect();
    await client.query('BEGIN');

    try {
      await callback(client);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  } finally {
    await client.end();
  }
}
