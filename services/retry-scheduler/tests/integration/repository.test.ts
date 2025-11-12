/**
 * Integration Tests - PostgreSQL Repository
 *
 * Tests database operations with real PostgreSQL connection.
 * Note: These tests require a running PostgreSQL instance.
 */

import {
  initPool,
  closePool,
  createSchema,
  saveRetryTask,
  getDueRetryTasks,
  updateRetryTask,
  markRetrySuccess,
  markRetryFailed,
  healthCheck,
  RetryTask,
} from '../../src/repository';
import { v4 as uuidv4 } from 'uuid';

// Skip integration tests if PostgreSQL is not available
const RUN_INTEGRATION_TESTS = process.env.RUN_INTEGRATION_TESTS === 'true';
const describeIntegration = RUN_INTEGRATION_TESTS ? describe : describe.skip;

describeIntegration('PostgreSQL Repository Integration', () => {
  beforeAll(async () => {
    // Initialize database pool
    initPool();
    await createSchema();
  });

  afterAll(async () => {
    // Close database pool
    await closePool();
  });

  beforeEach(async () => {
    // Clean up retry_queue table before each test
    const pool = require('../../src/repository').getPool();
    await pool.query('TRUNCATE TABLE retry_queue RESTART IDENTITY');
  });

  describe('Schema Creation', () => {
    it('should create retry_queue table', async () => {
      const pool = require('../../src/repository').getPool();
      const result = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables
          WHERE table_name = 'retry_queue'
        );
      `);

      expect(result.rows[0].exists).toBe(true);
    });

    it('should have correct columns', async () => {
      const pool = require('../../src/repository').getPool();
      const result = await pool.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'retry_queue'
        ORDER BY ordinal_position;
      `);

      const columnNames = result.rows.map((row: any) => row.column_name);

      expect(columnNames).toContain('id');
      expect(columnNames).toContain('message_id');
      expect(columnNames).toContain('original_payload');
      expect(columnNames).toContain('original_queue');
      expect(columnNames).toContain('error_reason');
      expect(columnNames).toContain('retry_count');
      expect(columnNames).toContain('max_retries');
      expect(columnNames).toContain('next_retry_at');
      expect(columnNames).toContain('status');
    });

    it('should have index on next_retry_at and status', async () => {
      const pool = require('../../src/repository').getPool();
      const result = await pool.query(`
        SELECT indexname
        FROM pg_indexes
        WHERE tablename = 'retry_queue';
      `);

      const indexNames = result.rows.map((row: any) => row.indexname);

      expect(indexNames).toContain('idx_retry_next_retry');
    });
  });

  describe('saveRetryTask', () => {
    it('should save a new retry task', async () => {
      const task: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test payload'),
        original_queue: 'test.queue',
        error_reason: 'Test error',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 5000),
        status: 'pending',
      };

      await saveRetryTask(task);

      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [task.message_id]
      );

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].message_id).toBe(task.message_id);
      expect(result.rows[0].original_queue).toBe(task.original_queue);
      expect(result.rows[0].retry_count).toBe(0);
    });

    it('should upsert task if message_id already exists', async () => {
      const messageId = uuidv4();

      // Insert initial task
      const task1: RetryTask = {
        message_id: messageId,
        original_payload: Buffer.from('payload 1'),
        original_queue: 'queue.1',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 2000),
        status: 'pending',
      };

      await saveRetryTask(task1);

      // Update with same message_id
      const task2: RetryTask = {
        message_id: messageId,
        original_payload: Buffer.from('payload 2'),
        original_queue: 'queue.2',
        retry_count: 1,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 4000),
        status: 'pending',
      };

      await saveRetryTask(task2);

      // Should only have one row
      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [messageId]
      );

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].original_queue).toBe('queue.2');
      expect(result.rows[0].retry_count).toBe(1);
    });

    it('should handle binary payload correctly', async () => {
      const payload = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"

      const task: RetryTask = {
        message_id: uuidv4(),
        original_payload: payload,
        original_queue: 'test.queue',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 5000),
        status: 'pending',
      };

      await saveRetryTask(task);

      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT original_payload FROM retry_queue WHERE message_id = $1',
        [task.message_id]
      );

      expect(result.rows[0].original_payload).toEqual(payload);
    });
  });

  describe('getDueRetryTasks', () => {
    it('should return tasks due for retry', async () => {
      // Create past-due task
      const pastTask: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test'),
        original_queue: 'test.queue',
        retry_count: 1,
        max_retries: 3,
        next_retry_at: new Date(Date.now() - 5000), // 5 seconds ago
        status: 'pending',
      };

      await saveRetryTask(pastTask);

      const dueTasks = await getDueRetryTasks();

      expect(dueTasks).toHaveLength(1);
      expect(dueTasks[0].message_id).toBe(pastTask.message_id);
    });

    it('should not return future tasks', async () => {
      // Create future task
      const futureTask: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test'),
        original_queue: 'test.queue',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 60000), // 1 minute in future
        status: 'pending',
      };

      await saveRetryTask(futureTask);

      const dueTasks = await getDueRetryTasks();

      expect(dueTasks).toHaveLength(0);
    });

    it('should not return non-pending tasks', async () => {
      const pool = require('../../src/repository').getPool();

      // Create retried task (manually set status)
      const messageId = uuidv4();
      await pool.query(`
        INSERT INTO retry_queue
        (message_id, original_payload, original_queue, retry_count, max_retries, next_retry_at, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [messageId, Buffer.from('test'), 'test.queue', 1, 3, new Date(Date.now() - 5000), 'retried']);

      const dueTasks = await getDueRetryTasks();

      expect(dueTasks).toHaveLength(0);
    });

    it('should return multiple due tasks ordered by next_retry_at', async () => {
      const now = Date.now();

      const task1: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test1'),
        original_queue: 'queue.1',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(now - 10000), // 10 seconds ago
        status: 'pending',
      };

      const task2: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test2'),
        original_queue: 'queue.2',
        retry_count: 1,
        max_retries: 3,
        next_retry_at: new Date(now - 5000), // 5 seconds ago
        status: 'pending',
      };

      await saveRetryTask(task1);
      await saveRetryTask(task2);

      const dueTasks = await getDueRetryTasks();

      expect(dueTasks).toHaveLength(2);
      // Should be ordered by next_retry_at ASC (oldest first)
      expect(dueTasks[0].message_id).toBe(task1.message_id);
      expect(dueTasks[1].message_id).toBe(task2.message_id);
    });

    it('should respect limit parameter', async () => {
      // Create 10 due tasks
      for (let i = 0; i < 10; i++) {
        const task: RetryTask = {
          message_id: uuidv4(),
          original_payload: Buffer.from(`test${i}`),
          original_queue: 'test.queue',
          retry_count: 0,
          max_retries: 3,
          next_retry_at: new Date(Date.now() - 5000),
          status: 'pending',
        };
        await saveRetryTask(task);
      }

      const dueTasks = await getDueRetryTasks(5);

      expect(dueTasks).toHaveLength(5);
    });
  });

  describe('updateRetryTask', () => {
    it('should update retry count and status', async () => {
      const task: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test'),
        original_queue: 'test.queue',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 5000),
        status: 'pending',
      };

      await saveRetryTask(task);

      // Update task
      task.retry_count = 1;
      task.status = 'retried';
      await updateRetryTask(task);

      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [task.message_id]
      );

      expect(result.rows[0].retry_count).toBe(1);
      expect(result.rows[0].status).toBe('retried');
    });
  });

  describe('markRetrySuccess', () => {
    it('should mark task as retried', async () => {
      const task: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test'),
        original_queue: 'test.queue',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 5000),
        status: 'pending',
      };

      await saveRetryTask(task);
      await markRetrySuccess(task.message_id);

      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT status FROM retry_queue WHERE message_id = $1',
        [task.message_id]
      );

      expect(result.rows[0].status).toBe('retried');
    });
  });

  describe('markRetryFailed', () => {
    it('should mark task as failed', async () => {
      const task: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test'),
        original_queue: 'test.queue',
        retry_count: 3,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 5000),
        status: 'pending',
      };

      await saveRetryTask(task);
      await markRetryFailed(task.message_id);

      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT status FROM retry_queue WHERE message_id = $1',
        [task.message_id]
      );

      expect(result.rows[0].status).toBe('failed');
    });
  });

  describe('healthCheck', () => {
    it('should return true when database is healthy', async () => {
      const healthy = await healthCheck();
      expect(healthy).toBe(true);
    });

    it('should return false when database connection fails', async () => {
      // Close the pool to simulate connection failure
      await closePool();

      const healthy = await healthCheck();
      expect(healthy).toBe(false);

      // Reinitialize for other tests
      initPool();
      await createSchema();
    });
  });

  describe('Concurrent Operations', () => {
    it('should handle concurrent inserts without conflicts', async () => {
      const tasks = Array.from({ length: 10 }, (_, i) => ({
        message_id: uuidv4(),
        original_payload: Buffer.from(`test${i}`),
        original_queue: `queue.${i}`,
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 5000),
        status: 'pending' as const,
      }));

      // Save all tasks concurrently
      await Promise.all(tasks.map(task => saveRetryTask(task)));

      const pool = require('../../src/repository').getPool();
      const result = await pool.query('SELECT COUNT(*) FROM retry_queue');

      expect(parseInt(result.rows[0].count)).toBe(10);
    });

    it('should handle concurrent upserts on same message_id', async () => {
      const messageId = uuidv4();

      const upserts = Array.from({ length: 5 }, (_, i) => ({
        message_id: messageId,
        original_payload: Buffer.from(`payload${i}`),
        original_queue: `queue.${i}`,
        retry_count: i,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 5000),
        status: 'pending' as const,
      }));

      // Execute concurrent upserts
      await Promise.all(upserts.map(task => saveRetryTask(task)));

      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT COUNT(*) FROM retry_queue WHERE message_id = $1',
        [messageId]
      );

      // Should only have one row due to upsert
      expect(parseInt(result.rows[0].count)).toBe(1);
    });
  });
});
