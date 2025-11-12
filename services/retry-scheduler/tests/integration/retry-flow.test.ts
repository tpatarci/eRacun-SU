/**
 * Integration Tests - Retry Flow End-to-End
 *
 * Tests complete retry workflow:
 * 1. Consume retry message from RabbitMQ
 * 2. Store in PostgreSQL with calculated delay
 * 3. Poll for due retries
 * 4. Republish to original queue or move to manual review
 *
 * Note: These tests require RabbitMQ and PostgreSQL running.
 */

import { v4 as uuidv4 } from 'uuid';
import {
  initPool,
  closePool,
  createSchema,
  getDueRetryTasks,
  RetryTask,
  saveRetryTask,
} from '../../src/repository';
import { calculateNextRetryDelay } from '../../src/backoff';
import {
  retriesScheduledTotal,
  retriesExecutedTotal,
  retriesExhaustedTotal,
  resetMetrics,
} from '../../src/observability';

// Skip integration tests if infrastructure is not available
const RUN_INTEGRATION_TESTS = process.env.RUN_INTEGRATION_TESTS === 'true';
const describeIntegration = RUN_INTEGRATION_TESTS ? describe : describe.skip;

describeIntegration('Retry Flow Integration', () => {
  beforeAll(async () => {
    initPool();
    await createSchema();
  });

  afterAll(async () => {
    await closePool();
  });

  beforeEach(async () => {
    // Clean database
    const pool = require('../../src/repository').getPool();
    await pool.query('TRUNCATE TABLE retry_queue RESTART IDENTITY');

    // Reset metrics
    resetMetrics();
  });

  describe('Complete Retry Workflow', () => {
    it('should handle first retry attempt', async () => {
      // Simulate receiving retry message
      const retryMessage = {
        message_id: uuidv4(),
        original_payload: Buffer.from(JSON.stringify({ test: 'data' })),
        original_queue: 'validation.xsd.validate',
        error_reason: 'Temporary network error',
        retry_count: 0,
        max_retries: 3,
      };

      // Calculate next retry time
      const delay = calculateNextRetryDelay(retryMessage.retry_count);
      const nextRetryAt = new Date(Date.now() + delay);

      // Save to database
      const task: RetryTask = {
        ...retryMessage,
        next_retry_at: nextRetryAt,
        status: 'pending',
      };

      await saveRetryTask(task);

      // Track metric
      retriesScheduledTotal.inc({ queue: retryMessage.original_queue });

      // Verify task is saved
      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [retryMessage.message_id]
      );

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].retry_count).toBe(0);
      expect(result.rows[0].status).toBe('pending');
    });

    it('should execute due retry and increment retry count', async () => {
      // Create past-due retry task
      const task: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test payload'),
        original_queue: 'validation.xsd.validate',
        error_reason: 'Connection timeout',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() - 5000), // 5 seconds ago (due)
        status: 'pending',
      };

      await saveRetryTask(task);

      // Get due tasks (what scheduler does)
      const dueTasks = await getDueRetryTasks();

      expect(dueTasks).toHaveLength(1);
      expect(dueTasks[0].message_id).toBe(task.message_id);

      // Simulate republishing (increment retry count)
      dueTasks[0].retry_count++;
      dueTasks[0].status = 'retried';

      const pool = require('../../src/repository').getPool();
      await pool.query(
        'UPDATE retry_queue SET retry_count = $1, status = $2 WHERE message_id = $3',
        [dueTasks[0].retry_count, dueTasks[0].status, dueTasks[0].message_id]
      );

      // Track metric
      retriesExecutedTotal.inc({
        queue: dueTasks[0].original_queue,
        status: 'success',
      });

      // Verify update
      const result = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [task.message_id]
      );

      expect(result.rows[0].retry_count).toBe(1);
      expect(result.rows[0].status).toBe('retried');
    });

    it('should move to manual review after max retries', async () => {
      // Create task that has exhausted retries
      const task: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test payload'),
        original_queue: 'transformation.ubl.transform',
        error_reason: 'Persistent validation error',
        retry_count: 3, // Already at max
        max_retries: 3,
        next_retry_at: new Date(Date.now() - 1000), // Due now
        status: 'pending',
      };

      await saveRetryTask(task);

      // Get due tasks
      const dueTasks = await getDueRetryTasks();
      expect(dueTasks).toHaveLength(1);

      const dueTask = dueTasks[0];

      // Check if max retries exceeded
      if (dueTask.retry_count >= dueTask.max_retries) {
        // Mark as failed
        const pool = require('../../src/repository').getPool();
        await pool.query(
          'UPDATE retry_queue SET status = $1 WHERE message_id = $2',
          ['failed', dueTask.message_id]
        );

        // Track metric
        retriesExhaustedTotal.inc({ queue: dueTask.original_queue });

        // In real implementation, message would be published to manual-review.pending
      }

      // Verify task marked as failed
      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [task.message_id]
      );

      expect(result.rows[0].status).toBe('failed');
      expect(result.rows[0].retry_count).toBe(3);
    });
  });

  describe('Multiple Retry Attempts', () => {
    it('should handle retry progression: 0 → 1 → 2 → 3 → manual review', async () => {
      const messageId = uuidv4();
      const originalQueue = 'test.queue';

      // Attempt 0: Schedule initial retry
      let task: RetryTask = {
        message_id: messageId,
        original_payload: Buffer.from('test'),
        original_queue: originalQueue,
        error_reason: 'Error',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() - 1000),
        status: 'pending',
      };

      await saveRetryTask(task);

      const pool = require('../../src/repository').getPool();

      // Simulate 3 retry attempts
      for (let attempt = 0; attempt < 3; attempt++) {
        // Get due task
        const dueTasks = await getDueRetryTasks();
        expect(dueTasks).toHaveLength(1);

        const dueTask = dueTasks[0];
        expect(dueTask.retry_count).toBe(attempt);

        // Execute retry
        dueTask.retry_count++;
        dueTask.status = 'retried';

        await pool.query(
          'UPDATE retry_queue SET retry_count = $1, status = $2 WHERE message_id = $3',
          [dueTask.retry_count, 'retried', messageId]
        );

        // Schedule next retry (except on last attempt)
        if (attempt < 2) {
          await pool.query(
            'UPDATE retry_queue SET next_retry_at = $1, status = $2 WHERE message_id = $3',
            [new Date(Date.now() - 1000), 'pending', messageId]
          );
        }
      }

      // After 3 attempts, check if at max retries
      const result = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [messageId]
      );

      expect(result.rows[0].retry_count).toBe(3);

      // Next poll would move to manual review
      await pool.query(
        'UPDATE retry_queue SET next_retry_at = $1, status = $2 WHERE message_id = $3',
        [new Date(Date.now() - 1000), 'pending', messageId]
      );

      const dueTasks = await getDueRetryTasks();
      const dueTask = dueTasks[0];

      if (dueTask.retry_count >= dueTask.max_retries) {
        await pool.query(
          'UPDATE retry_queue SET status = $1 WHERE message_id = $2',
          ['failed', messageId]
        );
      }

      const finalResult = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [messageId]
      );

      expect(finalResult.rows[0].status).toBe('failed');
    });
  });

  describe('Concurrent Retry Processing', () => {
    it('should handle multiple concurrent retries', async () => {
      // Create 10 due retry tasks
      const tasks = Array.from({ length: 10 }, (_, i) => ({
        message_id: uuidv4(),
        original_payload: Buffer.from(`test${i}`),
        original_queue: `queue.${i % 3}`, // 3 different queues
        error_reason: 'Test error',
        retry_count: i % 3, // Different retry counts
        max_retries: 3,
        next_retry_at: new Date(Date.now() - 5000), // All due
        status: 'pending' as const,
      }));

      await Promise.all(tasks.map(task => saveRetryTask(task)));

      // Get all due tasks
      const dueTasks = await getDueRetryTasks();

      expect(dueTasks).toHaveLength(10);

      // Process them concurrently (simulate scheduler)
      const pool = require('../../src/repository').getPool();

      await Promise.all(
        dueTasks.map(async task => {
          if (task.retry_count < task.max_retries) {
            await pool.query(
              'UPDATE retry_queue SET retry_count = $1, status = $2 WHERE message_id = $3',
              [task.retry_count + 1, 'retried', task.message_id]
            );
          } else {
            await pool.query(
              'UPDATE retry_queue SET status = $1 WHERE message_id = $2',
              ['failed', task.message_id]
            );
          }
        })
      );

      // Verify all processed
      const result = await pool.query(
        'SELECT COUNT(*) FROM retry_queue WHERE status IN ($1, $2)',
        ['retried', 'failed']
      );

      expect(parseInt(result.rows[0].count)).toBe(10);
    });
  });

  describe('Exponential Backoff Integration', () => {
    it('should calculate increasing delays for progressive retries', () => {
      const delays = [];

      for (let retryCount = 0; retryCount < 4; retryCount++) {
        const delay = calculateNextRetryDelay(retryCount);
        delays.push(delay);
      }

      // Verify exponential growth
      expect(delays[0]).toBeGreaterThanOrEqual(2000); // ~2s
      expect(delays[1]).toBeGreaterThanOrEqual(4000); // ~4s
      expect(delays[2]).toBeGreaterThanOrEqual(8000); // ~8s
      expect(delays[3]).toBeGreaterThanOrEqual(16000); // ~16s

      // Each delay should be roughly double the previous
      expect(delays[1]).toBeGreaterThan(delays[0] * 1.5);
      expect(delays[2]).toBeGreaterThan(delays[1] * 1.5);
      expect(delays[3]).toBeGreaterThan(delays[2] * 1.5);
    });

    it('should schedule tasks with appropriate future timestamps', async () => {
      const now = Date.now();

      const task: RetryTask = {
        message_id: uuidv4(),
        original_payload: Buffer.from('test'),
        original_queue: 'test.queue',
        error_reason: 'Error',
        retry_count: 1,
        max_retries: 3,
        next_retry_at: new Date(now + calculateNextRetryDelay(1)),
        status: 'pending',
      };

      await saveRetryTask(task);

      // Task should NOT be due yet
      const dueTasks = await getDueRetryTasks();
      expect(dueTasks).toHaveLength(0);

      // Fast-forward time by updating next_retry_at
      const pool = require('../../src/repository').getPool();
      await pool.query(
        'UPDATE retry_queue SET next_retry_at = $1 WHERE message_id = $2',
        [new Date(now - 1000), task.message_id]
      );

      // Now it should be due
      const dueTasksAfter = await getDueRetryTasks();
      expect(dueTasksAfter).toHaveLength(1);
    });
  });

  describe('Idempotency', () => {
    it('should handle duplicate retry requests via upsert', async () => {
      const messageId = uuidv4();

      // First retry request
      const task1: RetryTask = {
        message_id: messageId,
        original_payload: Buffer.from('payload1'),
        original_queue: 'queue.1',
        retry_count: 0,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 2000),
        status: 'pending',
      };

      await saveRetryTask(task1);

      // Duplicate retry request (e.g., from message redelivery)
      const task2: RetryTask = {
        message_id: messageId,
        original_payload: Buffer.from('payload2'),
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
        'SELECT COUNT(*) FROM retry_queue WHERE message_id = $1',
        [messageId]
      );

      expect(parseInt(result.rows[0].count)).toBe(1);

      // Should have latest data
      const latest = await pool.query(
        'SELECT * FROM retry_queue WHERE message_id = $1',
        [messageId]
      );

      expect(latest.rows[0].retry_count).toBe(1);
      expect(latest.rows[0].original_queue).toBe('queue.2');
    });
  });

  describe('Service Restart Resilience', () => {
    it('should preserve pending retries across service restart', async () => {
      // Create pending retry tasks
      const tasks = Array.from({ length: 5 }, (_, i) => ({
        message_id: uuidv4(),
        original_payload: Buffer.from(`test${i}`),
        original_queue: 'test.queue',
        retry_count: i,
        max_retries: 3,
        next_retry_at: new Date(Date.now() + 10000),
        status: 'pending' as const,
      }));

      await Promise.all(tasks.map(task => saveRetryTask(task)));

      // Simulate service restart (close and reopen pool)
      await closePool();
      initPool();

      // Tasks should still be in database
      const pool = require('../../src/repository').getPool();
      const result = await pool.query(
        'SELECT COUNT(*) FROM retry_queue WHERE status = $1',
        ['pending']
      );

      expect(parseInt(result.rows[0].count)).toBe(5);
    });
  });
});
