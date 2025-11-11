/**
 * Retry Scheduler
 *
 * Polls for due retries and executes them.
 */

import { Channel } from 'amqplib';
import { logger } from './observability';
import { getDueRetryTasks, updateRetryTask, markRetrySuccess, markRetryFailed, updateQueueDepthMetric } from './repository';
import { republishMessage, moveToManualReview } from './publisher';

// =============================================================================
// CONFIGURATION
// =============================================================================

const RETRY_POLL_INTERVAL_MS = parseInt(process.env.RETRY_POLL_INTERVAL_MS || '10000', 10);

// =============================================================================
// STATE
// =============================================================================

let schedulerInterval: NodeJS.Timeout | null = null;

// =============================================================================
// SCHEDULER FUNCTIONS
// =============================================================================

/**
 * Start retry scheduler (poll for due retries)
 *
 * @param channel - RabbitMQ channel for republishing
 */
export function startScheduler(channel: Channel): void {
  if (schedulerInterval) {
    logger.warn('Scheduler already started');
    return;
  }

  logger.info({ poll_interval_ms: RETRY_POLL_INTERVAL_MS }, 'Starting retry scheduler');

  // Immediate first poll
  pollRetries(channel);

  // Schedule recurring polls
  schedulerInterval = setInterval(() => {
    pollRetries(channel);
  }, RETRY_POLL_INTERVAL_MS);
}

/**
 * Poll for due retries and execute them
 */
async function pollRetries(channel: Channel): Promise<void> {
  try {
    // Get due retry tasks
    const dueTasks = await getDueRetryTasks();

    if (dueTasks.length === 0) {
      logger.debug('No due retry tasks found');
      return;
    }

    logger.info({ due_tasks_count: dueTasks.length }, 'Processing due retry tasks');

    // Process each due task
    for (const task of dueTasks) {
      try {
        if (task.retry_count >= task.max_retries) {
          // Max retries exceeded → move to manual review
          await moveToManualReview(channel, task);
          await markRetryFailed(task.message_id);

          logger.warn(
            {
              message_id: task.message_id,
              retry_count: task.retry_count,
              max_retries: task.max_retries,
            },
            'Max retries exceeded - moved to manual review'
          );
        } else {
          // Republish to original queue
          await republishMessage(channel, task);

          // Increment retry count and mark as retried
          task.retry_count++;
          task.status = 'retried';
          await updateRetryTask(task);
          await markRetrySuccess(task.message_id);

          logger.info(
            {
              message_id: task.message_id,
              original_queue: task.original_queue,
              retry_count: task.retry_count,
            },
            'Retry executed successfully'
          );
        }
      } catch (error) {
        logger.error(
          {
            error,
            message_id: task.message_id,
            original_queue: task.original_queue,
          },
          'Failed to execute retry for task'
        );
        // Continue with next task (don't let one failure stop all retries)
      }
    }

    // Update queue depth metric after processing
    await updateQueueDepthMetric();
  } catch (error) {
    logger.error({ error }, 'Failed to poll retry tasks');
  }
}

/**
 * Stop retry scheduler
 */
export function stopScheduler(): void {
  if (schedulerInterval) {
    clearInterval(schedulerInterval);
    schedulerInterval = null;
    logger.info('Retry scheduler stopped');
  }
}

export default {
  startScheduler,
  stopScheduler,
};
