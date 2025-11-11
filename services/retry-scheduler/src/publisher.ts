/**
 * Message Publisher
 *
 * Republishes messages to original queues or manual review queue.
 */

import { Channel } from 'amqplib';
import { logger, retriesExecutedTotal, retriesExhaustedTotal } from './observability';
import { RetryTask } from './repository';

// =============================================================================
// CONFIGURATION
// =============================================================================

const MANUAL_REVIEW_QUEUE = process.env.MANUAL_REVIEW_QUEUE || 'manual-review.pending';

// =============================================================================
// PUBLISHER FUNCTIONS
// =============================================================================

/**
 * Republish message to original queue
 *
 * @param channel - RabbitMQ channel
 * @param task - Retry task
 */
export async function republishMessage(channel: Channel, task: RetryTask): Promise<void> {
  try {
    // Publish to original queue with retry headers
    channel.sendToQueue(
      task.original_queue,
      task.original_payload,
      {
        persistent: true,
        headers: {
          'x-retry-count': task.retry_count,
          'x-original-error': task.error_reason,
          'x-retry-scheduler': 'true',
        },
      }
    );

    // Track metric
    retriesExecutedTotal.inc({
      queue: task.original_queue,
      status: 'success',
    });

    logger.info(
      {
        message_id: task.message_id,
        original_queue: task.original_queue,
        retry_count: task.retry_count,
      },
      'Message republished to original queue'
    );
  } catch (error) {
    // Track metric
    retriesExecutedTotal.inc({
      queue: task.original_queue,
      status: 'failed',
    });

    logger.error(
      {
        error,
        message_id: task.message_id,
        original_queue: task.original_queue,
      },
      'Failed to republish message'
    );
    throw error;
  }
}

/**
 * Move message to manual review queue (max retries exceeded)
 *
 * @param channel - RabbitMQ channel
 * @param task - Retry task
 */
export async function moveToManualReview(channel: Channel, task: RetryTask): Promise<void> {
  try {
    // Prepare manual review payload with context
    const manualReviewPayload = {
      message_id: task.message_id,
      original_queue: task.original_queue,
      original_payload: task.original_payload.toString('base64'),
      error_reason: task.error_reason,
      retry_count: task.retry_count,
      max_retries: task.max_retries,
      failed_at: new Date().toISOString(),
    };

    // Publish to manual review queue
    channel.sendToQueue(
      MANUAL_REVIEW_QUEUE,
      Buffer.from(JSON.stringify(manualReviewPayload)),
      {
        persistent: true,
        headers: {
          'x-max-retries-exceeded': 'true',
          'x-original-queue': task.original_queue,
        },
      }
    );

    // Track metric
    retriesExhaustedTotal.inc({
      queue: task.original_queue,
    });

    logger.warn(
      {
        message_id: task.message_id,
        original_queue: task.original_queue,
        retry_count: task.retry_count,
        max_retries: task.max_retries,
      },
      'Message moved to manual review (max retries exceeded)'
    );
  } catch (error) {
    logger.error(
      {
        error,
        message_id: task.message_id,
      },
      'Failed to move message to manual review'
    );
    throw error;
  }
}

export default {
  republishMessage,
  moveToManualReview,
};
