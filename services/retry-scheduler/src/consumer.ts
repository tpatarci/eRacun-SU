/**
 * RabbitMQ Consumer
 *
 * Consumes retry requests from retry.scheduled queue.
 */

import amqp, { Channel, Connection, ConsumeMessage } from 'amqplib';
import { logger, retriesScheduledTotal } from './observability';
import { saveRetryTask, RetryTask } from './repository';
import { calculateNextRetryTime } from './backoff';

// =============================================================================
// CONFIGURATION
// =============================================================================

const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';
const RETRY_QUEUE = process.env.RETRY_QUEUE || 'retry.scheduled';
const RABBITMQ_PREFETCH = parseInt(process.env.RABBITMQ_PREFETCH || '10', 10);
const DEFAULT_MAX_RETRIES = parseInt(process.env.DEFAULT_MAX_RETRIES || '3', 10);

// =============================================================================
// STATE
// =============================================================================

let connection: Connection | null = null;
let channel: Channel | null = null;

// =============================================================================
// CONSUMER FUNCTIONS
// =============================================================================

export async function startConsumer(): Promise<Channel> {
  try {
    logger.info({ rabbitmq_url: RABBITMQ_URL, queue: RETRY_QUEUE }, 'Connecting to RabbitMQ');

    // Connect to RabbitMQ
    connection = await amqp.connect(RABBITMQ_URL);
    channel = await connection.createChannel();

    // Assert queue exists
    await channel.assertQueue(RETRY_QUEUE, {
      durable: true,
    });

    // Set prefetch
    await channel.prefetch(RABBITMQ_PREFETCH);

    // Start consuming
    await channel.consume(
      RETRY_QUEUE,
      async (msg: ConsumeMessage | null) => {
        if (!msg) return;

        try {
          await processRetryMessage(msg);
          channel!.ack(msg);
        } catch (error) {
          logger.error({ error, message: msg.content.toString() }, 'Failed to process retry message');
          channel!.nack(msg, false, true); // Requeue for retry
        }
      },
      {
        noAck: false,
      }
    );

    logger.info('RabbitMQ consumer started');
    return channel;
  } catch (error) {
    logger.error({ error }, 'Failed to start RabbitMQ consumer');
    throw error;
  }
}

async function processRetryMessage(msg: ConsumeMessage): Promise<void> {
  // Parse retry message
  const retryMsg = JSON.parse(msg.content.toString());

  logger.debug(
    {
      message_id: retryMsg.message_id,
      original_queue: retryMsg.original_queue,
      retry_count: retryMsg.retry_count,
    },
    'Processing retry message'
  );

  // Calculate next retry time
  const nextRetryAt = calculateNextRetryTime(retryMsg.retry_count);

  // Save to database
  const task: RetryTask = {
    message_id: retryMsg.message_id,
    original_payload: Buffer.from(retryMsg.original_payload, 'base64'),
    original_queue: retryMsg.original_queue,
    error_reason: retryMsg.error_reason,
    retry_count: retryMsg.retry_count,
    max_retries: retryMsg.max_retries || DEFAULT_MAX_RETRIES,
    next_retry_at: nextRetryAt,
    status: 'pending',
  };

  await saveRetryTask(task);

  // Track metric
  retriesScheduledTotal.inc({
    queue: retryMsg.original_queue,
  });

  logger.info(
    {
      message_id: task.message_id,
      original_queue: task.original_queue,
      retry_count: task.retry_count,
      next_retry_at: nextRetryAt,
    },
    'Retry scheduled'
  );
}

export async function closeConsumer(): Promise<void> {
  if (channel) {
    await channel.close();
    channel = null;
  }

  if (connection) {
    await connection.close();
    connection = null;
  }

  logger.info('RabbitMQ consumer closed');
}

export function getChannel(): Channel | null {
  return channel;
}

export default {
  startConsumer,
  closeConsumer,
  getChannel,
};
