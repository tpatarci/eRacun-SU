/**
 * DLQ Consumer
 *
 * Consumes messages from dead letter queue, classifies errors, and routes appropriately
 *
 * See: README.md §6.2 for consumer logic
 */

import amqp, { Channel, Connection, ConsumeMessage } from 'amqplib';
import { DLQMessage, ServiceConfig } from './types';
import { classifyError, extractServiceName } from './classifier';
import { routeError, RouterDependencies } from './router';
import { ManualReviewRepository } from './repository';
import { createLogger } from './utils/logger';
import {
  dlqMessagesProcessed,
  dlqClassificationDistribution,
  dlqProcessingDuration,
  updateManualReviewPendingCount,
} from './observability';

const logger = createLogger('consumer');

export class DLQConsumer {
  private connection?: Connection;
  private channel?: Channel;
  private retryChannel?: Channel;
  private repository: ManualReviewRepository;
  private config: ServiceConfig;
  private isShuttingDown = false;

  constructor(config: ServiceConfig, repository: ManualReviewRepository) {
    this.config = config;
    this.repository = repository;
  }

  /**
   * Start consuming from dead letter queue
   */
  async start(): Promise<void> {
    logger.info('Starting DLQ consumer', {
      rabbitmqUrl: this.config.dlq.rabbitmqUrl.replace(/:[^:@]+@/, ':***@'),
      dlqExchange: this.config.dlq.dlqExchange,
      dlqQueue: this.config.dlq.dlqQueue,
    });

    try {
      // Connect to RabbitMQ
      this.connection = await amqp.connect(this.config.dlq.rabbitmqUrl);
      this.channel = await this.connection.createChannel();
      this.retryChannel = await this.connection.createChannel();

      // Set prefetch to limit concurrent processing
      await this.channel.prefetch(10);

      // Ensure dead letter exchange exists
      await this.channel.assertExchange(this.config.dlq.dlqExchange, 'topic', {
        durable: true,
      });

      // Ensure DLQ consumer queue exists
      await this.channel.assertQueue(this.config.dlq.dlqQueue, {
        durable: true,
      });

      // Bind to DLQ exchange (consume all *.dlq messages)
      await this.channel.bindQueue(
        this.config.dlq.dlqQueue,
        this.config.dlq.dlqExchange,
        '*.dlq'
      );

      // Ensure retry and manual review queues exist
      await this.retryChannel.assertQueue(this.config.dlq.retryQueue, {
        durable: true,
      });
      await this.retryChannel.assertQueue(this.config.dlq.manualReviewQueue, {
        durable: true,
      });

      // Start consuming
      await this.channel.consume(
        this.config.dlq.dlqQueue,
        (msg) => this.handleMessage(msg),
        { noAck: false }
      );

      // Start periodic stats update
      this.startStatsUpdater();

      logger.info('DLQ consumer started successfully');
    } catch (error) {
      logger.error('Failed to start DLQ consumer', { error });
      throw error;
    }
  }

  /**
   * Handle incoming DLQ message
   *
   * @param msg - RabbitMQ message
   */
  private async handleMessage(msg: ConsumeMessage | null): Promise<void> {
    if (!msg || this.isShuttingDown) {
      return;
    }

    const startTime = Date.now();

    try {
      const dlqMessage = this.parseDLQMessage(msg);
      const serviceName = extractServiceName(dlqMessage);

      logger.info('Processing DLQ message', {
        originalQueue: dlqMessage.original_queue,
        serviceName,
      });

      // Classify error
      const classification = classifyError(dlqMessage);
      dlqClassificationDistribution.inc({ classification });

      // Route based on classification
      const routerDeps: RouterDependencies = {
        retryChannel: this.retryChannel!,
        retryQueue: this.config.dlq.retryQueue,
        manualReviewQueue: this.config.dlq.manualReviewQueue,
        repository: this.repository,
        maxRetries: this.config.dlq.maxRetries,
        transientRetryDelayMs: this.config.dlq.transientRetryDelayMs,
        notificationServiceUrl: this.config.notificationServiceUrl,
      };

      await routeError(dlqMessage, classification, routerDeps);

      // Metrics
      const duration = (Date.now() - startTime) / 1000;
      dlqProcessingDuration.observe({ classification }, duration);
      dlqMessagesProcessed.inc({ classification, service: serviceName });

      // Acknowledge message
      this.channel!.ack(msg);

      logger.info('DLQ message processed successfully', {
        classification,
        serviceName,
        durationMs: Date.now() - startTime,
      });
    } catch (error) {
      logger.error('Failed to process DLQ message', { error });

      // Negative acknowledgment (requeue)
      if (!this.isShuttingDown) {
        this.channel!.nack(msg, false, true);
      }
    }
  }

  /**
   * Parse RabbitMQ message into DLQMessage format
   *
   * @param msg - RabbitMQ message
   * @returns DLQMessage
   */
  private parseDLQMessage(msg: ConsumeMessage): DLQMessage {
    const headers = msg.properties.headers || {};

    return {
      original_message: msg.content,
      original_routing_key: (headers['x-original-routing-key'] as string) || '',
      original_queue: (headers['x-first-death-queue'] as string) || '',
      error: {
        reason: (headers['x-death-reason'] as string) || 'Unknown error',
        exception: (headers['x-exception-stacktrace'] as string) || '',
        timestamp: Date.now(),
      },
      headers: {
        'x-death': (headers['x-death'] as any) || [],
        'x-first-death-reason': (headers['x-first-death-reason'] as string) || '',
        'x-first-death-queue': (headers['x-first-death-queue'] as string) || '',
        'x-first-death-exchange': (headers['x-first-death-exchange'] as string) || '',
      },
    };
  }

  /**
   * Start periodic stats updater
   *
   * Updates Prometheus gauges every 30 seconds
   */
  private startStatsUpdater(): void {
    const updateStats = async () => {
      try {
        const stats = await this.repository.getStats();
        updateManualReviewPendingCount(stats.pending_count);
      } catch (error) {
        logger.error('Failed to update stats', { error });
      }
    };

    // Initial update
    updateStats();

    // Update every 30 seconds
    setInterval(updateStats, 30000);
  }

  /**
   * Gracefully shutdown consumer
   */
  async stop(): Promise<void> {
    logger.info('Stopping DLQ consumer');
    this.isShuttingDown = true;

    try {
      if (this.channel) {
        await this.channel.close();
      }

      if (this.retryChannel) {
        await this.retryChannel.close();
      }

      if (this.connection) {
        await this.connection.close();
      }

      await this.repository.close();

      logger.info('DLQ consumer stopped successfully');
    } catch (error) {
      logger.error('Error during shutdown', { error });
    }
  }
}
