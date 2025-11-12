/**
 * Message Publisher Module
 *
 * Publishes classified files to downstream processors.
 * - RabbitMQ connection management
 * - Message serialization and publishing
 * - Publisher confirms for reliability
 */

import amqp, { Connection, ConfirmChannel, Options } from 'amqplib';
import { ClassificationResult } from './classifier';
import {
  logger,
  filesRoutedTotal,
  classificationDuration,
  withSpan,
} from './observability';

/**
 * Message bus configuration
 */
export interface MessageBusConfig {
  url: string;
  exchange: string;
  durable: boolean;
  persistent: boolean;
}

/**
 * Classification command message
 */
export interface ClassifyFileCommand {
  /** Unique message ID */
  messageId: string;
  /** Original email message ID */
  emailMessageId: string;
  /** Attachment ID */
  attachmentId: string;
  /** Filename */
  filename: string;
  /** Classification result */
  classification: ClassificationResult;
  /** File content (base64 encoded) */
  content: string;
  /** Message timestamp */
  timestamp: string;
  /** Source */
  source: string;
}

/**
 * Message Publisher for RabbitMQ
 */
export class MessagePublisher {
  private config: MessageBusConfig;
  private connection: Connection | null = null;
  private channel: ConfirmChannel | null = null;
  private isConnected = false;

  constructor(config: MessageBusConfig) {
    this.config = config;
  }

  /**
   * Connect to RabbitMQ
   */
  async connect(): Promise<void> {
    return withSpan(
      'messagebus.connect',
      {
        exchange: this.config.exchange,
      },
      async () => {
        if (this.isConnected) {
          logger.info('Message bus already connected');
          return;
        }

        logger.info({ url: this.maskUrl(this.config.url) }, 'Connecting to message bus');

        try {
          // Create connection
          this.connection = (await amqp.connect(this.config.url)) as any as Connection;

          // Handle connection errors
          this.connection!.on('error', (err: Error) => {
            logger.error({ err }, 'Message bus connection error');
            this.isConnected = false;
          });

          this.connection!.on('close', () => {
            logger.info('Message bus connection closed');
            this.isConnected = false;
          });

          // Create channel with publisher confirms
          this.channel = await (this.connection as any).createConfirmChannel();

          // Handle channel errors
          this.channel!.on('error', (err: Error) => {
            logger.error({ err }, 'Message bus channel error');
          });

          this.channel!.on('close', () => {
            logger.info('Message bus channel closed');
          });

          // Declare exchange
          await this.channel!.assertExchange(
            this.config.exchange,
            'topic',
            {
              durable: this.config.durable,
            }
          );

          this.isConnected = true;
          logger.info('Message bus connected successfully');
        } catch (err) {
          logger.error({ err }, 'Failed to connect to message bus');
          throw err;
        }
      }
    );
  }

  /**
   * Disconnect from RabbitMQ
   */
  async disconnect(): Promise<void> {
    logger.info('Disconnecting from message bus');

    try {
      if (this.channel) {
        await this.channel.close();
        this.channel = null;
      }

      if (this.connection) {
        await (this.connection as any).close();
        this.connection = null;
      }

      this.isConnected = false;
      logger.info('Message bus disconnected');
    } catch (err) {
      logger.error({ err }, 'Error disconnecting from message bus');
      throw err;
    }
  }

  /**
   * Publish classified file to processor
   */
  async publishClassification(command: ClassifyFileCommand): Promise<void> {
    const endTimer = classificationDuration.startTimer({ operation: 'publish' });

    try {
      await withSpan(
        'messagebus.publish',
        {
          messageId: command.messageId,
          processor: command.classification.processor,
        },
        async (span) => {
          if (!this.channel) {
            throw new Error('Channel not available');
          }

          // Determine routing key based on processor
          const routingKey = this.getRoutingKey(command.classification.processor);

          // Serialize message
          const messageBuffer = Buffer.from(JSON.stringify(command));

          // Publish options
          const publishOptions: Options.Publish = {
            persistent: this.config.persistent,
            contentType: 'application/json',
            contentEncoding: 'utf-8',
            timestamp: Date.now(),
            messageId: command.messageId,
            priority: this.getPriority(command.classification.priority),
          };

          logger.info(
            {
              messageId: command.messageId,
              processor: command.classification.processor,
              routingKey,
              size: messageBuffer.length,
            },
            'Publishing classification to processor'
          );

          try {
            // Publish message to exchange
            this.channel.publish(
              this.config.exchange,
              routingKey,
              messageBuffer,
              publishOptions
            );

            // Wait for broker confirmation
            await this.channel.waitForConfirms();

            logger.info(
              { messageId: command.messageId },
              'Message published successfully'
            );

            filesRoutedTotal.inc({
              processor: command.classification.processor,
              status: 'success',
            });

            span.setAttribute('status', 'success');
          } catch (err) {
            logger.error(
              { err, messageId: command.messageId },
              'Failed to publish message'
            );

            filesRoutedTotal.inc({
              processor: command.classification.processor,
              status: 'error',
            });

            span.setAttribute('status', 'error');
            throw err;
          }
        }
      );
    } catch (err) {
      logger.error({ err, messageId: command.messageId }, 'Failed to publish classification');
      throw err;
    } finally {
      endTimer();
    }
  }

  /**
   * Get routing key for processor
   */
  private getRoutingKey(processor: string): string {
    const routingKeys: Record<string, string> = {
      'pdf-parser': 'file.pdf.classify',
      'xml-parser': 'file.xml.classify',
      'ocr-processing-service': 'file.image.classify',
      'manual-review-queue': 'file.manual-review',
    };

    return routingKeys[processor] || 'file.unknown';
  }

  /**
   * Convert priority to RabbitMQ priority number
   */
  private getPriority(priority: string): number {
    const priorities: Record<string, number> = {
      high: 10,
      medium: 5,
      low: 1,
    };

    return priorities[priority] || 5;
  }

  /**
   * Get connection status
   */
  getConnectionStatus(): boolean {
    return this.isConnected;
  }

  /**
   * Mask sensitive information in URL
   */
  private maskUrl(url: string): string {
    try {
      const parsed = new URL(url);
      if (parsed.password) {
        parsed.password = '***';
      }
      return parsed.toString();
    } catch {
      return 'invalid-url';
    }
  }
}

/**
 * Create message publisher from environment variables
 */
export function createMessagePublisherFromEnv(): MessagePublisher {
  const config: MessageBusConfig = {
    url: process.env.RABBITMQ_URL || 'amqp://localhost:5672',
    exchange: process.env.RABBITMQ_OUTPUT_EXCHANGE || 'eracun.classified',
    durable: process.env.RABBITMQ_DURABLE !== 'false',
    persistent: process.env.RABBITMQ_PERSISTENT !== 'false',
  };

  logger.info(
    {
      exchange: config.exchange,
      durable: config.durable,
      persistent: config.persistent,
    },
    'Creating message publisher'
  );

  return new MessagePublisher(config);
}
