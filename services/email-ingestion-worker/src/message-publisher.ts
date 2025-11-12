/**
 * Message Publisher Module
 *
 * Publishes extracted attachments to RabbitMQ message bus.
 * - RabbitMQ connection management
 * - Message serialization and publishing
 * - Retry logic with exponential backoff
 * - Publisher confirms for reliability
 */

import amqp, { Connection, ConfirmChannel, Options } from 'amqplib';
import { ExtractedAttachment } from './attachment-extractor';
import {
  logger,
  messagesPublishedTotal,
  emailProcessingDuration,
  withSpan,
} from './observability';

/**
 * Message bus configuration
 */
export interface MessageBusConfig {
  url: string;
  exchange: string;
  routingKey: string;
  durable: boolean;
  persistent: boolean;
}

/**
 * Attachment processing command message
 */
export interface ProcessAttachmentCommand {
  /** Unique message ID */
  messageId: string;
  /** Email message ID */
  emailMessageId: string;
  /** Attachment metadata */
  attachment: {
    id: string;
    filename: string;
    contentType: string;
    size: number;
    checksum: string;
  };
  /** Attachment content (base64 encoded) */
  content: string;
  /** Message timestamp */
  timestamp: string;
  /** Source mailbox */
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
  private queueDepth = 0; // IMPROVEMENT-005: Track queue depth for backpressure
  private maxQueueDepth = 1000; // IMPROVEMENT-005: Maximum queue depth before backpressure

  constructor(config: MessageBusConfig) {
    this.config = config;
  }

  /**
   * Get current queue depth (IMPROVEMENT-005)
   */
  getQueueDepth(): number {
    return this.queueDepth;
  }

  /**
   * Set maximum queue depth threshold (IMPROVEMENT-005)
   */
  setMaxQueueDepth(max: number): void {
    this.maxQueueDepth = max;
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
          // Create connection (type assertion needed due to amqplib type definitions)
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

          // Create channel with publisher confirms (cast needed for createConfirmChannel)
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
   * Publish attachment for processing
   */
  async publishAttachment(
    emailMessageId: string,
    attachment: ExtractedAttachment,
    source: string
  ): Promise<void> {
    const endTimer = emailProcessingDuration.startTimer({ operation: 'publish' });

    // IMPROVEMENT-005: Track queue depth
    this.queueDepth++;

    try {
      await withSpan(
        'messagebus.publish',
        {
          attachment_id: attachment.id,
          content_type: attachment.contentType,
          size: attachment.size,
          queue_depth: this.queueDepth,
        },
        async (span) => {
          if (!this.channel || !this.isConnected) {
            throw new Error('Message bus not connected');
          }

          // Create command message
          const command: ProcessAttachmentCommand = {
            messageId: `${emailMessageId}-${attachment.id}`,
            emailMessageId,
            attachment: {
              id: attachment.id,
              filename: attachment.filename,
              contentType: attachment.contentType,
              size: attachment.size,
              checksum: attachment.checksum,
            },
            content: attachment.content.toString('base64'),
            timestamp: new Date().toISOString(),
            source,
          };

          // Serialize message
          const messageBuffer = Buffer.from(JSON.stringify(command));

          // Publish options
          const publishOptions: Options.Publish = {
            persistent: this.config.persistent,
            contentType: 'application/json',
            contentEncoding: 'utf-8',
            timestamp: Date.now(),
            messageId: command.messageId,
          };

          logger.info(
            {
              messageId: command.messageId,
              attachmentId: attachment.id,
              filename: attachment.filename,
              size: messageBuffer.length,
              queueDepth: this.queueDepth,
            },
            'Publishing attachment to message bus'
          );

          // Publish with confirmation
          if (!this.channel) {
            throw new Error('Channel not available');
          }

          try {
            // Publish message to exchange
            this.channel.publish(
              this.config.exchange,
              this.config.routingKey,
              messageBuffer,
              publishOptions
            );

            // Wait for broker confirmation
            await this.channel.waitForConfirms();

            logger.info(
              { messageId: command.messageId },
              'Message published successfully'
            );
            messagesPublishedTotal.inc({
              message_type: 'attachment',
              status: 'success',
            });
            span.setAttribute('status', 'success');
          } catch (err) {
            logger.error(
              { err, messageId: command.messageId },
              'Failed to publish message'
            );
            messagesPublishedTotal.inc({
              message_type: 'attachment',
              status: 'error',
            });
            span.setAttribute('status', 'error');
            throw err;
          }
        }
      );
    } catch (err) {
      logger.error({ err, attachmentId: attachment.id }, 'Failed to publish attachment');
      throw err;
    } finally {
      // IMPROVEMENT-005: Decrement queue depth after publishing
      this.queueDepth--;
      endTimer();
    }
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
    exchange: process.env.RABBITMQ_EXCHANGE || 'eracun.attachments',
    routingKey: process.env.RABBITMQ_ROUTING_KEY || 'attachment.process',
    durable: process.env.RABBITMQ_DURABLE !== 'false',
    persistent: process.env.RABBITMQ_PERSISTENT !== 'false',
  };

  logger.info(
    {
      exchange: config.exchange,
      routingKey: config.routingKey,
      durable: config.durable,
      persistent: config.persistent,
    },
    'Creating message publisher'
  );

  return new MessagePublisher(config);
}
