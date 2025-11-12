/**
 * Message Consumer Module
 *
 * Consumes PDF classification messages from file-classifier service.
 * - RabbitMQ connection management
 * - Message deserialization
 * - Processing coordination
 * - Error handling and retries
 */

import amqp, { Connection, Channel, ConsumeMessage } from 'amqplib';
import { logger, queueDepth, withSpan } from './observability';

/**
 * Message bus configuration
 */
export interface MessageBusConfig {
  url: string;
  exchange: string;
  queue: string;
  routingKey: string;
  prefetchCount: number;
}

/**
 * PDF classification message from file-classifier
 */
export interface PDFClassificationMessage {
  /** Unique message ID */
  messageId: string;
  /** Email message ID */
  emailMessageId: string;
  /** Attachment ID */
  attachmentId: string;
  /** Filename */
  filename: string;
  /** Classification result */
  classification: {
    processor: string;
    priority: string;
    category: string;
    mimeType: string;
    extension: string;
    size: number;
    confidence: string;
  };
  /** PDF content (base64 encoded) */
  content: string;
  /** Message timestamp */
  timestamp: string;
  /** Source mailbox */
  source: string;
}

/**
 * Message processor callback
 */
export type MessageProcessor = (message: PDFClassificationMessage) => Promise<void>;

/**
 * Message Consumer for RabbitMQ
 */
export class MessageConsumer {
  private config: MessageBusConfig;
  private connection: Connection | null = null;
  private channel: Channel | null = null;
  private isConnected = false;
  private processor: MessageProcessor;

  constructor(config: MessageBusConfig, processor: MessageProcessor) {
    this.config = config;
    this.processor = processor;
  }

  /**
   * Connect to RabbitMQ and start consuming
   */
  async connect(): Promise<void> {
    return withSpan(
      'messagebus.connect',
      {
        exchange: this.config.exchange,
        queue: this.config.queue,
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

          // Create channel
          this.channel = await (this.connection as any).createChannel();

          // Handle channel errors
          this.channel!.on('error', (err: Error) => {
            logger.error({ err }, 'Message bus channel error');
          });

          this.channel!.on('close', () => {
            logger.info('Message bus channel closed');
          });

          // Set prefetch count
          await this.channel!.prefetch(this.config.prefetchCount);

          // Declare exchange
          await this.channel!.assertExchange(this.config.exchange, 'topic', {
            durable: true,
          });

          // Declare queue
          await this.channel!.assertQueue(this.config.queue, {
            durable: true,
          });

          // Bind queue to exchange
          await this.channel!.bindQueue(
            this.config.queue,
            this.config.exchange,
            this.config.routingKey
          );

          // Start consuming messages
          await this.channel!.consume(
            this.config.queue,
            (msg) => this.handleMessage(msg),
            {
              noAck: false, // Require explicit acknowledgment
            }
          );

          this.isConnected = true;
          logger.info('Message bus connected and consuming');

          // Monitor queue depth
          this.startQueueMonitoring();
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
   * Handle incoming message
   */
  private async handleMessage(msg: ConsumeMessage | null): Promise<void> {
    if (!msg) {
      logger.warn('Received null message');
      return;
    }

    try {
      await withSpan(
        'messagebus.handleMessage',
        {
          messageId: msg.properties.messageId || 'unknown',
        },
        async (span) => {
          // Parse message content
          const content = msg.content.toString('utf-8');
          const message: PDFClassificationMessage = JSON.parse(content);

          logger.info(
            {
              messageId: message.messageId,
              attachmentId: message.attachmentId,
              filename: message.filename,
            },
            'Processing PDF message'
          );

          span.setAttribute('attachment_id', message.attachmentId);
          span.setAttribute('filename', message.filename);

          // Process message
          await this.processor(message);

          // Acknowledge message
          this.channel!.ack(msg);

          logger.info({ messageId: message.messageId }, 'Message processed successfully');
          span.setAttribute('status', 'success');
        }
      );
    } catch (err) {
      logger.error({ err, messageId: msg.properties.messageId }, 'Failed to process message');

      // Reject message and requeue to avoid data loss
      this.channel!.nack(msg, false, true);
    }
  }

  /**
   * Monitor queue depth periodically
   */
  private startQueueMonitoring(): void {
    setInterval(async () => {
      try {
        if (this.channel && this.isConnected) {
          const queueInfo = await this.channel.checkQueue(this.config.queue);
          queueDepth.set({ queue: this.config.queue }, queueInfo.messageCount);
        }
      } catch (err) {
        logger.error({ err }, 'Failed to check queue depth');
      }
    }, 10000); // Check every 10 seconds
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
 * Create message consumer from environment variables
 */
export function createMessageConsumerFromEnv(processor: MessageProcessor): MessageConsumer {
  const config: MessageBusConfig = {
    url: process.env.RABBITMQ_URL || 'amqp://localhost:5672',
    exchange: process.env.RABBITMQ_EXCHANGE || 'eracun.files',
    queue: process.env.RABBITMQ_QUEUE || 'pdf-parser-queue',
    routingKey: process.env.RABBITMQ_ROUTING_KEY || 'file.pdf.classify',
    prefetchCount: parseInt(process.env.RABBITMQ_PREFETCH || '10', 10),
  };

  logger.info(
    {
      exchange: config.exchange,
      queue: config.queue,
      routingKey: config.routingKey,
      prefetchCount: config.prefetchCount,
    },
    'Creating message consumer'
  );

  return new MessageConsumer(config, processor);
}
