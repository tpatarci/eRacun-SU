/**
 * Message Publisher Module
 *
 * Publishes parsed invoice data to data-extractor service.
 * - RabbitMQ connection management
 * - Message serialization
 * - Publisher confirms
 * - Error handling and retries
 */

import amqp, { Connection, ConfirmChannel, Options } from 'amqplib';
import { logger, withSpan } from './observability';
import { ParsedInvoice } from './invoice-parser';

/**
 * Message bus configuration
 */
export interface PublisherConfig {
  url: string;
  exchange: string;
  routingKey: string;
  persistent: boolean;
}

/**
 * Parsed invoice command for data-extractor
 */
export interface ParsedInvoiceCommand {
  /** Unique message ID */
  messageId: string;
  /** Email message ID */
  emailMessageId: string;
  /** Attachment ID */
  attachmentId: string;
  /** Original filename */
  filename: string;
  /** PDF metadata */
  pdfMetadata: {
    pageCount: number;
    isScanned: boolean;
    quality: string;
    size: number;
  };
  /** Parsed invoice data */
  invoice: ParsedInvoice;
  /** Message timestamp */
  timestamp: string;
  /** Source mailbox */
  source: string;
}

/**
 * Message Publisher for RabbitMQ
 */
export class MessagePublisher {
  private config: PublisherConfig;
  private connection: Connection | null = null;
  private channel: ConfirmChannel | null = null;
  private isConnected = false;

  constructor(config: PublisherConfig) {
    this.config = config;
  }

  /**
   * Connect to RabbitMQ
   */
  async connect(): Promise<void> {
    return withSpan(
      'messagebus.publisher.connect',
      {
        exchange: this.config.exchange,
      },
      async () => {
        if (this.isConnected) {
          logger.info('Message publisher already connected');
          return;
        }

        logger.info({ url: this.maskUrl(this.config.url) }, 'Connecting message publisher');

        try {
          // Create connection
          this.connection = (await amqp.connect(this.config.url)) as any as Connection;

          // Handle connection errors
          this.connection!.on('error', (err: Error) => {
            logger.error({ err }, 'Publisher connection error');
            this.isConnected = false;
          });

          this.connection!.on('close', () => {
            logger.info('Publisher connection closed');
            this.isConnected = false;
          });

          // Create confirm channel
          this.channel = await (this.connection as any).createConfirmChannel();

          // Handle channel errors
          this.channel!.on('error', (err: Error) => {
            logger.error({ err }, 'Publisher channel error');
          });

          this.channel!.on('close', () => {
            logger.info('Publisher channel closed');
          });

          // Declare exchange
          await this.channel!.assertExchange(this.config.exchange, 'topic', {
            durable: true,
          });

          this.isConnected = true;
          logger.info('Message publisher connected');
        } catch (err) {
          logger.error({ err }, 'Failed to connect message publisher');
          throw err;
        }
      }
    );
  }

  /**
   * Disconnect from RabbitMQ
   */
  async disconnect(): Promise<void> {
    logger.info('Disconnecting message publisher');

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
      logger.info('Message publisher disconnected');
    } catch (err) {
      logger.error({ err }, 'Error disconnecting message publisher');
      throw err;
    }
  }

  /**
   * Publish parsed invoice
   */
  async publishParsedInvoice(command: ParsedInvoiceCommand): Promise<void> {
    const channel = this.channel;
    if (!channel || !this.isConnected) {
      throw new Error('Publisher not connected');
    }

    return withSpan(
      'messagebus.publisher.publish',
      {
        messageId: command.messageId,
        attachmentId: command.attachmentId,
      },
      async (span) => {
        logger.info(
          {
            messageId: command.messageId,
            attachmentId: command.attachmentId,
            confidence: command.invoice.confidence,
          },
          'Publishing parsed invoice'
        );

        span.setAttribute('confidence', command.invoice.confidence);
        span.setAttribute('extracted_fields', command.invoice.extractedFields.length);

        // Serialize message
        const messageBuffer = Buffer.from(JSON.stringify(command));

        // Publish options
        const publishOptions: Options.Publish = {
          persistent: this.config.persistent,
          contentType: 'application/json',
          messageId: command.messageId,
          timestamp: Date.now(),
          headers: {
            confidence: command.invoice.confidence,
            isScanned: command.pdfMetadata.isScanned,
          },
        };

        // Publish with confirmation
        channel.publish(
          this.config.exchange,
          this.config.routingKey,
          messageBuffer,
          publishOptions
        );

        await channel.waitForConfirms();

        logger.info({ messageId: command.messageId }, 'Parsed invoice published successfully');
        span.setAttribute('status', 'success');
      }
    );
  }

  /**
   * Publish scanned PDF to OCR service
   */
  async publishScannedPDF(
    messageId: string,
    attachmentId: string,
    filename: string,
    content: string,
    source: string
  ): Promise<void> {
    const channel = this.channel;
    if (!channel || !this.isConnected) {
      throw new Error('Publisher not connected');
    }

    return withSpan(
      'messagebus.publisher.publishScannedPDF',
      {
        messageId,
        attachmentId,
      },
      async () => {
        logger.info(
          {
            messageId,
            attachmentId,
            filename,
          },
          'Publishing scanned PDF to OCR service'
        );

        const ocrCommand = {
          messageId: `ocr-${messageId}`,
          attachmentId,
          filename,
          content, // base64 PDF content
          timestamp: new Date().toISOString(),
          source,
        };

        const messageBuffer = Buffer.from(JSON.stringify(ocrCommand));

        const publishOptions: Options.Publish = {
          persistent: this.config.persistent,
          contentType: 'application/json',
          messageId: ocrCommand.messageId,
          timestamp: Date.now(),
        };

        // Publish to OCR routing key
        channel.publish(
          this.config.exchange,
          'file.image.classify', // Route to OCR service
          messageBuffer,
          publishOptions
        );

        await channel.waitForConfirms();

        logger.info({ messageId }, 'Scanned PDF published to OCR');
      }
    );
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
  const config: PublisherConfig = {
    url: process.env.RABBITMQ_URL || 'amqp://localhost:5672',
    exchange: process.env.RABBITMQ_EXCHANGE || 'eracun.invoices',
    routingKey: process.env.RABBITMQ_ROUTING_KEY_PARSED || 'invoice.parsed',
    persistent: process.env.RABBITMQ_PERSISTENT !== 'false',
  };

  logger.info(
    {
      exchange: config.exchange,
      routingKey: config.routingKey,
      persistent: config.persistent,
    },
    'Creating message publisher'
  );

  return new MessagePublisher(config);
}
