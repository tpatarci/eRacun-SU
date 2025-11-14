/**
 * Message Consumer
 * Consumes OCR requests from RabbitMQ
 */

import amqplib, { Channel, Connection, ConsumeMessage } from 'amqplib';
import pino from 'pino';
import { OCRProcessor } from './ocr-processor';
import { OCRRequest, OCRResponse } from './types';

const logger = pino({ name: 'message-consumer' });

export class MessageConsumer {
  private connection?: any;
  private channel?: Channel;
  private readonly processor: OCRProcessor;
  private readonly queueName: string;
  private readonly rabbitUrl: string;
  private isConnected = false;

  constructor(processor: OCRProcessor, options: { rabbitUrl?: string; queueName?: string } = {}) {
    this.processor = processor;
    this.rabbitUrl = options.rabbitUrl || process.env.RABBITMQ_URL || 'amqp://localhost:5672';
    this.queueName = options.queueName || 'files.image.ocr';
  }

  /**
   * Connect to RabbitMQ and start consuming messages
   */
  async start(): Promise<void> {
    try {
      logger.info({ rabbitUrl: this.rabbitUrl, queue: this.queueName }, 'Connecting to RabbitMQ');

      const connection = await amqplib.connect(this.rabbitUrl);
      const channel = await connection.createChannel();

      this.connection = connection;
      this.channel = channel;

      // Assert queue exists
      await channel.assertQueue(this.queueName, {
        durable: true,
        arguments: {
          'x-queue-type': 'quorum' // High availability
        }
      });

      // Assert result queue
      await channel.assertQueue('ocr.results', {
        durable: true
      });

      // Set prefetch to process one message at a time
      await channel.prefetch(1);

      // Start consuming
      await channel.consume(
        this.queueName,
        async (msg: ConsumeMessage | null) => {
          if (msg) {
            await this.handleMessage(msg);
          }
        },
        { noAck: false }
      );

      this.isConnected = true;
      logger.info('Message consumer started successfully');

      // Handle connection errors
      connection.on('error', error => {
        logger.error({ error }, 'RabbitMQ connection error');
        this.isConnected = false;
      });

      connection.on('close', () => {
        logger.warn('RabbitMQ connection closed');
        this.isConnected = false;
        // Attempt reconnection after delay
        setTimeout(() => this.reconnect(), 5000);
      });
    } catch (error) {
      logger.error({ error }, 'Failed to start message consumer');
      throw error;
    }
  }

  /**
   * Handle incoming message
   */
  private async handleMessage(msg: ConsumeMessage): Promise<void> {
    const messageId = msg.properties.messageId || 'unknown';

    try {
      const request: OCRRequest = JSON.parse(msg.content.toString());

      logger.info({ messageId, fileId: request.fileId }, 'Processing OCR message');

      // Process OCR request
      const response = await this.processor.processRequest(request);

      // Publish result
      await this.publishResult(response);

      // Acknowledge message
      this.channel!.ack(msg);

      logger.info(
        { messageId, fileId: request.fileId, success: response.success },
        'OCR message processed successfully'
      );
    } catch (error) {
      logger.error({ error, messageId }, 'Failed to process OCR message');

      // Reject message and requeue (up to 3 times)
      const retryCount = (msg.properties.headers?.['x-retry-count'] || 0) as number;
      if (retryCount < 3) {
        logger.warn({ messageId, retryCount }, 'Requeuing message');
        this.channel!.nack(msg, false, true);
      } else {
        logger.error({ messageId }, 'Max retries exceeded, moving to DLQ');
        // Send to dead letter queue
        await this.publishToDeadLetter(msg);
        this.channel!.ack(msg);
      }
    }
  }

  /**
   * Publish OCR result to results queue
   */
  private async publishResult(response: OCRResponse): Promise<void> {
    if (!this.channel) {
      throw new Error('Channel not initialized');
    }

    const message = Buffer.from(JSON.stringify(response));

    this.channel.publish('', 'ocr.results', message, {
      persistent: true,
      contentType: 'application/json',
      timestamp: Date.now()
    });

    logger.debug({ fileId: response.fileId }, 'Published OCR result');
  }

  /**
   * Publish failed message to dead letter queue
   */
  private async publishToDeadLetter(msg: ConsumeMessage): Promise<void> {
    if (!this.channel) {
      throw new Error('Channel not initialized');
    }

    await this.channel.assertQueue('ocr.dlq', { durable: true });

    this.channel.publish('', 'ocr.dlq', msg.content, {
      persistent: true,
      headers: {
        'x-original-queue': this.queueName,
        'x-failure-reason': 'max-retries-exceeded',
        'x-original-timestamp': msg.properties.timestamp
      }
    });

    logger.warn({ messageId: msg.properties.messageId }, 'Message sent to DLQ');
  }

  /**
   * Reconnect to RabbitMQ
   */
  private async reconnect(): Promise<void> {
    if (this.isConnected) {
      return;
    }

    logger.info('Attempting to reconnect to RabbitMQ');

    try {
      await this.start();
    } catch (error) {
      logger.error({ error }, 'Reconnection failed, retrying in 10 seconds');
      setTimeout(() => this.reconnect(), 10000);
    }
  }

  /**
   * Stop consuming messages and close connections
   */
  async stop(): Promise<void> {
    logger.info('Stopping message consumer');

    try {
      if (this.channel) {
        await this.channel.close();
      }
      if (this.connection) {
        await this.connection.close();
      }
      this.isConnected = false;
      logger.info('Message consumer stopped successfully');
    } catch (error) {
      logger.error({ error }, 'Error stopping message consumer');
      throw error;
    }
  }

  /**
   * Check if consumer is healthy
   */
  isHealthy(): boolean {
    return this.isConnected && !!this.channel && !!this.connection;
  }
}
