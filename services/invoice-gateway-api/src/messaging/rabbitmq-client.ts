/**
 * RabbitMQ Client for Command-Based Communication
 *
 * Implements request-response pattern (RPC) for synchronous commands
 * between services using RabbitMQ.
 */

import * as amqp from 'amqplib';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';

const logger = pino({ name: 'rabbitmq-client' });

export interface CommandMessage {
  id: string;
  type: string;
  payload: unknown;
  timestamp: string;
  correlationId?: string;
}

export interface CommandResponse {
  id: string;
  success: boolean;
  data?: unknown;
  error?: {
    code: string;
    message: string;
  };
}

export class RabbitMQClient {
  private connection: amqp.Connection | null = null;
  private channel: amqp.Channel | null = null;
  private readonly url: string;
  private readonly maxRetries = 3;
  private readonly retryDelay = 2000; // 2 seconds

  constructor(url?: string) {
    this.url = url || process.env.RABBITMQ_URL || 'amqp://localhost:5672';
  }

  /**
   * Connect to RabbitMQ with automatic retry
   */
  async connect(): Promise<void> {
    let attempt = 0;

    while (attempt < this.maxRetries) {
      try {
        logger.info({ url: this.url, attempt }, 'Connecting to RabbitMQ');

        this.connection = await amqp.connect(this.url);
        this.channel = await this.connection.createChannel();

        // Handle connection errors
        this.connection.on('error', (err) => {
          logger.error({ error: err }, 'RabbitMQ connection error');
        });

        this.connection.on('close', () => {
          logger.warn('RabbitMQ connection closed');
        });

        logger.info('Connected to RabbitMQ');
        return;

      } catch (error) {
        attempt++;
        logger.error({ error, attempt }, 'Failed to connect to RabbitMQ');

        if (attempt >= this.maxRetries) {
          throw new Error(`Failed to connect to RabbitMQ after ${this.maxRetries} attempts`);
        }

        // Exponential backoff with jitter
        const delay = this.retryDelay * Math.pow(2, attempt) + Math.random() * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  /**
   * Send command and wait for response (RPC pattern)
   */
  async sendCommand<T = unknown>(
    queue: string,
    command: Omit<CommandMessage, 'id' | 'timestamp'>
  ): Promise<CommandResponse> {
    if (!this.channel) {
      throw new Error('RabbitMQ channel not initialized. Call connect() first.');
    }

    const correlationId = command.correlationId || uuidv4();
    const message: CommandMessage = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      ...command,
      correlationId,
    };

    // Create exclusive reply queue
    const { queue: replyQueue } = await this.channel.assertQueue('', {
      exclusive: true,
      autoDelete: true,
    });

    // Promise to resolve when response is received
    const responsePromise = new Promise<CommandResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Command timeout after 30s: ${command.type}`));
      }, 30000); // 30 second timeout

      // Consume response from reply queue
      this.channel!.consume(
        replyQueue,
        (msg) => {
          if (!msg) return;

          if (msg.properties.correlationId === correlationId) {
            clearTimeout(timeout);

            const response: CommandResponse = JSON.parse(msg.content.toString());
            this.channel!.ack(msg);

            resolve(response);
          }
        },
        { noAck: false }
      );
    });

    // Send command to target queue
    await this.channel.assertQueue(queue, { durable: true });
    this.channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)), {
      correlationId,
      replyTo: replyQueue,
      persistent: true,
      contentType: 'application/json',
      timestamp: Date.now(),
    });

    logger.debug({ queue, commandType: command.type, correlationId }, 'Command sent');

    return responsePromise;
  }

  /**
   * Consume commands from queue (for service workers)
   */
  async consumeCommands(
    queue: string,
    handler: (message: CommandMessage) => Promise<CommandResponse>
  ): Promise<void> {
    if (!this.channel) {
      throw new Error('RabbitMQ channel not initialized. Call connect() first.');
    }

    await this.channel.assertQueue(queue, { durable: true });
    await this.channel.prefetch(1); // Process one message at a time

    logger.info({ queue }, 'Started consuming commands');

    this.channel.consume(
      queue,
      async (msg) => {
        if (!msg) return;

        try {
          const command: CommandMessage = JSON.parse(msg.content.toString());
          logger.debug({ queue, commandType: command.type }, 'Processing command');

          // Execute handler
          const response = await handler(command);

          // Send response back
          if (msg.properties.replyTo) {
            this.channel!.sendToQueue(
              msg.properties.replyTo,
              Buffer.from(JSON.stringify(response)),
              {
                correlationId: msg.properties.correlationId,
                contentType: 'application/json',
              }
            );
          }

          // Acknowledge message
          this.channel!.ack(msg);

        } catch (error) {
          logger.error({ error, queue }, 'Error processing command');

          // Send error response
          if (msg.properties.replyTo) {
            const errorResponse: CommandResponse = {
              id: uuidv4(),
              success: false,
              error: {
                code: 'COMMAND_PROCESSING_ERROR',
                message: error instanceof Error ? error.message : 'Unknown error',
              },
            };

            this.channel!.sendToQueue(
              msg.properties.replyTo,
              Buffer.from(JSON.stringify(errorResponse)),
              {
                correlationId: msg.properties.correlationId,
                contentType: 'application/json',
              }
            );
          }

          // Negative acknowledge (requeue on transient errors)
          this.channel!.nack(msg, false, false);
        }
      },
      { noAck: false }
    );
  }

  /**
   * Gracefully close connection
   */
  async close(): Promise<void> {
    try {
      if (this.channel) {
        await this.channel.close();
        this.channel = null;
      }

      if (this.connection) {
        await this.connection.close();
        this.connection = null;
      }

      logger.info('RabbitMQ connection closed');
    } catch (error) {
      logger.error({ error }, 'Error closing RabbitMQ connection');
    }
  }
}
