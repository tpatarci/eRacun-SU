/* eslint-disable @typescript-eslint/no-var-requires */
import { Buffer } from 'buffer';
import { randomUUID } from 'crypto';
import { logger } from '../observability';
import { RpcClient, RpcRequest } from './rpc-client';
import { InMemoryRpcClient } from './in-memory-rpc-client';

interface RabbitConfig {
  url: string;
  replyQueue?: string;
  defaultTimeoutMs: number;
  prefetch: number;
}

interface AmqpMessage {
  content: Buffer;
  properties: {
    correlationId?: string;
  };
}

interface AmqpChannel {
  assertQueue(queue: string, options?: Record<string, unknown>): Promise<{ queue: string }>;
  consume(
    queue: string,
    onMessage: (msg: AmqpMessage | null) => void,
    options?: Record<string, unknown>
  ): Promise<{ consumerTag: string }>;
  sendToQueue(queue: string, content: Buffer, options?: Record<string, unknown>): boolean;
  prefetch(count: number): Promise<void> | void;
  close(): Promise<void>;
}

interface AmqpConnection {
  createChannel(): Promise<AmqpChannel>;
  on(event: string, listener: (...args: unknown[]) => void): void;
  close(): Promise<void>;
}

interface AmqpModule {
  connect(url: string): Promise<AmqpConnection>;
}

interface PendingRpc {
  resolve: (payload: Uint8Array) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

/**
 * RabbitMQ RPC client that falls back to the in-memory implementation when
 * amqplib is not available (e.g., during CI or local unit tests).
 */
export class RabbitMQRpcClient implements RpcClient {
  private readonly fallback = new InMemoryRpcClient();
  private readonly config: RabbitConfig;
  private readonly pending = new Map<string, PendingRpc>();
  private readonly amqp: AmqpModule | null;
  private connection: AmqpConnection | null = null;
  private channel: AmqpChannel | null = null;
  private replyQueue?: string;
  private useFallback: boolean;

  constructor(config?: Partial<RabbitConfig>) {
    this.config = {
      url: process.env.RABBITMQ_URL || 'amqp://rabbitmq:5672',
      replyQueue: process.env.ADMIN_PORTAL_REPLY_QUEUE,
      defaultTimeoutMs: parseInt(process.env.RABBITMQ_TIMEOUT_MS || '5000', 10),
      prefetch: parseInt(process.env.RABBITMQ_PREFETCH || '5', 10),
      ...config,
    };

    try {
      this.amqp = require('amqplib') as AmqpModule;
      this.useFallback = false;
    } catch (err) {
      this.amqp = null;
      this.useFallback = true;
      logger.warn(
        { err },
        'amqplib dependency unavailable; defaulting admin portal messaging to in-memory RPC'
      );
    }
  }

  async request(request: RpcRequest): Promise<Uint8Array> {
    if (this.useFallback || !this.amqp) {
      return this.fallback.request(request);
    }

    const channel = await this.ensureChannel();
    if (!channel || !this.replyQueue) {
      logger.error('Unable to initialize RabbitMQ channel, falling back to memory bus');
      this.useFallback = true;
      return this.fallback.request(request);
    }

    const timeoutMs = request.timeoutMs ?? this.config.defaultTimeoutMs;
    return new Promise<Uint8Array>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(request.correlationId);
        reject(new Error(`RPC timeout after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(request.correlationId, { resolve, reject, timeout });

      const headers = Object.entries(request.headers || {}).reduce<Record<string, string>>(
        (acc, [key, value]) => {
          if (typeof value === 'string') {
            acc[key] = value;
          }
          return acc;
        },
        {}
      );

      const messageId = request.messageId || request.correlationId || randomUUID();
      const payloadBuffer = Buffer.from(request.payload);

      const published = channel.sendToQueue(request.routingKey, payloadBuffer, {
        correlationId: request.correlationId,
        replyTo: this.replyQueue,
        headers,
        messageId,
        contentType: 'application/octet-stream',
        timestamp: Date.now(),
      });

      if (!published) {
        clearTimeout(timeout);
        this.pending.delete(request.correlationId);
        reject(new Error(`Failed to publish message to ${request.routingKey}`));
      }
    });
  }

  async close(): Promise<void> {
    if (this.channel) {
      await this.channel.close();
      this.channel = null;
    }
    if (this.connection) {
      await this.connection.close();
      this.connection = null;
    }
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('RabbitMQ client closed'));
    }
    this.pending.clear();
    await this.fallback.close();
  }

  private async ensureChannel(): Promise<AmqpChannel | null> {
    if (!this.amqp) {
      return null;
    }

    if (this.channel) {
      return this.channel;
    }

    try {
      this.connection = await this.amqp.connect(this.config.url);
      this.connection.on('error', (err) => {
        logger.error({ err }, 'RabbitMQ connection error');
        this.useFallback = true;
      });

      this.connection.on('close', () => {
        logger.warn('RabbitMQ connection closed');
        this.connection = null;
        this.channel = null;
        this.replyQueue = undefined;
      });

      this.channel = await this.connection.createChannel();
      if (this.channel.prefetch) {
        await this.channel.prefetch(this.config.prefetch);
      }

      const replyQueue = await this.channel.assertQueue(this.config.replyQueue || '', {
        exclusive: !this.config.replyQueue,
        durable: false,
        autoDelete: !this.config.replyQueue,
      });
      this.replyQueue = replyQueue.queue;

      await this.channel.consume(
        this.replyQueue,
        (message) => this.handleResponse(message),
        { noAck: true }
      );

      return this.channel;
    } catch (err) {
      logger.error({ err }, 'Failed to bootstrap RabbitMQ channel');
      this.useFallback = true;
      return null;
    }
  }

  private handleResponse(message: AmqpMessage | null) {
    if (!message || !message.properties.correlationId) {
      return;
    }

    const pending = this.pending.get(message.properties.correlationId);
    if (!pending) {
      return;
    }

    clearTimeout(pending.timeout);
    this.pending.delete(message.properties.correlationId);
    pending.resolve(new Uint8Array(message.content));
  }
}
