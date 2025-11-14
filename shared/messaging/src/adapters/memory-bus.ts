/**
 * In-Memory Message Bus
 *
 * Temporary implementation for PENDING-006
 * Provides message bus functionality without external dependencies
 * Will be replaced with real RabbitMQ/Kafka when infrastructure is ready
 */

import EventEmitter from 'eventemitter3';
import { pino } from 'pino';
import type { IMessageBus } from './interfaces.js';
import type { Message, MessageHandler } from '../types/index.js';

const logger = pino({ name: 'memory-bus' });

/**
 * In-Memory Message Bus Implementation
 *
 * Features:
 * - Topic-based pub/sub
 * - Request-response (RPC) pattern
 * - Async message handling
 * - Error handling and logging
 * - No external dependencies
 */
export class InMemoryMessageBus implements IMessageBus {
  private readonly emitter: EventEmitter;
  private readonly pendingRequests: Map<string, {
    resolve: (value: unknown) => void;
    reject: (error: Error) => void;
    timeout: NodeJS.Timeout;
  }> = new Map();
  private closed = false;

  constructor() {
    this.emitter = new EventEmitter();
    logger.info('In-Memory Message Bus initialized');
  }

  /**
   * Publish message to topic
   */
  async publish<T>(
    topic: string,
    payload: T,
    options?: {
      correlationId?: string;
      replyTo?: string;
      metadata?: Record<string, unknown>;
    }
  ): Promise<void> {
    if (this.closed) {
      throw new Error('Message bus is closed');
    }

    const message: Message<T> = {
      id: this.generateMessageId(),
      type: topic,
      payload,
      timestamp: new Date().toISOString(),
      correlationId: options?.correlationId,
      replyTo: options?.replyTo,
      metadata: options?.metadata,
    };

    logger.debug({ topic, messageId: message.id }, 'Publishing message');

    // Emit asynchronously (non-blocking)
    setImmediate(() => {
      this.emitter.emit(topic, message);
    });
  }

  /**
   * Subscribe to topic
   */
  async subscribe<T>(
    topic: string,
    handler: MessageHandler<T>
  ): Promise<() => void> {
    if (this.closed) {
      throw new Error('Message bus is closed');
    }

    logger.info({ topic }, 'Subscribing to topic');

    const wrappedHandler = async (message: Message<T>) => {
      try {
        logger.debug(
          { topic, messageId: message.id },
          'Handling message'
        );
        await handler(message);
      } catch (error) {
        logger.error(
          { error, topic, messageId: message.id },
          'Message handler error'
        );
      }
    };

    this.emitter.on(topic, wrappedHandler);

    // Return unsubscribe function
    return () => {
      logger.info({ topic }, 'Unsubscribing from topic');
      this.emitter.off(topic, wrappedHandler);
    };
  }

  /**
   * Request-response pattern (RPC)
   */
  async request<TReq, TRes>(
    topic: string,
    payload: TReq,
    timeout: number = 30000
  ): Promise<TRes> {
    if (this.closed) {
      throw new Error('Message bus is closed');
    }

    const correlationId = this.generateMessageId();
    const replyTo = `${topic}.reply.${correlationId}`;

    logger.debug({ topic, correlationId }, 'Sending request');

    return new Promise<TRes>((resolve, reject) => {
      // Set up timeout
      const timeoutHandle = setTimeout(() => {
        this.pendingRequests.delete(correlationId);
        reject(new Error(`Request timeout after ${timeout}ms`));
      }, timeout);

      // Store pending request
      this.pendingRequests.set(correlationId, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timeout: timeoutHandle,
      });

      // Subscribe to reply topic
      const replyHandler = (message: Message<TRes>) => {
        if (message.correlationId === correlationId) {
          const pending = this.pendingRequests.get(correlationId);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingRequests.delete(correlationId);
            this.emitter.off(replyTo, replyHandler);
            pending.resolve(message.payload);
          }
        }
      };

      this.emitter.on(replyTo, replyHandler);

      // Publish request
      this.publish(topic, payload, { correlationId, replyTo }).catch(reject);
    });
  }

  /**
   * Reply to request
   */
  async reply<T>(message: Message, payload: T): Promise<void> {
    if (this.closed) {
      throw new Error('Message bus is closed');
    }

    if (!message.replyTo || !message.correlationId) {
      throw new Error('Cannot reply: message has no replyTo or correlationId');
    }

    logger.debug(
      { replyTo: message.replyTo, correlationId: message.correlationId },
      'Sending reply'
    );

    await this.publish(message.replyTo, payload, {
      correlationId: message.correlationId,
    });
  }

  /**
   * Close message bus
   */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }

    logger.info('Closing message bus');

    // Cancel all pending requests
    for (const [correlationId, pending] of this.pendingRequests.entries()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('Message bus closed'));
    }
    this.pendingRequests.clear();

    // Remove all listeners
    this.emitter.removeAllListeners();

    this.closed = true;
  }

  /**
   * Health check
   */
  isHealthy(): boolean {
    return !this.closed;
  }

  /**
   * Generate message ID (UUID v4)
   */
  private generateMessageId(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }
}

/**
 * Create in-memory message bus instance
 */
export function createInMemoryMessageBus(): IMessageBus {
  return new InMemoryMessageBus();
}
