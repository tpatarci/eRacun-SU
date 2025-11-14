/**
 * Message Bus Interface
 *
 * Common interface for all message bus implementations
 * (in-memory, RabbitMQ, Kafka)
 */

import type { Message, MessageHandler } from '../types/index.js';

/**
 * Message Bus Interface
 */
export interface IMessageBus {
  /**
   * Publish a message to a topic
   * @param topic - Topic name
   * @param payload - Message payload
   * @param options - Optional message options
   */
  publish<T>(
    topic: string,
    payload: T,
    options?: {
      correlationId?: string;
      replyTo?: string;
      metadata?: Record<string, unknown>;
    }
  ): Promise<void>;

  /**
   * Subscribe to a topic
   * @param topic - Topic name
   * @param handler - Message handler function
   * @returns Unsubscribe function
   */
  subscribe<T>(topic: string, handler: MessageHandler<T>): Promise<() => void>;

  /**
   * Request-response pattern (RPC)
   * @param topic - Topic name
   * @param payload - Request payload
   * @param timeout - Response timeout (ms)
   * @returns Response payload
   */
  request<TReq, TRes>(
    topic: string,
    payload: TReq,
    timeout?: number
  ): Promise<TRes>;

  /**
   * Reply to a request
   * @param message - Original request message
   * @param payload - Response payload
   */
  reply<T>(message: Message, payload: T): Promise<void>;

  /**
   * Close the message bus
   */
  close(): Promise<void>;

  /**
   * Health check
   */
  isHealthy(): boolean;
}
