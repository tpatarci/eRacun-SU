/**
 * Shared Messaging Types
 */

/**
 * Message envelope
 */
export interface Message<T = unknown> {
  /** Message ID (UUID) */
  id: string;
  /** Message type/topic */
  type: string;
  /** Message payload */
  payload: T;
  /** Timestamp */
  timestamp: string;
  /** Correlation ID (for request-response) */
  correlationId?: string;
  /** Reply-to topic (for request-response) */
  replyTo?: string;
  /** Metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Message handler function
 */
export type MessageHandler<T = unknown> = (message: Message<T>) => Promise<void> | void;

/**
 * Message bus configuration
 */
export interface MessageBusConfig {
  /** Bus type */
  type: 'memory' | 'rabbitmq' | 'kafka';
  /** Connection URL (for RabbitMQ/Kafka) */
  url?: string;
  /** Additional options */
  options?: Record<string, unknown>;
}
