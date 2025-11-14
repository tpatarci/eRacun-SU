/**
 * @eracun/messaging
 *
 * Shared messaging abstractions for eRačun platform
 *
 * PENDING-006 Resolution:
 * This library provides a temporary in-memory message bus adapter
 * that allows all services to publish/consume messages without
 * waiting for RabbitMQ/Kafka infrastructure setup.
 *
 * When the real bus topology is ready, we only swap the transport
 * layer and keep the service contracts unchanged.
 */

export type { IMessageBus } from './adapters/interfaces.js';
export type { Message, MessageHandler, MessageBusConfig } from './types/index.js';

export { InMemoryMessageBus, createInMemoryMessageBus } from './adapters/memory-bus.js';

import { createInMemoryMessageBus } from './adapters/memory-bus.js';
import type { IMessageBus } from './adapters/interfaces.js';
import type { MessageBusConfig } from './types/index.js';

/**
 * Create message bus based on configuration
 *
 * Currently only supports in-memory implementation.
 * Will be extended to support RabbitMQ and Kafka.
 */
export function createMessageBus(config: MessageBusConfig): IMessageBus {
  switch (config.type) {
    case 'memory':
      return createInMemoryMessageBus();
    case 'rabbitmq':
      // TODO: Implement when RabbitMQ is available
      throw new Error('RabbitMQ not yet implemented - use memory for now');
    case 'kafka':
      // TODO: Implement when Kafka is available
      throw new Error('Kafka not yet implemented - use memory for now');
    default:
      throw new Error(`Unknown message bus type: ${config.type}`);
  }
}

/**
 * Get default message bus (in-memory)
 */
let defaultBus: IMessageBus | null = null;

export function getMessageBus(): IMessageBus {
  if (!defaultBus) {
    defaultBus = createInMemoryMessageBus();
  }
  return defaultBus;
}
