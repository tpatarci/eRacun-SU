import { EventEmitter } from 'node:events';

export interface MessageProperties {
  messageId?: string;
  contentType?: string;
  timestamp?: number;
  headers?: Record<string, unknown>;
  persistent?: boolean;
}

export interface MessageFields {
  deliveryTag: number;
  exchange: string;
  routingKey: string;
  queue: string;
}

export interface ConsumeMessage {
  content: Buffer;
  fields: MessageFields;
  properties: MessageProperties;
}

export interface ConsumeOptions {
  noAck?: boolean;
}

export interface AssertQueueReply {
  queue: string;
  messageCount: number;
  consumerCount: number;
}

export namespace Options {
  export interface Publish extends MessageProperties {}
}

type ConsumeHandler = (msg: ConsumeMessage | null) => void;

type Binding = {
  queue: string;
  routingKey: string;
};

type QueueState = {
  name: string;
  messages: ConsumeMessage[];
  consumers: Set<ConsumeHandler>;
};

class MockBroker {
  private exchanges = new Map<string, Binding[]>();
  private queues = new Map<string, QueueState>();
  private deliveryTag = 1;

  reset(): void {
    this.exchanges.clear();
    this.queues.clear();
    this.deliveryTag = 1;
  }

  assertExchange(name: string): void {
    if (!this.exchanges.has(name)) {
      this.exchanges.set(name, []);
    }
  }

  assertQueue(name: string): QueueState {
    let queue = this.queues.get(name);
    if (!queue) {
      queue = { name, messages: [], consumers: new Set() };
      this.queues.set(name, queue);
    }
    return queue;
  }

  bindQueue(queue: string, exchange: string, routingKey: string): void {
    this.assertExchange(exchange);
    const bindings = this.exchanges.get(exchange)!;
    bindings.push({ queue, routingKey });
  }

  publish(
    exchange: string,
    routingKey: string,
    content: Buffer,
    properties: MessageProperties = {}
  ): void {
    if (!this.exchanges.has(exchange)) {
      return;
    }
    const bindings = this.exchanges.get(exchange)!;
    const matching = bindings.filter((binding) => binding.routingKey === routingKey);

    for (const binding of matching) {
      const queue = this.assertQueue(binding.queue);
      const message: ConsumeMessage = {
        content: Buffer.from(content),
        properties: { ...properties },
        fields: {
          deliveryTag: this.deliveryTag++,
          exchange,
          routingKey,
          queue: binding.queue,
        },
      };

      if (queue.consumers.size > 0) {
        for (const handler of queue.consumers) {
          // Simulate async delivery
          setImmediate(() => handler(message));
        }
      } else {
        queue.messages.push(message);
      }
    }
  }

  consume(queueName: string, handler: ConsumeHandler): string {
    const queue = this.assertQueue(queueName);
    queue.consumers.add(handler);
    while (queue.messages.length > 0) {
      const message = queue.messages.shift();
      if (message) {
        setImmediate(() => handler(message));
      }
    }
    return `mock-consumer-${queue.consumers.size}`;
  }

  ack(_message?: ConsumeMessage | null): void {
    // No-op: delivery is synchronous for the mock
  }

  nack(message: ConsumeMessage, _allUpTo = false, requeue = false): void {
    if (!requeue) {
      return;
    }
    const queueState = this.queues.get(message.fields.queue);
    if (queueState) {
      queueState.messages.unshift(message);
    }
  }

  checkQueue(queueName: string): AssertQueueReply {
    const queue = this.assertQueue(queueName);
    return {
      queue: queue.name,
      messageCount: queue.messages.length,
      consumerCount: queue.consumers.size,
    };
  }

  drainQueue(queueName: string): ConsumeMessage[] {
    const queue = this.assertQueue(queueName);
    const drained = [...queue.messages];
    queue.messages.length = 0;
    return drained;
  }
}

const broker = new MockBroker();

export class MockChannel extends EventEmitter {
  constructor(private readonly isConfirm: boolean) {
    super();
  }

  async prefetch(): Promise<void> {
    // Prefetch is ignored in mock implementation
  }

  async assertExchange(name: string): Promise<void> {
    broker.assertExchange(name);
  }

  async assertQueue(name: string): Promise<AssertQueueReply> {
    broker.assertQueue(name);
    return broker.checkQueue(name);
  }

  async bindQueue(queue: string, exchange: string, routingKey: string): Promise<void> {
    broker.bindQueue(queue, exchange, routingKey);
  }

  async consume(
    queue: string,
    handler: ConsumeHandler,
    _options?: ConsumeOptions
  ): Promise<{ consumerTag: string }> {
    const consumerTag = broker.consume(queue, handler);
    return { consumerTag };
  }

  ack(message: ConsumeMessage): void {
    broker.ack(message);
  }

  nack(message: ConsumeMessage, allUpTo = false, requeue = false): void {
    broker.nack(message, allUpTo, requeue);
  }

  publish(
    exchange: string,
    routingKey: string,
    content: Buffer,
    options?: Options.Publish
  ): boolean {
    broker.publish(exchange, routingKey, content, options);
    return true;
  }

  async waitForConfirms(): Promise<void> {
    if (!this.isConfirm) {
      return;
    }
  }

  async checkQueue(queue: string): Promise<AssertQueueReply> {
    return broker.checkQueue(queue);
  }

  async close(): Promise<void> {
    this.emit('close');
  }
}

export class MockConnection extends EventEmitter {
  async createChannel(): Promise<MockChannel> {
    return new MockChannel(false);
  }

  async createConfirmChannel(): Promise<MockChannel> {
    return new MockChannel(true);
  }

  async close(): Promise<void> {
    this.emit('close');
  }
}

export type Channel = MockChannel;
export type ConfirmChannel = MockChannel;
export type Connection = MockConnection;

export async function connect(): Promise<MockConnection> {
  return new MockConnection();
}

export function resetMockBroker(): void {
  broker.reset();
}

export function publishMockMessage(
  exchange: string,
  routingKey: string,
  content: Buffer,
  properties?: MessageProperties
): void {
  broker.publish(exchange, routingKey, content, properties);
}

export function drainMockQueue(queueName: string): ConsumeMessage[] {
  return broker.drainQueue(queueName);
}

const amqp = { connect };
export default amqp;
export { broker as mockBroker };
