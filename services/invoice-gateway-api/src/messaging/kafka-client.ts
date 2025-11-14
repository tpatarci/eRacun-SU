/**
 * Kafka Client for Event-Based Communication
 *
 * Implements publish-subscribe pattern for broadcasting domain events
 * across services using Apache Kafka.
 */

import { Kafka, Producer, Consumer, EachMessagePayload, Admin } from 'kafkajs';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';

const logger = pino({ name: 'kafka-client' });

export interface DomainEvent {
  id: string;
  type: string;
  source: string;
  data: unknown;
  timestamp: string;
  version: string;
  correlationId?: string;
}

export type EventHandler = (event: DomainEvent) => Promise<void>;

export class KafkaClient {
  private kafka: Kafka;
  private producer: Producer | null = null;
  private consumers: Map<string, Consumer> = new Map();
  private admin: Admin | null = null;
  private readonly serviceName: string;

  constructor(serviceName: string, brokers?: string[]) {
    this.serviceName = serviceName;

    const kafkaBrokers = brokers || [
      process.env.KAFKA_BROKER || 'localhost:9092'
    ];

    this.kafka = new Kafka({
      clientId: serviceName,
      brokers: kafkaBrokers,
      retry: {
        initialRetryTime: 300,
        retries: 8,
        multiplier: 2,
        maxRetryTime: 30000,
      },
      logLevel: parseInt(process.env.KAFKA_LOG_LEVEL || '2'), // ERROR level
    });

    logger.info({ serviceName, brokers: kafkaBrokers }, 'Kafka client initialized');
  }

  /**
   * Connect producer and admin client
   */
  async connect(): Promise<void> {
    try {
      // Create producer
      this.producer = this.kafka.producer({
        allowAutoTopicCreation: false,
        transactionTimeout: 30000,
      });

      await this.producer.connect();
      logger.info('Kafka producer connected');

      // Create admin client
      this.admin = this.kafka.admin();
      await this.admin.connect();
      logger.info('Kafka admin client connected');

    } catch (error) {
      logger.error({ error }, 'Failed to connect to Kafka');
      throw error;
    }
  }

  /**
   * Publish domain event to topic
   */
  async publishEvent(topic: string, event: Omit<DomainEvent, 'id' | 'timestamp' | 'source'>): Promise<void> {
    if (!this.producer) {
      throw new Error('Kafka producer not initialized. Call connect() first.');
    }

    const domainEvent: DomainEvent = {
      id: uuidv4(),
      source: this.serviceName,
      timestamp: new Date().toISOString(),
      version: '1.0',
      ...event,
    };

    try {
      await this.producer.send({
        topic,
        messages: [
          {
            key: domainEvent.id,
            value: JSON.stringify(domainEvent),
            headers: {
              'event-type': domainEvent.type,
              'event-version': domainEvent.version,
              'correlation-id': domainEvent.correlationId || '',
            },
          },
        ],
      });

      logger.debug({ topic, eventType: event.type, eventId: domainEvent.id }, 'Event published');

    } catch (error) {
      logger.error({ error, topic, eventType: event.type }, 'Failed to publish event');
      throw error;
    }
  }

  /**
   * Subscribe to events from topic
   */
  async subscribeToEvents(
    topic: string,
    groupId: string,
    handler: EventHandler
  ): Promise<void> {
    try {
      const consumer = this.kafka.consumer({
        groupId,
        sessionTimeout: 30000,
        heartbeatInterval: 3000,
      });

      await consumer.connect();
      logger.info({ topic, groupId }, 'Kafka consumer connected');

      await consumer.subscribe({ topic, fromBeginning: false });

      await consumer.run({
        eachMessage: async (payload: EachMessagePayload) => {
          const { topic, partition, message } = payload;

          try {
            if (!message.value) {
              logger.warn({ topic, partition }, 'Received empty message');
              return;
            }

            const event: DomainEvent = JSON.parse(message.value.toString());

            logger.debug(
              {
                topic,
                partition,
                offset: message.offset,
                eventType: event.type,
                eventId: event.id,
              },
              'Processing event'
            );

            // Execute handler
            await handler(event);

          } catch (error) {
            logger.error(
              {
                error,
                topic,
                partition,
                offset: message.offset,
              },
              'Error processing event'
            );

            // Events are not retried - dead letter queue should be configured in Kafka
            throw error;
          }
        },
      });

      this.consumers.set(topic, consumer);
      logger.info({ topic, groupId }, 'Started consuming events');

    } catch (error) {
      logger.error({ error, topic, groupId }, 'Failed to subscribe to events');
      throw error;
    }
  }

  /**
   * Create topic with configuration
   */
  async createTopic(
    topic: string,
    numPartitions = 3,
    replicationFactor = 1
  ): Promise<void> {
    if (!this.admin) {
      throw new Error('Kafka admin client not initialized. Call connect() first.');
    }

    try {
      const topics = await this.admin.listTopics();

      if (topics.includes(topic)) {
        logger.debug({ topic }, 'Topic already exists');
        return;
      }

      await this.admin.createTopics({
        topics: [
          {
            topic,
            numPartitions,
            replicationFactor,
            configEntries: [
              { name: 'retention.ms', value: '604800000' }, // 7 days
              { name: 'compression.type', value: 'snappy' },
            ],
          },
        ],
      });

      logger.info({ topic, numPartitions, replicationFactor }, 'Topic created');

    } catch (error) {
      logger.error({ error, topic }, 'Failed to create topic');
      throw error;
    }
  }

  /**
   * Gracefully disconnect all consumers and producer
   */
  async disconnect(): Promise<void> {
    try {
      // Disconnect all consumers
      for (const [topic, consumer] of this.consumers) {
        await consumer.disconnect();
        logger.info({ topic }, 'Consumer disconnected');
      }
      this.consumers.clear();

      // Disconnect producer
      if (this.producer) {
        await this.producer.disconnect();
        this.producer = null;
        logger.info('Producer disconnected');
      }

      // Disconnect admin client
      if (this.admin) {
        await this.admin.disconnect();
        this.admin = null;
        logger.info('Admin client disconnected');
      }

      logger.info('Kafka client disconnected');

    } catch (error) {
      logger.error({ error }, 'Error disconnecting Kafka client');
    }
  }
}
