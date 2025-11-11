import { Kafka, Consumer, EachMessagePayload } from 'kafkajs';
import { writeAuditEvent, AuditEvent } from './writer';
import {
  logger,
  auditConsumerLag,
  createSpan,
  setSpanError,
} from './observability';

let consumer: Consumer | null = null;

/**
 * Start Kafka consumer for audit-log topic
 *
 * CRITICAL: This consumer MUST NOT commit offsets until PostgreSQL write succeeds
 * to prevent data loss
 */
export async function startConsumer(): Promise<void> {
  const span = createSpan('start_consumer');

  try {
    const brokers = (process.env.KAFKA_BROKERS || 'localhost:9092').split(',');
    const topic = process.env.KAFKA_TOPIC || 'audit-log';
    const groupId = process.env.KAFKA_GROUP_ID || 'audit-logger-group';

    logger.info({
      brokers,
      topic,
      group_id: groupId,
    }, 'Initializing Kafka consumer');

    const kafka = new Kafka({
      clientId: 'audit-logger',
      brokers,
      retry: {
        initialRetryTime: 300,
        retries: 8,
        maxRetryTime: 30000,
      },
    });

    consumer = kafka.consumer({
      groupId,
      sessionTimeout: 30000,
      heartbeatInterval: 3000,
      // Start from earliest to never lose events
      fromBeginning: true,
    });

    await consumer.connect();
    logger.info('Kafka consumer connected');

    await consumer.subscribe({
      topic,
      fromBeginning: true,
    });

    logger.info({ topic }, 'Subscribed to audit-log topic');

    // Start consuming messages
    await consumer.run({
      autoCommit: false, // Manual commit after successful write
      eachMessage: async (payload: EachMessagePayload) => {
        await handleMessage(payload);
      },
    });

    span.end();
    logger.info('Kafka consumer started successfully');

  } catch (error) {
    setSpanError(span, error as Error);
    span.end();
    logger.error({ err: error }, 'Failed to start Kafka consumer');
    throw error;
  }
}

/**
 * Handle individual Kafka message
 */
async function handleMessage(payload: EachMessagePayload): Promise<void> {
  const { topic, partition, message } = payload;
  const span = createSpan('handle_kafka_message', {
    'kafka.topic': topic,
    'kafka.partition': partition,
    'kafka.offset': message.offset,
  });

  try {
    if (!message.value) {
      logger.warn({
        topic,
        partition,
        offset: message.offset,
      }, 'Received empty message - skipping');
      await consumer?.commitOffsets([{
        topic,
        partition,
        offset: (parseInt(message.offset) + 1).toString(),
      }]);
      span.end();
      return;
    }

    // Parse audit event from Kafka message
    const eventData = JSON.parse(message.value.toString());
    const auditEvent: AuditEvent = {
      event_id: eventData.event_id,
      invoice_id: eventData.invoice_id,
      service_name: eventData.service_name,
      event_type: eventData.event_type,
      timestamp_ms: parseInt(eventData.timestamp_ms),
      user_id: eventData.user_id,
      request_id: eventData.request_id,
      metadata: eventData.metadata || {},
      previous_hash: eventData.previous_hash,
      event_hash: eventData.event_hash,
    };

    logger.debug({
      event_id: auditEvent.event_id,
      invoice_id: auditEvent.invoice_id,
      service: auditEvent.service_name,
      event_type: auditEvent.event_type,
      partition,
      offset: message.offset,
    }, 'Processing audit event');

    // Write to PostgreSQL (this is the critical operation)
    await writeAuditEvent(auditEvent);

    // ONLY commit offset after successful write
    await consumer?.commitOffsets([{
      topic,
      partition,
      offset: (parseInt(message.offset) + 1).toString(),
    }]);

    // Update consumer lag metric
    const lag = payload.heartbeat.sessionTimeout; // Approximate lag
    auditConsumerLag.set({ partition: partition.toString() }, lag);

    span.end();

    logger.debug({
      event_id: auditEvent.event_id,
      partition,
      offset: message.offset,
    }, 'Audit event processed and committed');

  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error({
      err: error,
      topic,
      partition,
      offset: message.offset,
    }, 'Failed to process audit event - offset NOT committed, will retry');

    // DO NOT commit offset on error - Kafka will redeliver
    // This ensures we never lose audit events
    throw error;
  }
}

/**
 * Stop Kafka consumer gracefully
 */
export async function stopConsumer(): Promise<void> {
  if (consumer) {
    logger.info('Stopping Kafka consumer');
    await consumer.disconnect();
    consumer = null;
    logger.info('Kafka consumer stopped');
  }
}

/**
 * Get consumer instance (for testing)
 */
export function getConsumer(): Consumer | null {
  return consumer;
}
