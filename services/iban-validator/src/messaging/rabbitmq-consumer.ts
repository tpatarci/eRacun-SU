/**
 * RabbitMQ Consumer for IBAN Validation
 *
 * Consumes validation requests from RabbitMQ queue and publishes results
 */

import amqp from 'amqplib';
import type { Logger } from 'pino';
import { validateIBAN, validateIBANBatch, type IBANValidationResult } from '../iban-validator.js';
import { recordValidation, recordBatchValidation, recordError } from '../observability/metrics.js';

const QUEUE_NAME = 'iban-validation-requests';
const RESULT_QUEUE_NAME = 'iban-validation-results';
const EXCHANGE_NAME = 'eracun-validation';
const PREFETCH_COUNT = 10;

/**
 * Message format for validation requests
 */
interface ValidationRequest {
  requestId: string;
  iban?: string;
  ibans?: string[];
  replyTo?: string;
  correlationId?: string;
}

/**
 * Message format for validation responses
 */
interface ValidationResponse {
  requestId: string;
  result?: IBANValidationResult;
  results?: IBANValidationResult[];
  error?: string;
  timestamp: string;
}

/**
 * Setup RabbitMQ connection and consumer
 */
export async function setupRabbitMQ(url: string, logger: Logger): Promise<void> {
  try {
    // Connect to RabbitMQ
    const connection = await amqp.connect(url);
    logger.info('Connected to RabbitMQ');

    // Handle connection errors
    connection.on('error', (err: Error) => {
      logger.error({ error: err }, 'RabbitMQ connection error');
      recordError('rabbitmq_connection');
    });

    connection.on('close', () => {
      logger.warn('RabbitMQ connection closed');
      // Attempt reconnection after 5 seconds
      setTimeout(() => {
        setupRabbitMQ(url, logger).catch((error: Error) => {
          logger.error({ error }, 'Failed to reconnect to RabbitMQ');
        });
      }, 5000);
    });

    // Create channel
    const channel = await connection.createChannel();
    logger.info('Created RabbitMQ channel');

    // Assert exchange
    await channel.assertExchange(EXCHANGE_NAME, 'topic', { durable: true });

    // Assert queues
    await channel.assertQueue(QUEUE_NAME, { durable: true });
    await channel.assertQueue(RESULT_QUEUE_NAME, { durable: true });

    // Bind queue to exchange
    await channel.bindQueue(QUEUE_NAME, EXCHANGE_NAME, 'iban.validation.request');
    await channel.bindQueue(RESULT_QUEUE_NAME, EXCHANGE_NAME, 'iban.validation.result');

    // Set prefetch count
    await channel.prefetch(PREFETCH_COUNT);

    // Start consuming
    await channel.consume(QUEUE_NAME, async (msg) => {
      if (!msg) return;

      try {
        await handleMessage(msg, channel, logger);
      } catch (error) {
        logger.error({ error, messageId: msg.properties.messageId }, 'Failed to handle message');
        recordError('message_handling');

        // Reject and requeue message
        channel.nack(msg, false, true);
      }
    });

    logger.info(`Consuming from queue: ${QUEUE_NAME}`);
  } catch (error) {
    logger.error({ error }, 'Failed to setup RabbitMQ');
    throw error;
  }
}

/**
 * Handle incoming validation request message
 */
async function handleMessage(msg: amqp.ConsumeMessage, channel: amqp.Channel, logger: Logger): Promise<void> {
  const start = Date.now();
  const content = msg.content.toString();

  try {
    const request: ValidationRequest = JSON.parse(content);
    logger.info({ requestId: request.requestId }, 'Processing validation request');

    let response: ValidationResponse;

    // Single IBAN validation
    if (request.iban) {
      const result = validateIBAN(request.iban);
      const duration = (Date.now() - start) / 1000;
      recordValidation(result.valid ? 'valid' : 'invalid', 'rabbitmq', duration);

      response = {
        requestId: request.requestId,
        result,
        timestamp: new Date().toISOString(),
      };
    }
    // Batch validation
    else if (request.ibans && Array.isArray(request.ibans)) {
      const results = validateIBANBatch(request.ibans);
      recordBatchValidation(request.ibans.length, 'rabbitmq');

      response = {
        requestId: request.requestId,
        results,
        timestamp: new Date().toISOString(),
      };
    }
    // Invalid request
    else {
      response = {
        requestId: request.requestId,
        error: 'Invalid request: must provide either "iban" or "ibans"',
        timestamp: new Date().toISOString(),
      };
      recordError('invalid_request');
    }

    // Publish response
    const replyTo = request.replyTo || RESULT_QUEUE_NAME;
    const correlationId = request.correlationId || msg.properties.correlationId;

    await channel.publish(
      EXCHANGE_NAME,
      'iban.validation.result',
      Buffer.from(JSON.stringify(response)),
      {
        contentType: 'application/json',
        correlationId,
        replyTo,
        timestamp: Date.now(),
      }
    );

    logger.info(
      { requestId: request.requestId, durationMs: Date.now() - start },
      'Validation request processed'
    );

    // Acknowledge message
    channel.ack(msg);
  } catch (error) {
    logger.error({ error, content }, 'Failed to parse message');
    recordError('message_parsing');

    // Reject message (don't requeue if parsing failed)
    channel.nack(msg, false, false);
  }
}

/**
 * Close RabbitMQ connection gracefully
 * Note: This is a placeholder since we don't maintain module-level connection
 */
export async function closeRabbitMQ(logger: Logger): Promise<void> {
  logger.info('RabbitMQ cleanup requested');
}
