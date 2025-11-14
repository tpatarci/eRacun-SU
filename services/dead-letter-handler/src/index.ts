/**
 * Dead Letter Handler Service
 *
 * Main entry point - starts DLQ consumer and HTTP API
 *
 * Monitors dead letter queues, classifies errors, routes to retry/manual review
 *
 * See: README.md for complete specification
 */

import express from 'express';
import { ServiceConfig } from './types';
import { DLQConsumer } from './consumer';
import { createAPI, APIDependencies } from './api';
import { ManualReviewRepository, MockManualReviewRepository } from './repository';
import { createLogger } from './utils/logger';
import { getMetrics } from './observability';

const logger = createLogger('main');

/**
 * Load service configuration from environment
 *
 * @returns ServiceConfig
 */
function loadConfig(): ServiceConfig {
  return {
    serviceName: process.env.SERVICE_NAME || 'dead-letter-handler',
    nodeEnv: process.env.NODE_ENV || 'development',
    httpPort: parseInt(process.env.HTTP_PORT || '8081', 10),
    prometheusPort: parseInt(process.env.PROMETHEUS_PORT || '9091', 10),
    databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/eracun',
    notificationServiceUrl: process.env.NOTIFICATION_SERVICE_URL,
    kafkaBrokers: process.env.KAFKA_BROKERS,
    errorEventsTopic: process.env.ERROR_EVENTS_TOPIC || 'error-events',
    logLevel: process.env.LOG_LEVEL || 'info',
    dlq: {
      rabbitmqUrl: process.env.RABBITMQ_URL || 'amqp://localhost:5672',
      dlqExchange: process.env.DLQ_EXCHANGE || 'dlx',
      dlqQueue: process.env.DLQ_QUEUE || 'dlq-handler-consumer',
      retryQueue: process.env.RETRY_QUEUE || 'retry.scheduled',
      manualReviewQueue: process.env.MANUAL_REVIEW_QUEUE || 'manual-review.pending',
      maxRetries: parseInt(process.env.MAX_RETRIES || '3', 10),
      transientRetryDelayMs: parseInt(process.env.TRANSIENT_RETRY_DELAY_MS || '5000', 10),
    },
  };
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  logger.info('Starting Dead Letter Handler Service');

  const config = loadConfig();

  logger.info('Configuration loaded', {
    serviceName: config.serviceName,
    nodeEnv: config.nodeEnv,
    httpPort: config.httpPort,
    prometheusPort: config.prometheusPort,
  });

  // Initialize repository
  const useMock = config.nodeEnv === 'development' && !process.env.DATABASE_URL;
  const repository = useMock
    ? new MockManualReviewRepository()
    : new ManualReviewRepository(config.databaseUrl);

  if (useMock) {
    logger.warn('Using mock repository (development mode)');
  }

  // Start DLQ consumer
  const consumer = new DLQConsumer(config, repository);
  await consumer.start();

  // Start Prometheus metrics server
  const metricsApp = express();
  metricsApp.get('/metrics', async (_req, res) => {
    res.set('Content-Type', 'text/plain');
    res.send(await getMetrics());
  });
  metricsApp.listen(config.prometheusPort, () => {
    logger.info('Prometheus metrics server listening', { port: config.prometheusPort });
  });

  // Wait for consumer channel to be ready (small delay)
  await new Promise((resolve) => setTimeout(resolve, 1000));

  // Start HTTP API
  const apiDeps: APIDependencies = {
    repository,
    retryChannel: (consumer as any).retryChannel, // Access retry channel
  };
  createAPI(apiDeps, config.httpPort);

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info('Shutdown signal received', { signal });

    await consumer.stop();

    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  logger.info('Dead Letter Handler Service started successfully');
}

// Run if executed directly
if (require.main === module) {
  main().catch((error) => {
    logger.error('Fatal error during startup', { error });
    process.exit(1);
  });
}

export { main };
