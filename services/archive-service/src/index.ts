/**
 * Archive Service Entry Point
 *
 * Regulatory-compliant 11-year invoice archive with:
 * - Immutable WORM storage (S3 Object Lock)
 * - Monthly signature validation
 * - Forensic audit trail
 * - Hot/warm/cold tiering
 *
 * See: docs/adr/004-archive-compliance-layer.md
 */

import { createLogger } from './utils/logger';
import { startMetricsServer } from './utils/metrics';
import { startApiServer } from './api/server';
import { startIngestionWorker } from './consumers/ingestion-worker';
import { config } from './config';

const logger = createLogger('archive-service');

async function main(): Promise<void> {
  logger.info('Starting archive-service...', { version: config.version });

  try {
    // Start metrics exporter (Prometheus)
    await startMetricsServer(config.observability.metricsPort);
    logger.info('Metrics server started', { port: config.observability.metricsPort });

    // Start REST API server
    await startApiServer(config.api.port);
    logger.info('API server started', { port: config.api.port });

    // Start RabbitMQ ingestion worker
    await startIngestionWorker(config.rabbitmq);
    logger.info('Ingestion worker started', { queue: config.rabbitmq.queue });

    logger.info('Archive service ready');
  } catch (error) {
    logger.error('Failed to start archive service', { error });
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully...');
  process.exit(0);
});

// Unhandled errors
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason, promise });
  process.exit(1);
});

main().catch((error) => {
  logger.error('Fatal error in main', { error });
  process.exit(1);
});
