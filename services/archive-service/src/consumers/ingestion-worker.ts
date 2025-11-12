/**
 * RabbitMQ Ingestion Worker
 *
 * Consumes ArchiveInvoiceCommand messages and persists to archive.
 * See: docs/adr/004-archive-compliance-layer.md §47-54
 */

import { createLogger } from '../utils/logger';

const logger = createLogger('ingestion-worker');

export interface RabbitMQConfig {
  url: string;
  queue: string;
  exchange: string;
  prefetch: number;
}

export async function startIngestionWorker(config: RabbitMQConfig): Promise<void> {
  logger.info('Starting ingestion worker', { queue: config.queue });

  // TODO: Connect to RabbitMQ
  // TODO: Set up consumer with prefetch limit
  // TODO: Process ArchiveInvoiceCommand messages
  // TODO: Implement idempotency checks
  // TODO: Persist to PostgreSQL + S3

  logger.warn('Ingestion worker not yet implemented');
}
