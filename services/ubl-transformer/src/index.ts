/**
 * UBL Transformer Service Entry Point
 */

import 'reflect-metadata';
// Initialize tracing BEFORE importing other modules
import { startTracing, stopTracing } from './tracing';
import { createContainer } from '@eracun/di-container';
import { Container } from 'inversify';
import { FormatDetector } from './transformers/format-detector';
import { UBLTransformer } from './transformers/ubl-transformer';
import pino from 'pino';

const logger = pino({ name: 'ubl-transformer' });

async function start() {
  // Initialize OpenTelemetry tracing
  await startTracing();
  try {
    logger.info('Starting UBL Transformer service');

    // Create DI container
    const container = createContainer();

    // Bind local services
    container.bind<FormatDetector>(FormatDetector).toSelf();
    container.bind<UBLTransformer>(UBLTransformer).toSelf();

    logger.info('UBL Transformer service started successfully');

    // Graceful shutdown
    const shutdown = async (signal: string) => {
      logger.info({ signal }, 'Received shutdown signal');
      await stopTracing();
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

  } catch (error) {
    logger.error({ error }, 'Failed to start service');
    process.exit(1);
  }
}

start();
