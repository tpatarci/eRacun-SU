/**
 * Validation Coordinator Service Entry Point
 */

import 'reflect-metadata';
import { createContainer } from '@eracun/di-container';
import { ValidationCoordinator } from './coordinators/validation-coordinator';
import { ErrorAggregator } from './aggregators/error-aggregator';
import pino from 'pino';

const logger = pino({ name: 'validation-coordinator' });

async function start() {
  try {
    logger.info('Starting Validation Coordinator service');

    // Create DI container
    const container = createContainer();

    // Bind local services
    container.bind<ErrorAggregator>(ErrorAggregator).toSelf();
    container.bind<ValidationCoordinator>(ValidationCoordinator).toSelf();

    logger.info('Validation Coordinator service started successfully');

    // Graceful shutdown
    const shutdown = (signal: string) => {
      logger.info({ signal }, 'Received shutdown signal');
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
