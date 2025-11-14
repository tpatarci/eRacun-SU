/**
 * Invoice Gateway API Entry Point
 * Central entry point for all invoice submissions
 */

import 'reflect-metadata';
// Initialize tracing BEFORE importing other modules
import { startTracing, stopTracing } from './tracing';
import { createApp } from './app';
import { createContainer } from '@eracun/di-container';
import pino from 'pino';

const logger = pino({
  name: 'invoice-gateway-api',
  level: process.env.LOG_LEVEL || 'info',
});

async function start() {
  // Initialize OpenTelemetry tracing
  await startTracing();
  try {
    // Create DI container
    const container = createContainer();

    // Create Express app
    const app = createApp(container);

    // Start server
    const port = process.env.PORT || 3001;
    const server = app.listen(port, () => {
      logger.info({ port }, 'Invoice Gateway API started');
      logger.info(`OpenAPI spec: http://localhost:${port}/api/v1/docs`);
      logger.info(`Health check: http://localhost:${port}/api/v1/health`);
    });

    // Graceful shutdown
    const shutdown = async (signal: string) => {
      logger.info({ signal }, 'Received shutdown signal');

      server.close(async () => {
        await stopTracing();
        logger.info('HTTP server closed');
        process.exit(0);
      });

      // Force shutdown after 10 seconds
      setTimeout(() => {
        logger.error('Forceful shutdown after timeout');
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

  } catch (error) {
    logger.error({ error }, 'Failed to start server');
    process.exit(1);
  }
}

start();
