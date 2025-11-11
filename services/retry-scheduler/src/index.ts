/**
 * Retry Scheduler - Main Entry Point
 *
 * Features:
 * - RabbitMQ consumer (retry.scheduled queue)
 * - PostgreSQL persistent queue
 * - Retry scheduler (poll for due retries)
 * - Exponential backoff + jitter
 * - Health check endpoints
 * - Prometheus metrics endpoint
 * - Graceful shutdown
 */

import express from 'express';
import {
  logger,
  initTracing,
  shutdownTracing,
  getMetrics,
  serviceUp,
} from './observability';
import {
  initPool,
  closePool,
  createSchema,
  healthCheck as dbHealthCheck,
  updateQueueDepthMetric,
} from './repository';
import { startConsumer, closeConsumer, getChannel } from './consumer';
import { startScheduler, stopScheduler } from './scheduler';

// =============================================================================
// CONFIGURATION
// =============================================================================

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '8086', 10);

// =============================================================================
// STATE
// =============================================================================

let httpServer: any = null;
let isShuttingDown = false;

// =============================================================================
// HTTP API
// =============================================================================

function startHttpApi(): void {
  const app = express();

  /**
   * GET /health - Health check
   */
  app.get('/health', async (req, res) => {
    const dbHealthy = await dbHealthCheck();
    const channelHealthy = getChannel() !== null;

    const healthy = dbHealthy && channelHealthy;

    res.status(healthy ? 200 : 503).json({
      status: healthy ? 'healthy' : 'unhealthy',
      uptime_seconds: process.uptime(),
      checks: {
        database: dbHealthy ? 'ok' : 'failed',
        rabbitmq: channelHealthy ? 'ok' : 'failed',
      },
    });
  });

  /**
   * GET /ready - Readiness check
   */
  app.get('/ready', async (req, res) => {
    const dbHealthy = await dbHealthCheck();
    const channelHealthy = getChannel() !== null;

    const ready = dbHealthy && channelHealthy;

    res.status(ready ? 200 : 503).json({
      status: ready ? 'ready' : 'not_ready',
      dependencies: {
        database: dbHealthy ? 'connected' : 'disconnected',
        rabbitmq: channelHealthy ? 'connected' : 'disconnected',
      },
    });
  });

  /**
   * GET /metrics - Prometheus metrics
   */
  app.get('/metrics', async (req, res) => {
    try {
      const metrics = await getMetrics();
      res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.send(metrics);
    } catch (error) {
      logger.error({ error }, 'Failed to generate metrics');
      res.status(500).send('Failed to generate metrics');
    }
  });

  httpServer = app.listen(HTTP_PORT, () => {
    logger.info({ port: HTTP_PORT }, 'HTTP API server started');
  });
}

async function closeHttpApi(): Promise<void> {
  return new Promise((resolve) => {
    if (httpServer) {
      httpServer.close(() => {
        logger.info('HTTP API server closed');
        resolve();
      });
    } else {
      resolve();
    }
  });
}

// =============================================================================
// INITIALIZATION & SHUTDOWN
// =============================================================================

async function initialize(): Promise<void> {
  logger.info('Initializing retry-scheduler service...');

  try {
    // Initialize tracing
    initTracing();

    // Initialize database
    initPool();
    await createSchema();

    // Start RabbitMQ consumer
    const channel = await startConsumer();

    // Start retry scheduler
    startScheduler(channel);

    // Update queue depth metric on startup
    await updateQueueDepthMetric();

    // Start HTTP API
    startHttpApi();

    // Mark service as up
    serviceUp.set(1);

    logger.info('Retry-scheduler service initialized successfully');
  } catch (error) {
    logger.error({ error }, 'Failed to initialize retry-scheduler service');
    throw error;
  }
}

async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress');
    return;
  }

  isShuttingDown = true;
  logger.info({ signal }, 'Shutting down retry-scheduler service...');

  try {
    // Mark service as down
    serviceUp.set(0);

    // Stop HTTP API
    await closeHttpApi();

    // Stop scheduler
    stopScheduler();

    // Close RabbitMQ consumer
    await closeConsumer();

    // Close database pool
    await closePool();

    // Shutdown tracing
    await shutdownTracing();

    logger.info('Retry-scheduler service shutdown complete');
    process.exit(0);
  } catch (error) {
    logger.error({ error }, 'Error during shutdown');
    process.exit(1);
  }
}

// =============================================================================
// SIGNAL HANDLERS
// =============================================================================

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (error) => {
  logger.fatal({ error }, 'Uncaught exception');
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  logger.fatal({ reason }, 'Unhandled promise rejection');
  shutdown('unhandledRejection');
});

// =============================================================================
// START SERVICE
// =============================================================================

initialize().catch((error) => {
  logger.fatal({ error }, 'Failed to start retry-scheduler service');
  process.exit(1);
});
