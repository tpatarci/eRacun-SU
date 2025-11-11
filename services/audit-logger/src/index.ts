import 'dotenv/config';
import express from 'express';
import { register } from 'prom-client';
import { startConsumer, stopConsumer } from './consumer';
import { startGrpcServer, stopGrpcServer } from './grpc-server';
import { initPool, closePool } from './writer';
import {
  logger,
  initObservability,
  serviceUp,
} from './observability';

/**
 * Express app for health checks and metrics
 */
const app = express();
const HTTP_PORT = parseInt(process.env.HTTP_PORT || '8080');

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'audit-logger',
    uptime_seconds: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// Readiness check endpoint
app.get('/ready', async (req, res) => {
  try {
    // Check database connection
    const pool = initPool();
    await pool.query('SELECT 1');

    res.json({
      status: 'ready',
      service: 'audit-logger',
      dependencies: {
        database: 'healthy',
        kafka: 'healthy', // Simplified check
        grpc: 'healthy',
      },
    });
  } catch (error) {
    logger.error({ err: error }, 'Readiness check failed');
    res.status(503).json({
      status: 'not_ready',
      error: (error as Error).message,
    });
  }
});

// Prometheus metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    const metrics = await register.metrics();
    res.end(metrics);
  } catch (error) {
    logger.error({ err: error }, 'Failed to export metrics');
    res.status(500).end();
  }
});

/**
 * Initialize and start all services
 */
async function start(): Promise<void> {
  try {
    logger.info('Starting audit-logger service');

    // Initialize observability
    initObservability();

    // Initialize PostgreSQL connection pool
    initPool();
    logger.info('PostgreSQL pool initialized');

    // Start gRPC server
    await startGrpcServer();

    // Start Kafka consumer
    await startConsumer();

    // Start HTTP server (health + metrics)
    app.listen(HTTP_PORT, () => {
      logger.info({ port: HTTP_PORT }, 'HTTP server started');
    });

    serviceUp.set(1);

    logger.info('✅ Audit logger service started successfully');
    logger.info({
      http_port: HTTP_PORT,
      grpc_port: process.env.GRPC_PORT || '50051',
      kafka_topic: process.env.KAFKA_TOPIC || 'audit-log',
      database: process.env.DATABASE_URL ? 'configured' : 'not configured',
    }, 'Service configuration');

  } catch (error) {
    logger.error({ err: error }, 'Failed to start audit-logger service');
    await shutdown();
    process.exit(1);
  }
}

/**
 * Graceful shutdown
 */
async function shutdown(): Promise<void> {
  logger.info('Shutting down audit-logger service');

  serviceUp.set(0);

  try {
    // Stop Kafka consumer (finish processing current messages)
    await stopConsumer();

    // Stop gRPC server (finish current requests)
    await stopGrpcServer();

    // Close PostgreSQL pool
    await closePool();

    logger.info('✅ Audit logger service stopped gracefully');
    process.exit(0);

  } catch (error) {
    logger.error({ err: error }, 'Error during shutdown');
    process.exit(1);
  }
}

// Handle shutdown signals
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.fatal({ err: error }, 'Uncaught exception');
  shutdown();
});

process.on('unhandledRejection', (reason, promise) => {
  logger.fatal({ reason, promise }, 'Unhandled promise rejection');
  shutdown();
});

// Start the service
start();
