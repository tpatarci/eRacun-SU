/**
 * KPD Registry Sync Service - Main Entry Point
 *
 * Orchestrates:
 * - Database initialization
 * - gRPC server (port 50052)
 * - HTTP API server (port 8088)
 * - Daily sync cron job (3 AM)
 * - Observability (Prometheus, Jaeger, Pino)
 * - Graceful shutdown (SIGTERM, SIGINT)
 *
 * Environment Variables:
 * - SYNC_ON_STARTUP: Sync immediately on startup (default: true)
 * - SYNC_CRON: Cron expression for daily sync (default: "0 3 * * *")
 */

import * as cron from 'node-cron';
import {
  logger,
  initializeTracing,
  shutdownTracing,
  getMetricsRegistry,
} from './observability';
import {
  initializePool,
  initializeSchema,
  closePool,
  checkDatabaseHealth,
} from './repository';
import { syncKPDCodes, SyncResult } from './sync';
import { startGRPCServer, stopGRPCServer, forceStopGRPCServer } from './grpc-server';
import { startHTTPServer, stopHTTPServer } from './api';

// ============================================================================
// Configuration
// ============================================================================

const SYNC_ON_STARTUP = process.env.SYNC_ON_STARTUP !== 'false'; // Default: true
const SYNC_CRON = process.env.SYNC_CRON || '0 3 * * *'; // Daily at 3 AM
const GRACEFUL_SHUTDOWN_TIMEOUT_MS = 30000; // 30 seconds

// ============================================================================
// Global State
// ============================================================================

let cronJob: cron.ScheduledTask | null = null;
let isShuttingDown = false;

// ============================================================================
// Startup Sequence
// ============================================================================

/**
 * Main startup function
 */
async function startup(): Promise<void> {
  logger.info('KPD Registry Sync service starting...');

  try {
    // Step 1: Initialize observability
    initializeTracing();
    logger.info('Observability initialized');

    // Step 2: Initialize database connection pool
    initializePool();
    logger.info('Database pool initialized');

    // Step 3: Initialize database schema
    await initializeSchema();
    logger.info('Database schema initialized');

    // Step 4: Check database health
    const dbHealthy = await checkDatabaseHealth();
    if (!dbHealthy) {
      throw new Error('Database health check failed');
    }
    logger.info('Database health check passed');

    // Step 5: Start gRPC server
    await startGRPCServer();
    logger.info('gRPC server started');

    // Step 6: Start HTTP API server
    await startHTTPServer();
    logger.info('HTTP API server started');

    // Step 7: Schedule daily sync (cron job)
    cronJob = cron.schedule(SYNC_CRON, async () => {
      logger.info('Cron job triggered: Starting scheduled sync');
      try {
        const result = await syncKPDCodes();
        if (result.success) {
          logger.info(result, 'Scheduled sync completed successfully');
        } else {
          logger.error(result, 'Scheduled sync failed');
        }
      } catch (error) {
        logger.error({ err: error }, 'Scheduled sync threw exception');
      }
    });
    logger.info({ cron: SYNC_CRON }, 'Cron job scheduled for daily sync');

    // Step 8: Sync on startup (optional)
    if (SYNC_ON_STARTUP) {
      logger.info('SYNC_ON_STARTUP=true, triggering initial sync');
      try {
        const result = await syncKPDCodes();
        if (result.success) {
          logger.info(result, 'Initial sync completed successfully');
        } else {
          logger.error(result, 'Initial sync failed (continuing anyway)');
        }
      } catch (error) {
        logger.error({ err: error }, 'Initial sync threw exception (continuing anyway)');
      }
    } else {
      logger.info('SYNC_ON_STARTUP=false, skipping initial sync');
    }

    // Step 9: Service ready
    logger.info('✅ KPD Registry Sync service is ready');
  } catch (error) {
    logger.error({ err: error }, 'Startup failed');
    process.exit(1);
  }
}

// ============================================================================
// Shutdown Sequence
// ============================================================================

/**
 * Graceful shutdown handler
 */
async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress, forcing exit');
    process.exit(1);
  }

  isShuttingDown = true;
  logger.info({ signal }, 'Shutdown signal received, starting graceful shutdown');

  // Set timeout for forced shutdown
  const forceShutdownTimeout = setTimeout(() => {
    logger.error('Graceful shutdown timeout exceeded, forcing exit');
    forceStopGRPCServer();
    process.exit(1);
  }, GRACEFUL_SHUTDOWN_TIMEOUT_MS);

  try {
    // Step 1: Stop accepting new requests
    logger.info('Stopping HTTP server');
    await stopHTTPServer();

    // Step 2: Stop gRPC server (drain existing requests)
    logger.info('Stopping gRPC server');
    await stopGRPCServer();

    // Step 3: Stop cron job
    if (cronJob) {
      logger.info('Stopping cron job');
      cronJob.stop();
      cronJob = null;
    }

    // Step 4: Close database pool
    logger.info('Closing database pool');
    await closePool();

    // Step 5: Shutdown tracing
    logger.info('Shutting down tracing');
    await shutdownTracing();

    // Clear timeout
    clearTimeout(forceShutdownTimeout);

    logger.info('✅ Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    logger.error({ err: error }, 'Error during shutdown');
    clearTimeout(forceShutdownTimeout);
    process.exit(1);
  }
}

// ============================================================================
// Signal Handlers
// ============================================================================

/**
 * Register signal handlers for graceful shutdown
 */
function registerSignalHandlers(): void {
  // SIGTERM (sent by Docker, Kubernetes, systemd stop)
  process.on('SIGTERM', () => {
    shutdown('SIGTERM');
  });

  // SIGINT (Ctrl+C in terminal)
  process.on('SIGINT', () => {
    shutdown('SIGINT');
  });

  // Uncaught exception
  process.on('uncaughtException', (error) => {
    logger.error({ err: error }, 'Uncaught exception, shutting down');
    shutdown('uncaughtException');
  });

  // Unhandled promise rejection
  process.on('unhandledRejection', (reason, promise) => {
    logger.error({ reason, promise }, 'Unhandled promise rejection, shutting down');
    shutdown('unhandledRejection');
  });
}

// ============================================================================
// Main Execution
// ============================================================================

/**
 * Main entry point
 */
async function main(): Promise<void> {
  // Register signal handlers
  registerSignalHandlers();

  // Start service
  await startup();
}

// Run main function
main().catch((error) => {
  logger.error({ err: error }, 'Fatal error in main()');
  process.exit(1);
});
