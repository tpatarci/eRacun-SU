import { createApp } from './api/app.js';
import { initDb } from './shared/db.js';
import { loadConfig } from './shared/config.js';
import { logger } from './shared/logger.js';
import { initializeInvoiceSubmission, getInvoiceSubmissionService } from './jobs/invoice-submission.js';
import { createPollerManager } from './ingestion/poller-manager.js';

const config = loadConfig();

// Global poller manager for multi-user email polling
let pollerManager: ReturnType<typeof createPollerManager> | null = null;

async function start() {
  try {
    // Initialize database
    initDb(config.DATABASE_URL);

    // Initialize job queue
    initializeInvoiceSubmission(config.REDIS_URL);

    // Initialize poller manager for multi-user email polling
    pollerManager = createPollerManager({
      defaultPollIntervalMs: 60000, // 1 minute default
    });
    logger.info('Poller manager initialized for multi-user email polling');

    // Create Express app
    const app = createApp();

    // Start HTTP server
    const server = app.listen(config.PORT, () => {
      logger.info(`eRačun listening on port ${config.PORT}`);
    });

    // Graceful shutdown
    const shutdown = async () => {
      logger.info('Shutting down gracefully');

      // Stop all email pollers
      if (pollerManager) {
        try {
          await pollerManager.stopAll();
          logger.info('All email pollers stopped');
        } catch (error) {
          logger.error({ error }, 'Error stopping email pollers during shutdown');
        }
      }

      // Close HTTP server
      server.close();

      // Shutdown job queue
      try {
        await getInvoiceSubmissionService().shutdown();
        logger.info('Job queue service stopped');
      } catch (error) {
        logger.error({ error }, 'Error stopping job queue during shutdown');
      }

      logger.info('Shutdown complete');
      process.exit(0);
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);

  } catch (error) {
    logger.error({ error }, 'Failed to start application');
    process.exit(1);
  }
}

/**
 * Get the global poller manager instance
 *
 * @returns PollerManager instance or null if not initialized
 */
export function getPollerManager() {
  return pollerManager;
}

// Start the application if this is the main module
if (require.main === module) {
  start();
}

export { start };
