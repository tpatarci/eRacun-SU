import { createApp } from './api/app.js';
import { initDb } from './shared/db.js';
import { loadConfig } from './shared/config.js';
import { logger } from './shared/logger.js';
import { initializeInvoiceSubmission, getInvoiceSubmissionService } from './jobs/invoice-submission.js';

const config = loadConfig();

async function start() {
  try {
    // Initialize database
    initDb(config.DATABASE_URL);

    // Initialize job queue
    initializeInvoiceSubmission(config.REDIS_URL);

    // Create Express app
    const app = createApp();

    // Start HTTP server
    const server = app.listen(config.PORT, () => {
      logger.info(`eRačun MVP listening on port ${config.PORT}`);
    });

    // Graceful shutdown
    const shutdown = async () => {
      logger.info('Shutting down gracefully');
      server.close();
      await getInvoiceSubmissionService().shutdown();
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

// Start the application if this is the main module
if (require.main === module) {
  start();
}

export { start };
