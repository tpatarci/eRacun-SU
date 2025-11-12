import { CertificateRepository } from './repository';
import { ApiServer } from './api';
import { ExpirationMonitor } from './expiration-monitor';
import { createAlertHandler } from './alerting';
import {
  logger,
  initObservability,
  shutdownObservability,
  databaseConnected,
} from './observability';

/**
 * Certificate Lifecycle Manager Service
 *
 * Main entry point for the service.
 *
 * Responsibilities:
 * - HTTP API server for certificate management
 * - Daily cron job for expiration monitoring
 * - Alert notifications via notification-service
 * - Prometheus metrics endpoint
 *
 * Usage:
 *   npm run dev    # Development mode
 *   npm start      # Production mode
 */

class CertificateLifecycleManagerService {
  private repository!: CertificateRepository;
  private apiServer!: ApiServer;
  private expirationMonitor!: ExpirationMonitor;

  /**
   * Initialize and start the service
   */
  async start(): Promise<void> {
    try {
      logger.info('Starting Certificate Lifecycle Manager service...');

      // Initialize observability
      initObservability();

      // Validate required environment variables
      this.validateEnvironment();

      // Initialize database repository
      await this.initializeDatabase();

      // Initialize alert handler
      const alertHandler = createAlertHandler(
        process.env.NOTIFICATION_SERVICE_URL
      );

      // Initialize expiration monitor
      this.expirationMonitor = new ExpirationMonitor(
        this.repository,
        alertHandler
      );

      // Start expiration monitor (daily at 9 AM)
      const cronSchedule = process.env.EXPIRATION_CHECK_CRON || '0 9 * * *';
      this.expirationMonitor.start(cronSchedule);

      // Run initial expiration check (optional, can be disabled)
      if (process.env.RUN_INITIAL_CHECK !== 'false') {
        logger.info('Running initial expiration check...');
        await this.expirationMonitor.checkCertificateExpiration();
      }

      // Initialize and start HTTP API server
      this.apiServer = new ApiServer(this.repository);
      const httpPort = parseInt(process.env.HTTP_PORT || '8087', 10);
      await this.apiServer.start(httpPort);

      // Register shutdown handlers
      this.registerShutdownHandlers();

      logger.info(
        {
          httpPort,
          databaseUrl: this.maskDatabaseUrl(process.env.DATABASE_URL),
          cronSchedule,
        },
        'Certificate Lifecycle Manager service started successfully'
      );
    } catch (error) {
      logger.error({ error }, 'Failed to start service');
      process.exit(1);
    }
  }

  /**
   * Validate required environment variables
   */
  private validateEnvironment(): void {
    const required = ['DATABASE_URL'];

    const missing = required.filter((key) => !process.env[key]);

    if (missing.length > 0) {
      throw new Error(
        `Missing required environment variables: ${missing.join(', ')}`
      );
    }

    logger.info('Environment variables validated');
  }

  /**
   * Initialize database connection and schema
   */
  private async initializeDatabase(): Promise<void> {
    logger.info('Initializing database connection...');

    this.repository = new CertificateRepository(process.env.DATABASE_URL);

    // Test database connection
    const isHealthy = await this.repository.healthCheck();

    if (!isHealthy) {
      throw new Error('Database health check failed');
    }

    logger.info('Database connection established');

    // Initialize schema
    logger.info('Initializing database schema...');
    await this.repository.initializeSchema();
    logger.info('Database schema initialized');

    databaseConnected.set(1);
  }

  /**
   * Graceful shutdown
   */
  private async shutdown(): Promise<void> {
    logger.info('Shutting down Certificate Lifecycle Manager service...');

    try {
      // Stop expiration monitor
      if (this.expirationMonitor) {
        this.expirationMonitor.stop();
        logger.info('Expiration monitor stopped');
      }

      // Close database connection
      if (this.repository) {
        await this.repository.close();
        logger.info('Database connection closed');
      }

      // Shutdown observability
      shutdownObservability();

      logger.info('Certificate Lifecycle Manager service shut down successfully');
      process.exit(0);
    } catch (error) {
      logger.error({ error }, 'Error during shutdown');
      process.exit(1);
    }
  }

  /**
   * Register process signal handlers for graceful shutdown
   */
  private registerShutdownHandlers(): void {
    // Handle SIGTERM (sent by systemd on stop)
    process.on('SIGTERM', () => {
      logger.info('Received SIGTERM signal');
      this.shutdown();
    });

    // Handle SIGINT (Ctrl+C)
    process.on('SIGINT', () => {
      logger.info('Received SIGINT signal');
      this.shutdown();
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error({ error }, 'Uncaught exception');
      this.shutdown();
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error({ reason, promise }, 'Unhandled promise rejection');
      this.shutdown();
    });

    logger.info('Shutdown handlers registered');
  }

  /**
   * Mask database URL for logging (hide password)
   */
  private maskDatabaseUrl(url?: string): string {
    if (!url) return 'UNDEFINED';

    try {
      const parsed = new URL(url);
      if (parsed.password) {
        parsed.password = '***MASKED***';
      }
      return parsed.toString();
    } catch {
      return 'INVALID_URL';
    }
  }
}

// Start the service
const service = new CertificateLifecycleManagerService();
service.start().catch((error) => {
  logger.error({ error }, 'Fatal error during service startup');
  process.exit(1);
});
