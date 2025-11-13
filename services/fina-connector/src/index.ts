import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import amqp, { Channel, ConsumeMessage } from 'amqplib';
import type { Connection } from 'amqplib';
import {
  logger,
  initObservability,
  shutdownObservability,
  getMetrics,
  serviceUp,
} from './observability.js';
import { createFINAClient, SOAPClientConfig, FINASOAPClient } from './soap-client.js';
import {
  createSignatureServiceClient,
  SignatureServiceClient,
} from './signature-integration.js';
import {
  createFiscalizationService,
  FiscalizationService,
  FiscalizationConfig,
} from './fiscalization.js';
import {
  createOfflineQueueManager,
  OfflineQueueManager,
  OfflineQueueConfig,
} from './offline-queue.js';
import type {
  FiscalizationMessage,
  FiscalizationResultMessage,
} from './types.js';

/**
 * IMPROVEMENT-028: Safe JSON stringify with circular reference protection
 */
function safeStringify(obj: any): string {
  const seen = new WeakSet();

  return JSON.stringify(obj, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[Circular Reference]';
      }
      seen.add(value);
    }
    return value;
  });
}

/**
 * Application Configuration
 */
interface AppConfig {
  /** Service port */
  port: number;
  /** FINA WSDL URL */
  finaWsdlUrl: string;
  /** FINA endpoint URL */
  finaEndpointUrl: string;
  /** FINA request timeout */
  finaTimeout: number;
  /** Digital Signature Service URL */
  signatureServiceUrl: string;
  /** Signature service timeout */
  signatureTimeout: number;
  /** PostgreSQL connection string */
  databaseUrl: string;
  /** RabbitMQ connection string */
  rabbitMqUrl: string;
  /** RabbitMQ fiscalization queue name */
  fiscalizationQueueName: string;
  /** RabbitMQ result queue name */
  resultQueueName: string;
  /** Max retry attempts */
  maxRetries: number;
  /** Enable offline queue */
  offlineQueueEnabled: boolean;
  /** Offline queue max age (hours) */
  offlineQueueMaxAgeHours: number;
  /** Retry delay base (seconds) */
  retryDelaySeconds: number;
}

/**
 * Load configuration from environment variables
 */
function loadConfig(): AppConfig {
  return {
    port: parseInt(process.env.PORT || '3003'),
    finaWsdlUrl:
      process.env.FINA_WSDL_URL ||
      'https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl',
    finaEndpointUrl:
      process.env.FINA_ENDPOINT_URL ||
      'https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest',
    finaTimeout: parseInt(process.env.FINA_TIMEOUT || '10000'),
    signatureServiceUrl:
      process.env.SIGNATURE_SERVICE_URL || 'http://localhost:3002',
    signatureTimeout: parseInt(process.env.SIGNATURE_TIMEOUT || '5000'),
    databaseUrl:
      process.env.DATABASE_URL || 'postgresql://localhost/eracun_fina',
    rabbitMqUrl: process.env.RABBITMQ_URL || 'amqp://localhost',
    fiscalizationQueueName:
      process.env.FISCALIZATION_QUEUE || 'fina.fiscalization.requests',
    resultQueueName:
      process.env.RESULT_QUEUE || 'fina.fiscalization.results',
    maxRetries: parseInt(process.env.MAX_RETRIES || '3'),
    offlineQueueEnabled: process.env.OFFLINE_QUEUE_ENABLED !== 'false',
    offlineQueueMaxAgeHours: parseInt(
      process.env.OFFLINE_QUEUE_MAX_AGE_HOURS || '48'
    ),
    retryDelaySeconds: parseInt(process.env.RETRY_DELAY_SECONDS || '2'),
  };
}

/**
 * FINA Connector Application
 */
class FINAConnectorApp {
  private config: AppConfig;
  private app: express.Application;
  private server: any;
  private dbPool: Pool;
  private soapClient: FINASOAPClient | null = null; // IMPROVEMENT-006: For WSDL health checks
  private rabbitConnection: Connection | null = null;
  private rabbitChannel: Channel | null = null;
  private fiscalizationService: FiscalizationService | null = null;
  private offlineQueueManager: OfflineQueueManager | null = null;
  private isShuttingDown = false;
  // IMPROVEMENT-027: Scheduled cleanup timer for expired queue entries
  private cleanupTimer: NodeJS.Timer | null = null;

  constructor(config: AppConfig) {
    this.config = config;
    this.app = express();
    this.dbPool = new Pool({ connectionString: config.databaseUrl });
  }

  /**
   * Initialize application
   */
  async initialize(): Promise<void> {
    logger.info('Initializing FINA Connector service');

    // Initialize observability
    initObservability();

    // Initialize database
    await this.initializeDatabase();

    // Initialize SOAP client
    const soapClientConfig: SOAPClientConfig = {
      wsdlUrl: this.config.finaWsdlUrl,
      endpointUrl: this.config.finaEndpointUrl,
      timeout: this.config.finaTimeout,
      disableCache: process.env.NODE_ENV !== 'production',
      // IMPROVEMENT-006: WSDL refresh configuration
      wsdlRefreshIntervalHours: parseInt(process.env.WSDL_REFRESH_INTERVAL_HOURS || '24'),
      wsdlRequestTimeoutMs: parseInt(process.env.WSDL_REQUEST_TIMEOUT_MS || '10000'),
    };

    this.soapClient = createFINAClient(soapClientConfig);
    await this.soapClient.initialize();

    // Initialize signature service client
    const signatureClient = createSignatureServiceClient({
      baseUrl: this.config.signatureServiceUrl,
      timeout: this.config.signatureTimeout,
      maxRetries: 3,
    });

    // Initialize fiscalization service
    const fiscalizationConfig: FiscalizationConfig = {
      maxRetries: this.config.maxRetries,
      offlineQueueEnabled: this.config.offlineQueueEnabled,
      retryDelayBase: this.config.retryDelaySeconds * 1000,
    };

    this.fiscalizationService = createFiscalizationService(
      this.soapClient,
      signatureClient,
      fiscalizationConfig
    );

    // Initialize offline queue manager
    const offlineQueueConfig: OfflineQueueConfig = {
      pool: this.dbPool,
      maxAge: this.config.offlineQueueMaxAgeHours * 60 * 60 * 1000,
      maxRetries: this.config.maxRetries,
      batchSize: 10,
    };

    this.offlineQueueManager = createOfflineQueueManager(offlineQueueConfig);
    await this.offlineQueueManager.initialize();

    // Initialize RabbitMQ
    await this.initializeRabbitMQ();

    // Initialize HTTP server
    this.initializeHttpServer();

    // IMPROVEMENT-027: Start scheduled cleanup of expired queue entries
    this.startCleanupScheduler();

    // Set up graceful shutdown
    this.setupGracefulShutdown();

    logger.info('FINA Connector service initialized successfully');
  }

  /**
   * IMPROVEMENT-027: Start scheduled cleanup of expired offline queue entries
   * Runs every hour to remove entries older than the configured max age
   */
  private startCleanupScheduler(): void {
    if (!this.offlineQueueManager) {
      logger.warn('Offline queue manager not initialized, skipping cleanup scheduler');
      return;
    }

    // Run cleanup every hour (3,600,000 milliseconds)
    const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

    this.cleanupTimer = setInterval(async () => {
      try {
        if (this.isShuttingDown || !this.offlineQueueManager) {
          return;
        }

        const removedCount = await this.offlineQueueManager.cleanupExpired();

        if (removedCount > 0) {
          logger.info({
            removedCount,
          }, 'Scheduled cleanup removed expired queue entries');
        }
      } catch (error) {
        logger.error({ error }, 'Scheduled cleanup failed, will retry at next interval');
        // Don't throw - let cleanup retry at next interval
      }
    }, CLEANUP_INTERVAL_MS);

    // Also run cleanup immediately on startup (with delay to allow initialization)
    setTimeout(async () => {
      try {
        if (this.isShuttingDown || !this.offlineQueueManager) {
          return;
        }

        const removedCount = await this.offlineQueueManager.cleanupExpired();

        logger.info({
          removedCount,
        }, 'Initial cleanup on startup removed expired entries');
      } catch (error) {
        logger.warn({ error }, 'Initial cleanup failed, will retry at next scheduled interval');
      }
    }, 5000); // Wait 5 seconds after startup before first cleanup

    logger.info('Offline queue cleanup scheduler started (runs every hour)');
  }

  /**
   * Initialize database connection
   */
  private async initializeDatabase(): Promise<void> {
    try {
      await this.dbPool.query('SELECT 1');
      logger.info('Database connection established');
    } catch (error) {
      logger.error({ error }, 'Failed to connect to database');
      throw error;
    }
  }

  /**
   * Initialize RabbitMQ connection and consumers
   */
  private async initializeRabbitMQ(): Promise<void> {
    try {
      logger.info({ url: this.config.rabbitMqUrl }, 'Connecting to RabbitMQ');

      const connection = await amqp.connect(this.config.rabbitMqUrl);
      this.rabbitConnection = connection as unknown as Connection;
      this.rabbitChannel = await (connection as any).createChannel();

      if (!this.rabbitChannel) {
        throw new Error('Failed to create RabbitMQ channel');
      }

      // Declare queues
      await this.rabbitChannel.assertQueue(this.config.fiscalizationQueueName, {
        durable: true,
      });
      await this.rabbitChannel.assertQueue(this.config.resultQueueName, {
        durable: true,
      });

      // Set prefetch to 1 (process one message at a time)
      await this.rabbitChannel.prefetch(1);

      // Start consuming
      await this.rabbitChannel.consume(
        this.config.fiscalizationQueueName,
        this.handleFiscalizationMessage.bind(this),
        { noAck: false }
      );

      logger.info('RabbitMQ consumer started');

      // Handle connection errors
      (connection as any).on('error', (error: Error) => {
        logger.error({ error }, 'RabbitMQ connection error');
      });

      (connection as any).on('close', () => {
        logger.warn('RabbitMQ connection closed');
        if (!this.isShuttingDown) {
          // Attempt reconnection
          setTimeout(() => this.initializeRabbitMQ(), 5000);
        }
      });
    } catch (error) {
      logger.error({ error }, 'Failed to initialize RabbitMQ');
      throw error;
    }
  }

  /**
   * Handle fiscalization message from RabbitMQ
   */
  private async handleFiscalizationMessage(
    msg: ConsumeMessage | null
  ): Promise<void> {
    if (!msg || !this.rabbitChannel) {
      return;
    }

    const content = msg.content.toString();
    let message: FiscalizationMessage | undefined;

    try {
      message = JSON.parse(content) as FiscalizationMessage;

      if (!message || !message.messageId || !message.invoice) {
        throw new Error('Invalid message format');
      }

      logger.info({
        messageId: message.messageId,
        invoiceId: message.invoiceId,
        invoiceNumber: message.invoice.brojRacuna,
      }, 'Processing fiscalization message');

      // Process fiscalization
      const result = await this.fiscalizationService!.fiscalizeInvoice({
        racun: message.invoice,
      });

      // Publish result
      await this.publishResult(message, result.success, result.jir, result.error);

      // Handle offline queueing
      if (result.queuedOffline) {
        await this.offlineQueueManager!.enqueue(
          { racun: message.invoice },
          message.invoiceId,
          result.error
        );
      }

      // Acknowledge message
      this.rabbitChannel.ack(msg);

      logger.info({
        messageId: message.messageId,
        success: result.success,
        jir: result.jir,
      }, 'Fiscalization message processed');
    } catch (error) {
      logger.error({
        error,
        messageId: message?.messageId,
      }, 'Failed to process fiscalization message');

      // Reject and requeue (will retry)
      if (this.rabbitChannel) {
        this.rabbitChannel.nack(msg, false, true);
      }
    }
  }

  /**
   * Publish fiscalization result to RabbitMQ
   */
  private async publishResult(
    originalMessage: FiscalizationMessage,
    success: boolean,
    jir?: string,
    error?: any
  ): Promise<void> {
    try {
      const resultMessage: FiscalizationResultMessage = {
        messageId: originalMessage.messageId,
        invoiceId: originalMessage.invoiceId,
        jir,
        success,
        error,
        timestamp: new Date(),
        correlationId: originalMessage.correlationId,
      };

      this.rabbitChannel!.sendToQueue(
        this.config.resultQueueName,
        Buffer.from(safeStringify(resultMessage)), // IMPROVEMENT-028: Use safe stringify
        {
          persistent: true,
          correlationId: originalMessage.correlationId,
        }
      );

      logger.debug({
        messageId: originalMessage.messageId,
        success,
      }, 'Published fiscalization result');
    } catch (error) {
      logger.error({
        error,
        messageId: originalMessage.messageId,
      }, 'Failed to publish result');
      // Don't throw - message was processed successfully
    }
  }

  /**
   * Initialize HTTP server for health checks and metrics
   */
  private initializeHttpServer(): void {
    this.app.use(express.json());

    // Health check
    this.app.get('/health', async (req: Request, res: Response) => {
      const dbHealthy = await this.checkDatabaseHealth();
      const rabbitHealthy = this.rabbitConnection !== null;

      const healthy = dbHealthy && rabbitHealthy;

      res.status(healthy ? 200 : 503).json({
        status: healthy ? 'healthy' : 'unhealthy',
        service: 'fina-connector',
        timestamp: new Date().toISOString(),
        checks: {
          database: dbHealthy ? 'ok' : 'failed',
          rabbitmq: rabbitHealthy ? 'ok' : 'failed',
        },
      });
    });

    // Readiness check
    this.app.get('/ready', (req: Request, res: Response) => {
      const ready =
        this.fiscalizationService !== null &&
        this.offlineQueueManager !== null;

      res.status(ready ? 200 : 503).json({
        ready,
        service: 'fina-connector',
        timestamp: new Date().toISOString(),
      });
    });

    // Prometheus metrics
    this.app.get('/metrics', async (req: Request, res: Response) => {
      try {
        const metrics = await getMetrics();
        res.set('Content-Type', 'text/plain; version=0.0.4');
        res.send(metrics);
      } catch (error) {
        logger.error({ error }, 'Failed to export metrics');
        res.status(500).send('Failed to export metrics');
      }
    });

    // Offline queue stats
    this.app.get('/queue/stats', async (req: Request, res: Response) => {
      try {
        const stats = await this.offlineQueueManager!.getStats();
        res.json(stats);
      } catch (error) {
        logger.error({ error }, 'Failed to get queue stats');
        res.status(500).json({ error: 'Failed to get queue stats' });
      }
    });

    // IMPROVEMENT-006: WSDL cache health check endpoint
    this.app.get('/health/wsdl', (req: Request, res: Response) => {
      if (!this.soapClient) {
        return res.status(503).json({
          status: 'unavailable',
          message: 'SOAP client not initialized',
        });
      }

      const wsdlInfo = this.soapClient.getWSDLInfo();

      const isHealthy =
        wsdlInfo.version &&
        wsdlInfo.expiresAt &&
        new Date() < wsdlInfo.expiresAt;

      const status = isHealthy ? 200 : 503;
      const statusText = isHealthy ? 'healthy' : 'stale';

      res.status(status).json({
        status: statusText,
        wsdl: {
          version: wsdlInfo.version,
          lastFetched: wsdlInfo.lastFetched?.toISOString(),
          expiresAt: wsdlInfo.expiresAt?.toISOString(),
        },
        timestamp: new Date().toISOString(),
      });
    });

    // IMPROVEMENT-006: WSDL cache metrics endpoint
    this.app.get('/metrics/wsdl', (req: Request, res: Response) => {
      if (!this.soapClient) {
        return res.status(503).json({
          error: 'SOAP client not initialized',
        });
      }

      const wsdlInfo = this.soapClient.getWSDLInfo();

      res.json({
        version: wsdlInfo.version,
        lastFetched: wsdlInfo.lastFetched?.toISOString(),
        expiresAt: wsdlInfo.expiresAt?.toISOString(),
        environment: this.config.finaWsdlUrl.includes('cistest') ? 'test' : 'production',
      });
    });

    this.server = this.app.listen(this.config.port, () => {
      logger.info({ port: this.config.port }, 'HTTP server listening');
    });
  }

  /**
   * Check database health
   */
  private async checkDatabaseHealth(): Promise<boolean> {
    try {
      await this.dbPool.query('SELECT 1');
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Set up graceful shutdown handlers
   */
  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      if (this.isShuttingDown) {
        return;
      }

      this.isShuttingDown = true;
      logger.info({ signal }, 'Shutting down gracefully');

      serviceUp.set(0);

      // IMPROVEMENT-027: Clear cleanup scheduler timer
      if (this.cleanupTimer) {
        clearInterval(this.cleanupTimer);
        this.cleanupTimer = null;
        logger.info('Cleanup scheduler stopped');
      }

      // Stop accepting new messages
      if (this.rabbitChannel) {
        try {
          await this.rabbitChannel.close();
        } catch (error) {
          // Ignore
        }
      }

      // Close HTTP server
      if (this.server) {
        this.server.close();
      }

      // Close RabbitMQ connection
      if (this.rabbitConnection) {
        try {
          await (this.rabbitConnection as any).close();
        } catch (error) {
          // Ignore
        }
      }

      // Close database pool
      await this.dbPool.end();

      shutdownObservability();

      logger.info('Shutdown complete');
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }

  /**
   * Start application
   */
  async start(): Promise<void> {
    await this.initialize();
    logger.info('FINA Connector service started');
  }
}

/**
 * Main entry point
 */
async function main() {
  try {
    const config = loadConfig();

    logger.info({
      config: {
        port: config.port,
        finaWsdlUrl: config.finaWsdlUrl,
        signatureServiceUrl: config.signatureServiceUrl,
        offlineQueueEnabled: config.offlineQueueEnabled,
      },
    }, 'Starting FINA Connector service');

    const app = new FINAConnectorApp(config);
    await app.start();
  } catch (error) {
    logger.fatal({ error }, 'Failed to start FINA Connector service');
    process.exit(1);
  }
}

// Start application
main();
