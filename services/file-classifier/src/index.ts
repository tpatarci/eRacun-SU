/**
 * File Classifier Service - Main Entry Point
 *
 * Orchestrates file classification and routing.
 * - Message consumption from email-ingestion-worker
 * - File type detection
 * - Classification and routing logic
 * - Message publishing to processors
 */

import http from 'http';
import { logger, getMetricsRegistry } from './observability';
import { FileDetector, createFileDetectorFromEnv } from './file-detector';
import { Classifier, createClassifierFromEnv } from './classifier';
import {
  MessageConsumer,
  AttachmentMessage,
  createMessageConsumerFromEnv,
} from './message-consumer';
import {
  MessagePublisher,
  ClassifyFileCommand,
  createMessagePublisherFromEnv,
} from './message-publisher';

/**
 * File Classifier Service
 */
class FileClassifierService {
  private fileDetector: FileDetector;
  private classifier: Classifier;
  private messageConsumer: MessageConsumer;
  private messagePublisher: MessagePublisher;
  private metricsServer: http.Server | null = null;
  private isShuttingDown = false;

  constructor() {
    // Initialize components
    this.fileDetector = createFileDetectorFromEnv();
    this.classifier = createClassifierFromEnv();
    this.messagePublisher = createMessagePublisherFromEnv();

    // Create message consumer with processor callback
    this.messageConsumer = createMessageConsumerFromEnv(
      this.processAttachment.bind(this)
    );
  }

  /**
   * Start the service
   */
  async start(): Promise<void> {
    try {
      logger.info('Starting File Classifier Service');

      // Connect to message bus (publisher)
      await this.messagePublisher.connect();

      // Connect to message bus (consumer)
      await this.messageConsumer.connect();

      // Start metrics server
      this.startMetricsServer();

      // Setup graceful shutdown
      this.setupGracefulShutdown();

      logger.info('File Classifier Service started successfully');
    } catch (err) {
      logger.error({ err }, 'Failed to start service');
      throw err;
    }
  }

  /**
   * Stop the service
   */
  async stop(): Promise<void> {
    if (this.isShuttingDown) {
      logger.warn('Shutdown already in progress');
      return;
    }

    this.isShuttingDown = true;
    logger.info('Stopping File Classifier Service');

    try {
      // Disconnect from message bus
      await this.messageConsumer.disconnect();
      await this.messagePublisher.disconnect();

      // Close metrics server
      if (this.metricsServer) {
        await new Promise<void>((resolve) => {
          this.metricsServer!.close(() => resolve());
        });
      }

      logger.info('File Classifier Service stopped successfully');
    } catch (err) {
      logger.error({ err }, 'Error during service shutdown');
      throw err;
    }
  }

  /**
   * Process attachment message
   */
  private async processAttachment(message: AttachmentMessage): Promise<void> {
    logger.info(
      {
        messageId: message.messageId,
        attachmentId: message.attachment.id,
        filename: message.attachment.filename,
      },
      'Processing attachment'
    );

    try {
      // Decode base64 content
      const contentBuffer = Buffer.from(message.content, 'base64');

      // Detect file type
      const detectedFile = await this.fileDetector.detectFileType(
        contentBuffer,
        message.attachment.filename
      );

      logger.info(
        {
          attachmentId: message.attachment.id,
          mimeType: detectedFile.mimeType,
          extension: detectedFile.extension,
          detectionMethod: detectedFile.detectionMethod,
          isSupported: detectedFile.isSupported,
        },
        'File type detected'
      );

      // Classify file and determine routing
      const classification = this.classifier.classify(detectedFile);

      logger.info(
        {
          attachmentId: message.attachment.id,
          processor: classification.processor,
          priority: classification.priority,
          category: classification.category,
          confidence: classification.confidence,
        },
        'File classified'
      );

      // Create classification command
      const command: ClassifyFileCommand = {
        messageId: `classify-${message.messageId}`,
        emailMessageId: message.emailMessageId,
        attachmentId: message.attachment.id,
        filename: message.attachment.filename,
        classification,
        content: message.content, // Pass through base64 content
        timestamp: new Date().toISOString(),
        source: message.source,
      };

      // Publish to appropriate processor
      await this.messagePublisher.publishClassification(command);

      logger.info(
        {
          messageId: message.messageId,
          attachmentId: message.attachment.id,
          processor: classification.processor,
        },
        'Attachment processing complete'
      );
    } catch (err) {
      logger.error(
        {
          err,
          messageId: message.messageId,
          attachmentId: message.attachment.id,
        },
        'Failed to process attachment'
      );
      throw err;
    }
  }

  /**
   * Start Prometheus metrics HTTP server
   */
  private startMetricsServer(): void {
    const port = parseInt(process.env.METRICS_PORT || '9090', 10);

    this.metricsServer = http.createServer(async (req, res) => {
      if (req.url === '/metrics') {
        res.setHeader('Content-Type', getMetricsRegistry().contentType);
        res.end(await getMetricsRegistry().metrics());
      } else if (req.url === '/health') {
        const isHealthy =
          this.messageConsumer.getConnectionStatus() &&
          this.messagePublisher.getConnectionStatus();

        res.statusCode = isHealthy ? 200 : 503;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            status: isHealthy ? 'healthy' : 'unhealthy',
            consumer: this.messageConsumer.getConnectionStatus(),
            publisher: this.messagePublisher.getConnectionStatus(),
            timestamp: new Date().toISOString(),
          })
        );
      } else {
        res.statusCode = 404;
        res.end('Not Found');
      }
    });

    this.metricsServer.listen(port, () => {
      logger.info({ port }, 'Metrics server started');
    });
  }

  /**
   * Setup graceful shutdown handlers
   */
  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      logger.info({ signal }, 'Received shutdown signal');
      try {
        await this.stop();
        process.exit(0);
      } catch (err) {
        logger.error({ err }, 'Error during shutdown');
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    process.on('unhandledRejection', (reason, promise) => {
      logger.error({ reason, promise }, 'Unhandled promise rejection');
    });

    process.on('uncaughtException', (err) => {
      logger.error({ err }, 'Uncaught exception');
      process.exit(1);
    });
  }
}

// Start service if running as main module
if (require.main === module) {
  const service = new FileClassifierService();

  service.start().catch((err) => {
    logger.error({ err }, 'Fatal error starting service');
    process.exit(1);
  });
}

export { FileClassifierService };
