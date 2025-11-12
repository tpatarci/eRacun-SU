/**
 * Email Ingestion Worker - Main Entry Point
 *
 * Orchestrates email monitoring, attachment extraction, and message bus publishing.
 * - IMAP client initialization
 * - Email polling coordination
 * - Attachment processing pipeline
 * - Graceful shutdown handling
 */

import http from 'http';
import { logger, getMetricsRegistry } from './observability';
import { ImapClient, createImapClientFromEnv } from './imap-client';
import { EmailPoller, createEmailPollerFromEnv } from './email-poller';
import {
  AttachmentExtractor,
  createAttachmentExtractorFromEnv,
} from './attachment-extractor';
import {
  MessagePublisher,
  createMessagePublisherFromEnv,
} from './message-publisher';
import {
  EmailRepository,
  createEmailRepositoryFromEnv,
} from './repository';
import { Readable } from 'stream';

/**
 * Email Ingestion Worker Service
 */
class EmailIngestionWorkerService {
  private imapClient: ImapClient;
  private emailPoller: EmailPoller;
  private attachmentExtractor: AttachmentExtractor;
  private messagePublisher: MessagePublisher;
  private repository: EmailRepository;
  private metricsServer: http.Server | null = null;
  private isShuttingDown = false;

  constructor() {
    // Initialize components
    this.imapClient = createImapClientFromEnv();
    this.attachmentExtractor = createAttachmentExtractorFromEnv();
    this.messagePublisher = createMessagePublisherFromEnv();
    this.repository = createEmailRepositoryFromEnv();

    // Create email poller with processor callback
    this.emailPoller = createEmailPollerFromEnv(
      this.imapClient,
      this.processEmail.bind(this)
    );
  }

  /**
   * Start the service
   */
  async start(): Promise<void> {
    try {
      logger.info('Starting Email Ingestion Worker Service');

      // Initialize database schema
      await this.repository.initialize();

      // Connect to message bus
      await this.messagePublisher.connect();

      // Connect to IMAP server
      await this.imapClient.connect();

      // Start email polling
      this.emailPoller.start();

      // Start metrics server
      this.startMetricsServer();

      // Setup graceful shutdown
      this.setupGracefulShutdown();

      logger.info('Email Ingestion Worker Service started successfully');
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
    logger.info('Stopping Email Ingestion Worker Service');

    try {
      // Stop email polling
      this.emailPoller.stop();

      // Disconnect from IMAP
      await this.imapClient.disconnect();

      // Disconnect from message bus
      await this.messagePublisher.disconnect();

      // Close database connection
      await this.repository.close();

      // Close metrics server
      if (this.metricsServer) {
        await new Promise<void>((resolve) => {
          this.metricsServer!.close(() => resolve());
        });
      }

      logger.info('Email Ingestion Worker Service stopped successfully');
    } catch (err) {
      logger.error({ err }, 'Error during service shutdown');
      throw err;
    }
  }

  /**
   * Process a single email by UID
   */
  private async processEmail(uid: number): Promise<void> {
    logger.info({ uid }, 'Processing email');

    try {
      // Check if already processed
      const alreadyProcessed = await this.repository.isEmailProcessed(uid);
      if (alreadyProcessed) {
        logger.info({ uid }, 'Email already processed, skipping');
        return;
      }

      // Fetch email from IMAP
      const emailStream = await this.fetchEmailStream(uid);

      // Parse email and extract attachments
      const parsedEmail = await this.attachmentExtractor.parseEmail(emailStream);

      logger.info(
        {
          uid,
          messageId: parsedEmail.messageId,
          subject: parsedEmail.subject,
          attachments: parsedEmail.attachments.length,
        },
        'Email parsed successfully'
      );

      // Check if message ID already processed (duplicate detection)
      const messageIdProcessed = await this.repository.isMessageIdProcessed(
        parsedEmail.messageId
      );
      if (messageIdProcessed) {
        logger.info(
          { uid, messageId: parsedEmail.messageId },
          'Message ID already processed, skipping'
        );
        return;
      }

      // Save processed email to database
      const emailId = await this.repository.saveProcessedEmail(
        uid,
        parsedEmail.messageId,
        parsedEmail.subject,
        parsedEmail.from,
        parsedEmail.to,
        parsedEmail.date,
        parsedEmail.attachments.length
      );

      // Process each attachment
      for (const attachment of parsedEmail.attachments) {
        try {
          // Publish attachment to message bus
          await this.messagePublisher.publishAttachment(
            parsedEmail.messageId,
            attachment,
            process.env.EMAIL_MAILBOX || 'INBOX'
          );

          // Save attachment metadata to database
          await this.repository.saveProcessedAttachment(
            emailId,
            attachment.id,
            attachment.filename,
            attachment.contentType,
            attachment.size,
            attachment.checksum
          );

          logger.info(
            { uid, attachmentId: attachment.id, filename: attachment.filename },
            'Attachment published successfully'
          );
        } catch (err) {
          logger.error(
            { err, uid, attachmentId: attachment.id },
            'Failed to publish attachment'
          );
          // Continue processing other attachments
        }
      }

      logger.info({ uid, messageId: parsedEmail.messageId }, 'Email processing complete');
    } catch (err) {
      logger.error({ err, uid }, 'Failed to process email');

      // Save error status to database (best effort)
      try {
        await this.repository.saveProcessedEmail(
          uid,
          `error-${uid}`,
          'Error',
          'unknown',
          [],
          new Date(),
          0,
          'error',
          err instanceof Error ? err.message : 'Unknown error'
        );
      } catch (dbErr) {
        logger.error({ err: dbErr, uid }, 'Failed to save error status');
      }

      throw err;
    }
  }

  /**
   * Fetch email as stream from IMAP
   */
  private async fetchEmailStream(uid: number): Promise<Readable> {
    return new Promise<Readable>((resolve, reject) => {
      const fetch = this.imapClient.fetchMessage(uid, {
        bodies: '',
        struct: true,
      });

      fetch.on('message', (msg) => {
        msg.on('body', (stream) => {
          resolve(stream);
        });

        msg.on('error', (err) => {
          logger.error({ err, uid }, 'Error fetching message');
          reject(err);
        });
      });

      fetch.once('error', (err) => {
        logger.error({ err, uid }, 'Fetch error');
        reject(err);
      });

      fetch.once('end', () => {
        logger.debug({ uid }, 'Fetch complete');
      });
    });
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
          this.imapClient.getConnectionStatus() &&
          this.messagePublisher.getConnectionStatus();

        res.statusCode = isHealthy ? 200 : 503;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            status: isHealthy ? 'healthy' : 'unhealthy',
            imap: this.imapClient.getConnectionStatus(),
            messagebus: this.messagePublisher.getConnectionStatus(),
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
  const service = new EmailIngestionWorkerService();

  service.start().catch((err) => {
    logger.error({ err }, 'Fatal error starting service');
    process.exit(1);
  });
}

export { EmailIngestionWorkerService };
