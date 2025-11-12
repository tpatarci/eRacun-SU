/**
 * PDF Parser Service - Main Entry Point
 *
 * Orchestrates PDF parsing workflow:
 * 1. Consume PDF files from file-classifier
 * 2. Extract text from PDFs
 * 3. Parse invoice data
 * 4. Publish to data-extractor OR route scanned PDFs to OCR
 * 5. Provide observability endpoints
 */

import http from 'http';
import { logger, getMetricsRegistry, pdfsProcessedTotal } from './observability';
import {
  MessageConsumer,
  PDFClassificationMessage,
  createMessageConsumerFromEnv,
} from './message-consumer';
import {
  MessagePublisher,
  ParsedInvoiceCommand,
  createMessagePublisherFromEnv,
} from './message-publisher';
import { PDFExtractor, createPDFExtractorFromEnv } from './pdf-extractor';
import { InvoiceParser } from './invoice-parser';

/**
 * PDF Parser Service
 */
class PDFParserService {
  private messageConsumer: MessageConsumer;
  private messagePublisher: MessagePublisher;
  private pdfExtractor: PDFExtractor;
  private invoiceParser: InvoiceParser;
  private metricsServer: http.Server | null = null;
  private isShuttingDown = false;

  constructor() {
    // Initialize components
    this.pdfExtractor = createPDFExtractorFromEnv();
    this.invoiceParser = new InvoiceParser();
    this.messagePublisher = createMessagePublisherFromEnv();
    this.messageConsumer = createMessageConsumerFromEnv(this.processPDF.bind(this));
  }

  /**
   * Start the service
   */
  async start(): Promise<void> {
    try {
      logger.info('Starting PDF Parser Service');

      // Connect to message bus
      await this.messagePublisher.connect();
      await this.messageConsumer.connect();

      // Start metrics server
      this.startMetricsServer();

      // Setup graceful shutdown
      this.setupGracefulShutdown();

      logger.info('PDF Parser Service started successfully');
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
    logger.info('Stopping PDF Parser Service');

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

      logger.info('PDF Parser Service stopped successfully');
    } catch (err) {
      logger.error({ err }, 'Error during service shutdown');
      throw err;
    }
  }

  /**
   * Process a single PDF file
   */
  private async processPDF(message: PDFClassificationMessage): Promise<void> {
    logger.info(
      {
        messageId: message.messageId,
        attachmentId: message.attachmentId,
        filename: message.filename,
      },
      'Processing PDF'
    );

    try {
      // Decode base64 content
      const pdfBuffer = Buffer.from(message.content, 'base64');

      // Extract text and metadata from PDF
      const extracted = await this.pdfExtractor.extractPDF(pdfBuffer, message.filename);

      logger.info(
        {
          attachmentId: message.attachmentId,
          pageCount: extracted.pageCount,
          textLength: extracted.text.length,
          isScanned: extracted.isScanned,
          quality: extracted.quality,
        },
        'PDF extraction complete'
      );

      // If PDF is scanned, route to OCR service
      if (extracted.isScanned) {
        logger.info(
          { attachmentId: message.attachmentId },
          'PDF is scanned, routing to OCR service'
        );

        await this.messagePublisher.publishScannedPDF(
          message.messageId,
          message.attachmentId,
          message.filename,
          message.content, // Pass through base64 content
          message.source
        );

        pdfsProcessedTotal.inc({ status: 'scanned' });
        return;
      }

      // Parse invoice data from extracted text
      const parsedInvoice = this.invoiceParser.parseInvoice(extracted.text);

      logger.info(
        {
          attachmentId: message.attachmentId,
          confidence: parsedInvoice.confidence,
          extractedFields: parsedInvoice.extractedFields.length,
          hasInvoiceNumber: !!parsedInvoice.invoiceNumber,
          hasTotal: !!parsedInvoice.amounts.total,
        },
        'Invoice parsing complete'
      );

      // Create parsed invoice command
      const command: ParsedInvoiceCommand = {
        messageId: `parsed-${message.messageId}`,
        emailMessageId: message.emailMessageId,
        attachmentId: message.attachmentId,
        filename: message.filename,
        pdfMetadata: {
          pageCount: extracted.pageCount,
          isScanned: extracted.isScanned,
          quality: extracted.quality,
          size: extracted.size,
        },
        invoice: parsedInvoice,
        timestamp: new Date().toISOString(),
        source: message.source,
      };

      // Publish parsed invoice to data-extractor
      await this.messagePublisher.publishParsedInvoice(command);

      pdfsProcessedTotal.inc({ status: 'success' });

      logger.info(
        { messageId: message.messageId, attachmentId: message.attachmentId },
        'PDF processing complete'
      );
    } catch (err) {
      logger.error(
        {
          err,
          messageId: message.messageId,
          attachmentId: message.attachmentId,
        },
        'Failed to process PDF'
      );

      pdfsProcessedTotal.inc({ status: 'error' });
      throw err;
    }
  }

  /**
   * Start Prometheus metrics HTTP server
   */
  private startMetricsServer(): void {
    const port = parseInt(process.env.METRICS_PORT || '9091', 10);

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
  const service = new PDFParserService();

  service.start().catch((err) => {
    logger.error({ err }, 'Fatal error starting service');
    process.exit(1);
  });
}

export { PDFParserService };
