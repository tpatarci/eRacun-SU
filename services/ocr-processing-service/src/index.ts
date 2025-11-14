/**
 * OCR Processing Service
 * Main entry point
 */

import pino from 'pino';
import { OCRProcessor } from './ocr-processor';
import { MessageConsumer } from './message-consumer';

const logger = pino({ name: 'ocr-service' });

export { OCRProcessor, MessageConsumer };
export * from './types';

/**
 * Main service class
 */
export class OCRProcessingService {
  private readonly processor: OCRProcessor;
  private readonly consumer: MessageConsumer;

  constructor() {
    // Initialize processor with configuration
    this.processor = new OCRProcessor({
      minConfidence: parseFloat(process.env.MIN_CONFIDENCE || '0.7'),
      enableTableExtraction: process.env.ENABLE_TABLE_EXTRACTION !== 'false',
      enableLanguageDetection: process.env.ENABLE_LANGUAGE_DETECTION !== 'false',
      preprocessImages: process.env.PREPROCESS_IMAGES !== 'false',
      maxImageSize: parseInt(process.env.MAX_IMAGE_SIZE || String(20 * 1024 * 1024), 10)
    });

    // Initialize consumer
    this.consumer = new MessageConsumer(this.processor, {
      rabbitUrl: process.env.RABBITMQ_URL,
      queueName: process.env.OCR_QUEUE_NAME || 'files.image.ocr'
    });
  }

  /**
   * Start the service
   */
  async start(): Promise<void> {
    logger.info('Starting OCR Processing Service');

    try {
      // Health check OCR engine
      const healthy = await this.processor.healthCheck();
      if (!healthy) {
        throw new Error('OCR engine health check failed');
      }

      // Start consuming messages
      await this.consumer.start();

      logger.info('OCR Processing Service started successfully');

      // Graceful shutdown
      process.on('SIGTERM', () => this.stop());
      process.on('SIGINT', () => this.stop());
    } catch (error) {
      logger.error({ error }, 'Failed to start OCR Processing Service');
      throw error;
    }
  }

  /**
   * Stop the service
   */
  async stop(): Promise<void> {
    logger.info('Stopping OCR Processing Service');

    try {
      await this.consumer.stop();
      logger.info('OCR Processing Service stopped successfully');
      process.exit(0);
    } catch (error) {
      logger.error({ error }, 'Error stopping OCR Processing Service');
      process.exit(1);
    }
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{
    healthy: boolean;
    processor: boolean;
    consumer: boolean;
  }> {
    const processorHealthy = await this.processor.healthCheck();
    const consumerHealthy = this.consumer.isHealthy();

    return {
      healthy: processorHealthy && consumerHealthy,
      processor: processorHealthy,
      consumer: consumerHealthy
    };
  }
}

// Start service if run directly
if (require.main === module) {
  const service = new OCRProcessingService();
  service.start().catch(error => {
    logger.fatal({ error }, 'Service crashed');
    process.exit(1);
  });
}
