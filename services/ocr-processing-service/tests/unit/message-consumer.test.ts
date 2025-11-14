/**
 * Unit Tests for Message Consumer
 */

import { MessageConsumer } from '../../src/message-consumer';
import { OCRProcessor } from '../../src/ocr-processor';

// Mock amqplib
jest.mock('amqplib', () => ({
  connect: jest.fn()
}));

describe('MessageConsumer', () => {
  let processor: OCRProcessor;
  let consumer: MessageConsumer;

  beforeEach(() => {
    processor = new OCRProcessor({
      preprocessImages: false
    });

    consumer = new MessageConsumer(processor, {
      rabbitUrl: 'amqp://localhost:5672',
      queueName: 'test.ocr.queue'
    });
  });

  afterEach(async () => {
    // Clean up
    if (consumer.isHealthy()) {
      await consumer.stop().catch(() => {
        // Ignore errors in test cleanup
      });
    }
  });

  describe('initialization', () => {
    it('should create consumer with default options', () => {
      const defaultConsumer = new MessageConsumer(processor);
      expect(defaultConsumer).toBeInstanceOf(MessageConsumer);
    });

    it('should create consumer with custom options', () => {
      const customConsumer = new MessageConsumer(processor, {
        rabbitUrl: 'amqp://custom:5672',
        queueName: 'custom.queue'
      });
      expect(customConsumer).toBeInstanceOf(MessageConsumer);
    });
  });

  describe('isHealthy', () => {
    it('should return false when not connected', () => {
      expect(consumer.isHealthy()).toBe(false);
    });
  });

  describe('connection lifecycle', () => {
    it('should handle start failure gracefully', async () => {
      // Mock will fail to connect since RabbitMQ is not running in test
      await expect(consumer.start()).rejects.toThrow();
    });

    it('should handle stop when not started', async () => {
      // Should complete without error even if not started
      await expect(consumer.stop()).resolves.not.toThrow();
    });
  });
});
