/**
 * Unit Tests for OCR Processing Service
 */

import { OCRProcessingService } from '../../src/index';

// Mock dependencies
jest.mock('../../src/message-consumer', () => {
  return {
    MessageConsumer: jest.fn().mockImplementation(() => {
      return {
        start: jest.fn().mockRejectedValue(new Error('RabbitMQ not available')),
        stop: jest.fn().mockResolvedValue(undefined),
        isHealthy: jest.fn().mockReturnValue(false)
      };
    })
  };
});

describe('OCRProcessingService', () => {
  let service: OCRProcessingService;

  beforeEach(() => {
    service = new OCRProcessingService();
  });

  describe('initialization', () => {
    it('should create service instance', () => {
      expect(service).toBeInstanceOf(OCRProcessingService);
    });
  });

  describe('healthCheck', () => {
    it('should return health status', async () => {
      const health = await service.healthCheck();

      expect(health).toHaveProperty('healthy');
      expect(health).toHaveProperty('processor');
      expect(health).toHaveProperty('consumer');
      expect(typeof health.healthy).toBe('boolean');
      expect(typeof health.processor).toBe('boolean');
      expect(typeof health.consumer).toBe('boolean');
    });

    it('should report processor health', async () => {
      const health = await service.healthCheck();
      expect(health.processor).toBe(true);
    });
  });

  describe('lifecycle', () => {
    it('should handle start failure gracefully', async () => {
      // Will fail because RabbitMQ is not running in test
      await expect(service.start()).rejects.toThrow();
    });
  });
});
