/**
 * Unit Tests for OCR Processor
 */

import { OCRProcessor } from '../../src/ocr-processor';
import { OCRRequest } from '../../src/types';

describe('OCRProcessor', () => {
  let processor: OCRProcessor;

  beforeEach(() => {
    processor = new OCRProcessor({
      minConfidence: 0.7,
      enableTableExtraction: true,
      enableLanguageDetection: true,
      preprocessImages: false // Disable for faster tests
    });
  });

  describe('processRequest', () => {
    it('should process a valid image with high quality', async () => {
      // Create a minimal valid PNG (1x1 pixel)
      const pngBuffer = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAA/UlEQVR4nO3RMQ0AMAzAsPIn3d1FsBw2gkiZJWV+B3AZEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmPItjz4K6zWe61QCAAAAABJRU5ErkJggg==',
        'base64'
      );

      const request: OCRRequest = {
        fileId: 'test-123',
        filename: 'test.png',
        content: pngBuffer.toString('base64'),
        mimeType: 'image/png',
        metadata: {
          sourceService: 'file-classifier',
          timestamp: new Date().toISOString()
        }
      };

      const response = await processor.processRequest(request);

      expect(response.fileId).toBe('test-123');
      expect(response.success).toBe(true);
      expect(response.extractedText).toBeDefined();
      expect(response.confidence).toBeGreaterThanOrEqual(0);
      expect(response.confidence).toBeLessThanOrEqual(1);
      expect(response.processingTime).toBeGreaterThan(0);
    });

    it('should handle low quality scanned images', async () => {
      // Simulate low quality by using a very small image
      const lowQualityPng = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAA/UlEQVR4nO3RMQ0AMAzAsPIn3d1FsBw2gkiZJWV+B3AZEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmPItjz4K6zWe61QCAAAAABJRU5ErkJggg==',
        'base64'
      );

      const request: OCRRequest = {
        fileId: 'low-quality-456',
        filename: 'scanned.png',
        content: lowQualityPng.toString('base64'),
        mimeType: 'image/png',
        metadata: {
          sourceService: 'file-classifier',
          timestamp: new Date().toISOString()
        }
      };

      const response = await processor.processRequest(request);

      expect(response.fileId).toBe('low-quality-456');
      expect(response.success).toBe(true);
      expect(response.extractedText).toBeDefined();
    });

    it('should extract text blocks', async () => {
      const pngBuffer = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAA/UlEQVR4nO3RMQ0AMAzAsPIn3d1FsBw2gkiZJWV+B3AZEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmPItjz4K6zWe61QCAAAAABJRU5ErkJggg==',
        'base64'
      );

      const request: OCRRequest = {
        fileId: 'blocks-789',
        filename: 'invoice.png',
        content: pngBuffer.toString('base64'),
        mimeType: 'image/png',
        metadata: {
          sourceService: 'file-classifier',
          timestamp: new Date().toISOString()
        }
      };

      const response = await processor.processRequest(request);

      expect(response.blocks).toBeDefined();
      expect(Array.isArray(response.blocks)).toBe(true);
      if (response.blocks && response.blocks.length > 0) {
        expect(response.blocks[0]).toHaveProperty('text');
        expect(response.blocks[0]).toHaveProperty('confidence');
        expect(response.blocks[0]).toHaveProperty('type');
      }
    });

    it('should extract tables when enabled', async () => {
      const processorWithTables = new OCRProcessor({
        enableTableExtraction: true,
        preprocessImages: false
      });

      const pngBuffer = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAA/UlEQVR4nO3RMQ0AMAzAsPIn3d1FsBw2gkiZJWV+B3AZEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmPItjz4K6zWe61QCAAAAABJRU5ErkJggg==',
        'base64'
      );

      const request: OCRRequest = {
        fileId: 'table-999',
        filename: 'table.png',
        content: pngBuffer.toString('base64'),
        mimeType: 'image/png',
        metadata: {
          sourceService: 'file-classifier',
          timestamp: new Date().toISOString()
        }
      };

      const response = await processorWithTables.processRequest(request);

      expect(response.success).toBe(true);
      // Tables may or may not be present depending on image content
      if (response.tables) {
        expect(Array.isArray(response.tables)).toBe(true);
      }
    });

    it('should reject invalid image data', async () => {
      const request: OCRRequest = {
        fileId: 'invalid-001',
        filename: 'corrupt.png',
        content: Buffer.from('not a valid image').toString('base64'),
        mimeType: 'image/png',
        metadata: {
          sourceService: 'file-classifier',
          timestamp: new Date().toISOString()
        }
      };

      const response = await processor.processRequest(request);

      expect(response.success).toBe(false);
      expect(response.errors.length).toBeGreaterThan(0);
    });

    it('should handle empty base64 content', async () => {
      const request: OCRRequest = {
        fileId: 'empty-002',
        filename: 'empty.png',
        content: '',
        mimeType: 'image/png',
        metadata: {
          sourceService: 'file-classifier',
          timestamp: new Date().toISOString()
        }
      };

      const response = await processor.processRequest(request);

      expect(response.success).toBe(false);
      expect(response.errors.length).toBeGreaterThan(0);
    });

    it('should include language detection', async () => {
      const pngBuffer = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAA/UlEQVR4nO3RMQ0AMAzAsPIn3d1FsBw2gkiZJWV+B3AZEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmPItjz4K6zWe61QCAAAAABJRU5ErkJggg==',
        'base64'
      );

      const request: OCRRequest = {
        fileId: 'lang-003',
        filename: 'croatian.png',
        content: pngBuffer.toString('base64'),
        mimeType: 'image/png',
        metadata: {
          sourceService: 'file-classifier',
          timestamp: new Date().toISOString()
        }
      };

      const response = await processor.processRequest(request);

      expect(response.success).toBe(true);
      expect(response.language).toBeDefined();
      expect(typeof response.language).toBe('string');
    });
  });

  describe('processBatch', () => {
    it('should process multiple requests in batch', async () => {
      const pngBuffer = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAA/UlEQVR4nO3RMQ0AMAzAsPIn3d1FsBw2gkiZJWV+B3AZEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmPItjz4K6zWe61QCAAAAABJRU5ErkJggg==',
        'base64'
      );

      const requests: OCRRequest[] = [
        {
          fileId: 'batch-001',
          filename: 'doc1.png',
          content: pngBuffer.toString('base64'),
          mimeType: 'image/png',
          metadata: { sourceService: 'test', timestamp: new Date().toISOString() }
        },
        {
          fileId: 'batch-002',
          filename: 'doc2.png',
          content: pngBuffer.toString('base64'),
          mimeType: 'image/png',
          metadata: { sourceService: 'test', timestamp: new Date().toISOString() }
        },
        {
          fileId: 'batch-003',
          filename: 'doc3.png',
          content: pngBuffer.toString('base64'),
          mimeType: 'image/png',
          metadata: { sourceService: 'test', timestamp: new Date().toISOString() }
        }
      ];

      const responses = await processor.processBatch(requests);

      expect(responses).toHaveLength(3);
      expect(responses[0].fileId).toBe('batch-001');
      expect(responses[1].fileId).toBe('batch-002');
      expect(responses[2].fileId).toBe('batch-003');
      expect(responses.every(r => r.success)).toBe(true);
    });

    it('should handle mixed success/failure in batch', async () => {
      const validPng = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAA/UlEQVR4nO3RMQ0AMAzAsPIn3d1FsBw2gkiZJWV+B3AZEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmNIjCExhsQYEmPItjz4K6zWe61QCAAAAABJRU5ErkJggg==',
        'base64'
      );

      const requests: OCRRequest[] = [
        {
          fileId: 'mixed-001',
          filename: 'valid.png',
          content: validPng.toString('base64'),
          mimeType: 'image/png',
          metadata: { sourceService: 'test', timestamp: new Date().toISOString() }
        },
        {
          fileId: 'mixed-002',
          filename: 'invalid.png',
          content: Buffer.from('invalid').toString('base64'),
          mimeType: 'image/png',
          metadata: { sourceService: 'test', timestamp: new Date().toISOString() }
        }
      ];

      const responses = await processor.processBatch(requests);

      expect(responses).toHaveLength(2);
      expect(responses[0].success).toBe(true);
      expect(responses[1].success).toBe(false);
    });
  });

  describe('healthCheck', () => {
    it('should pass health check', async () => {
      const healthy = await processor.healthCheck();
      expect(healthy).toBe(true);
    });
  });
});
