/**
 * File Detector Property-Based Tests
 *
 * These tests use fast-check to verify properties that should hold
 * for all possible inputs, catching edge cases that example-based
 * tests might miss.
 */

import * as fc from 'fast-check';
import { FileDetector } from '../../src/file-detector';

describe('FileDetector - Property-Based Tests', () => {
  let detector: FileDetector;

  beforeEach(() => {
    detector = new FileDetector({
      maxFileSize: 10 * 1024 * 1024, // 10MB
      minFileSize: 1,
      supportedMimeTypes: [
        'application/pdf',
        'application/xml',
        'text/xml',
        'image/jpeg',
        'image/png',
        'application/zip',
      ],
    });
  });

  describe('File Size Validation Properties', () => {
    it('should accept any file within size limits', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 10 * 1024 * 1024 }), // Valid size range
          fc.string({ minLength: 1, maxLength: 255 }), // Filename
          async (size, filename) => {
            const buffer = Buffer.alloc(size, 'a');
            const result = await detector.detectFileType(buffer, filename);

            // Should not fail due to size
            expect(result.size).toBe(size);
            expect(result.size).toBeGreaterThanOrEqual(1);
            expect(result.size).toBeLessThanOrEqual(10 * 1024 * 1024);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject files exceeding maximum size', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 10 * 1024 * 1024 + 1, max: 50 * 1024 * 1024 }), // Oversized
          fc.string({ minLength: 1, maxLength: 255 }),
          async (size, filename) => {
            const buffer = Buffer.alloc(size, 'a');

            await expect(
              detector.detectFileType(buffer, filename)
            ).rejects.toThrow();
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have deterministic size reporting', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 100, maxLength: 10000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          async (data, filename) => {
            const buffer = Buffer.from(data);
            const result1 = await detector.detectFileType(buffer, filename);
            const result2 = await detector.detectFileType(buffer, filename);

            // Same input should produce same size
            expect(result1.size).toBe(result2.size);
            expect(result1.size).toBe(buffer.length);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('MIME Detection Determinism', () => {
    it('should produce deterministic MIME types for identical inputs', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 100, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          async (data, filename) => {
            const buffer = Buffer.from(data);

            const result1 = await detector.detectFileType(buffer, filename);
            const result2 = await detector.detectFileType(buffer, filename);

            // Determinism: same input = same output
            expect(result1.mimeType).toBe(result2.mimeType);
            expect(result1.extension).toBe(result2.extension);
            expect(result1.detectionMethod).toBe(result2.detectionMethod);
            expect(result1.isSupported).toBe(result2.isSupported);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should always return a valid MIME type string', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 10, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          async (data, filename) => {
            const buffer = Buffer.from(data);
            const result = await detector.detectFileType(buffer, filename);

            // MIME type should always be a non-empty string
            expect(typeof result.mimeType).toBe('string');
            expect(result.mimeType.length).toBeGreaterThan(0);

            // MIME type should follow standard format (type/subtype)
            if (result.mimeType !== 'application/octet-stream') {
              expect(result.mimeType).toMatch(/^[a-z]+\/[a-z0-9\-\+\.]+$/i);
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('PDF Detection Properties', () => {
    it('should detect all valid PDF magic numbers', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '2.0'),
          fc.string({ minLength: 10, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          async (pdfVersion, content, filename) => {
            const pdfBuffer = Buffer.from(`%PDF-${pdfVersion}\n${content}`, 'utf-8');
            const result = await detector.detectFileType(pdfBuffer, filename);

            // All valid PDF versions should be detected as PDF
            expect(result.mimeType).toBe('application/pdf');
            expect(result.extension).toBe('pdf');
            expect(result.detectionMethod).toBe('magic-number');
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('XML Detection Properties', () => {
    it('should detect XML files with various declarations', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('1.0', '1.1'),
          fc.constantFrom('UTF-8', 'UTF-16', 'ISO-8859-1'),
          fc.string({ minLength: 10, maxLength: 100 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          async (version, encoding, content, filename) => {
            const xmlBuffer = Buffer.from(
              `<?xml version="${version}" encoding="${encoding}"?>\n<root>${content}</root>`,
              'utf-8'
            );
            const result = await detector.detectFileType(xmlBuffer, filename);

            // All valid XML should be detected
            expect(['application/xml', 'text/xml']).toContain(result.mimeType);
            expect(result.extension).toBe('xml');
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Confidence Score Properties', () => {
    it('should always return confidence scores between 0 and 1', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 10, maxLength: 5000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          async (data, filename) => {
            const buffer = Buffer.from(data);
            const result = await detector.detectFileType(buffer, filename);

            if (result.confidence !== undefined) {
              expect(result.confidence).toBeGreaterThanOrEqual(0);
              expect(result.confidence).toBeLessThanOrEqual(1);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have higher confidence for magic number detection', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            { magic: '%PDF-1.4', mime: 'application/pdf' },
            { magic: '<?xml', mime: 'application/xml' },
            { magic: 'PK\x03\x04', mime: 'application/zip' }
          ),
          fc.string({ minLength: 10, maxLength: 100 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          async (format, content, filename) => {
            const buffer = Buffer.from(format.magic + content, 'binary');
            const result = await detector.detectFileType(buffer, filename);

            // Magic number detection should have higher confidence
            if (result.detectionMethod === 'magic-number' && result.confidence) {
              expect(result.confidence).toBeGreaterThan(0.7);
            }
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Extension Consistency Properties', () => {
    it('should maintain consistency between MIME type and extension', () => {
      const mimeExtensionMap: Record<string, string> = {
        'application/pdf': 'pdf',
        'application/xml': 'xml',
        'text/xml': 'xml',
        'application/zip': 'zip',
        'image/jpeg': 'jpg',
        'image/png': 'png',
      };

      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 10, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          async (data, filename) => {
            const buffer = Buffer.from(data);
            const result = await detector.detectFileType(buffer, filename);

            // If we recognize the MIME type, extension should match
            if (mimeExtensionMap[result.mimeType]) {
              expect(result.extension).toBe(mimeExtensionMap[result.mimeType]);
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Filename Sanitization Properties', () => {
    it('should handle any valid filename without throwing', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 255 }),
          fc.uint8Array({ minLength: 10, maxLength: 100 }),
          async (filename, data) => {
            const buffer = Buffer.from(data);

            // Should not throw for any reasonable filename
            await expect(
              detector.detectFileType(buffer, filename)
            ).resolves.toBeDefined();
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Invoice File Identification Properties', () => {
    it('should identify invoice-related files consistently', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('application/pdf', 'application/xml', 'text/xml'),
          fc.uint8Array({ minLength: 100, maxLength: 1000 }),
          fc.constantFrom('invoice.pdf', 'racun.xml', 'faktura.xml', 'invoice_123.pdf'),
          async (mimeType, data, filename) => {
            // Create buffer with appropriate magic number
            let buffer: Buffer;
            if (mimeType === 'application/pdf') {
              buffer = Buffer.concat([
                Buffer.from('%PDF-1.4\n'),
                Buffer.from(data)
              ]);
            } else {
              buffer = Buffer.concat([
                Buffer.from('<?xml version="1.0"?>'),
                Buffer.from(data)
              ]);
            }

            const result = await detector.detectFileType(buffer, filename);

            // Invoice files (PDF/XML) should be marked as invoice-relevant
            expect(['application/pdf', 'application/xml', 'text/xml'])
              .toContain(result.mimeType);
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
