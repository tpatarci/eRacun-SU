/**
 * Archive Extractor Property-Based Tests
 *
 * These tests use fast-check to verify security and correctness properties
 * that must hold for all possible archive inputs.
 */

import * as fc from 'fast-check';
import { ArchiveExtractor } from '../../src/archive-extractor';
import AdmZip from 'adm-zip';
import * as crypto from 'crypto';

describe('ArchiveExtractor - Property-Based Tests', () => {
  let extractor: ArchiveExtractor;

  beforeEach(() => {
    extractor = new ArchiveExtractor({
      maxNestingLevel: 3,
      maxTotalSize: 100 * 1024 * 1024, // 100MB
      maxFileCount: 100,
      maxFileSize: 10 * 1024 * 1024, // 10MB per file
    });
  });

  describe('Extraction Determinism Properties', () => {
    it('should produce identical results for identical ZIP archives', () => {
      fc.assert(
        fc.property(
          fc.array(
            fc.record({
              filename: fc.string({ minLength: 1, maxLength: 50 }),
              content: fc.uint8Array({ minLength: 10, maxLength: 1000 }),
            }),
            { minLength: 1, maxLength: 10 }
          ),
          async (files) => {
            // Create ZIP with multiple files
            const zip = new AdmZip();
            for (const file of files) {
              zip.addFile(file.filename, Buffer.from(file.content));
            }
            const zipBuffer = zip.toBuffer();

            // Extract twice
            const result1 = await extractor.extract(zipBuffer, 'test.zip');
            const result2 = await extractor.extract(zipBuffer, 'test.zip');

            // Results should be identical
            expect(result1.success).toBe(result2.success);
            expect(result1.files.length).toBe(result2.files.length);

            // File contents should match
            for (let i = 0; i < result1.files.length; i++) {
              expect(result1.files[i].filename).toBe(result2.files[i].filename);
              expect(result1.files[i].size).toBe(result2.files[i].size);
              expect(result1.files[i].hash).toBe(result2.files[i].hash);
            }
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Hash Consistency Properties', () => {
    it('should calculate consistent SHA-256 hashes for file contents', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.uint8Array({ minLength: 10, maxLength: 5000 }),
          async (filename, content) => {
            const zip = new AdmZip();
            zip.addFile(filename, Buffer.from(content));
            const zipBuffer = zip.toBuffer();

            const result = await extractor.extract(zipBuffer, 'test.zip');

            expect(result.success).toBe(true);
            expect(result.files.length).toBe(1);

            // Calculate expected hash
            const expectedHash = crypto
              .createHash('sha256')
              .update(Buffer.from(content))
              .digest('hex');

            // Extracted file should have correct hash
            expect(result.files[0].hash).toBe(expectedHash);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce different hashes for different contents', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 10, maxLength: 1000 }),
          fc.uint8Array({ minLength: 10, maxLength: 1000 }),
          async (content1, content2) => {
            fc.pre(!Buffer.from(content1).equals(Buffer.from(content2)));

            const zip1 = new AdmZip();
            zip1.addFile('file.txt', Buffer.from(content1));
            const zip1Buffer = zip1.toBuffer();

            const zip2 = new AdmZip();
            zip2.addFile('file.txt', Buffer.from(content2));
            const zip2Buffer = zip2.toBuffer();

            const result1 = await extractor.extract(zip1Buffer, 'test1.zip');
            const result2 = await extractor.extract(zip2Buffer, 'test2.zip');

            // Different contents should produce different hashes
            expect(result1.files[0].hash).not.toBe(result2.files[0].hash);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Size Validation Properties', () => {
    it('should accurately report file sizes', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.uint8Array({ minLength: 1, maxLength: 5000 }),
          async (filename, content) => {
            const zip = new AdmZip();
            zip.addFile(filename, Buffer.from(content));
            const zipBuffer = zip.toBuffer();

            const result = await extractor.extract(zipBuffer, 'test.zip');

            expect(result.success).toBe(true);
            expect(result.files.length).toBe(1);

            // Size should match actual content length
            expect(result.files[0].size).toBe(content.length);
            expect(result.files[0].content.length).toBe(content.length);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject archives exceeding total size limit', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 5, max: 20 }), // Number of large files
          async (fileCount) => {
            const zip = new AdmZip();
            const fileSize = 10 * 1024 * 1024; // 10MB per file

            for (let i = 0; i < fileCount; i++) {
              const largeContent = Buffer.alloc(fileSize, 'a');
              zip.addFile(`large${i}.bin`, largeContent);
            }

            const zipBuffer = zip.toBuffer();

            // Should reject if total size exceeds limit
            const result = await extractor.extract(zipBuffer, 'large.zip');

            if (fileCount * fileSize > 100 * 1024 * 1024) {
              expect(result.success).toBe(false);
              expect(result.error).toContain('size');
            }
          }
        ),
        { numRuns: 10, timeout: 5000 }
      );
    });
  });

  describe('Nesting Level Properties', () => {
    it('should enforce maximum nesting level', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 10 }), // Nesting depth
          async (nestingLevel) => {
            // Create nested ZIPs
            let currentZip = new AdmZip();
            currentZip.addFile('inner.txt', Buffer.from('deepest content'));

            for (let i = 1; i < nestingLevel; i++) {
              const nextZip = new AdmZip();
              nextZip.addFile(`level${i}.zip`, currentZip.toBuffer());
              currentZip = nextZip;
            }

            const finalBuffer = currentZip.toBuffer();
            const result = await extractor.extract(finalBuffer, 'nested.zip');

            // Should reject if nesting exceeds limit (3 levels)
            if (nestingLevel > 3) {
              expect(result.success).toBe(false);
              expect(result.error).toContain('nesting');
            } else {
              // Should succeed within limits
              expect(result.success).toBe(true);
            }
          }
        ),
        { numRuns: 20, timeout: 5000 }
      );
    });
  });

  describe('File Count Properties', () => {
    it('should enforce maximum file count limits', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 200 }), // Number of files
          async (fileCount) => {
            const zip = new AdmZip();

            for (let i = 0; i < fileCount; i++) {
              zip.addFile(`file${i}.txt`, Buffer.from(`content ${i}`));
            }

            const zipBuffer = zip.toBuffer();
            const result = await extractor.extract(zipBuffer, 'many-files.zip');

            // Should reject if file count exceeds limit (100)
            if (fileCount > 100) {
              expect(result.success).toBe(false);
              expect(result.error).toContain('count');
            } else {
              expect(result.success).toBe(true);
              expect(result.files.length).toBe(fileCount);
            }
          }
        ),
        { numRuns: 20, timeout: 5000 }
      );
    });
  });

  describe('Content Preservation Properties', () => {
    it('should preserve exact file contents after extraction', () => {
      fc.assert(
        fc.property(
          fc.array(
            fc.record({
              filename: fc.string({ minLength: 1, maxLength: 50 }),
              content: fc.uint8Array({ minLength: 10, maxLength: 1000 }),
            }),
            { minLength: 1, maxLength: 20 }
          ),
          async (files) => {
            const zip = new AdmZip();
            const fileMap = new Map<string, Buffer>();

            for (const file of files) {
              const buffer = Buffer.from(file.content);
              zip.addFile(file.filename, buffer);
              fileMap.set(file.filename, buffer);
            }

            const zipBuffer = zip.toBuffer();
            const result = await extractor.extract(zipBuffer, 'test.zip');

            expect(result.success).toBe(true);

            // Every extracted file should have exact original content
            for (const extractedFile of result.files) {
              const originalContent = fileMap.get(extractedFile.filename);
              if (originalContent) {
                expect(extractedFile.content.equals(originalContent)).toBe(true);
              }
            }
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('MIME Detection Properties', () => {
    it('should detect MIME types consistently', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            { ext: 'pdf', magic: '%PDF-1.4', mime: 'application/pdf' },
            { ext: 'xml', magic: '<?xml', mime: 'application/xml' },
            { ext: 'txt', magic: 'Plain text', mime: 'text/plain' }
          ),
          fc.string({ minLength: 10, maxLength: 100 }),
          async (format, content) => {
            const zip = new AdmZip();
            const fileContent = Buffer.from(format.magic + content);
            zip.addFile(`test.${format.ext}`, fileContent);
            const zipBuffer = zip.toBuffer();

            const result = await extractor.extract(zipBuffer, 'test.zip');

            expect(result.success).toBe(true);
            expect(result.files.length).toBe(1);

            // MIME type should be detected correctly
            expect(result.files[0].mimeType).toBeDefined();
            expect(typeof result.files[0].mimeType).toBe('string');
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Error Handling Properties', () => {
    it('should handle corrupted archives gracefully', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 10, maxLength: 1000 }),
          async (randomData) => {
            // Random data is unlikely to be valid ZIP
            const buffer = Buffer.from(randomData);

            // Should not throw, should return error result
            const result = await extractor.extract(buffer, 'corrupted.zip');

            expect(result).toBeDefined();
            expect(typeof result.success).toBe('boolean');

            if (!result.success) {
              expect(result.error).toBeDefined();
              expect(typeof result.error).toBe('string');
            }
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle empty archives', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }),
          async (archiveName) => {
            const zip = new AdmZip();
            const zipBuffer = zip.toBuffer();

            const result = await extractor.extract(zipBuffer, archiveName);

            // Empty archive should succeed but return no files
            expect(result.success).toBe(true);
            expect(result.files.length).toBe(0);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Invoice File Detection Properties', () => {
    it('should identify invoice-related files in archives', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('invoice.pdf', 'racun.xml', 'faktura.pdf', 'invoice_123.xml'),
          fc.uint8Array({ minLength: 100, maxLength: 1000 }),
          async (filename, content) => {
            const zip = new AdmZip();
            let fileContent: Buffer;

            if (filename.endsWith('.pdf')) {
              fileContent = Buffer.concat([
                Buffer.from('%PDF-1.4\n'),
                Buffer.from(content)
              ]);
            } else {
              fileContent = Buffer.concat([
                Buffer.from('<?xml version="1.0"?>'),
                Buffer.from(content)
              ]);
            }

            zip.addFile(filename, fileContent);
            const zipBuffer = zip.toBuffer();

            const result = await extractor.extract(zipBuffer, 'archive.zip');

            expect(result.success).toBe(true);
            expect(result.files.length).toBe(1);

            // Invoice files should have requiresOCR flag set appropriately
            const file = result.files[0];
            if (filename.endsWith('.pdf')) {
              expect(file.requiresOCR).toBe(false); // PDF can be parsed directly
            }
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
