/**
 * Unit Tests for Attachment Handler
 */

import { AttachmentHandler } from '../../src/attachment-handler';
import { VirusScanner } from '../../src/virus-scanner';

describe('AttachmentHandler', () => {
  let handler: AttachmentHandler;

  beforeEach(() => {
    handler = new AttachmentHandler({
      maxFileSize: 5 * 1024 * 1024,
      maxFiles: 50,
      enableVirusScan: false // Disable for faster tests
    });
  });

  describe('processAttachment', () => {
    it('should process a single PDF file', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4\nMock PDF content');
      const result = await handler.processAttachment(pdfBuffer, 'invoice.pdf');

      expect(result.success).toBe(true);
      expect(result.files).toHaveLength(1);
      expect(result.files[0].filename).toBe('invoice.pdf');
      expect(result.files[0].mimeType).toContain('pdf');
    });

    it('should process a single XML file', async () => {
      const xmlBuffer = Buffer.from('<?xml version="1.0"?><invoice></invoice>');
      const result = await handler.processAttachment(xmlBuffer, 'invoice.xml');

      expect(result.success).toBe(true);
      expect(result.files).toHaveLength(1);
      expect(result.files[0].mimeType).toContain('xml');
    });

    it('should process an empty ZIP archive', async () => {
      // Minimal empty ZIP file
      const zipBuffer = Buffer.from([
        0x50, 0x4B, 0x05, 0x06, // End of central directory signature
        0x00, 0x00, 0x00, 0x00, // Disk numbers
        0x00, 0x00, 0x00, 0x00, // Central directory records
        0x00, 0x00, 0x00, 0x00, // Size and offset
        0x00, 0x00              // Comment length
      ]);

      const result = await handler.processAttachment(zipBuffer, 'archive.zip');

      expect(result.files).toHaveLength(0);
      expect(result.metadata.archives).toBe(0);
    });

    it('should reject empty file', async () => {
      const emptyBuffer = Buffer.from([]);
      const result = await handler.processAttachment(emptyBuffer, 'empty.pdf');

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some(err => err.toLowerCase().includes('empty'))).toBe(true);
    });

    it('should handle processing errors gracefully', async () => {
      const invalidBuffer = Buffer.from('invalid data');
      const result = await handler.processAttachment(invalidBuffer, '');

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('createMetadata', () => {
    it('should create metadata for PDF file', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4\nContent');
      const metadata = await handler.createMetadata(pdfBuffer, 'test.pdf');

      expect(metadata.filename).toBe('test.pdf');
      expect(metadata.size).toBe(pdfBuffer.length);
      expect(metadata.hash).toBeDefined();
      expect(metadata.hash.length).toBe(64); // SHA-256 hex string
      expect(metadata.isArchive).toBe(false);
    });

    it('should create metadata for ZIP file', async () => {
      const zipBuffer = Buffer.from([0x50, 0x4B, 0x03, 0x04]);
      const metadata = await handler.createMetadata(zipBuffer, 'test.zip');

      expect(metadata.mimeType).toContain('zip');
      expect(metadata.isArchive).toBe(true);
    });

    it('should include virus scan result', async () => {
      const buffer = Buffer.from('test content');
      const metadata = await handler.createMetadata(buffer, 'test.txt');

      expect(metadata.virusScanResult).toBeDefined();
      expect(metadata.virusScanResult?.scanner).toBeDefined();
    });
  });

  describe('validateFile', () => {
    it('should validate a good file', async () => {
      const buffer = Buffer.from('%PDF-1.4\nContent');
      const metadata = await handler.createMetadata(buffer, 'test.pdf');
      const validation = await handler.validateFile(buffer, 'test.pdf', metadata);

      expect(validation.valid).toBe(true);
      expect(validation.errors.length).toBe(0);
    });

    it('should reject empty buffer', async () => {
      const buffer = Buffer.from([]);
      const metadata = await handler.createMetadata(buffer, 'test.pdf');
      const validation = await handler.validateFile(buffer, 'test.pdf', metadata);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContainEqual(
        expect.objectContaining({
          code: 'EMPTY_FILE',
          fatal: true
        })
      );
    });

    it('should reject invalid filename', async () => {
      const buffer = Buffer.from('content');
      const metadata = await handler.createMetadata(buffer, '');
      const validation = await handler.validateFile(buffer, '', metadata);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContainEqual(
        expect.objectContaining({
          code: 'INVALID_FILENAME'
        })
      );
    });

    it('should warn about suspicious filenames', async () => {
      const buffer = Buffer.from('content');
      const metadata = await handler.createMetadata(buffer, 'malware.exe');
      const validation = await handler.validateFile(buffer, 'malware.exe', metadata);

      expect(validation.warnings).toContainEqual(
        expect.objectContaining({
          code: 'SUSPICIOUS_FILENAME'
        })
      );
    });
  });

  describe('healthCheck', () => {
    it('should return health status', async () => {
      const health = await handler.healthCheck();

      expect(typeof health).toBe('boolean');
    });
  });
});
