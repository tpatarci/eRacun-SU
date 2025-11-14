/**
 * Unit Tests for File Processor
 */

import { FileProcessor } from '../../src/file-processor';
import { DownloadResult } from '../../src/types';

describe('FileProcessor', () => {
  let processor: FileProcessor;

  beforeEach(() => {
    processor = new FileProcessor('sftp.example.com');
  });

  describe('processDownload', () => {
    it('should process a successful download', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4\nTest PDF');

      const download: DownloadResult = {
        success: true,
        file: {
          name: 'invoice.pdf',
          path: '/invoices/invoice.pdf',
          size: pdfBuffer.length,
          modifyTime: new Date(),
          type: 'file'
        },
        buffer: pdfBuffer,
        downloadTime: 100
      };

      const message = await processor.processDownload(download);

      expect(message).not.toBeNull();
      expect(message?.filename).toBe('invoice.pdf');
      expect(message?.mimeType).toContain('pdf');
      expect(message?.size).toBe(pdfBuffer.length);
      expect(message?.checksum).toBeDefined();
      expect(message?.content).toBeDefined();
    });

    it('should return null for failed download', async () => {
      const download: DownloadResult = {
        success: false,
        file: {
          name: 'invoice.pdf',
          path: '/invoices/invoice.pdf',
          size: 0,
          modifyTime: new Date(),
          type: 'file'
        },
        error: 'Connection timeout',
        downloadTime: 5000
      };

      const message = await processor.processDownload(download);

      expect(message).toBeNull();
    });

    it('should detect PDF MIME type', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4\nTest PDF');

      const download: DownloadResult = {
        success: true,
        file: {
          name: 'document.pdf',
          path: '/invoices/document.pdf',
          size: pdfBuffer.length,
          modifyTime: new Date(),
          type: 'file'
        },
        buffer: pdfBuffer,
        downloadTime: 100
      };

      const message = await processor.processDownload(download);

      expect(message?.mimeType).toBe('application/pdf');
    });

    it('should calculate checksum', async () => {
      const buffer = Buffer.from('test content');

      const download: DownloadResult = {
        success: true,
        file: {
          name: 'test.txt',
          path: '/test.txt',
          size: buffer.length,
          modifyTime: new Date(),
          type: 'file'
        },
        buffer,
        downloadTime: 10
      };

      const message = await processor.processDownload(download);

      expect(message?.checksum).toHaveLength(64); // SHA-256 hex length
    });
  });
});
