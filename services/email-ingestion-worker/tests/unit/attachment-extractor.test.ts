/**
 * Attachment Extractor Module Tests
 */

import { Readable } from 'stream';
import { AttachmentExtractor } from '../../src/attachment-extractor';

describe('AttachmentExtractor', () => {
  let extractor: AttachmentExtractor;

  beforeEach(() => {
    extractor = new AttachmentExtractor({
      allowedMimeTypes: ['application/pdf', 'application/xml', 'text/xml'],
      maxFileSize: 10 * 1024 * 1024,
      minFileSize: 100,
    });
  });

  describe('parseEmail', () => {
    it('should parse simple email without attachments', async () => {
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>

This is a test email body.`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.messageId).toBe('<test@example.com>');
      expect(parsed.subject).toBe('Test Email');
      expect(parsed.from).toBe('sender@example.com');
      expect(parsed.to).toContain('recipient@example.com');
      expect(parsed.attachments).toHaveLength(0);
    });

    it('should parse email with PDF attachment', async () => {
      const boundary = 'boundary123';
      const pdfContent = Buffer.from('%PDF-1.4\ntest pdf content');
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Invoice Email
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/plain

Email body text.

--${boundary}
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

${pdfContent.toString('base64')}
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('invoice.pdf');
      expect(parsed.attachments[0].contentType).toBe('application/pdf');
      expect(parsed.attachments[0].size).toBeGreaterThan(0);
      expect(parsed.attachments[0].checksum).toBeDefined();
      expect(parsed.attachments[0].id).toBeDefined();
    });

    it('should parse email with XML attachment', async () => {
      const boundary = 'boundary456';
      const xmlContent = '<?xml version="1.0"?><invoice><total>100</total></invoice>';
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Invoice XML
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/plain

Email body text.

--${boundary}
Content-Type: application/xml; name="invoice.xml"
Content-Disposition: attachment; filename="invoice.xml"

${xmlContent}
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('invoice.xml');
      expect(parsed.attachments[0].contentType).toBe('application/xml');
    });

    it('should filter out attachments with disallowed MIME types', async () => {
      const boundary = 'boundary789';
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Mixed Attachments
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/plain

Email body text.

--${boundary}
Content-Type: application/zip; name="archive.zip"
Content-Disposition: attachment; filename="archive.zip"
Content-Transfer-Encoding: base64

UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      // ZIP file should be filtered out
      expect(parsed.attachments).toHaveLength(0);
    });

    it('should filter out attachments exceeding max file size', async () => {
      const smallExtractor = new AttachmentExtractor({
        allowedMimeTypes: ['application/pdf'],
        maxFileSize: 100, // Very small limit
        minFileSize: 10,
      });

      const boundary = 'boundary-size';
      const largeContent = Buffer.alloc(200, 'x'); // 200 bytes
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Large File
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: application/pdf; name="large.pdf"
Content-Disposition: attachment; filename="large.pdf"
Content-Transfer-Encoding: base64

${largeContent.toString('base64')}
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await smallExtractor.parseEmail(stream);

      // Large file should be filtered out
      expect(parsed.attachments).toHaveLength(0);
    });

    it('should filter out attachments below min file size', async () => {
      const boundary = 'boundary-small';
      const tinyContent = 'x'; // Very small content
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Tiny File
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: application/pdf; name="tiny.pdf"
Content-Disposition: attachment; filename="tiny.pdf"

${tinyContent}
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      // Tiny file should be filtered out
      expect(parsed.attachments).toHaveLength(0);
    });

    it('should handle email with multiple valid attachments', async () => {
      const boundary = 'boundary-multi';
      const pdf = Buffer.from('%PDF-1.4\ntest');
      const xml = '<?xml version="1.0"?><root></root>';
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Multiple Attachments
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: application/pdf; name="file1.pdf"
Content-Disposition: attachment; filename="file1.pdf"
Content-Transfer-Encoding: base64

${pdf.toString('base64')}
--${boundary}
Content-Type: application/xml; name="file2.xml"
Content-Disposition: attachment; filename="file2.xml"

${xml}
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.attachments).toHaveLength(2);
      expect(parsed.attachments[0].filename).toBe('file1.pdf');
      expect(parsed.attachments[1].filename).toBe('file2.xml');
    });

    it('should handle email without message ID', async () => {
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: No Message ID

Test body.`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.messageId).toBeDefined();
      expect(parsed.messageId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      );
    });

    it('should handle email without subject', async () => {
      const emailContent = `From: sender@example.com
To: recipient@example.com

Test body.`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.subject).toBe('(no subject)');
    });

    it('should extract CC recipients', async () => {
      const emailContent = `From: sender@example.com
To: recipient@example.com
Cc: cc1@example.com, cc2@example.com
Subject: CC Test

Test body.`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.cc).toHaveLength(2);
      expect(parsed.cc).toContain('cc1@example.com');
      expect(parsed.cc).toContain('cc2@example.com');
    });

    it('should extract text and HTML bodies', async () => {
      const boundary = 'alt-boundary';
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Alternative Bodies
Content-Type: multipart/alternative; boundary="${boundary}"

--${boundary}
Content-Type: text/plain

Plain text body

--${boundary}
Content-Type: text/html

<html><body>HTML body</body></html>

--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.textBody).toContain('Plain text body');
      expect(parsed.htmlBody).toContain('HTML body');
    });
  });

  describe('Filter Options', () => {
    it('should get current filter options', () => {
      const options = extractor.getFilterOptions();

      expect(options.allowedMimeTypes).toContain('application/pdf');
      expect(options.maxFileSize).toBe(10 * 1024 * 1024);
      expect(options.minFileSize).toBe(100);
    });

    it('should update filter options', () => {
      extractor.setFilterOptions({
        maxFileSize: 5 * 1024 * 1024,
      });

      const options = extractor.getFilterOptions();
      expect(options.maxFileSize).toBe(5 * 1024 * 1024);
    });

    it('should allow all MIME types when filter is empty', async () => {
      const permissiveExtractor = new AttachmentExtractor({
        allowedMimeTypes: [], // Empty = allow all
        maxFileSize: 10 * 1024 * 1024,
        minFileSize: 100,
      });

      const boundary = 'any-type';
      const content = Buffer.alloc(200, 'x');
      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Any Type
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: application/vnd.custom; name="custom.dat"
Content-Disposition: attachment; filename="custom.dat"
Content-Transfer-Encoding: base64

${content.toString('base64')}
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await permissiveExtractor.parseEmail(stream);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].contentType).toBe('application/vnd.custom');
    });
  });

  describe('Checksum Calculation', () => {
    it('should calculate different checksums for different content', async () => {
      const boundary = 'checksum-test';
      const content1 = Buffer.from('content1');
      const content2 = Buffer.from('content2');

      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Checksum Test
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: application/pdf; name="file1.pdf"
Content-Disposition: attachment; filename="file1.pdf"
Content-Transfer-Encoding: base64

${content1.toString('base64')}
--${boundary}
Content-Type: application/pdf; name="file2.pdf"
Content-Disposition: attachment; filename="file2.pdf"
Content-Transfer-Encoding: base64

${content2.toString('base64')}
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.attachments).toHaveLength(2);
      expect(parsed.attachments[0].checksum).not.toBe(parsed.attachments[1].checksum);
    });

    it('should calculate same checksum for identical content', async () => {
      const boundary = 'same-checksum';
      const content = Buffer.from('identical content');

      const emailContent = `From: sender@example.com
To: recipient@example.com
Subject: Same Checksum
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: application/pdf; name="file1.pdf"
Content-Disposition: attachment; filename="file1.pdf"
Content-Transfer-Encoding: base64

${content.toString('base64')}
--${boundary}
Content-Type: application/pdf; name="file2.pdf"
Content-Disposition: attachment; filename="file2.pdf"
Content-Transfer-Encoding: base64

${content.toString('base64')}
--${boundary}--`;

      const stream = Readable.from([emailContent]);
      const parsed = await extractor.parseEmail(stream);

      expect(parsed.attachments).toHaveLength(2);
      expect(parsed.attachments[0].checksum).toBe(parsed.attachments[1].checksum);
    });
  });
});
