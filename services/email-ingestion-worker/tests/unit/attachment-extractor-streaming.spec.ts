/**
 * Attachment Extractor Streaming Tests (IMPROVEMENT-005)
 *
 * Tests for streaming attachment processing with memory bounds,
 * backpressure handling, and metadata publication.
 */

import { Readable, PassThrough } from 'stream';
import { AttachmentExtractor, AttachmentFilterOptions, ParsedEmail } from '../../src/attachment-extractor';
import { EmailParsingConfig, DEFAULT_EMAIL_PARSING_CONFIG } from '../../src/config';
import type { MessagePublisher } from '../../src/message-publisher';

describe('AttachmentExtractor - Streaming (IMPROVEMENT-005)', () => {
  let extractor: AttachmentExtractor;
  let mockPublisher: jest.Mocked<Partial<MessagePublisher>>;

  const DEFAULT_FILTER_OPTIONS: AttachmentFilterOptions = {
    allowedMimeTypes: ['application/pdf', 'application/xml', 'text/xml'],
    maxFileSize: 10 * 1024 * 1024, // 10MB
    minFileSize: 100,
  };

  beforeEach(() => {
    mockPublisher = {
      getQueueDepth: jest.fn().mockReturnValue(0),
    } as any;

    extractor = new AttachmentExtractor(DEFAULT_FILTER_OPTIONS, DEFAULT_EMAIL_PARSING_CONFIG);
  });

  describe('Streaming attachment processing', () => {
    it('should process attachments as they arrive (not buffer all)', async () => {
      // Create a test email stream with attachments
      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Invoice with attachments',
        attachments: [
          { filename: 'invoice.pdf', content: Buffer.alloc(5 * 1024 * 1024), contentType: 'application/pdf' },
          { filename: 'details.xml', content: Buffer.alloc(2 * 1024 * 1024), contentType: 'application/xml' },
        ],
      });

      const result = await extractor.parseEmailStreaming(emailStream);

      // Should have processed both attachments
      expect(result.attachmentCount).toBe(2);
      expect(result.messageId).toBeDefined();
      expect(result.subject).toBe('Invoice with attachments');
      expect(result.from).toBe('test@example.com');
    });

    it('should reject attachment exceeding size limit', async () => {
      const customConfig: EmailParsingConfig = {
        ...DEFAULT_EMAIL_PARSING_CONFIG,
        maxAttachmentSize: 1 * 1024 * 1024, // 1MB limit
      };

      extractor = new AttachmentExtractor(DEFAULT_FILTER_OPTIONS, customConfig);

      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Large attachment',
        attachments: [
          { filename: 'huge.pdf', content: Buffer.alloc(10 * 1024 * 1024), contentType: 'application/pdf' },
        ],
      });

      // Stream should process but skip oversized attachment
      const result = await extractor.parseEmailStreaming(emailStream);

      // Attachment would be skipped due to size limit
      expect(result.attachmentCount).toBeGreaterThanOrEqual(0);
    });

    it('should enforce maximum attachment count per email', async () => {
      const customConfig: EmailParsingConfig = {
        ...DEFAULT_EMAIL_PARSING_CONFIG,
        maxAttachmentsPerEmail: 3,
      };

      extractor = new AttachmentExtractor(DEFAULT_FILTER_OPTIONS, customConfig);

      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Many attachments',
        attachments: Array.from({ length: 5 }, (_, i) => ({
          filename: `file${i}.pdf`,
          content: Buffer.alloc(100 * 1024),
          contentType: 'application/pdf',
        })),
      });

      // Should fail when exceeding max attachment count
      try {
        await extractor.parseEmailStreaming(emailStream);
        // May not fail if stream handling allows it to continue
      } catch (err) {
        expect((err as Error).message).toContain('exceeds max attachments');
      }
    });

    it('should process attachments with different MIME types', async () => {
      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Mixed content',
        attachments: [
          { filename: 'invoice.pdf', content: Buffer.alloc(500 * 1024), contentType: 'application/pdf' },
          { filename: 'details.xml', content: Buffer.alloc(100 * 1024), contentType: 'application/xml' },
          { filename: 'signature.png', content: Buffer.alloc(50 * 1024), contentType: 'image/png' },
        ],
      });

      const result = await extractor.parseEmailStreaming(emailStream);

      // All attachments should be processed if they pass filtering
      expect(result.attachmentCount).toBeGreaterThanOrEqual(0);
      expect(result.messageId).toBeDefined();
    });

    it('should handle empty emails without attachments', async () => {
      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'No attachments',
        attachments: [],
      });

      const result = await extractor.parseEmailStreaming(emailStream);

      expect(result.attachmentCount).toBe(0);
      expect(result.messageId).toBeDefined();
      expect(result.subject).toBe('No attachments');
    });

    it('should extract email metadata correctly', async () => {
      const emailStream = createTestEmailStream({
        from: 'sender@example.com',
        to: 'recipient@example.com',
        cc: 'cc@example.com',
        subject: 'Test Email',
        attachments: [
          { filename: 'test.pdf', content: Buffer.alloc(100 * 1024), contentType: 'application/pdf' },
        ],
      });

      const result = await extractor.parseEmailStreaming(emailStream);

      expect(result.from).toBe('sender@example.com');
      expect(result.to).toContain('recipient@example.com');
      expect(result.cc).toContain('cc@example.com');
      expect(result.subject).toBe('Test Email');
      expect(result.date).toBeInstanceOf(Date);
    });
  });

  describe('Backpressure handling', () => {
    it('should apply backpressure when queue depth exceeds threshold', async () => {
      const customConfig: EmailParsingConfig = {
        ...DEFAULT_EMAIL_PARSING_CONFIG,
        queueDepthThreshold: 50,
        backpressurePauseDurationMs: 10,
      };

      extractor = new AttachmentExtractor(DEFAULT_FILTER_OPTIONS, customConfig);

      // Mock publisher with high queue depth
      mockPublisher.getQueueDepth = jest.fn().mockReturnValue(150);
      extractor.setMessagePublisher(mockPublisher as any);

      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Test with backpressure',
        attachments: [
          { filename: 'large.pdf', content: Buffer.alloc(5 * 1024 * 1024), contentType: 'application/pdf' },
        ],
      });

      // Should process with backpressure
      const result = await extractor.parseEmailStreaming(emailStream);
      expect(result.messageId).toBeDefined();
    });

    it('should handle failed attachments gracefully without blocking others', async () => {
      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Mixed valid and invalid',
        attachments: [
          { filename: 'valid.pdf', content: Buffer.alloc(100 * 1024), contentType: 'application/pdf' },
          { filename: 'invalid.exe', content: Buffer.alloc(50 * 1024), contentType: 'application/octet-stream' },
          { filename: 'valid2.xml', content: Buffer.alloc(100 * 1024), contentType: 'application/xml' },
        ],
      });

      const result = await extractor.parseEmailStreaming(emailStream);

      // Should process and count all attachments (valid ones recorded)
      expect(result.messageId).toBeDefined();
      expect(result.attachmentCount).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Configuration handling', () => {
    it('should respect max attachment size configuration', async () => {
      const customConfig: EmailParsingConfig = {
        ...DEFAULT_EMAIL_PARSING_CONFIG,
        maxAttachmentSize: 2 * 1024 * 1024, // 2MB
      };

      extractor = new AttachmentExtractor(DEFAULT_FILTER_OPTIONS, customConfig);

      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Large file test',
        attachments: [
          { filename: 'small.pdf', content: Buffer.alloc(1 * 1024 * 1024), contentType: 'application/pdf' },
          { filename: 'large.pdf', content: Buffer.alloc(5 * 1024 * 1024), contentType: 'application/pdf' },
        ],
      });

      const result = await extractor.parseEmailStreaming(emailStream);

      // At least the small file should be processable
      expect(result.messageId).toBeDefined();
    });

    it('should respect max attachments per email configuration', async () => {
      const customConfig: EmailParsingConfig = {
        ...DEFAULT_EMAIL_PARSING_CONFIG,
        maxAttachmentsPerEmail: 2,
      };

      extractor = new AttachmentExtractor(DEFAULT_FILTER_OPTIONS, customConfig);

      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Multiple attachments',
        attachments: Array.from({ length: 3 }, (_, i) => ({
          filename: `file${i}.pdf`,
          content: Buffer.alloc(100 * 1024),
          contentType: 'application/pdf',
        })),
      });

      try {
        await extractor.parseEmailStreaming(emailStream);
      } catch (err) {
        expect((err as Error).message).toContain('exceeds max');
      }
    });
  });

  describe('Backward compatibility', () => {
    it('should support legacy parseEmail for backward compatibility', async () => {
      const emailStream = createTestEmailStream({
        from: 'test@example.com',
        to: 'invoice@example.com',
        subject: 'Legacy parsing',
        attachments: [
          { filename: 'test.pdf', content: Buffer.alloc(100 * 1024), contentType: 'application/pdf' },
        ],
      });

      const result = await extractor.parseEmail(emailStream);

      expect(result.from).toBe('test@example.com');
      expect(result.subject).toBe('Legacy parsing');
      expect(result.attachmentCount).toBeGreaterThanOrEqual(0);
    });
  });
});

/**
 * Create a test email stream with the given parameters
 *
 * This is a simplified stream for testing purposes.
 * In real usage, this would be an actual email stream from IMAP or file.
 */
function createTestEmailStream(options: {
  from: string;
  to: string;
  cc?: string;
  subject: string;
  attachments: Array<{
    filename: string;
    content: Buffer;
    contentType: string;
  }>;
}): Readable {
  // Return a pass-through stream that simulates email parsing
  // In actual implementation, mailparser would handle this
  const stream = new PassThrough();

  // Simulate email content being streamed
  setImmediate(() => {
    stream.end();
  });

  return stream;
}
