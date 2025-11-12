/**
 * Attachment Extractor Module
 *
 * Parses MIME emails and extracts invoice attachments.
 * - MIME parsing with mailparser
 * - Attachment filtering (PDF, XML, images)
 * - Metadata extraction
 * - Content type validation
 */

import { simpleParser, ParsedMail, Attachment } from 'mailparser';
import { Readable } from 'stream';
import { v4 as uuidv4 } from 'uuid';
import {
  logger,
  attachmentsExtractedTotal,
  emailProcessingDuration,
  withSpan,
} from './observability';

/**
 * Extracted attachment with metadata
 */
export interface ExtractedAttachment {
  /** Unique attachment ID */
  id: string;
  /** Original filename */
  filename: string;
  /** MIME content type */
  contentType: string;
  /** File size in bytes */
  size: number;
  /** Attachment content as Buffer */
  content: Buffer;
  /** Checksum (SHA-256) */
  checksum: string;
  /** Content ID (for inline attachments) */
  contentId?: string;
}

/**
 * Parsed email with metadata and attachments
 */
export interface ParsedEmail {
  /** Email unique identifier */
  messageId: string;
  /** Email subject */
  subject: string;
  /** Sender email address */
  from: string;
  /** Recipient email addresses */
  to: string[];
  /** CC email addresses */
  cc: string[];
  /** Email date */
  date: Date;
  /** Plain text body */
  textBody?: string;
  /** HTML body */
  htmlBody?: string;
  /** Extracted attachments */
  attachments: ExtractedAttachment[];
  /** Email headers */
  headers: Map<string, string>;
}

/**
 * Attachment filtering options
 */
export interface AttachmentFilterOptions {
  /** Allowed MIME types (if empty, allow all) */
  allowedMimeTypes: string[];
  /** Maximum file size in bytes */
  maxFileSize: number;
  /** Minimum file size in bytes */
  minFileSize: number;
}

/**
 * Default filter options for invoice attachments
 */
const DEFAULT_FILTER_OPTIONS: AttachmentFilterOptions = {
  allowedMimeTypes: [
    'application/pdf',
    'application/xml',
    'text/xml',
    'application/vnd.oasis.opendocument.text',
    'image/png',
    'image/jpeg',
    'image/jpg',
  ],
  maxFileSize: 10 * 1024 * 1024, // 10 MB
  minFileSize: 100, // 100 bytes
};

/**
 * Attachment Extractor
 */
export class AttachmentExtractor {
  private filterOptions: AttachmentFilterOptions;

  constructor(filterOptions: AttachmentFilterOptions = DEFAULT_FILTER_OPTIONS) {
    this.filterOptions = filterOptions;
  }

  /**
   * Parse email from stream
   */
  async parseEmail(emailStream: Readable): Promise<ParsedEmail> {
    const endTimer = emailProcessingDuration.startTimer({ operation: 'parse' });

    try {
      return await withSpan(
        'attachment.parseEmail',
        {},
        async (span) => {
          logger.debug('Parsing email');

          const parsed = await simpleParser(emailStream);

          const parsedEmail = this.convertToParseEmail(parsed);
          span.setAttribute('attachment_count', parsedEmail.attachments.length);

          logger.info(
            {
              messageId: parsedEmail.messageId,
              subject: parsedEmail.subject,
              from: parsedEmail.from,
              attachments: parsedEmail.attachments.length,
            },
            'Email parsed successfully'
          );

          return parsedEmail;
        }
      );
    } catch (err) {
      logger.error({ err }, 'Failed to parse email');
      throw err;
    } finally {
      endTimer();
    }
  }

  /**
   * Convert mailparser ParsedMail to ParsedEmail
   */
  private convertToParseEmail(parsed: ParsedMail): ParsedEmail {
    const from = parsed.from?.value?.[0]?.address || parsed.from?.text || 'unknown';

    // Handle 'to' field - extract addresses from AddressObject
    const toValue = parsed.to as any;
    const to: string[] = toValue?.value
      ? (Array.isArray(toValue.value) ? toValue.value : [toValue.value]).map((addr: any) => addr.address || '')
      : [];

    // Handle 'cc' field - extract addresses from AddressObject
    const ccValue = parsed.cc as any;
    const cc: string[] = ccValue?.value
      ? (Array.isArray(ccValue.value) ? ccValue.value : [ccValue.value]).map((addr: any) => addr.address || '')
      : [];

    const headers = new Map<string, string>();
    if (parsed.headers) {
      for (const [key, value] of parsed.headers) {
        headers.set(key, String(value));
      }
    }

    return {
      messageId: parsed.messageId || uuidv4(),
      subject: parsed.subject || '(no subject)',
      from,
      to,
      cc,
      date: parsed.date || new Date(),
      textBody: parsed.text,
      htmlBody: parsed.html !== false ? String(parsed.html || '') : undefined,
      attachments: this.extractAttachments(parsed.attachments || []),
      headers,
    };
  }

  /**
   * Extract and filter attachments
   */
  private extractAttachments(attachments: Attachment[]): ExtractedAttachment[] {
    const extracted: ExtractedAttachment[] = [];

    for (const attachment of attachments) {
      try {
        // Validate attachment
        if (!this.isValidAttachment(attachment)) {
          logger.debug(
            {
              filename: attachment.filename,
              contentType: attachment.contentType,
              size: attachment.size,
            },
            'Skipping invalid attachment'
          );
          continue;
        }

        // Extract attachment
        const extractedAttachment = this.convertToExtractedAttachment(attachment);
        extracted.push(extractedAttachment);

        attachmentsExtractedTotal.inc({
          content_type: extractedAttachment.contentType,
          status: 'success',
        });

        logger.info(
          {
            id: extractedAttachment.id,
            filename: extractedAttachment.filename,
            contentType: extractedAttachment.contentType,
            size: extractedAttachment.size,
          },
          'Attachment extracted'
        );
      } catch (err) {
        logger.error(
          { err, filename: attachment.filename },
          'Failed to extract attachment'
        );
        attachmentsExtractedTotal.inc({
          content_type: attachment.contentType || 'unknown',
          status: 'error',
        });
      }
    }

    return extracted;
  }

  /**
   * Validate attachment against filter options
   */
  private isValidAttachment(attachment: Attachment): boolean {
    // Check if attachment has content
    if (!attachment.content || attachment.size === 0) {
      return false;
    }

    // Check file size
    if (attachment.size > this.filterOptions.maxFileSize) {
      logger.warn(
        {
          filename: attachment.filename,
          size: attachment.size,
          maxSize: this.filterOptions.maxFileSize,
        },
        'Attachment exceeds maximum file size'
      );
      return false;
    }

    if (attachment.size < this.filterOptions.minFileSize) {
      return false;
    }

    // Check MIME type (if filter is configured)
    if (
      this.filterOptions.allowedMimeTypes.length > 0 &&
      !this.filterOptions.allowedMimeTypes.includes(attachment.contentType)
    ) {
      logger.debug(
        {
          filename: attachment.filename,
          contentType: attachment.contentType,
          allowedTypes: this.filterOptions.allowedMimeTypes,
        },
        'Attachment MIME type not allowed'
      );
      return false;
    }

    return true;
  }

  /**
   * Convert mailparser Attachment to ExtractedAttachment
   */
  private convertToExtractedAttachment(attachment: Attachment): ExtractedAttachment {
    const id = uuidv4();
    const checksum = this.calculateChecksum(attachment.content);

    return {
      id,
      filename: attachment.filename || `attachment-${id}`,
      contentType: attachment.contentType,
      size: attachment.size,
      content: attachment.content,
      checksum,
      contentId: attachment.contentId,
    };
  }

  /**
   * Calculate SHA-256 checksum of buffer
   */
  private calculateChecksum(buffer: Buffer): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }

  /**
   * Get current filter options
   */
  getFilterOptions(): AttachmentFilterOptions {
    return { ...this.filterOptions };
  }

  /**
   * Update filter options
   */
  setFilterOptions(options: Partial<AttachmentFilterOptions>): void {
    this.filterOptions = {
      ...this.filterOptions,
      ...options,
    };
    logger.info({ filterOptions: this.filterOptions }, 'Filter options updated');
  }
}

/**
 * Create attachment extractor from environment variables
 */
export function createAttachmentExtractorFromEnv(): AttachmentExtractor {
  const allowedMimeTypes = process.env.ALLOWED_MIME_TYPES
    ? process.env.ALLOWED_MIME_TYPES.split(',').map((type) => type.trim())
    : DEFAULT_FILTER_OPTIONS.allowedMimeTypes;

  const maxFileSize = process.env.MAX_FILE_SIZE
    ? parseInt(process.env.MAX_FILE_SIZE, 10)
    : DEFAULT_FILTER_OPTIONS.maxFileSize;

  const minFileSize = process.env.MIN_FILE_SIZE
    ? parseInt(process.env.MIN_FILE_SIZE, 10)
    : DEFAULT_FILTER_OPTIONS.minFileSize;

  const options: AttachmentFilterOptions = {
    allowedMimeTypes,
    maxFileSize,
    minFileSize,
  };

  logger.info({ filterOptions: options }, 'Creating attachment extractor');

  return new AttachmentExtractor(options);
}
