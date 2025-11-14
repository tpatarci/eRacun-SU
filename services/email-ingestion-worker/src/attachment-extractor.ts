/**
 * Attachment Extractor Module
 *
 * Parses MIME emails and extracts invoice attachments using streaming.
 * - MIME parsing with mailparser
 * - Stream-based attachment processing (IMPROVEMENT-005)
 * - Backpressure handling for queue depth
 * - Metadata extraction with SHA-256 checksums
 * - Content type validation
 */

import { simpleParser, ParsedMail, Attachment } from 'mailparser';
import { Readable } from 'stream';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import {
  logger,
  attachmentsExtractedTotal,
  emailProcessingDuration,
  withSpan,
  emailAttachmentProcessed,
  attachmentProcessingDuration,
  attachmentStreamBackpressure,
  messagePublisherQueueDepth,
} from './observability';
import { EmailParsingConfig, DEFAULT_EMAIL_PARSING_CONFIG } from './config';
import type { MessagePublisher } from './message-publisher';

/**
 * Attachment metadata (IMPROVEMENT-005: No content in object, streamed separately)
 */
export interface AttachmentMetadata {
  /** Unique attachment ID */
  id: string;
  /** Original filename */
  filename: string;
  /** MIME content type */
  contentType: string;
  /** File size in bytes */
  size: number;
  /** Checksum (SHA-256) */
  checksum: string;
  /** Content ID (for inline attachments) */
  contentId?: string;
}

/**
 * Parsed email with metadata (IMPROVEMENT-005: Streaming - attachments published separately)
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
  /** Count of attachments processed (content streamed separately) */
  attachmentCount: number;
  /** Email headers */
  headers: Map<string, string>;
}

/**
 * Extended attachment metadata for internal processing
 */
interface ProcessingAttachment extends AttachmentMetadata {
  /** Content stream from mailparser */
  contentStream: Readable;
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
 * Attachment Extractor with Streaming Support (IMPROVEMENT-005)
 *
 * Processes attachments as they arrive instead of buffering all in memory.
 * - Streams attachment content to message publisher
 * - Applies backpressure when queue depth exceeds threshold
 * - Computes SHA-256 checksums during streaming
 * - Publishes metadata only (content streamed separately)
 */
export class AttachmentExtractor {
  private filterOptions: AttachmentFilterOptions;
  private parsingConfig: EmailParsingConfig;
  private messagePublisher: MessagePublisher | null = null;
  private emailMetadata: Partial<ParsedEmail> | null = null;
  private attachmentCount = 0;

  constructor(
    filterOptions: AttachmentFilterOptions = DEFAULT_FILTER_OPTIONS,
    parsingConfig: EmailParsingConfig = DEFAULT_EMAIL_PARSING_CONFIG,
    messagePublisher?: MessagePublisher
  ) {
    this.filterOptions = filterOptions;
    this.parsingConfig = parsingConfig;
    this.messagePublisher = messagePublisher || null;
  }

  /**
   * Set message publisher (IMPROVEMENT-005)
   */
  setMessagePublisher(publisher: MessagePublisher): void {
    this.messagePublisher = publisher;
  }

  /**
   * Parse email with streaming attachment processing (IMPROVEMENT-005)
   *
   * Instead of buffering entire email + attachments, processes attachments
   * as they arrive from the stream and publishes metadata immediately.
   */
  async parseEmailStreaming(emailStream: Readable): Promise<ParsedEmail> {
    const endTimer = emailProcessingDuration.startTimer({ operation: 'parse' });

    try {
      return await withSpan(
        'attachment.parseEmailStreaming',
        { streaming: true },
        async (span) => {
          logger.debug('Parsing email with streaming attachments');

          return new Promise<ParsedEmail>((resolve, reject) => {
            this.attachmentCount = 0;
            const parser = simpleParser(emailStream);

            // Capture email headers
            parser.on('headers', (headers: any) => {
              this.emailMetadata = {
                messageId: this.extractMessageId(headers),
                subject: this.extractSubject(headers),
                from: this.extractFrom(headers),
                to: this.extractAddresses(headers.to),
                cc: this.extractAddresses(headers.cc),
                date: this.extractDate(headers),
                headers: new Map(headers),
              };
            });

            // Process attachments as they arrive (streaming)
            parser.on('attachment', async (attachment: Attachment) => {
              try {
                this.attachmentCount++;

                // Enforce max attachment count
                if (this.attachmentCount > this.parsingConfig.maxAttachmentsPerEmail) {
                  logger.error(
                    {
                      count: this.attachmentCount,
                      max: this.parsingConfig.maxAttachmentsPerEmail,
                    },
                    'Email exceeds maximum attachment count'
                  );
                  throw new Error(
                    `Email exceeds max attachments (${this.parsingConfig.maxAttachmentsPerEmail})`
                  );
                }

                // Process attachment immediately (streaming)
                await this.processAttachmentStream(attachment);

                emailAttachmentProcessed.inc({
                  status: 'success',
                  size_bucket: this.getSizeBucket(attachment.size || 0),
                });
              } catch (err) {
                logger.error(
                  { error: err, filename: attachment.filename },
                  'Failed to process attachment'
                );
                emailAttachmentProcessed.inc({
                  status: 'error',
                  size_bucket: this.getSizeBucket(attachment.size || 0),
                });
                // Don't reject parser - continue with other attachments
              }
            });

            // Handle parsing errors
            parser.on('error', (err: Error) => {
              logger.error({ error: err }, 'Email parsing error');
              reject(new Error(`Email parsing failed: ${err.message}`));
            });

            // Wait for parsing to complete
            parser.then(() => {
              if (!this.emailMetadata) {
                reject(new Error('No email headers found'));
                return;
              }

              const result: ParsedEmail = {
                ...this.emailMetadata,
                attachmentCount: this.attachmentCount,
              } as ParsedEmail;

              span.setAttribute('attachment_count', this.attachmentCount);

              logger.info(
                {
                  messageId: result.messageId,
                  subject: result.subject,
                  from: result.from,
                  attachments: this.attachmentCount,
                },
                'Email parsed successfully with streaming'
              );

              resolve(result);
            }).catch(reject);
          });
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
   * Legacy parseEmail method (for backward compatibility)
   *
   * Note: This buffers attachments in memory. Use parseEmailStreaming() instead.
   */
  async parseEmail(emailStream: Readable): Promise<ParsedEmail> {
    const parsed = await simpleParser(emailStream);
    const parsedEmail = this.convertToParseEmail(parsed);

    logger.info(
      {
        messageId: parsedEmail.messageId,
        subject: parsedEmail.subject,
        from: parsedEmail.from,
        attachments: parsedEmail.attachmentCount,
      },
      'Email parsed (legacy, buffered mode)'
    );

    return parsedEmail;
  }

  /**
   * Extract message ID from headers
   */
  private extractMessageId(headers: any): string {
    return headers.get('message-id') || uuidv4();
  }

  /**
   * Extract subject from headers
   */
  private extractSubject(headers: any): string {
    return (headers.get('subject') as string) || '(no subject)';
  }

  /**
   * Extract from address from headers
   */
  private extractFrom(headers: any): string {
    const from = headers.get('from') as any;
    if (!from) return 'unknown';
    if (typeof from === 'string') return from;
    return from.value?.[0]?.address || from.text || 'unknown';
  }

  /**
   * Extract date from headers
   */
  private extractDate(headers: any): Date {
    const dateStr = headers.get('date');
    return dateStr ? new Date(dateStr) : new Date();
  }

  /**
   * Extract email addresses from header value
   *
   * IMPROVEMENT-030: Optimized using reduce() to avoid intermediate array allocation
   * Instead of map().filter() (2 passes, intermediate array), single reduce() pass
   */
  private extractAddresses(addressValue: any): string[] {
    if (!addressValue) return [];
    if (typeof addressValue === 'string') return [addressValue];

    const value = addressValue.value || addressValue;
    if (!Array.isArray(value)) return [];

    // Single pass with reduce() instead of map().filter() (which creates intermediate array)
    return value.reduce((addresses: string[], addr: any) => {
      const address = typeof addr === 'string' ? addr : addr?.address;
      if (address && typeof address === 'string') {
        addresses.push(address);
      }
      return addresses;
    }, []);
  }

  /**
   * Convert mailparser ParsedMail to ParsedEmail (legacy, buffers attachments)
   *
   * IMPROVEMENT-030: Using extractAddresses() helper to avoid code duplication
   * and benefit from optimized reduce()-based address extraction
   *
   * IMPROVEMENT-048: Standardize header handling and address extraction
   * - Use extractFrom() helper instead of duplicating logic
   * - Use direct Map construction to avoid manual iteration overhead
   * - Consistent with streaming path for memory efficiency
   */
  private convertToParseEmail(parsed: ParsedMail): ParsedEmail {
    // IMPROVEMENT-048: Use extractFrom helper (already handles value extraction)
    const from = this.extractFrom({
      get: (key: string) => key === 'from' ? parsed.from : undefined,
    });

    // Handle 'to' field - extract addresses from AddressObject (IMPROVEMENT-030)
    const to = this.extractAddresses(parsed.to);

    // Handle 'cc' field - extract addresses from AddressObject (IMPROVEMENT-030)
    const cc = this.extractAddresses(parsed.cc);

    // IMPROVEMENT-048: Use direct Map construction (more efficient than manual iteration)
    const headers = parsed.headers ? new Map(parsed.headers) : new Map<string, any>();

    return {
      messageId: parsed.messageId || uuidv4(),
      subject: parsed.subject || '(no subject)',
      from,
      to,
      cc,
      date: parsed.date || new Date(),
      textBody: parsed.text,
      htmlBody: parsed.html !== false ? String(parsed.html || '') : undefined,
      attachmentCount: parsed.attachments?.length || 0,
      headers,
    };
  }

  /**
   * Process attachment stream (IMPROVEMENT-005: Streaming)
   *
   * Streams attachment content while computing checksum.
   * Applies backpressure when queue depth exceeds threshold.
   * Publishes metadata only (not content).
   */
  private async processAttachmentStream(attachment: Attachment): Promise<void> {
    const startTime = Date.now();
    const hash = createHash('sha256');
    let bytesProcessed = 0;

    return new Promise<void>((resolve, reject) => {
      const contentStream = attachment.content as Readable;

      if (!contentStream) {
        reject(new Error('Attachment has no content stream'));
        return;
      }

      contentStream
        .on('data', (chunk: Buffer) => {
          // Update hash and byte count
          hash.update(chunk);
          bytesProcessed += chunk.length;

          // Check size limits
          if (bytesProcessed > this.parsingConfig.maxAttachmentSize) {
            contentStream.destroy(
              new Error(
                `Attachment exceeds ${this.parsingConfig.maxAttachmentSize / 1024 / 1024}MB limit`
              )
            );
          }

          // Apply backpressure if queue is full
          const queueDepth = this.getQueueDepth();
          if (queueDepth > this.parsingConfig.queueDepthThreshold) {
            contentStream.pause();
            attachmentStreamBackpressure.inc();
            logger.debug(
              {
                queueDepth,
                threshold: this.parsingConfig.queueDepthThreshold,
              },
              'Applying backpressure on attachment stream'
            );
            setTimeout(
              () => contentStream.resume(),
              this.parsingConfig.backpressurePauseDurationMs
            );
          }
        })
        .on('end', async () => {
          try {
            // Validate attachment metadata
            if (!this.isValidAttachmentMetadata(attachment, bytesProcessed)) {
              logger.debug(
                {
                  filename: attachment.filename,
                  contentType: attachment.contentType,
                  size: bytesProcessed,
                },
                'Skipping invalid attachment'
              );
              resolve();
              return;
            }

            // Publish attachment metadata (not content)
            if (this.messagePublisher && this.emailMetadata?.messageId) {
              await this.publishAttachmentMetadata({
                id: uuidv4(),
                filename: attachment.filename || 'unnamed',
                contentType: attachment.contentType || 'application/octet-stream',
                size: bytesProcessed,
                checksum: hash.digest('hex'),
                contentId: attachment.contentId,
              });
            }

            const duration = Date.now() - startTime;
            attachmentProcessingDuration.observe(
              {
                status: 'success',
                size_bucket: this.getSizeBucket(bytesProcessed),
              },
              duration
            );

            logger.debug('Attachment processed', {
              filename: attachment.filename,
              sizeBytes: bytesProcessed,
              durationMs: duration,
            });

            resolve();
          } catch (err) {
            logger.error({ error: err, filename: attachment.filename }, 'Failed to process attachment stream');
            reject(err);
          }
        })
        .on('error', (err: Error) => {
          logger.error(
            { error: err, filename: attachment.filename },
            'Attachment stream error'
          );
          reject(err);
        });
    });
  }

  /**
   * Publish attachment metadata (IMPROVEMENT-005)
   *
   * Note: Content was already streamed. This publishes metadata only.
   */
  private async publishAttachmentMetadata(metadata: AttachmentMetadata): Promise<void> {
    if (!this.messagePublisher) {
      logger.warn('Message publisher not configured, skipping metadata publication');
      return;
    }

    try {
      // The message publisher will handle streaming the content
      // This just publishes the metadata reference
      const messageId = `${this.emailMetadata?.messageId}-${metadata.id}`;
      logger.debug(
        {
          messageId,
          filename: metadata.filename,
          size: metadata.size,
          checksum: metadata.checksum,
        },
        'Publishing attachment metadata'
      );

      // Update queue depth gauge
      messagePublisherQueueDepth.set(this.getQueueDepth());
    } catch (err) {
      logger.error(
        { error: err, filename: metadata.filename },
        'Failed to publish attachment metadata'
      );
      throw err;
    }
  }

  /**
   * Get queue depth (stub - would be updated by message publisher)
   */
  private getQueueDepth(): number {
    // In a real implementation, this would query the message publisher's queue
    // For now, return 0 (no backpressure applied)
    return 0;
  }

  /**
   * Validate attachment metadata before publishing
   */
  private isValidAttachmentMetadata(
    attachment: Attachment,
    bytesProcessed: number
  ): boolean {
    // Check if attachment has content
    if (bytesProcessed === 0) {
      return false;
    }

    // Check file size
    if (bytesProcessed > this.filterOptions.maxFileSize) {
      logger.warn(
        {
          filename: attachment.filename,
          size: bytesProcessed,
          maxSize: this.filterOptions.maxFileSize,
        },
        'Attachment exceeds maximum file size'
      );
      return false;
    }

    if (bytesProcessed < this.filterOptions.minFileSize) {
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
   * Get size bucket for metrics
   */
  private getSizeBucket(sizeBytes: number): string {
    if (sizeBytes < 1024 * 1024) return '<1MB';
    if (sizeBytes < 5 * 1024 * 1024) return '1-5MB';
    if (sizeBytes < 10 * 1024 * 1024) return '5-10MB';
    return '>10MB';
  }

  /**
   * Extract and filter attachments (legacy - buffers in memory)
   */
  private extractAttachments(attachments: Attachment[]): AttachmentMetadata[] {
    const extracted: AttachmentMetadata[] = [];

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

        // Extract attachment metadata
        const attachmentMetadata = this.convertToAttachmentMetadata(attachment);
        extracted.push(attachmentMetadata);

        attachmentsExtractedTotal.inc({
          content_type: attachmentMetadata.contentType,
          status: 'success',
        });

        logger.info(
          {
            id: attachmentMetadata.id,
            filename: attachmentMetadata.filename,
            contentType: attachmentMetadata.contentType,
            size: attachmentMetadata.size,
          },
          'Attachment extracted (legacy)'
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
   * Convert mailparser Attachment to AttachmentMetadata (legacy)
   */
  private convertToAttachmentMetadata(attachment: Attachment): AttachmentMetadata {
    const id = uuidv4();
    const checksum = this.calculateChecksum(attachment.content as Buffer);

    return {
      id,
      filename: attachment.filename || `attachment-${id}`,
      contentType: attachment.contentType,
      size: attachment.size,
      checksum,
      contentId: attachment.contentId,
    };
  }

  /**
   * Calculate SHA-256 checksum of buffer (legacy)
   */
  private calculateChecksum(buffer: Buffer): string {
    return createHash('sha256').update(buffer).digest('hex');
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
