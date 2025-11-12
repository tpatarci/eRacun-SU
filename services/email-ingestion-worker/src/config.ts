/**
 * Email Ingestion Worker Configuration
 *
 * Configuration for email parsing, streaming, and processing.
 */

/**
 * Email parsing and streaming configuration
 */
export interface EmailParsingConfig {
  /** Maximum attachment size in bytes (default: 20MB) */
  maxAttachmentSize: number;
  /** Maximum number of attachments per email (default: 10) */
  maxAttachmentsPerEmail: number;
  /** Stream buffer size in bytes (default: 64KB) */
  streamBufferSize: number;
  /** Queue depth threshold for backpressure (default: 100) */
  queueDepthThreshold: number;
  /** Backpressure pause duration in milliseconds (default: 100ms) */
  backpressurePauseDurationMs: number;
}

/**
 * Default configuration
 */
export const DEFAULT_EMAIL_PARSING_CONFIG: EmailParsingConfig = {
  maxAttachmentSize: parseInt(process.env.MAX_ATTACHMENT_SIZE_MB ?? '20') * 1024 * 1024,
  maxAttachmentsPerEmail: parseInt(process.env.MAX_ATTACHMENTS ?? '10'),
  streamBufferSize: parseInt(process.env.STREAM_BUFFER_SIZE ?? '65536'),
  queueDepthThreshold: parseInt(process.env.QUEUE_DEPTH_THRESHOLD ?? '100'),
  backpressurePauseDurationMs: parseInt(process.env.BACKPRESSURE_PAUSE_MS ?? '100'),
};
