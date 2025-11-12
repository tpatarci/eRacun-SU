/**
 * Observability Module
 *
 * Provides logging, metrics, and distributed tracing for email-ingestion-worker.
 * - Pino logging with PII masking
 * - Prometheus metrics
 * - OpenTelemetry tracing
 */

import pino from 'pino';
import { Registry, Counter, Gauge, Histogram } from 'prom-client';
import { trace, context, Span, SpanStatusCode } from '@opentelemetry/api';

// =============================================================================
// LOGGING
// =============================================================================

/**
 * Pino logger with PII masking
 */
export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => {
      return { level: label.toUpperCase() };
    },
  },
  redact: {
    paths: [
      'email',
      'password',
      '*.email',
      '*.password',
      'from',
      'to',
      'cc',
      'bcc',
    ],
    remove: true,
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

// =============================================================================
// METRICS
// =============================================================================

const register = new Registry();

/**
 * Total emails fetched from IMAP
 */
export const emailsFetchedTotal = new Counter({
  name: 'email_ingestion_emails_fetched_total',
  help: 'Total number of emails fetched from IMAP',
  labelNames: ['mailbox', 'status'], // status: success, error
  registers: [register],
});

/**
 * Total attachments extracted
 */
export const attachmentsExtractedTotal = new Counter({
  name: 'email_ingestion_attachments_extracted_total',
  help: 'Total number of attachments extracted from emails',
  labelNames: ['content_type', 'status'], // status: success, error
  registers: [register],
});

/**
 * Total messages published to RabbitMQ
 */
export const messagesPublishedTotal = new Counter({
  name: 'email_ingestion_messages_published_total',
  help: 'Total number of messages published to message bus',
  labelNames: ['message_type', 'status'], // status: success, error
  registers: [register],
});

/**
 * Current IMAP connection status
 */
export const imapConnectionStatus = new Gauge({
  name: 'email_ingestion_imap_connection_status',
  help: 'IMAP connection status (1=connected, 0=disconnected)',
  labelNames: ['mailbox'],
  registers: [register],
});

/**
 * Email processing duration
 */
export const emailProcessingDuration = new Histogram({
  name: 'email_ingestion_email_processing_duration_seconds',
  help: 'Email processing duration in seconds',
  labelNames: ['operation'], // operation: fetch, parse, extract, publish
  buckets: [0.1, 0.5, 1, 2, 5, 10],
  registers: [register],
});

/**
 * Email inbox unread count
 */
export const inboxUnreadCount = new Gauge({
  name: 'email_ingestion_inbox_unread_count',
  help: 'Number of unread emails in inbox',
  labelNames: ['mailbox'],
  registers: [register],
});

/**
 * Get Prometheus metrics registry
 */
export function getMetricsRegistry(): Registry {
  return register;
}

// =============================================================================
// DISTRIBUTED TRACING
// =============================================================================

const tracer = trace.getTracer('email-ingestion-worker', '1.0.0');

/**
 * Create a new span for distributed tracing
 *
 * @param name - Span name
 * @param attributes - Span attributes
 * @param fn - Function to execute within span
 * @returns Result of fn execution
 */
export async function withSpan<T>(
  name: string,
  attributes: Record<string, string | number>,
  fn: (span: Span) => Promise<T>
): Promise<T> {
  const span = tracer.startSpan(name, {
    attributes,
  });

  try {
    const result = await context.with(
      trace.setSpan(context.active(), span),
      () => fn(span)
    );
    span.setStatus({ code: SpanStatusCode.OK });
    return result;
  } catch (error) {
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : 'Unknown error',
    });
    span.recordException(error as Error);
    throw error;
  } finally {
    span.end();
  }
}

/**
 * Get current active span
 */
export function getActiveSpan(): Span | undefined {
  return trace.getSpan(context.active());
}
