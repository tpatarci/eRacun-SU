/**
 * Observability Module
 *
 * Provides metrics, logging, and distributed tracing for PDF parser service.
 * - Prometheus metrics (parsing stats, errors, performance)
 * - Structured logging with Pino
 * - OpenTelemetry distributed tracing
 */

import pino from 'pino';
import { Registry, Counter, Histogram, Gauge } from 'prom-client';
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
    paths: ['filename', '*.filename', 'text', '*.text', 'content', '*.content'],
    remove: true,
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

// =============================================================================
// METRICS
// =============================================================================

const register = new Registry();

/**
 * Total PDFs processed
 */
export const pdfsProcessedTotal = new Counter({
  name: 'pdf_parser_pdfs_processed_total',
  help: 'Total number of PDFs processed',
  labelNames: ['status'], // status: success, error, scanned
  registers: [register],
});

/**
 * PDF parsing errors
 */
export const pdfParsingErrorsTotal = new Counter({
  name: 'pdf_parser_errors_total',
  help: 'Total number of PDF parsing errors',
  labelNames: ['error_type'], // error_type: corrupt, encrypted, unsupported, timeout
  registers: [register],
});

/**
 * Invoices extracted
 */
export const invoicesExtractedTotal = new Counter({
  name: 'pdf_parser_invoices_extracted_total',
  help: 'Total number of invoices successfully extracted',
  labelNames: ['extraction_quality'], // quality: high, medium, low
  registers: [register],
});

/**
 * PDF parsing duration
 */
export const pdfParsingDuration = new Histogram({
  name: 'pdf_parser_parsing_duration_seconds',
  help: 'Time taken to parse PDF documents',
  labelNames: ['operation'], // operation: extract, parse, total
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
  registers: [register],
});

/**
 * PDF file size
 */
export const pdfFileSizeBytes = new Histogram({
  name: 'pdf_parser_file_size_bytes',
  help: 'Size of processed PDF files',
  buckets: [1024, 10240, 102400, 1048576, 10485760], // 1KB, 10KB, 100KB, 1MB, 10MB
  registers: [register],
});

/**
 * PDF page count
 */
export const pdfPageCount = new Histogram({
  name: 'pdf_parser_page_count',
  help: 'Number of pages in processed PDFs',
  buckets: [1, 2, 5, 10, 20, 50, 100],
  registers: [register],
});

/**
 * Message queue depth (current backlog)
 */
export const queueDepth = new Gauge({
  name: 'pdf_parser_queue_depth',
  help: 'Current depth of PDF processing queue',
  labelNames: ['queue'],
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

const tracer = trace.getTracer('pdf-parser-service', '1.0.0');

/**
 * Execute function within a traced span
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
    const result = await context.with(trace.setSpan(context.active(), span), () => fn(span));
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
