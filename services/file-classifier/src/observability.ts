/**
 * Observability Module
 *
 * Provides logging, metrics, and distributed tracing for file-classifier.
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
    paths: ['filename', '*.filename', 'filePath', '*.filePath'],
    remove: true,
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

// =============================================================================
// METRICS
// =============================================================================

const register = new Registry();

/**
 * Total files classified
 */
export const filesClassifiedTotal = new Counter({
  name: 'file_classifier_files_classified_total',
  help: 'Total number of files classified',
  labelNames: ['file_type', 'status'], // status: success, error
  registers: [register],
});

/**
 * Files routed to each processor
 */
export const filesRoutedTotal = new Counter({
  name: 'file_classifier_files_routed_total',
  help: 'Total number of files routed to processors',
  labelNames: ['processor', 'status'], // processor: pdf-parser, xml-parser, ocr, manual-review
  registers: [register],
});

/**
 * Classification errors
 */
export const classificationErrorsTotal = new Counter({
  name: 'file_classifier_classification_errors_total',
  help: 'Total number of classification errors',
  labelNames: ['error_type'], // error_type: unsupported_type, size_exceeded, detection_failed
  registers: [register],
});

/**
 * File classification duration
 */
export const classificationDuration = new Histogram({
  name: 'file_classifier_classification_duration_seconds',
  help: 'File classification duration in seconds',
  labelNames: ['operation'], // operation: detect, classify, route
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2],
  registers: [register],
});

/**
 * Current queue depth by processor
 */
export const queueDepth = new Gauge({
  name: 'file_classifier_queue_depth',
  help: 'Current queue depth by processor type',
  labelNames: ['processor'],
  registers: [register],
});

/**
 * File size distribution
 */
export const fileSizeBytes = new Histogram({
  name: 'file_classifier_file_size_bytes',
  help: 'File size distribution in bytes',
  labelNames: ['file_type'],
  buckets: [1024, 10240, 102400, 1048576, 10485760], // 1KB, 10KB, 100KB, 1MB, 10MB
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

const tracer = trace.getTracer('file-classifier', '1.0.0');

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
