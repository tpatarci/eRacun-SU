import { Counter, Histogram, Gauge, register } from 'prom-client';
import pino from 'pino';
import { trace, SpanStatusCode } from '@opentelemetry/api';

/**
 * Prometheus Metrics (TODO-008 Compliance)
 */

// Fiscalization operations counter
export const fiscalizationTotal = new Counter({
  name: 'fina_fiscalization_total',
  help: 'Total FINA fiscalization operations',
  labelNames: ['operation', 'status'], // operation: racuni, echo, provjera | status: success, failure
  registers: [register],
});

// Fiscalization duration histogram
export const fiscalizationDuration = new Histogram({
  name: 'fina_fiscalization_duration_seconds',
  help: 'FINA fiscalization operation duration in seconds',
  labelNames: ['operation'], // racuni, echo, provjera
  buckets: [0.5, 1, 2, 3, 5, 10],
  registers: [register],
});

// FINA errors counter
export const finaErrors = new Counter({
  name: 'fina_errors_total',
  help: 'Total FINA API errors',
  labelNames: ['error_code'], // s:001, s:002, s:003, etc.
  registers: [register],
});

// Retry counter
export const retryAttempts = new Counter({
  name: 'fina_retry_attempts_total',
  help: 'Total retry attempts for FINA operations',
  labelNames: ['operation', 'attempt'], // attempt: 1, 2, 3
  registers: [register],
});

// Offline queue gauge
export const offlineQueueDepth = new Gauge({
  name: 'fina_offline_queue_depth',
  help: 'Number of invoices in offline queue waiting for submission',
  registers: [register],
});

// Offline queue age gauge
export const offlineQueueMaxAge = new Gauge({
  name: 'fina_offline_queue_max_age_seconds',
  help: 'Age of oldest invoice in offline queue (seconds)',
  registers: [register],
});

// Service health gauge
export const serviceUp = new Gauge({
  name: 'fina_connector_up',
  help: 'FINA connector service is up (1) or down (0)',
  registers: [register],
});

// JIR received counter (successful fiscalizations)
export const jirReceived = new Counter({
  name: 'fina_jir_received_total',
  help: 'Total JIR (Unique Invoice Identifiers) received from FINA',
  registers: [register],
});

/**
 * Structured JSON Logging (TODO-008 Compliance)
 *
 * Mandatory fields:
 * - timestamp
 * - level
 * - service
 * - request_id
 * - invoice_id
 * - message
 *
 * WARNING: NEVER log OIB numbers or other PII
 */
export const logger = pino({
  name: 'fina-connector',
  level: process.env.LOG_LEVEL || 'info',
  transport:
    process.env.NODE_ENV !== 'production'
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname',
          },
        }
      : undefined,
  formatters: {
    level: (label) => ({ level: label }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  base: {
    service: 'fina-connector',
  },
  // Redact sensitive fields
  redact: {
    paths: ['oib', 'buyer_oib', 'seller_oib', '*.oib'],
    censor: '[REDACTED]',
  },
});

/**
 * PII Masking (TODO-008 Compliance)
 *
 * OIB numbers must be masked in logs
 */
export function maskOIB(oib: string): string {
  if (!oib || oib.length !== 11) {
    return 'INVALID_OIB';
  }
  return '***********'; // Full mask
}

/**
 * Mask JIR (Unique Invoice Identifier) for logging
 * JIR format: UUID (public identifier, no masking needed)
 */
export function maskJIR(jir: string): string {
  // JIR is public identifier, no masking needed
  // But we can abbreviate for readability
  if (!jir || jir.length < 8) {
    return jir || 'NO_JIR';
  }
  return jir.substring(0, 8) + '...';
}

/**
 * OpenTelemetry Tracing (TODO-008 Compliance)
 *
 * 100% sampling per TODO-008 decision
 */
export const tracer = trace.getTracer('fina-connector', '0.1.0');

/**
 * Create a new trace span with standard attributes
 */
export function createSpan(
  spanName: string,
  attributes: Record<string, string | number | boolean> = {}
) {
  return tracer.startSpan(spanName, {
    attributes: {
      'service.name': 'fina-connector',
      ...attributes,
    },
  });
}

/**
 * Set span error and status
 */
export function setSpanError(span: any, error: Error): void {
  span.setStatus({
    code: SpanStatusCode.ERROR,
    message: error.message,
  });
  span.recordException(error);
}

/**
 * End span with success status
 */
export function endSpanSuccess(span: any): void {
  span.setStatus({ code: SpanStatusCode.OK });
  span.end();
}

/**
 * Export Prometheus metrics endpoint
 */
export async function getMetrics(): Promise<string> {
  return await register.metrics();
}

/**
 * Reset metrics (for testing only)
 */
export function resetMetrics(): void {
  register.resetMetrics();
}

/**
 * Initialize observability
 */
export function initObservability(): void {
  // Set service up
  serviceUp.set(1);

  logger.info('Observability initialized for fina-connector');
  logger.info({
    metrics: [
      'fina_fiscalization_total',
      'fina_fiscalization_duration_seconds',
      'fina_errors_total',
      'fina_retry_attempts_total',
      'fina_offline_queue_depth',
      'fina_offline_queue_max_age_seconds',
      'fina_jir_received_total',
    ],
  }, 'Prometheus metrics registered');
}

/**
 * Shutdown observability
 */
export function shutdownObservability(): void {
  serviceUp.set(0);
  logger.info('Observability shutdown');
}
