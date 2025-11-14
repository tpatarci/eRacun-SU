import { Counter, Histogram, Gauge, register } from 'prom-client';
import pino from 'pino';
import { trace, SpanStatusCode } from '@opentelemetry/api';

/**
 * Prometheus Metrics (TODO-008 Compliance)
 */

// Signature operations counter
export const signatureTotal = new Counter({
  name: 'digital_signature_total',
  help: 'Total signature operations',
  labelNames: ['operation', 'status'], // operation: sign, verify, zki | status: success, failure
  registers: [register],
});

// Signature duration histogram
export const signatureDuration = new Histogram({
  name: 'digital_signature_duration_seconds',
  help: 'Signature operation duration in seconds',
  labelNames: ['operation'], // sign, verify, zki
  buckets: [0.1, 0.25, 0.5, 1, 2, 5, 10],
  registers: [register],
});

// Certificate operations counter
export const certificateOperations = new Counter({
  name: 'certificate_operations_total',
  help: 'Total certificate operations',
  labelNames: ['operation', 'status'], // operation: load, validate | status: success, failure
  registers: [register],
});

// Signature errors counter
export const signatureErrors = new Counter({
  name: 'digital_signature_errors_total',
  help: 'Total signature errors',
  labelNames: ['error_type'], // certificate_load, signature_generation, verification, invalid_xml
  registers: [register],
});

// Active certificates gauge
export const activeCertificates = new Gauge({
  name: 'active_certificates_count',
  help: 'Number of active certificates loaded',
  registers: [register],
});

// Certificate expiration days remaining (IMPROVEMENT-004)
export const certificateExpirationDays = new Gauge({
  name: 'certificate_expiration_days_remaining',
  help: 'Days remaining until certificate expiration',
  registers: [register],
});

// Certificate load time (IMPROVEMENT-004)
export const certificateLoadTime = new Histogram({
  name: 'certificate_load_time_seconds',
  help: 'Time taken to load and parse certificate from disk',
  buckets: [0.1, 0.5, 1, 2, 5],
  registers: [register],
});

// Service health gauge
export const serviceUp = new Gauge({
  name: 'digital_signature_service_up',
  help: 'Digital signature service is up (1) or down (0)',
  registers: [register],
});

// XMLDSig validation gauge
export const xmldsigValidations = new Counter({
  name: 'xmldsig_validations_total',
  help: 'Total XMLDSig signature validations',
  labelNames: ['result'], // valid, invalid
  registers: [register],
});

/**
 * Batch Signing Metrics
 */

// Batch signature operations counter
export const batchSignatureTotal = new Counter({
  name: 'batch_signature_total',
  help: 'Total batch signature operations',
  labelNames: ['status'], // success, failure
  registers: [register],
});

// Batch signature duration histogram
export const batchSignatureDuration = new Histogram({
  name: 'batch_signature_duration_seconds',
  help: 'Batch signature operation duration in seconds',
  buckets: [1, 5, 10, 30, 60, 120, 300], // 1s to 5min
  registers: [register],
});

// Batch size histogram
export const batchSignatureSize = new Histogram({
  name: 'batch_signature_size',
  help: 'Number of invoices in batch signature operation',
  buckets: [1, 10, 50, 100, 250, 500, 1000],
  registers: [register],
});

// Batch signature errors counter
export const batchSignatureErrors = new Counter({
  name: 'batch_signature_errors_total',
  help: 'Total batch signature errors',
  labelNames: ['error_type'], // individual_signature_failed, batch_operation_failed
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
 * - message
 *
 * WARNING: NEVER log certificate passwords or private keys
 */
export const logger = pino({
  name: 'digital-signature-service',
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
    service: 'digital-signature-service',
  },
  // Redact sensitive fields
  redact: {
    paths: ['password', 'privateKey', 'cert_password', '*.password'],
    censor: '[REDACTED]',
  },
});

/**
 * PII Masking (TODO-008 Compliance)
 *
 * OIB numbers must be masked in logs
 * Certificate serial numbers are public data (no masking required)
 */
export function maskOIB(oib: string): string {
  if (!oib || oib.length !== 11) {
    return 'INVALID_OIB';
  }
  return '***********'; // Full mask
}

/**
 * Mask certificate password for logging
 * CRITICAL: Never log actual passwords
 */
export function maskPassword(_password: string): string {
  return '[REDACTED]';
}

/**
 * OpenTelemetry Tracing (TODO-008 Compliance)
 *
 * 100% sampling per TODO-008 decision
 */
export const tracer = trace.getTracer('digital-signature-service', '0.1.0');

/**
 * Create a new trace span with standard attributes
 */
export function createSpan(
  spanName: string,
  attributes: Record<string, string | number | boolean> = {}
) {
  return tracer.startSpan(spanName, {
    attributes: {
      'service.name': 'digital-signature-service',
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
 * Initialize observability (IMPROVEMENT-004: Added certificate monitoring metrics)
 */
export function initObservability(): void {
  // Set service up
  serviceUp.set(1);

  logger.info('Observability initialized for digital-signature-service');
  logger.info({
    metrics: [
      'digital_signature_total',
      'digital_signature_duration_seconds',
      'certificate_operations_total',
      'digital_signature_errors_total',
      'active_certificates_count',
      'certificate_expiration_days_remaining', // IMPROVEMENT-004
      'certificate_load_time_seconds', // IMPROVEMENT-004
      'xmldsig_validations_total',
      'batch_signature_total', // Batch signing
      'batch_signature_duration_seconds', // Batch signing
      'batch_signature_size', // Batch signing
      'batch_signature_errors_total', // Batch signing
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
