import { Counter, Histogram, Gauge, Registry, register } from 'prom-client';
import pino from 'pino';
import { trace, context, SpanStatusCode } from '@opentelemetry/api';

/**
 * Prometheus Metrics (TODO-008 Compliance)
 */

// Request counter
export const validationTotal = new Counter({
  name: 'xsd_validation_total',
  help: 'Total XSD validations',
  labelNames: ['status'], // valid, invalid, error
  registers: [register],
});

// Latency histogram
export const validationDuration = new Histogram({
  name: 'xsd_validation_duration_seconds',
  help: 'XSD validation duration in seconds',
  labelNames: ['schema_type'],
  buckets: [0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10],
  registers: [register],
});

// Error counter
export const validationErrors = new Counter({
  name: 'xsd_validation_errors_total',
  help: 'Total XSD validation errors',
  labelNames: ['error_type'], // parse, schema, internal
  registers: [register],
});

// Queue depth gauge
export const queueDepth = new Gauge({
  name: 'xsd_validation_queue_depth',
  help: 'Current queue depth',
  registers: [register],
});

// Service health gauge
export const serviceUp = new Gauge({
  name: 'xsd_validator_up',
  help: 'XSD validator service is up (1) or down (0)',
  registers: [register],
});

// Schema loaded gauge
export const schemasLoaded = new Gauge({
  name: 'xsd_schemas_loaded',
  help: 'Number of XSD schemas loaded',
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
 */
export const logger = pino({
  name: 'xsd-validator',
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
    service: 'xsd-validator',
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
 * OpenTelemetry Tracing (TODO-008 Compliance)
 *
 * 100% sampling per TODO-008 decision
 */
export const tracer = trace.getTracer('xsd-validator', '0.1.0');

/**
 * Create a new trace span with standard attributes
 */
export function createSpan(
  spanName: string,
  attributes: Record<string, string | number | boolean> = {}
) {
  return tracer.startSpan(spanName, {
    attributes: {
      'service.name': 'xsd-validator',
      ...attributes,
    },
  });
}

/**
 * Set span error and status
 */
export function setSpanError(span: any, error: Error) {
  span.setStatus({
    code: SpanStatusCode.ERROR,
    message: error.message,
  });
  span.recordException(error);
}

/**
 * Export Prometheus metrics endpoint
 */
export async function getMetrics(): Promise<string> {
  return await register.metrics();
}

/**
 * Initialize observability
 */
export function initObservability() {
  // Set service up
  serviceUp.set(1);

  logger.info('Observability initialized');
}
