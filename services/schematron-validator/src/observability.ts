/**
 * Observability Module (TODO-008 Compliance)
 *
 * Implements cross-cutting observability concerns:
 * - Prometheus metrics (port 9101)
 * - Structured JSON logging (Pino)
 * - Distributed tracing (Jaeger via OpenTelemetry)
 * - PII masking (OIB, IBAN, VAT numbers)
 *
 * Compliance Requirements:
 * - 100% trace sampling (regulatory compliance, ISO 9000)
 * - 90-day log retention
 * - PII masking in all logs
 * - Request ID propagation
 */

import { register, Counter, Histogram, Gauge } from 'prom-client';
import pino from 'pino';
import { trace, SpanStatusCode, context, Span } from '@opentelemetry/api';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';

// ============================================================================
// Prometheus Metrics (Port 9101)
// ============================================================================

/**
 * Total number of validations performed
 * Labels: status (valid, invalid, error), rule_set
 */
export const validationTotal = new Counter({
  name: 'schematron_validation_total',
  help: 'Total number of Schematron validations performed',
  labelNames: ['status', 'rule_set']
});

/**
 * Validation processing duration
 * Labels: rule_set
 */
export const validationDuration = new Histogram({
  name: 'schematron_validation_duration_seconds',
  help: 'Schematron validation processing duration in seconds',
  labelNames: ['rule_set'],
  buckets: [0.1, 0.5, 1, 2, 5, 10] // Schematron is slower than XSD
});

/**
 * Number of rules checked per validation
 * Labels: rule_set
 */
export const rulesCheckedHistogram = new Histogram({
  name: 'schematron_rules_checked_total',
  help: 'Number of Schematron rules checked per validation',
  labelNames: ['rule_set'],
  buckets: [10, 50, 100, 150, 200, 300]
});

/**
 * Number of rules failed per validation
 * Labels: rule_set
 */
export const rulesFailedHistogram = new Histogram({
  name: 'schematron_rules_failed_total',
  help: 'Number of Schematron rules failed per validation',
  labelNames: ['rule_set'],
  buckets: [0, 1, 2, 5, 10, 20, 50]
});

/**
 * Number of rules currently loaded (gauge)
 * Labels: rule_set
 */
export const rulesLoaded = new Gauge({
  name: 'schematron_rules_loaded',
  help: 'Number of Schematron rules currently loaded in memory',
  labelNames: ['rule_set']
});

/**
 * Errors counted by rule ID
 * Labels: rule_id, rule_set
 */
export const errorsByRule = new Counter({
  name: 'schematron_errors_by_rule',
  help: 'Number of errors by Schematron rule ID',
  labelNames: ['rule_id', 'rule_set']
});

/**
 * Warnings counted by rule ID
 * Labels: rule_id, rule_set
 */
export const warningsByRule = new Counter({
  name: 'schematron_warnings_by_rule',
  help: 'Number of warnings by Schematron rule ID',
  labelNames: ['rule_id', 'rule_set']
});

/**
 * Rule cache size in bytes
 */
export const ruleCacheSize = new Gauge({
  name: 'schematron_rule_cache_size_bytes',
  help: 'Size of compiled Schematron XSLT cache in bytes'
});

/**
 * XSLT compilation time
 * Labels: rule_set
 */
export const xsltCompilationTime = new Histogram({
  name: 'schematron_xslt_compilation_time_seconds',
  help: 'Time to compile Schematron rules to XSLT in seconds',
  labelNames: ['rule_set'],
  buckets: [0.1, 0.5, 1, 2, 5]
});

/**
 * Get Prometheus metrics registry
 */
export function getMetricsRegistry() {
  return register;
}

// ============================================================================
// PII Masking (TODO-008 Compliance)
// ============================================================================

/**
 * Mask Croatian OIB (tax identification number)
 * Format: 11 digits → '***********'
 */
export function maskOIB(oib: string): string {
  if (!oib || typeof oib !== 'string') return 'INVALID_OIB';
  if (oib.length !== 11) return 'INVALID_OIB';
  if (!/^\d{11}$/.test(oib)) return 'INVALID_OIB';

  return '***********'; // Full mask (11 asterisks)
}

/**
 * Mask IBAN (International Bank Account Number)
 * Format: HR17 1234 5678 9012 3456 → HR** **** **** **** ****
 */
export function maskIBAN(iban: string): string {
  if (!iban || typeof iban !== 'string') return 'INVALID_IBAN';
  if (!iban.startsWith('HR')) return 'INVALID_IBAN';

  // Keep country code (HR) + first 2 digits, mask rest
  const countryCode = iban.slice(0, 2);
  const checkDigits = '**';
  const accountPart = '*'.repeat(iban.length - 4);

  return `${countryCode}${checkDigits} ${accountPart.match(/.{1,4}/g)?.join(' ') || '****'}`;
}

/**
 * Mask VAT number
 * Format: HR12345678901 → HR***********
 */
export function maskVAT(vat: string): string {
  if (!vat || typeof vat !== 'string') return 'INVALID_VAT';
  if (!vat.startsWith('HR')) return 'INVALID_VAT';

  const countryCode = vat.slice(0, 2);
  const masked = '*'.repeat(vat.length - 2);
  return `${countryCode}${masked}`;
}

/**
 * Mask all PII in text
 */
export function maskPII(text: string): string {
  if (!text) return text;

  let masked = text;

  // Mask OIB (11 consecutive digits)
  masked = masked.replace(/\b\d{11}\b/g, (match) => maskOIB(match));

  // Mask IBAN (HR followed by 19 characters)
  masked = masked.replace(/\bHR\d{19}\b/g, (match) => maskIBAN(match));

  // Mask VAT (HR followed by 11 digits)
  masked = masked.replace(/\bHR\d{11}\b/g, (match) => maskVAT(match));

  return masked;
}

// ============================================================================
// Structured Logging (Pino)
// ============================================================================

/**
 * Create Pino logger with PII masking
 */
export const logger = pino({
  name: 'schematron-validator',
  level: process.env.LOG_LEVEL || 'info',

  // Timestamp in ISO 8601 format
  timestamp: pino.stdTimeFunctions.isoTime,

  // Base fields (always present)
  base: {
    service: 'schematron-validator',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  },

  // Format log levels as strings
  formatters: {
    level: (label: string) => {
      return { level: label };
    }
  },

  // PII masking serializer
  serializers: {
    ...pino.stdSerializers,

    // Mask request fields
    req: (req: any) => {
      return {
        id: req.id,
        method: req.method,
        url: req.url,
        // Body masked (may contain PII)
        body: req.body ? '[REDACTED]' : undefined
      };
    },

    // Mask error messages
    err: (err: Error) => {
      return {
        type: err.name,
        message: maskPII(err.message),
        stack: maskPII(err.stack || '')
      };
    }
  }
});

/**
 * Log with automatic PII masking
 */
export function logInfo(fields: Record<string, any>, message: string) {
  const maskedFields = { ...fields };

  // Mask specific fields
  if (maskedFields.oib) maskedFields.oib = maskOIB(maskedFields.oib);
  if (maskedFields.iban) maskedFields.iban = maskIBAN(maskedFields.iban);
  if (maskedFields.vat) maskedFields.vat = maskVAT(maskedFields.vat);
  if (maskedFields.xml_content) maskedFields.xml_content = '[REDACTED]';

  logger.info(maskedFields, maskPII(message));
}

export function logError(fields: Record<string, any>, message: string) {
  const maskedFields = { ...fields };

  if (maskedFields.oib) maskedFields.oib = maskOIB(maskedFields.oib);
  if (maskedFields.iban) maskedFields.iban = maskIBAN(maskedFields.iban);
  if (maskedFields.vat) maskedFields.vat = maskVAT(maskedFields.vat);
  if (maskedFields.xml_content) maskedFields.xml_content = '[REDACTED]';

  logger.error(maskedFields, maskPII(message));
}

export function logWarn(fields: Record<string, any>, message: string) {
  const maskedFields = { ...fields };

  if (maskedFields.oib) maskedFields.oib = maskOIB(maskedFields.oib);
  if (maskedFields.iban) maskedFields.iban = maskIBAN(maskedFields.iban);
  if (maskedFields.vat) maskedFields.vat = maskVAT(maskedFields.vat);
  if (maskedFields.xml_content) maskedFields.xml_content = '[REDACTED]';

  logger.warn(maskedFields, maskPII(message));
}

// ============================================================================
// Distributed Tracing (Jaeger via OpenTelemetry)
// ============================================================================

let tracingInitialized = false;

/**
 * Initialize OpenTelemetry tracing with Jaeger exporter
 */
export function initializeTracing() {
  if (tracingInitialized) return;

  const jaegerHost = process.env.JAEGER_AGENT_HOST || 'localhost';
  const jaegerPort = parseInt(process.env.JAEGER_AGENT_PORT || '14268', 10);

  const sdk = new NodeSDK({
    serviceName: 'schematron-validator',
    traceExporter: new JaegerExporter({
      endpoint: `http://${jaegerHost}:${jaegerPort}/api/traces`
    }),
    instrumentations: [
      new HttpInstrumentation()
    ]
  });

  sdk.start();
  tracingInitialized = true;

  // Graceful shutdown
  process.on('SIGTERM', () => {
    sdk.shutdown()
      .then(() => logger.info('Tracing terminated'))
      .catch((error) => logger.error({ error }, 'Error shutting down tracing'));
  });

  logger.info({ jaeger_host: jaegerHost, jaeger_port: jaegerPort }, 'Distributed tracing initialized');
}

/**
 * Create a new span for tracing
 */
export function createSpan(name: string, attributes: Record<string, string | number> = {}): Span {
  const tracer = trace.getTracer('schematron-validator');
  const span = tracer.startSpan(name, {
    attributes: {
      'service.name': 'schematron-validator',
      ...attributes
    }
  });

  return span;
}

/**
 * Get active span
 */
export function getActiveSpan(): Span | undefined {
  return trace.getActiveSpan();
}

/**
 * Run function within span context
 */
export async function withSpan<T>(
  name: string,
  attributes: Record<string, string | number>,
  fn: (span: Span) => Promise<T>
): Promise<T> {
  const span = createSpan(name, attributes);

  try {
    const result = await fn(span);
    span.setStatus({ code: SpanStatusCode.OK });
    span.end();
    return result;
  } catch (error) {
    span.recordException(error as Error);
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: (error as Error).message
    });
    span.end();
    throw error;
  }
}

// ============================================================================
// Initialize Observability Stack
// ============================================================================

/**
 * Initialize all observability components
 */
export function initializeObservability() {
  // Initialize tracing
  initializeTracing();

  logger.info('Observability stack initialized (TODO-008 compliant)');
}
