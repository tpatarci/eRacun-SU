import { Counter, Histogram, Gauge, register } from 'prom-client';
import pino from 'pino';
import { trace, SpanStatusCode } from '@opentelemetry/api';

/**
 * Prometheus Metrics (TODO-008 Compliance)
 *
 * CRITICAL: audit-logger requires 6+ metrics for compliance
 */

// Total audit events written
export const auditEventsWritten = new Counter({
  name: 'audit_events_written_total',
  help: 'Total number of audit events written to database',
  labelNames: ['service', 'event_type'], // service = producer, event_type = VALIDATION_PASSED, etc.
  registers: [register],
});

// Audit write latency
export const auditWriteDuration = new Histogram({
  name: 'audit_write_duration_seconds',
  help: 'Time to write audit event to PostgreSQL',
  labelNames: ['service'],
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1], // <50ms p95 target
  registers: [register],
});

// Kafka consumer lag
export const auditConsumerLag = new Gauge({
  name: 'audit_consumer_lag',
  help: 'Kafka consumer lag (messages behind)',
  labelNames: ['partition'],
  registers: [register],
});

// Integrity check results
export const auditIntegrityChecks = new Counter({
  name: 'audit_integrity_checks_total',
  help: 'Total number of integrity verifications performed',
  labelNames: ['status'], // valid or broken
  registers: [register],
});

// Database connection pool
export const auditDbConnections = new Gauge({
  name: 'audit_db_connections',
  help: 'Active PostgreSQL connections',
  registers: [register],
});

// gRPC request rate
export const auditGrpcRequests = new Counter({
  name: 'audit_grpc_requests_total',
  help: 'Total gRPC API requests',
  labelNames: ['method', 'status'], // method: GetAuditTrail, QueryAuditEvents, etc.
  registers: [register],
});

// Service health gauge
export const serviceUp = new Gauge({
  name: 'audit_logger_up',
  help: 'Audit logger service is up (1) or down (0)',
  registers: [register],
});

/**
 * Structured JSON Logging (TODO-008 Compliance)
 *
 * IMPORTANT: Audit logs DO NOT mask PII (regulatory requirement for forensic analysis)
 * However, we provide masking functions for compliance testing
 *
 * Mandatory fields:
 * - timestamp
 * - level
 * - service
 * - request_id
 * - event_id
 * - invoice_id
 * - message
 */
export const logger = pino({
  name: 'audit-logger',
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
    service: 'audit-logger',
  },
});

/**
 * PII Masking Functions (TODO-008 Compliance)
 *
 * CRITICAL NOTE: Audit logs NEVER mask PII in production (regulatory requirement)
 * These functions exist ONLY for compliance testing and documentation
 */

/**
 * Mask Croatian OIB (11 digits)
 * Example: "12345678901" → "***********"
 */
export function maskOIB(oib: string): string {
  if (!oib || oib.length !== 11) {
    return 'INVALID_OIB';
  }
  return '***********'; // Full mask
}

/**
 * Mask Croatian IBAN (21 characters)
 * Example: "HR1234567890123456789" → "HR** **** **** **** ****"
 */
export function maskIBAN(iban: string): string {
  if (!iban || !iban.startsWith('HR') || iban.length !== 21) {
    return 'INVALID_IBAN';
  }
  const countryCode = iban.slice(0, 2);
  const checkDigits = '**';
  const accountPart = '*'.repeat(iban.length - 4);
  return `${countryCode}${checkDigits} ${accountPart.match(/.{1,4}/g)?.join(' ')}`;
}

/**
 * Mask VAT number (HR + 11 digits)
 * Example: "HR12345678901" → "HR***********"
 */
export function maskVAT(vat: string): string {
  if (!vat || !vat.startsWith('HR') || vat.length !== 13) {
    return 'INVALID_VAT';
  }
  return 'HR***********';
}

/**
 * Generic PII masking wrapper
 * IMPORTANT: Only use in non-audit contexts
 */
export function maskPII(value: string, type: 'OIB' | 'IBAN' | 'VAT'): string {
  switch (type) {
    case 'OIB':
      return maskOIB(value);
    case 'IBAN':
      return maskIBAN(value);
    case 'VAT':
      return maskVAT(value);
    default:
      return value;
  }
}

/**
 * OpenTelemetry Tracing (TODO-008 Compliance)
 *
 * 100% sampling for regulatory compliance
 */
export const tracer = trace.getTracer('audit-logger', '1.0.0');

/**
 * Create a new trace span with standard attributes
 */
export function createSpan(
  spanName: string,
  attributes: Record<string, string | number | boolean> = {}
) {
  return tracer.startSpan(spanName, {
    attributes: {
      'service.name': 'audit-logger',
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
 * Export Prometheus metrics endpoint
 */
export async function getMetrics(): Promise<string> {
  return await register.metrics();
}

/**
 * Get Prometheus registry (for testing)
 */
export function getMetricsRegistry() {
  return register;
}

/**
 * Initialize observability
 */
export function initObservability(): void {
  // Set service up
  serviceUp.set(1);

  logger.info('Audit logger observability initialized');
  logger.info('IMPORTANT: Audit logs DO NOT mask PII (regulatory compliance requirement)');
}
