import { Counter, Histogram, Gauge, register } from 'prom-client';
import pino from 'pino';
import { trace, SpanStatusCode } from '@opentelemetry/api';

/**
 * Prometheus Metrics (TODO-008 Compliance)
 *
 * Certificate Lifecycle Manager Metrics:
 * - certificates_expiring_count: Number of certificates expiring within threshold
 * - certificate_expiration_alerts_total: Total expiration alerts sent
 * - certificate_renewals_total: Total certificate renewals (success/failed)
 * - certificates_active: Number of active certificates by type
 * - certificate_parse_duration_seconds: Certificate parsing latency
 * - certificate_operations_total: Total certificate operations (upload, revoke, deploy)
 */

// Certificates expiring counter (by days until expiry)
export const certificatesExpiring = new Gauge({
  name: 'certificates_expiring_count',
  help: 'Number of certificates expiring within threshold',
  labelNames: ['days_until_expiry'], // 1, 7, 14, 30
  registers: [register],
});

// Certificate expiration alerts counter
export const certificateExpirationAlerts = new Counter({
  name: 'certificate_expiration_alerts_total',
  help: 'Total certificate expiration alerts sent',
  labelNames: ['severity'], // info, warning, critical, urgent
  registers: [register],
});

// Certificate renewals counter
export const certificateRenewals = new Counter({
  name: 'certificate_renewals_total',
  help: 'Total certificate renewals',
  labelNames: ['status'], // success, failed
  registers: [register],
});

// Active certificates gauge
export const activeCertificates = new Gauge({
  name: 'certificates_active',
  help: 'Number of active certificates',
  labelNames: ['cert_type'], // production, demo, test
  registers: [register],
});

// Certificate parsing duration histogram
export const certificateParseDuration = new Histogram({
  name: 'certificate_parse_duration_seconds',
  help: 'Certificate parsing duration in seconds',
  labelNames: ['operation'], // parse, validate, deploy
  buckets: [0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5],
  registers: [register],
});

// Certificate operations counter
export const certificateOperations = new Counter({
  name: 'certificate_operations_total',
  help: 'Total certificate operations',
  labelNames: ['operation', 'status'], // upload/revoke/deploy, success/failed
  registers: [register],
});

// Service health gauge
export const serviceUp = new Gauge({
  name: 'cert_lifecycle_manager_up',
  help: 'Certificate lifecycle manager service is up (1) or down (0)',
  registers: [register],
});

// Database connection health gauge
export const databaseConnected = new Gauge({
  name: 'cert_lifecycle_manager_database_connected',
  help: 'Database connection status (1 = connected, 0 = disconnected)',
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
 * - cert_id (when applicable)
 * - message
 *
 * Security: Never log certificate contents or passwords
 */
export const logger = pino({
  name: 'cert-lifecycle-manager',
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
    service: 'cert-lifecycle-manager',
  },
  // Redact sensitive fields (passwords, certificate contents)
  redact: {
    paths: ['password', 'cert_password', 'p12_password', 'cert_content', '*.password'],
    remove: true,
  },
});

/**
 * PII Masking (TODO-008 Compliance)
 *
 * Note: X.509 certificates are PUBLIC data (subject DN, issuer, serial number).
 * Only passwords need masking.
 */
export function maskPassword(password: string): string {
  if (!password) {
    return 'NO_PASSWORD';
  }
  return '***REDACTED***';
}

/**
 * OpenTelemetry Tracing (TODO-008 Compliance)
 *
 * 100% sampling per TODO-008 decision
 */
export const tracer = trace.getTracer('cert-lifecycle-manager', '1.0.0');

/**
 * Create a new trace span with standard attributes
 */
export function createSpan(
  spanName: string,
  attributes: Record<string, string | number | boolean> = {}
) {
  return tracer.startSpan(spanName, {
    attributes: {
      'service.name': 'cert-lifecycle-manager',
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

  logger.info('Observability initialized for cert-lifecycle-manager');
}

/**
 * Shutdown observability
 */
export function shutdownObservability() {
  serviceUp.set(0);
  logger.info('Observability shutdown for cert-lifecycle-manager');
}
