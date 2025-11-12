/**
 * Observability Module (TODO-008 Compliance)
 *
 * Implements cross-cutting observability concerns:
 * - Prometheus metrics (port 9093)
 * - Structured JSON logging (Pino)
 * - Distributed tracing (Jaeger via OpenTelemetry)
 *
 * Note: KPD codes are public data (no PII masking required)
 *
 * Compliance Requirements:
 * - 100% trace sampling (regulatory compliance, ISO 9000)
 * - 90-day log retention
 * - Request ID propagation
 */

import { register, Counter, Histogram, Gauge } from 'prom-client';
import pino from 'pino';
import { trace, SpanStatusCode, context, Span } from '@opentelemetry/api';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { PgInstrumentation } from '@opentelemetry/instrumentation-pg';

// ============================================================================
// Prometheus Metrics (Port 9093)
// ============================================================================

/**
 * Total number of KPD codes synced
 * Labels: action (added, updated, deleted)
 */
export const kpdCodesSynced = new Counter({
  name: 'kpd_codes_synced_total',
  help: 'Total number of KPD codes synced from DZS registry',
  labelNames: ['action'] // added, updated, deleted
});

/**
 * KPD sync processing duration
 */
export const kpdSyncDuration = new Histogram({
  name: 'kpd_sync_duration_seconds',
  help: 'KPD registry sync duration in seconds',
  buckets: [1, 5, 10, 30, 60, 120] // Up to 2 minutes
});

/**
 * Total number of KPD codes in local cache (gauge)
 */
export const kpdTotalCodes = new Gauge({
  name: 'kpd_total_codes',
  help: 'Total number of KPD codes in local cache'
});

/**
 * Total number of active KPD codes (gauge)
 */
export const kpdActiveCodes = new Gauge({
  name: 'kpd_active_codes',
  help: 'Total number of active KPD codes in local cache'
});

/**
 * Total number of lookup requests
 * Labels: status (found, not_found, error)
 */
export const kpdLookupRequests = new Counter({
  name: 'kpd_lookup_requests_total',
  help: 'Total number of KPD code lookup requests',
  labelNames: ['status'] // found, not_found, error
});

/**
 * KPD lookup duration
 */
export const kpdLookupDuration = new Histogram({
  name: 'kpd_lookup_duration_seconds',
  help: 'KPD code lookup duration in seconds',
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1] // <5ms p95 target
});

/**
 * KPD sync errors
 * Labels: error_type (network, parsing, database)
 */
export const kpdSyncErrors = new Counter({
  name: 'kpd_sync_errors_total',
  help: 'Total number of KPD sync errors',
  labelNames: ['error_type']
});

/**
 * Last successful sync timestamp (Unix timestamp in seconds)
 */
export const kpdLastSyncTimestamp = new Gauge({
  name: 'kpd_last_sync_timestamp_seconds',
  help: 'Timestamp of last successful KPD sync'
});

/**
 * Database connection pool metrics
 */
export const dbPoolSize = new Gauge({
  name: 'kpd_db_pool_size',
  help: 'Current database connection pool size'
});

export const dbPoolIdle = new Gauge({
  name: 'kpd_db_pool_idle',
  help: 'Number of idle database connections in pool'
});

/**
 * Get Prometheus metrics registry
 */
export function getMetricsRegistry() {
  return register;
}

// ============================================================================
// Structured Logging (Pino)
// ============================================================================

/**
 * Create Pino logger with structured output
 */
export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  base: {
    service: process.env.SERVICE_NAME || 'kpd-registry-sync',
    environment: process.env.NODE_ENV || 'production',
  },
  redact: {
    paths: [
      // No PII in KPD codes (public data)
      // But redact any potential credentials in logs
      'password',
      'secret',
      'token',
      'apiKey',
      'api_key',
    ],
    remove: true,
  },
});

// ============================================================================
// Distributed Tracing (OpenTelemetry + Jaeger)
// ============================================================================

let sdk: NodeSDK | null = null;

/**
 * Initialize OpenTelemetry SDK with Jaeger exporter
 */
export function initializeTracing(): void {
  const jaegerEndpoint = process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces';
  const sampleRate = parseFloat(process.env.TRACE_SAMPLE_RATE || '1.0');

  const exporter = new JaegerExporter({
    endpoint: jaegerEndpoint,
  });

  sdk = new NodeSDK({
    traceExporter: exporter,
    instrumentations: [
      new HttpInstrumentation(),
      new PgInstrumentation(),
    ],
    serviceName: process.env.SERVICE_NAME || 'kpd-registry-sync',
    // 100% sampling for regulatory compliance
    sampler: {
      shouldSample: () => {
        return {
          decision: Math.random() < sampleRate ? 1 : 0, // 1 = RECORD_AND_SAMPLE
        };
      },
      toString: () => 'CustomSampler',
    },
  });

  sdk.start();
  logger.info({ jaegerEndpoint, sampleRate }, 'OpenTelemetry tracing initialized');
}

/**
 * Shutdown tracing (for graceful shutdown)
 */
export async function shutdownTracing(): Promise<void> {
  if (sdk) {
    await sdk.shutdown();
    logger.info('OpenTelemetry tracing shut down');
  }
}

/**
 * Get the current tracer
 */
export function getTracer() {
  return trace.getTracer('kpd-registry-sync');
}

/**
 * Create a span for an operation
 */
export function createSpan(name: string, attributes?: Record<string, string | number | boolean>): Span {
  const tracer = getTracer();
  const span = tracer.startSpan(name, {
    attributes: attributes || {},
  });
  return span;
}

/**
 * End a span with success status
 */
export function endSpan(span: Span): void {
  span.setStatus({ code: SpanStatusCode.OK });
  span.end();
}

/**
 * End a span with error status
 */
export function endSpanWithError(span: Span, error: Error): void {
  span.setStatus({
    code: SpanStatusCode.ERROR,
    message: error.message,
  });
  span.recordException(error);
  span.end();
}

/**
 * Wrap an async operation with tracing
 */
export async function traceOperation<T>(
  operationName: string,
  operation: (span: Span) => Promise<T>,
  attributes?: Record<string, string | number | boolean>
): Promise<T> {
  const span = createSpan(operationName, attributes);
  try {
    const result = await operation(span);
    endSpan(span);
    return result;
  } catch (error) {
    endSpanWithError(span, error as Error);
    throw error;
  }
}

// ============================================================================
// Health Check Support
// ============================================================================

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime_seconds: number;
  dependencies: {
    database: 'up' | 'down';
    dz_s_api: 'up' | 'down' | 'unknown';
  };
  last_sync?: {
    timestamp: string;
    codes_added: number;
    codes_updated: number;
    codes_deleted: number;
  };
}

/**
 * Export metrics in Prometheus format
 */
export async function getMetrics(): Promise<string> {
  return register.metrics();
}

/**
 * Reset all metrics (for testing only)
 */
export function resetMetrics(): void {
  register.resetMetrics();
}
