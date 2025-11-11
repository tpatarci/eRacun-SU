/**
 * Observability Module (TODO-008 Compliance)
 *
 * Implements:
 * - Prometheus metrics (4+ metrics)
 * - Structured logging (Pino)
 * - Distributed tracing (OpenTelemetry)
 */

import { Counter, Gauge, register } from 'prom-client';
import pino from 'pino';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-node';
import { trace, Span, SpanStatusCode, context } from '@opentelemetry/api';

// =============================================================================
// ENVIRONMENT CONFIGURATION
// =============================================================================

const SERVICE_NAME = process.env.SERVICE_NAME || 'retry-scheduler';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const OTEL_ENDPOINT = process.env.OTEL_EXPORTER_JAEGER_ENDPOINT || 'http://localhost:14268/api/traces';

// =============================================================================
// PROMETHEUS METRICS (TODO-008 Requirement: 4+ metrics)
// =============================================================================

/**
 * Total retries scheduled
 * Labels: queue (original queue name)
 */
export const retriesScheduledTotal = new Counter({
  name: 'retries_scheduled_total',
  help: 'Total number of retries scheduled',
  labelNames: ['queue'],
});

/**
 * Total retries executed
 * Labels: queue, status (success/failed)
 */
export const retriesExecutedTotal = new Counter({
  name: 'retries_executed_total',
  help: 'Total number of retries executed',
  labelNames: ['queue', 'status'],
});

/**
 * Total retries exhausted (moved to manual review)
 * Labels: queue
 */
export const retriesExhaustedTotal = new Counter({
  name: 'retries_exhausted_total',
  help: 'Messages moved to manual review after max retries',
  labelNames: ['queue'],
});

/**
 * Current retry queue depth (pending tasks)
 */
export const retryQueueDepth = new Gauge({
  name: 'retry_queue_depth',
  help: 'Number of pending retry tasks in queue',
});

/**
 * Service health status (1 = healthy, 0 = unhealthy)
 */
export const serviceUp = new Gauge({
  name: 'service_up',
  help: 'Service health status (1 = up, 0 = down)',
});

/**
 * Get Prometheus metrics in text format
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

// =============================================================================
// STRUCTURED LOGGING (Pino)
// =============================================================================

export const logger = pino({
  level: LOG_LEVEL,
  formatters: {
    level: (label) => {
      return { level: label.toUpperCase() };
    },
  },
  // Redact sensitive fields
  redact: {
    paths: [
      'password',
      'token',
      'secret',
      'authorization',
      'cookie',
    ],
    censor: '[REDACTED]',
  },
  // Base fields for all logs
  base: {
    service: SERVICE_NAME,
    environment: process.env.NODE_ENV || 'development',
  },
  // Pretty print in development
  transport: process.env.NODE_ENV === 'development' ? {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'HH:MM:ss Z',
      ignore: 'pid,hostname',
    },
  } : undefined,
});

// =============================================================================
// DISTRIBUTED TRACING (OpenTelemetry)
// =============================================================================

let tracerProvider: NodeTracerProvider | null = null;

/**
 * Initialize OpenTelemetry tracing
 */
export function initTracing(): void {
  if (tracerProvider) {
    logger.warn('Tracing already initialized');
    return;
  }

  try {
    tracerProvider = new NodeTracerProvider();

    // Configure Jaeger exporter
    const jaegerExporter = new JaegerExporter({
      endpoint: OTEL_ENDPOINT,
    });

    // Use batch span processor for better performance
    tracerProvider.addSpanProcessor(new BatchSpanProcessor(jaegerExporter));

    // Register the provider
    tracerProvider.register();

    logger.info({ jaeger_endpoint: OTEL_ENDPOINT }, 'OpenTelemetry tracing initialized');
  } catch (error) {
    logger.error({ error }, 'Failed to initialize tracing');
  }
}

/**
 * Shutdown tracing (for graceful shutdown)
 */
export async function shutdownTracing(): Promise<void> {
  if (tracerProvider) {
    await tracerProvider.shutdown();
    tracerProvider = null;
    logger.info('OpenTelemetry tracing shutdown');
  }
}

/**
 * Get tracer instance
 */
export function getTracer() {
  return trace.getTracer(SERVICE_NAME);
}

/**
 * Create a new span for an operation
 */
export function createSpan(
  operationName: string,
  attributes?: Record<string, string | number>
): Span {
  const tracer = getTracer();
  const span = tracer.startSpan(operationName, {
    attributes: {
      'service.name': SERVICE_NAME,
      ...attributes,
    },
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
 * Set span error and end
 */
export function setSpanError(span: Span, error: Error): void {
  span.recordException(error);
  span.setStatus({
    code: SpanStatusCode.ERROR,
    message: error.message,
  });
  span.end();
}

/**
 * Execute function with tracing context
 */
export async function withSpan<T>(
  operationName: string,
  attributes: Record<string, string | number>,
  fn: (span: Span) => Promise<T>
): Promise<T> {
  const span = createSpan(operationName, attributes);

  try {
    const result = await context.with(trace.setSpan(context.active(), span), async () => {
      return await fn(span);
    });

    endSpan(span);
    return result;
  } catch (error) {
    setSpanError(span, error as Error);
    throw error;
  }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

// Initialize service_up gauge to 0 (will be set to 1 when service is ready)
serviceUp.set(0);

// Log startup
logger.info(
  {
    service_name: SERVICE_NAME,
    log_level: LOG_LEVEL,
    node_version: process.version,
  },
  'Observability module initialized'
);
