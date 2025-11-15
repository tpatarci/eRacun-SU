/**
 * Observability Module (TODO-008 Compliance)
 *
 * Implements:
 * - Prometheus metrics (6 metrics)
 * - Structured logging (Pino with PII masking)
 * - Distributed tracing (OpenTelemetry)
 *
 * CRITICAL: This module must be imported FIRST in index.ts
 */

import { Counter, Gauge, Histogram, register } from 'prom-client';
import pino from 'pino';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-node';
import { trace, Span, SpanStatusCode, context } from '@opentelemetry/api';

// =============================================================================
// ENVIRONMENT CONFIGURATION
// =============================================================================

const SERVICE_NAME = process.env.SERVICE_NAME || 'notification-service';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const OTEL_ENDPOINT = process.env.OTEL_EXPORTER_JAEGER_ENDPOINT || 'http://localhost:14268/api/traces';

// =============================================================================
// PROMETHEUS METRICS (TODO-008 Requirement: 3+ metrics)
// =============================================================================

/**
 * Total notifications sent
 * Labels: type (email/sms/webhook), priority (low/normal/high/critical), status (success/failed)
 */
export const notificationsSentTotal = new Counter({
  name: 'notifications_sent_total',
  help: 'Total number of notifications sent',
  labelNames: ['type', 'priority', 'status'],
});

/**
 * Notification send duration histogram
 * Labels: type (email/sms/webhook)
 */
export const notificationSendDuration = new Histogram({
  name: 'notification_send_duration_seconds',
  help: 'Time taken to send notification',
  labelNames: ['type'],
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30], // seconds
});

/**
 * Current notification queue depth
 */
export const notificationQueueDepth = new Gauge({
  name: 'notification_queue_depth',
  help: 'Number of pending notifications in queue',
});

/**
 * Service health status (1 = healthy, 0 = unhealthy)
 */
export const serviceUp = new Gauge({
  name: 'service_up',
  help: 'Service health status (1 = up, 0 = down)',
});

/**
 * Total notification retry attempts
 * Labels: type (email/sms/webhook), attempt (1/2/3)
 */
export const notificationRetryAttemptsTotal = new Counter({
  name: 'notification_retry_attempts_total',
  help: 'Total number of notification retry attempts',
  labelNames: ['type', 'attempt'],
});

/**
 * Total notification failures (after all retries exhausted)
 * Labels: type (email/sms/webhook), reason (smtp_error/rate_limit/timeout/etc)
 */
export const notificationFailuresTotal = new Counter({
  name: 'notification_failures_total',
  help: 'Total number of notification failures',
  labelNames: ['type', 'reason'],
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
// STRUCTURED LOGGING (Pino with PII Masking)
// =============================================================================

/**
 * PII Masking: Mask email addresses and phone numbers in logs
 *
 * Examples:
 * - user@example.com → u***@example.com
 * - +385912345678 → +385****5678
 */
function maskPII(obj: any): any {
  if (typeof obj === 'string') {
    // Mask email addresses (keep first letter and domain)
    obj = obj.replace(
      /([a-zA-Z])[a-zA-Z0-9._-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
      '$1***@$2'
    );

    // Mask phone numbers (keep country code and last 4 digits)
    obj = obj.replace(
      /(\+\d{1,3})\d+(\d{4})/g,
      '$1****$2'
    );

    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(maskPII);
  }

  if (obj !== null && typeof obj === 'object') {
    const masked: any = {};
    for (const key in obj) {
      // Mask sensitive fields
      if (['email', 'phone', 'recipient', 'recipients', 'to', 'from'].includes(key.toLowerCase())) {
        if (Array.isArray(obj[key])) {
          masked[key] = obj[key].map((item: string) => maskPII(item));
        } else {
          masked[key] = maskPII(obj[key]);
        }
      } else {
        masked[key] = maskPII(obj[key]);
      }
    }
    return masked;
  }

  return obj;
}

/**
 * Pino logger with PII masking
 */
export const logger = pino({
  level: LOG_LEVEL,
  formatters: {
    level: (label) => {
      return { level: label.toUpperCase() };
    },
  },
  // Redact sensitive fields automatically
  redact: {
    paths: [
      'password',
      'token',
      'secret',
      'authorization',
      'cookie',
      'smtp_password',
      'twilio_auth_token',
    ],
    censor: '[REDACTED]',
  },
  // Apply PII masking to all log messages
  hooks: {
    logMethod(inputArgs, method) {
      // Mask PII in all log arguments
      const maskedArgs = inputArgs.map((arg) => {
        if (typeof arg === 'object' && arg !== null) {
          return maskPII(arg);
        }
        return arg;
      });
      return method.apply(this, maskedArgs as [string, ...any[]]);
    },
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
    tracerProvider = new NodeTracerProvider({
      // No resource needed - defaults are sufficient
    });

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
 *
 * @param operationName - Name of the operation (e.g., 'send_email', 'send_sms')
 * @param attributes - Additional span attributes
 * @returns Span object
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
