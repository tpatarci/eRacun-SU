/**
 * Observability Module - TODO-008 Compliance
 *
 * This module provides:
 * - Prometheus metrics (6 metrics)
 * - Structured logging (Pino)
 * - Distributed tracing (OpenTelemetry)
 * - No PII masking needed (health data only)
 */

import { Counter, Gauge, Histogram, Registry } from 'prom-client';
import pino from 'pino';
import { trace, Span, SpanStatusCode } from '@opentelemetry/api';

// =============================================
// Prometheus Metrics Registry
// =============================================

export const register = new Registry();

// =============================================
// Metric 1: Service Health Status
// =============================================
// Tracks current health status of each monitored service
// 1 = healthy, 0.5 = degraded, 0 = unhealthy
export const serviceHealthStatus = new Gauge({
  name: 'service_health_status',
  help: 'Service health status (1=healthy, 0.5=degraded, 0=unhealthy)',
  labelNames: ['service'],
  registers: [register],
});

// =============================================
// Metric 2: Health Check Success Counter
// =============================================
// Total successful health checks per service
export const healthCheckSuccess = new Counter({
  name: 'health_check_success_total',
  help: 'Total number of successful health checks',
  labelNames: ['service'],
  registers: [register],
});

// =============================================
// Metric 3: Health Check Failures Counter
// =============================================
// Total failed health checks per service with reason
export const healthCheckFailures = new Counter({
  name: 'health_check_failures_total',
  help: 'Total number of failed health checks',
  labelNames: ['service', 'reason'],
  registers: [register],
});

// =============================================
// Metric 4: Circuit Breaker State
// =============================================
// Tracks circuit breaker state for each service
// 0 = closed, 1 = open, 0.5 = half-open
export const circuitBreakerState = new Gauge({
  name: 'circuit_breaker_state',
  help: 'Circuit breaker state (0=closed, 1=open, 0.5=half-open)',
  labelNames: ['service', 'breaker'],
  registers: [register],
});

// =============================================
// Metric 5: Health Check Duration
// =============================================
// Latency histogram for health check requests
export const healthCheckDuration = new Histogram({
  name: 'health_check_duration_seconds',
  help: 'Health check request duration in seconds',
  labelNames: ['service'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5], // 10ms, 50ms, 100ms, 500ms, 1s, 5s
  registers: [register],
});

// =============================================
// Metric 6: Service Up
// =============================================
// Health monitor service availability (1 = up, 0 = down)
export const serviceUp = new Gauge({
  name: 'service_up',
  help: 'Health monitor service availability',
  registers: [register],
});

// =============================================
// Structured Logging (Pino)
// =============================================

const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

export const logger = pino({
  level: LOG_LEVEL,
  transport:
    process.env.NODE_ENV !== 'production'
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'HH:MM:ss Z',
            ignore: 'pid,hostname',
          },
        }
      : undefined,
  formatters: {
    level(label) {
      return { level: label };
    },
  },
  base: {
    service: 'health-monitor',
    environment: process.env.NODE_ENV || 'development',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

// =============================================
// Distributed Tracing (OpenTelemetry)
// =============================================

const tracer = trace.getTracer('health-monitor', '1.0.0');

/**
 * Create a new tracing span
 * @param operationName - Name of the operation being traced
 * @param attributes - Optional key-value attributes for the span
 * @returns Span object
 */
export function createSpan(operationName: string, attributes?: Record<string, string | number>): Span {
  const span = tracer.startSpan(operationName);

  if (attributes) {
    Object.entries(attributes).forEach(([key, value]) => {
      span.setAttribute(key, value);
    });
  }

  return span;
}

/**
 * Set span error status
 * @param span - OpenTelemetry span
 * @param error - Error object
 */
export function setSpanError(span: Span, error: Error): void {
  span.setStatus({
    code: SpanStatusCode.ERROR,
    message: error.message,
  });
  span.recordException(error);
}

// =============================================
// Initialization
// =============================================

export function initObservability(): void {
  // Set service_up to 1 (service started)
  serviceUp.set(1);

  logger.info(
    {
      metrics_count: 6,
      log_level: LOG_LEVEL,
      tracing_enabled: true,
    },
    'Observability initialized (TODO-008 compliant)'
  );
}

// =============================================
// Helper Functions
// =============================================

/**
 * Map health status string to metric value
 * @param status - Health status ("healthy", "degraded", "unhealthy")
 * @returns Numeric value for Prometheus gauge
 */
export function healthStatusToMetric(status: string): number {
  switch (status.toLowerCase()) {
    case 'healthy':
      return 1;
    case 'degraded':
      return 0.5;
    case 'unhealthy':
      return 0;
    default:
      logger.warn({ status }, 'Unknown health status, defaulting to unhealthy');
      return 0;
  }
}

/**
 * Map circuit breaker state to metric value
 * @param state - Circuit breaker state ("closed", "open", "half-open")
 * @returns Numeric value for Prometheus gauge
 */
export function circuitBreakerStateToMetric(state: string): number {
  switch (state.toLowerCase()) {
    case 'closed':
      return 0;
    case 'open':
      return 1;
    case 'half-open':
    case 'half_open':
      return 0.5;
    default:
      logger.warn({ state }, 'Unknown circuit breaker state, defaulting to closed');
      return 0;
  }
}

// =============================================
// Export for Testing
// =============================================

export function resetMetrics(): void {
  register.clear();
}
