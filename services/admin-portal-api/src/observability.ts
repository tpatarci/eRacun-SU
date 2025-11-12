import { Counter, Histogram, Gauge, register } from 'prom-client';
import pino from 'pino';
import { trace, SpanStatusCode } from '@opentelemetry/api';

/**
 * Prometheus Metrics (TODO-008 Compliance)
 *
 * Required metrics for admin-portal-api:
 * 1. admin_api_requests_total (Counter)
 * 2. admin_api_duration_seconds (Histogram)
 * 3. admin_auth_attempts_total (Counter)
 * 4. admin_active_sessions (Gauge)
 */

// API request counter
export const apiRequests = new Counter({
  name: 'admin_api_requests_total',
  help: 'Total API requests',
  labelNames: ['method', 'endpoint', 'status'],
  registers: [register],
});

// API latency histogram
export const apiDuration = new Histogram({
  name: 'admin_api_duration_seconds',
  help: 'API request duration in seconds',
  labelNames: ['method', 'endpoint'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5],
  registers: [register],
});

// Authentication attempts counter
export const authAttempts = new Counter({
  name: 'admin_auth_attempts_total',
  help: 'Total authentication attempts',
  labelNames: ['status'], // success, failed, invalid_token
  registers: [register],
});

// Active sessions gauge
export const activeSessions = new Gauge({
  name: 'admin_active_sessions',
  help: 'Number of active user sessions',
  registers: [register],
});

// Service health gauge
export const serviceUp = new Gauge({
  name: 'admin_portal_api_up',
  help: 'Admin Portal API service is up (1) or down (0)',
  registers: [register],
});

// Database connection pool gauge
export const dbPoolConnections = new Gauge({
  name: 'admin_db_pool_connections',
  help: 'PostgreSQL connection pool status',
  labelNames: ['state'], // idle, active, waiting
  registers: [register],
});

// Downstream service call counter
export const downstreamCalls = new Counter({
  name: 'admin_downstream_calls_total',
  help: 'Total calls to downstream services',
  labelNames: ['service', 'operation', 'status'],
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
 * - user_id (optional, for authenticated requests)
 * - message
 */
export const logger = pino({
  name: 'admin-portal-api',
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
    service: 'admin-portal-api',
  },
});

/**
 * PII Masking (TODO-008 Compliance)
 *
 * Email addresses must be masked in logs
 */
export function maskEmail(email: string): string {
  if (!email || !email.includes('@')) {
    return 'INVALID_EMAIL';
  }

  const [localPart, domain] = email.split('@');

  // Show first 2 chars of local part + *** + @domain
  if (localPart.length <= 2) {
    return `${localPart[0]}***@${domain}`;
  }

  return `${localPart.substring(0, 2)}***@${domain}`;
}

/**
 * Mask JWT tokens in logs
 */
export function maskToken(token: string): string {
  if (!token || token.length < 10) {
    return 'INVALID_TOKEN';
  }

  // Show first 8 chars + ***
  return `${token.substring(0, 8)}***`;
}

/**
 * OpenTelemetry Tracing (TODO-008 Compliance)
 *
 * 100% sampling per TODO-008 decision
 */
export const tracer = trace.getTracer('admin-portal-api', '1.0.0');

/**
 * Create a new trace span with standard attributes
 */
export function createSpan(
  spanName: string,
  attributes: Record<string, string | number | boolean> = {}
) {
  return tracer.startSpan(spanName, {
    attributes: {
      'service.name': 'admin-portal-api',
      ...attributes,
    },
  });
}

/**
 * Set span error and status
 */
export function setSpanError(span: ReturnType<typeof tracer.startSpan>, error: Error) {
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

  // Initialize active sessions gauge
  activeSessions.set(0);

  logger.info('Observability initialized');
}

/**
 * Express middleware for request tracking
 */
export function requestTrackingMiddleware(
  req: any,
  res: any,
  next: any
) {
  const startTime = Date.now();
  const requestId = req.headers['x-request-id'] || `req-${Date.now()}-${Math.random()}`;
  req.requestId = requestId;

  // Create span for tracing
  const span = createSpan('http.request', {
    'http.method': req.method,
    'http.url': req.url,
    'http.request_id': requestId,
  });

  // Log request
  logger.info({
    request_id: requestId,
    method: req.method,
    path: req.path,
    user_agent: req.headers['user-agent'],
    msg: 'Incoming request',
  });

  // Track response
  res.on('finish', () => {
    const duration = (Date.now() - startTime) / 1000;

    // Update metrics
    apiRequests.inc({
      method: req.method,
      endpoint: req.route?.path || req.path,
      status: res.statusCode,
    });

    apiDuration.observe(
      {
        method: req.method,
        endpoint: req.route?.path || req.path,
      },
      duration
    );

    // Log response
    logger.info({
      request_id: requestId,
      method: req.method,
      path: req.path,
      status_code: res.statusCode,
      duration_ms: Math.round(duration * 1000),
      msg: 'Request completed',
    });

    // Close span
    span.end();
  });

  next();
}
