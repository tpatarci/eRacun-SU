/**
 * Prometheus Metrics Configuration
 *
 * Exposes metrics for monitoring invoice-gateway-api performance.
 * Metrics are scraped by Prometheus at /metrics endpoint.
 */

import { Registry, Counter, Histogram, Gauge, collectDefaultMetrics } from 'prom-client';

// Create a custom registry
export const register = new Registry();

// Collect default metrics (CPU, memory, event loop, etc.)
collectDefaultMetrics({
  register,
  prefix: 'invoice_gateway_',
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
});

// Custom Metrics

/**
 * HTTP Request Duration Histogram
 * Tracks request latency by method, route, and status code
 */
export const httpRequestDuration = new Histogram({
  name: 'invoice_gateway_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5],
  registers: [register],
});

/**
 * HTTP Request Counter
 * Tracks total number of requests by method, route, and status code
 */
export const httpRequestCounter = new Counter({
  name: 'invoice_gateway_http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register],
});

/**
 * Invoice Submission Counter
 * Tracks successful and failed invoice submissions
 */
export const invoiceSubmissionCounter = new Counter({
  name: 'invoice_gateway_submissions_total',
  help: 'Total number of invoice submissions',
  labelNames: ['status'],
  registers: [register],
});

/**
 * Idempotent Request Counter
 * Tracks idempotent requests (duplicate submissions)
 */
export const idempotentRequestCounter = new Counter({
  name: 'invoice_gateway_idempotent_requests_total',
  help: 'Total number of idempotent requests (duplicates)',
  registers: [register],
});

/**
 * Rate Limit Counter
 * Tracks rate-limited requests
 */
export const rateLimitCounter = new Counter({
  name: 'invoice_gateway_rate_limited_requests_total',
  help: 'Total number of rate-limited requests',
  labelNames: ['ip'],
  registers: [register],
});

/**
 * Active Requests Gauge
 * Tracks currently active (in-flight) requests
 */
export const activeRequests = new Gauge({
  name: 'invoice_gateway_active_requests',
  help: 'Number of active HTTP requests',
  registers: [register],
});

/**
 * Database Connection Pool Gauge
 * Tracks database connection pool utilization
 */
export const dbConnectionPoolSize = new Gauge({
  name: 'invoice_gateway_db_connection_pool_size',
  help: 'Database connection pool size',
  labelNames: ['state'],
  registers: [register],
});

/**
 * Error Counter
 * Tracks errors by type
 */
export const errorCounter = new Counter({
  name: 'invoice_gateway_errors_total',
  help: 'Total number of errors',
  labelNames: ['type', 'code'],
  registers: [register],
});
