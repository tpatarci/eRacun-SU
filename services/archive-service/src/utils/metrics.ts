/**
 * Prometheus Metrics Exporter
 *
 * Tracks archive ingestion, validation, and retrieval metrics.
 * See: CLAUDE.md §7.1 (Observability)
 */

import { Registry, Counter, Histogram, Gauge } from 'prom-client';
import express from 'express';

export const metricsRegistry = new Registry();

// Ingestion metrics
export const ingestionSuccess = new Counter({
  name: 'archive_ingestion_success_total',
  help: 'Total successful invoice archival operations',
  labelNames: ['channel'],
  registers: [metricsRegistry],
});

export const ingestionFailure = new Counter({
  name: 'archive_ingestion_failure_total',
  help: 'Total failed invoice archival operations',
  labelNames: ['channel', 'reason'],
  registers: [metricsRegistry],
});

export const ingestionDuration = new Histogram({
  name: 'archive_ingestion_duration_seconds',
  help: 'Duration of invoice archival operations',
  labelNames: ['channel'],
  buckets: [0.1, 0.5, 1, 2, 5, 10],
  registers: [metricsRegistry],
});

// Queue metrics
export const queueDepth = new Gauge({
  name: 'archive_queue_depth',
  help: 'Current depth of archive ingestion queue',
  registers: [metricsRegistry],
});

// Signature validation metrics
export const signatureValidationSuccess = new Counter({
  name: 'archive_signature_validation_success_total',
  help: 'Total successful signature validations',
  registers: [metricsRegistry],
});

export const signatureValidationFailed = new Counter({
  name: 'archive_signature_validation_failed_total',
  help: 'Total failed signature validations',
  labelNames: ['result'],
  registers: [metricsRegistry],
});

// Storage metrics
export const storageTierGauge = new Gauge({
  name: 'archive_storage_tier_count',
  help: 'Number of invoices per storage tier',
  labelNames: ['tier'],
  registers: [metricsRegistry],
});

// API metrics
export const apiResponseTime = new Histogram({
  name: 'archive_api_response_time_seconds',
  help: 'API response time',
  labelNames: ['method', 'path', 'status'],
  buckets: [0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5],
  registers: [metricsRegistry],
});

// Circuit breaker metrics
export const circuitBreakerOpen = new Gauge({
  name: 'archive_s3_circuit_breaker_open',
  help: 'S3 circuit breaker state (1=open, 0=closed)',
  registers: [metricsRegistry],
});

export async function startMetricsServer(port: number): Promise<void> {
  const app = express();

  app.get('/metrics', async (_req, res) => {
    res.set('Content-Type', metricsRegistry.contentType);
    res.end(await metricsRegistry.metrics());
  });

  app.listen(port);
}
