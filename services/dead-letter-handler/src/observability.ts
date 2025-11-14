/**
 * Observability - Prometheus Metrics
 *
 * Exposes metrics for monitoring DLQ processing:
 * - Messages processed (by classification)
 * - Retries scheduled
 * - Manual review routed
 * - Notifications sent
 * - Processing duration
 * - Manual review queue depth
 *
 * See: README.md §6.3 for complete metrics specification
 */

import { Counter, Gauge, Histogram, register } from 'prom-client';

// DLQ message processing
export const dlqMessagesProcessed = new Counter({
  name: 'dlq_messages_processed_total',
  help: 'Total DLQ messages processed',
  labelNames: ['classification', 'service'],
});

// Error classification distribution
export const dlqClassificationDistribution = new Counter({
  name: 'dlq_classification_total',
  help: 'Errors by classification type',
  labelNames: ['classification'],
});

// Retry routing rate
export const dlqRetriesScheduled = new Counter({
  name: 'dlq_retries_scheduled_total',
  help: 'Messages sent to retry-scheduler',
  labelNames: ['service'],
});

// Manual review routing
export const dlqManualReviewRouted = new Counter({
  name: 'dlq_manual_review_routed_total',
  help: 'Messages routed to manual review',
  labelNames: ['classification', 'service'],
});

// Manual review queue size
export const dlqManualReviewPending = new Gauge({
  name: 'dlq_manual_review_pending',
  help: 'Number of errors awaiting manual review',
});

// Processing latency
export const dlqProcessingDuration = new Histogram({
  name: 'dlq_processing_duration_seconds',
  help: 'Time to classify and route DLQ message',
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5],
  labelNames: ['classification'],
});

// Critical error notifications
export const dlqNotificationsSent = new Counter({
  name: 'dlq_notifications_sent_total',
  help: 'Critical error notifications sent',
  labelNames: ['severity'],
});

// Error events published to Kafka
export const dlqErrorEventsPublished = new Counter({
  name: 'dlq_error_events_published_total',
  help: 'Error events published to Kafka',
  labelNames: ['classification', 'service'],
});

// HTTP API requests
export const httpRequestsTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'],
});

export const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration',
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5],
  labelNames: ['method', 'route'],
});

/**
 * Get Prometheus metrics
 *
 * @returns Metrics in Prometheus format
 */
export async function getMetrics(): Promise<string> {
  return register.metrics();
}

/**
 * Update manual review pending count
 *
 * Should be called periodically (e.g., every 30 seconds)
 */
export async function updateManualReviewPendingCount(count: number): Promise<void> {
  dlqManualReviewPending.set(count);
}
