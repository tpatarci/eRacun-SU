/**
 * Prometheus Metrics Configuration for Validation Coordinator
 *
 * Tracks 6-layer validation pipeline execution and consensus mechanism.
 */

import { Registry, Counter, Histogram, Gauge, collectDefaultMetrics } from 'prom-client';
import { Request, Response } from 'express';

// Create a custom registry
export const register = new Registry();

// Collect default metrics (CPU, memory, event loop, etc.)
collectDefaultMetrics({
  register,
  prefix: 'validation_coordinator_',
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
});

// Custom Metrics

/**
 * Validation Pipeline Duration Histogram
 * Tracks total validation time across all layers
 */
export const validationPipelineDuration = new Histogram({
  name: 'validation_coordinator_pipeline_duration_seconds',
  help: 'Validation pipeline duration in seconds',
  labelNames: ['invoice_id'],
  buckets: [1, 2, 3, 5, 10, 30],
  registers: [register],
});

/**
 * Validation Layer Duration Histogram
 * Tracks execution time per validation layer
 */
export const validationLayerDuration = new Histogram({
  name: 'validation_coordinator_layer_duration_seconds',
  help: 'Validation layer duration in seconds',
  labelNames: ['layer'],
  buckets: [0.1, 0.5, 1, 2, 5, 10],
  registers: [register],
});

/**
 * Validation Result Counter
 * Tracks pass/fail by layer
 */
export const validationResultCounter = new Counter({
  name: 'validation_coordinator_results_total',
  help: 'Total number of validation results',
  labelNames: ['layer', 'result'],
  registers: [register],
});

/**
 * Consensus Decision Counter
 * Tracks consensus outcomes (passed, failed, indeterminate)
 */
export const consensusDecisionCounter = new Counter({
  name: 'validation_coordinator_consensus_decisions_total',
  help: 'Total number of consensus decisions',
  labelNames: ['decision'],
  registers: [register],
});

/**
 * Confidence Score Histogram
 * Tracks confidence scores distribution
 */
export const confidenceScoreHistogram = new Histogram({
  name: 'validation_coordinator_confidence_score',
  help: 'Validation confidence score distribution',
  buckets: [0, 0.2, 0.4, 0.6, 0.8, 1.0],
  registers: [register],
});

/**
 * Error Aggregation Counter
 * Tracks errors by severity and category
 */
export const errorAggregationCounter = new Counter({
  name: 'validation_coordinator_errors_aggregated_total',
  help: 'Total number of aggregated errors',
  labelNames: ['severity', 'category'],
  registers: [register],
});

/**
 * Active Validations Gauge
 * Tracks currently running validations
 */
export const activeValidations = new Gauge({
  name: 'validation_coordinator_active_validations',
  help: 'Number of currently active validations',
  registers: [register],
});

/**
 * AI Validation Toggle Gauge
 * Tracks whether AI validation is enabled
 */
export const aiValidationEnabled = new Gauge({
  name: 'validation_coordinator_ai_validation_enabled',
  help: 'Whether AI validation is enabled (1=enabled, 0=disabled)',
  registers: [register],
});

/**
 * Layer Success Rate Gauge
 * Tracks success rate per validation layer
 */
export const layerSuccessRate = new Gauge({
  name: 'validation_coordinator_layer_success_rate',
  help: 'Success rate per validation layer',
  labelNames: ['layer'],
  registers: [register],
});

/**
 * Metrics endpoint handler
 * Exposes metrics for Prometheus scraping
 */
export async function metricsHandler(req: Request, res: Response): Promise<void> {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (error) {
    res.status(500).end(error);
  }
}
