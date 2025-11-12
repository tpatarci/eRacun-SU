/**
 * Prometheus Metrics for OIB Validator Service
 */

import { Counter, Histogram, Registry, register } from 'prom-client';

// Validation metrics
export const validationCounter = new Counter({
  name: 'oib_validations_total',
  help: 'Total number of OIB validations performed',
  labelNames: ['result', 'source'],
  registers: [register],
});

export const validationDuration = new Histogram({
  name: 'oib_validation_duration_seconds',
  help: 'Duration of OIB validation in seconds',
  labelNames: ['result'],
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
  registers: [register],
});

export const batchValidationCounter = new Counter({
  name: 'oib_batch_validations_total',
  help: 'Total number of batch OIB validations performed',
  labelNames: ['source'],
  registers: [register],
});

export const batchValidationSize = new Histogram({
  name: 'oib_batch_validation_size',
  help: 'Size of batch validations',
  buckets: [1, 10, 50, 100, 500, 1000],
  registers: [register],
});

export const errorCounter = new Counter({
  name: 'oib_errors_total',
  help: 'Total number of errors encountered',
  labelNames: ['type'],
  registers: [register],
});

/**
 * Setup default metrics (CPU, memory, event loop, etc.)
 */
export function setupMetrics(): Registry {
  // collectDefaultMetrics({ register });
  return register;
}

/**
 * Record a validation result
 */
export function recordValidation(result: 'valid' | 'invalid', source: 'http' | 'rabbitmq', durationSeconds: number): void {
  validationCounter.inc({ result, source });
  validationDuration.observe({ result }, durationSeconds);
}

/**
 * Record a batch validation
 */
export function recordBatchValidation(size: number, source: 'http' | 'rabbitmq'): void {
  batchValidationCounter.inc({ source });
  batchValidationSize.observe(size);
}

/**
 * Record an error
 */
export function recordError(type: string): void {
  errorCounter.inc({ type });
}
