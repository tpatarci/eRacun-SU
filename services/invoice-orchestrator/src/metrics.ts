/**
 * Prometheus Metrics Configuration for Invoice Orchestrator
 *
 * Tracks saga execution, compensations, and workflow state transitions.
 */

import { Registry, Counter, Histogram, Gauge, collectDefaultMetrics } from 'prom-client';
import { Request, Response } from 'express';

// Create a custom registry
export const register = new Registry();

// Collect default metrics (CPU, memory, event loop, etc.)
collectDefaultMetrics({
  register,
  prefix: 'invoice_orchestrator_',
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
});

// Custom Metrics

/**
 * Saga Execution Duration
 * Tracks time to complete full saga workflow
 */
export const sagaExecutionDuration = new Histogram({
  name: 'invoice_orchestrator_saga_duration_seconds',
  help: 'Saga execution duration in seconds',
  labelNames: ['invoice_id', 'final_state'],
  buckets: [1, 2, 5, 10, 30, 60, 120],
  registers: [register],
});

/**
 * Saga State Transitions Counter
 * Tracks state machine transitions
 */
export const sagaStateTransitions = new Counter({
  name: 'invoice_orchestrator_state_transitions_total',
  help: 'Total number of state transitions',
  labelNames: ['from_state', 'to_state'],
  registers: [register],
});

/**
 * Saga Completion Counter
 * Tracks successful and failed saga completions
 */
export const sagaCompletionCounter = new Counter({
  name: 'invoice_orchestrator_saga_completions_total',
  help: 'Total number of saga completions',
  labelNames: ['status'],
  registers: [register],
});

/**
 * Compensation Execution Counter
 * Tracks compensation (rollback) executions
 */
export const compensationCounter = new Counter({
  name: 'invoice_orchestrator_compensations_total',
  help: 'Total number of compensation executions',
  labelNames: ['step'],
  registers: [register],
});

/**
 * Active Sagas Gauge
 * Tracks currently running sagas
 */
export const activeSagas = new Gauge({
  name: 'invoice_orchestrator_active_sagas',
  help: 'Number of currently active sagas',
  registers: [register],
});

/**
 * Message Queue Depth Gauge
 * Tracks RabbitMQ queue depth (when integrated)
 */
export const messageQueueDepth = new Gauge({
  name: 'invoice_orchestrator_queue_depth',
  help: 'Message queue depth',
  labelNames: ['queue_name'],
  registers: [register],
});

/**
 * Error Counter
 * Tracks errors by type
 */
export const errorCounter = new Counter({
  name: 'invoice_orchestrator_errors_total',
  help: 'Total number of errors',
  labelNames: ['type', 'step'],
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
