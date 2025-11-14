/**
 * Prometheus Metrics Configuration for UBL Transformer
 *
 * Tracks format detection, transformation success/failure, and processing times.
 */

import { Registry, Counter, Histogram, Gauge, collectDefaultMetrics } from 'prom-client';
import { Request, Response } from 'express';

// Create a custom registry
export const register = new Registry();

// Collect default metrics (CPU, memory, event loop, etc.)
collectDefaultMetrics({
  register,
  prefix: 'ubl_transformer_',
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
});

// Custom Metrics

/**
 * Transformation Duration Histogram
 * Tracks time to transform invoice to UBL 2.1
 */
export const transformationDuration = new Histogram({
  name: 'ubl_transformer_transformation_duration_seconds',
  help: 'Transformation duration in seconds',
  labelNames: ['source_format'],
  buckets: [0.1, 0.2, 0.5, 1, 2, 5, 10],
  registers: [register],
});

/**
 * Transformation Counter
 * Tracks successful and failed transformations
 */
export const transformationCounter = new Counter({
  name: 'ubl_transformer_transformations_total',
  help: 'Total number of transformations',
  labelNames: ['source_format', 'status'],
  registers: [register],
});

/**
 * Format Detection Counter
 * Tracks detected invoice formats
 */
export const formatDetectionCounter = new Counter({
  name: 'ubl_transformer_format_detections_total',
  help: 'Total number of format detections',
  labelNames: ['detected_format'],
  registers: [register],
});

/**
 * XML Size Gauge
 * Tracks input and output XML sizes
 */
export const xmlSizeGauge = new Gauge({
  name: 'ubl_transformer_xml_size_bytes',
  help: 'XML document size in bytes',
  labelNames: ['type'],
  registers: [register],
});

/**
 * Croatian CIUS Elements Added Counter
 * Tracks how many Croatian-specific elements were added
 */
export const ciusElementsCounter = new Counter({
  name: 'ubl_transformer_cius_elements_added_total',
  help: 'Total number of Croatian CIUS elements added',
  labelNames: ['element_type'],
  registers: [register],
});

/**
 * Active Transformations Gauge
 * Tracks currently running transformations
 */
export const activeTransformations = new Gauge({
  name: 'ubl_transformer_active_transformations',
  help: 'Number of currently active transformations',
  registers: [register],
});

/**
 * Error Counter
 * Tracks errors by type
 */
export const errorCounter = new Counter({
  name: 'ubl_transformer_errors_total',
  help: 'Total number of errors',
  labelNames: ['type', 'source_format'],
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
