/**
 * Exponential Backoff Calculator
 *
 * Calculates retry delays with exponential backoff and jitter
 * to prevent thundering herd problem.
 */

import { logger } from './observability';

// =============================================================================
// CONFIGURATION
// =============================================================================

const BASE_DELAY_MS = parseInt(process.env.BASE_DELAY_MS || '2000', 10); // 2 seconds
const MAX_DELAY_MS = parseInt(process.env.MAX_DELAY_MS || '60000', 10); // 60 seconds

// =============================================================================
// BACKOFF CALCULATION
// =============================================================================

/**
 * Calculate next retry delay with exponential backoff and jitter
 *
 * Formula: min(BASE_DELAY * 2^retryCount, MAX_DELAY) + jitter
 *
 * @param retryCount - Current retry attempt (0-based)
 * @returns Delay in milliseconds
 *
 * @example
 * calculateNextRetryDelay(0) // ~2000ms (2s + jitter)
 * calculateNextRetryDelay(1) // ~4000ms (4s + jitter)
 * calculateNextRetryDelay(2) // ~8000ms (8s + jitter)
 * calculateNextRetryDelay(3) // ~16000ms (16s + jitter)
 */
export function calculateNextRetryDelay(retryCount: number): number {
  // Exponential backoff: 2^retryCount
  const exponentialDelay = BASE_DELAY_MS * Math.pow(2, retryCount);

  // Cap at MAX_DELAY
  const cappedDelay = Math.min(exponentialDelay, MAX_DELAY_MS);

  // Add jitter (0-1000ms) to prevent thundering herd
  const jitter = Math.random() * 1000;

  const totalDelay = cappedDelay + jitter;

  logger.debug(
    {
      retry_count: retryCount,
      base_delay_ms: BASE_DELAY_MS,
      exponential_delay_ms: exponentialDelay,
      capped_delay_ms: cappedDelay,
      jitter_ms: jitter,
      total_delay_ms: totalDelay,
    },
    'Calculated retry delay'
  );

  return totalDelay;
}

/**
 * Calculate next retry timestamp
 *
 * @param retryCount - Current retry attempt
 * @returns Date object for next retry
 */
export function calculateNextRetryTime(retryCount: number): Date {
  const delay = calculateNextRetryDelay(retryCount);
  return new Date(Date.now() + delay);
}

/**
 * Get retry schedule for display purposes
 *
 * @param maxRetries - Maximum number of retries
 * @returns Array of delay times
 */
export function getRetrySchedule(maxRetries: number): number[] {
  const schedule: number[] = [];
  for (let i = 0; i < maxRetries; i++) {
    schedule.push(calculateNextRetryDelay(i));
  }
  return schedule;
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  calculateNextRetryDelay,
  calculateNextRetryTime,
  getRetrySchedule,
};
