/**
 * Circuit Breaker Configuration
 *
 * Implements resilience patterns using circuit breakers to prevent cascading failures
 * when external services (FINA API, digital-signature-service) are unavailable.
 *
 * Circuit Breaker States:
 * - CLOSED: Normal operation, all requests pass through
 * - OPEN: Service unavailable, all requests fail fast (no external calls)
 * - HALF_OPEN: Testing recovery, limited requests allowed
 *
 * Default Configuration:
 * - Error threshold: 50% failure rate
 * - Volume threshold: 10 requests minimum before circuit opens
 * - Timeout: 10 seconds per request
 * - Reset timeout: 30 seconds (time in OPEN state before attempting HALF_OPEN)
 */

import CircuitBreaker from 'opossum';
import {
  logger,
  circuitBreakerStateChanges,
  circuitBreakerOpen,
  circuitBreakerHalfOpen,
  circuitBreakerClosed,
  circuitBreakerFailure,
  circuitBreakerSuccess,
  circuitBreakerFallback,
  circuitBreakerTimeout,
} from './observability.js';

/**
 * Circuit Breaker Configuration
 */
export interface CircuitBreakerConfig {
  /** Circuit breaker name (for logging and metrics) */
  name: string;
  /** Request timeout (milliseconds) */
  timeout: number;
  /** Error threshold percentage (0-100) to open circuit */
  errorThresholdPercentage: number;
  /** Minimum requests before circuit can open */
  volumeThreshold: number;
  /** Time circuit stays open before attempting recovery (milliseconds) */
  resetTimeout: number;
  /** Enable circuit breaker (default: true) */
  enabled?: boolean;
}

/**
 * Default circuit breaker configuration
 */
export const DEFAULT_CIRCUIT_BREAKER_CONFIG: Omit<CircuitBreakerConfig, 'name'> = {
  timeout: 10000, // 10 seconds
  errorThresholdPercentage: 50, // 50% failure rate
  volumeThreshold: 10, // 10 requests minimum
  resetTimeout: 30000, // 30 seconds in OPEN state
  enabled: true,
};

/**
 * Circuit Breaker Error
 */
export class CircuitBreakerError extends Error {
  constructor(
    message: string,
    public circuitName: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'CircuitBreakerError';
  }
}

/**
 * Create configured circuit breaker with observability
 *
 * @param config - Circuit breaker configuration
 * @returns Circuit breaker instance
 */
export function createCircuitBreaker<T extends any[], R>(
  action: (...args: T) => Promise<R>,
  config: CircuitBreakerConfig
): CircuitBreaker<T, R> {
  // Check if circuit breakers are disabled
  if (config.enabled === false) {
    logger.info({
      name: config.name,
    }, 'Circuit breaker disabled, using pass-through wrapper');

    // Return pass-through wrapper (no circuit breaking)
    return {
      fire: action,
      // Stub other methods for compatibility
      on: () => {},
      open: () => {},
      close: () => {},
      halfOpen: () => {},
      stats: {
        fires: 0,
        successes: 0,
        failures: 0,
        timeouts: 0,
        cacheHits: 0,
        cacheMisses: 0,
        semaphoreRejections: 0,
        percentiles: {},
        latencyMean: 0,
        latencyTimes: [],
      },
    } as any;
  }

  const breaker = new CircuitBreaker(action, {
    timeout: config.timeout,
    errorThresholdPercentage: config.errorThresholdPercentage,
    volumeThreshold: config.volumeThreshold,
    resetTimeout: config.resetTimeout,
    name: config.name,
  });

  // Event: Circuit breaker state change (CLOSED → OPEN)
  breaker.on('open', () => {
    circuitBreakerStateChanges.inc({
      circuit: config.name,
      from: 'closed',
      to: 'open',
    });
    circuitBreakerOpen.set({ circuit: config.name }, 1);
    circuitBreakerClosed.set({ circuit: config.name }, 0);

    logger.warn({
      circuit: config.name,
      state: 'OPEN',
      errorThreshold: config.errorThresholdPercentage,
      volumeThreshold: config.volumeThreshold,
    }, 'Circuit breaker opened due to high failure rate');
  });

  // Event: Circuit breaker state change (OPEN → HALF_OPEN)
  breaker.on('halfOpen', () => {
    circuitBreakerStateChanges.inc({
      circuit: config.name,
      from: 'open',
      to: 'half_open',
    });
    circuitBreakerHalfOpen.set({ circuit: config.name }, 1);
    circuitBreakerOpen.set({ circuit: config.name }, 0);

    logger.info({
      circuit: config.name,
      state: 'HALF_OPEN',
    }, 'Circuit breaker testing recovery');
  });

  // Event: Circuit breaker state change (HALF_OPEN → CLOSED)
  breaker.on('close', () => {
    circuitBreakerStateChanges.inc({
      circuit: config.name,
      from: 'half_open',
      to: 'closed',
    });
    circuitBreakerClosed.set({ circuit: config.name }, 1);
    circuitBreakerHalfOpen.set({ circuit: config.name }, 0);

    logger.info({
      circuit: config.name,
      state: 'CLOSED',
    }, 'Circuit breaker closed, service recovered');
  });

  // Event: Successful request
  breaker.on('success', (result: R) => {
    circuitBreakerSuccess.inc({ circuit: config.name });

    logger.debug({
      circuit: config.name,
      state: breaker.opened ? 'OPEN' : breaker.halfOpen ? 'HALF_OPEN' : 'CLOSED',
    }, 'Circuit breaker request succeeded');
  });

  // Event: Failed request
  breaker.on('failure', (error: Error) => {
    circuitBreakerFailure.inc({ circuit: config.name });

    logger.warn({
      circuit: config.name,
      state: breaker.opened ? 'OPEN' : breaker.halfOpen ? 'HALF_OPEN' : 'CLOSED',
      error: error.message,
    }, 'Circuit breaker request failed');
  });

  // Event: Request timeout
  breaker.on('timeout', () => {
    circuitBreakerTimeout.inc({ circuit: config.name });

    logger.warn({
      circuit: config.name,
      timeout: config.timeout,
    }, 'Circuit breaker request timed out');
  });

  // Event: Fallback executed (circuit open, request rejected)
  breaker.on('fallback', (result: any) => {
    circuitBreakerFallback.inc({ circuit: config.name });

    logger.info({
      circuit: config.name,
    }, 'Circuit breaker fallback executed');
  });

  // Event: Circuit rejected (circuit open, no fallback)
  breaker.on('reject', () => {
    logger.warn({
      circuit: config.name,
      state: 'OPEN',
    }, 'Circuit breaker rejected request (circuit open)');

    throw new CircuitBreakerError(
      `Circuit breaker ${config.name} is OPEN`,
      config.name
    );
  });

  logger.info({
    name: config.name,
    timeout: config.timeout,
    errorThreshold: config.errorThresholdPercentage,
    volumeThreshold: config.volumeThreshold,
    resetTimeout: config.resetTimeout,
  }, 'Circuit breaker created');

  return breaker;
}

/**
 * Create circuit breaker for FINA SOAP operations
 */
export function createFINACircuitBreaker<T extends any[], R>(
  action: (...args: T) => Promise<R>,
  operationName: string,
  timeout?: number
): CircuitBreaker<T, R> {
  return createCircuitBreaker(action, {
    name: `fina-${operationName}`,
    timeout: timeout || DEFAULT_CIRCUIT_BREAKER_CONFIG.timeout,
    errorThresholdPercentage: DEFAULT_CIRCUIT_BREAKER_CONFIG.errorThresholdPercentage,
    volumeThreshold: DEFAULT_CIRCUIT_BREAKER_CONFIG.volumeThreshold,
    resetTimeout: DEFAULT_CIRCUIT_BREAKER_CONFIG.resetTimeout,
    enabled: process.env.CIRCUIT_BREAKER_ENABLED !== 'false',
  });
}

/**
 * Create circuit breaker for digital-signature-service operations
 */
export function createSignatureServiceCircuitBreaker<T extends any[], R>(
  action: (...args: T) => Promise<R>,
  operationName: string,
  timeout?: number
): CircuitBreaker<T, R> {
  return createCircuitBreaker(action, {
    name: `signature-service-${operationName}`,
    timeout: timeout || 5000, // Signature service has shorter timeout (5s)
    errorThresholdPercentage: DEFAULT_CIRCUIT_BREAKER_CONFIG.errorThresholdPercentage,
    volumeThreshold: DEFAULT_CIRCUIT_BREAKER_CONFIG.volumeThreshold,
    resetTimeout: DEFAULT_CIRCUIT_BREAKER_CONFIG.resetTimeout,
    enabled: process.env.CIRCUIT_BREAKER_ENABLED !== 'false',
  });
}

/**
 * Check if circuit breaker is open
 *
 * @param breaker - Circuit breaker instance
 * @returns True if circuit is open
 */
export function isCircuitBreakerOpen(breaker: CircuitBreaker<any, any>): boolean {
  return breaker.opened;
}

/**
 * Get circuit breaker statistics
 *
 * @param breaker - Circuit breaker instance
 * @returns Circuit breaker stats
 */
export function getCircuitBreakerStats(breaker: CircuitBreaker<any, any>): {
  name: string;
  state: 'OPEN' | 'HALF_OPEN' | 'CLOSED';
  fires: number;
  successes: number;
  failures: number;
  timeouts: number;
  failureRate: number;
} {
  const stats = breaker.stats;

  return {
    name: breaker.name,
    state: breaker.opened ? 'OPEN' : breaker.halfOpen ? 'HALF_OPEN' : 'CLOSED',
    fires: stats.fires,
    successes: stats.successes,
    failures: stats.failures,
    timeouts: stats.timeouts,
    failureRate:
      stats.fires > 0 ? ((stats.failures + stats.timeouts) / stats.fires) * 100 : 0,
  };
}

/**
 * Manually open circuit breaker (for testing or manual intervention)
 *
 * @param breaker - Circuit breaker instance
 */
export function openCircuitBreaker(breaker: CircuitBreaker<any, any>): void {
  breaker.open();

  logger.warn({
    circuit: breaker.name,
  }, 'Circuit breaker manually opened');
}

/**
 * Manually close circuit breaker (for testing or manual intervention)
 *
 * @param breaker - Circuit breaker instance
 */
export function closeCircuitBreaker(breaker: CircuitBreaker<any, any>): void {
  breaker.close();

  logger.info({
    circuit: breaker.name,
  }, 'Circuit breaker manually closed');
}
