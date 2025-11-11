/**
 * Circuit Breaker Monitoring Module
 *
 * Monitors circuit breaker states from service health responses:
 * - Tracks state changes (CLOSED → OPEN → HALF_OPEN)
 * - Detects when circuit breakers open (service degraded)
 * - Alerts when circuit stays open > 5 minutes (extended outage)
 */

import {
  logger,
  circuitBreakerState,
  circuitBreakerStateToMetric,
} from './observability';
import { HealthCheckResult } from './health-checker';

// =============================================
// Types
// =============================================

export enum CircuitBreakerState {
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half-open',
}

export interface CircuitBreakerInfo {
  service: string;
  breaker_name: string;
  state: CircuitBreakerState;
  failure_rate?: number;
  last_state_change_ms: number;
  consecutive_failures?: number;
}

// Track circuit breaker states
const circuitBreakers: Map<string, CircuitBreakerInfo> = new Map();

// =============================================
// Circuit Breaker Monitoring
// =============================================

/**
 * Extract and monitor circuit breakers from health check result
 * @param healthResult - Health check result from service
 * @returns Array of circuit breaker info
 */
export function monitorCircuitBreakers(healthResult: HealthCheckResult): CircuitBreakerInfo[] {
  const breakers: CircuitBreakerInfo[] = [];

  // Check if health response contains circuit breaker data
  const circuitBreakerCheck = healthResult.checks?.circuit_breaker;
  if (!circuitBreakerCheck) {
    return breakers;
  }

  // Extract circuit breaker state
  const state = normalizeCircuitBreakerState(circuitBreakerCheck.status || 'closed');
  const failureRate = circuitBreakerCheck.failure_rate;

  // Create circuit breaker info
  const breakerKey = `${healthResult.service_name}:default`;
  const breakerInfo: CircuitBreakerInfo = {
    service: healthResult.service_name,
    breaker_name: 'default',
    state,
    failure_rate: failureRate,
    last_state_change_ms: healthResult.timestamp_ms,
  };

  // Check for state change
  const previousInfo = circuitBreakers.get(breakerKey);
  if (previousInfo && previousInfo.state !== state) {
    logger.warn(
      {
        service: healthResult.service_name,
        breaker: 'default',
        previous_state: previousInfo.state,
        new_state: state,
        failure_rate: failureRate,
      },
      'Circuit breaker state changed'
    );

    // Update last state change timestamp
    breakerInfo.last_state_change_ms = healthResult.timestamp_ms;
  } else if (previousInfo) {
    // Keep previous timestamp if state unchanged
    breakerInfo.last_state_change_ms = previousInfo.last_state_change_ms;
  }

  // Update tracking map
  circuitBreakers.set(breakerKey, breakerInfo);

  // Update Prometheus metric
  circuitBreakerState.set(
    { service: healthResult.service_name, breaker: 'default' },
    circuitBreakerStateToMetric(state)
  );

  breakers.push(breakerInfo);

  return breakers;
}

/**
 * Normalize circuit breaker state string
 * @param state - State string from service response
 * @returns CircuitBreakerState
 */
function normalizeCircuitBreakerState(state: string): CircuitBreakerState {
  const normalized = state.toLowerCase().replace('_', '-');

  switch (normalized) {
    case 'closed':
      return CircuitBreakerState.CLOSED;
    case 'open':
      return CircuitBreakerState.OPEN;
    case 'half-open':
    case 'halfopen':
      return CircuitBreakerState.HALF_OPEN;
    default:
      logger.warn({ state }, 'Unknown circuit breaker state, defaulting to closed');
      return CircuitBreakerState.CLOSED;
  }
}

/**
 * Get all currently tracked circuit breakers
 * @returns Array of all circuit breaker info
 */
export function getAllCircuitBreakers(): CircuitBreakerInfo[] {
  return Array.from(circuitBreakers.values());
}

/**
 * Get circuit breakers in OPEN state
 * @returns Array of open circuit breakers
 */
export function getOpenCircuitBreakers(): CircuitBreakerInfo[] {
  return Array.from(circuitBreakers.values()).filter(
    (breaker) => breaker.state === CircuitBreakerState.OPEN
  );
}

/**
 * Get circuit breaker for a specific service
 * @param serviceName - Service name
 * @param breakerName - Circuit breaker name (default: 'default')
 * @returns CircuitBreakerInfo or undefined
 */
export function getCircuitBreaker(serviceName: string, breakerName = 'default'): CircuitBreakerInfo | undefined {
  return circuitBreakers.get(`${serviceName}:${breakerName}`);
}

/**
 * Check if circuit breaker requires P0 alert (open >5 minutes)
 * @param breaker - Circuit breaker info
 * @returns true if alert should be sent
 */
export function requiresP0Alert(breaker: CircuitBreakerInfo): boolean {
  if (breaker.state !== CircuitBreakerState.OPEN) {
    return false;
  }

  const openDurationMs = Date.now() - breaker.last_state_change_ms;
  const FIVE_MINUTES_MS = 5 * 60 * 1000;

  return openDurationMs > FIVE_MINUTES_MS;
}

/**
 * Check if circuit breaker requires P1 alert (just opened)
 * @param breaker - Circuit breaker info
 * @returns true if alert should be sent
 */
export function requiresP1Alert(breaker: CircuitBreakerInfo): boolean {
  if (breaker.state !== CircuitBreakerState.OPEN) {
    return false;
  }

  const openDurationMs = Date.now() - breaker.last_state_change_ms;
  const ONE_MINUTE_MS = 60 * 1000;

  // Alert if opened within last minute (newly opened)
  return openDurationMs < ONE_MINUTE_MS;
}

/**
 * Get circuit breakers requiring alerts
 * @returns Object with P0 and P1 alert lists
 */
export function getCircuitBreakersRequiringAlerts(): {
  p0_alerts: CircuitBreakerInfo[];
  p1_alerts: CircuitBreakerInfo[];
} {
  const openBreakers = getOpenCircuitBreakers();

  return {
    p0_alerts: openBreakers.filter(requiresP0Alert),
    p1_alerts: openBreakers.filter(requiresP1Alert),
  };
}

/**
 * Reset circuit breaker tracking (for testing)
 */
export function resetCircuitBreakers(): void {
  circuitBreakers.clear();
}
