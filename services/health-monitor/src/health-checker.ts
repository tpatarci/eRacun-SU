/**
 * Health Checker Module
 *
 * Core health checking logic:
 * - Polls service health endpoints
 * - Calculates health status (healthy/degraded/unhealthy)
 * - Implements retry logic (3 consecutive failures → UNHEALTHY)
 * - Tracks health state changes
 */

import axios, { AxiosError } from 'axios';
import {
  logger,
  createSpan,
  setSpanError,
  serviceHealthStatus,
  healthCheckSuccess,
  healthCheckFailures,
  healthCheckDuration,
  healthStatusToMetric,
} from './observability';
import { Service } from './service-registry';

// =============================================
// Types
// =============================================

export enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
}

export interface HealthCheckResult {
  service_name: string;
  status: HealthStatus;
  checks: {
    database?: { status: string; latency_ms?: number };
    message_queue?: { status: string; latency_ms?: number };
    circuit_breaker?: { status: string; failure_rate?: number };
  };
  uptime_seconds?: number;
  version?: string;
  timestamp_ms: number;
  latency_ms: number;
  error?: string;
}

// Track consecutive failures for each service
const failureCounters: Map<string, number> = new Map();

// Track consecutive successes for each service
const successCounters: Map<string, number> = new Map();

// Track last known status for each service
const lastKnownStatus: Map<string, HealthStatus> = new Map();

// =============================================
// Health Check Configuration
// =============================================

const HEALTH_CHECK_TIMEOUT_MS = parseInt(process.env.HEALTH_CHECK_TIMEOUT_MS || '5000');
const FAILURE_THRESHOLD = parseInt(process.env.FAILURE_THRESHOLD || '3');
const SUCCESS_THRESHOLD = 2; // 2 consecutive successes → mark HEALTHY

// =============================================
// Core Health Checking
// =============================================

/**
 * Check health of a single service
 * @param service - Service to check
 * @returns HealthCheckResult
 */
export async function checkServiceHealth(service: Service): Promise<HealthCheckResult> {
  const span = createSpan('check_service_health', {
    'service.name': service.name,
    'service.url': service.health_url,
  });

  const startTime = Date.now();

  try {
    // HTTP GET to health endpoint with timeout
    const response = await axios.get(service.health_url, {
      timeout: HEALTH_CHECK_TIMEOUT_MS,
      validateStatus: (status) => status >= 200 && status < 600, // Accept all HTTP statuses
    });

    const latency_ms = Date.now() - startTime;

    // Parse response
    const healthData = response.data;

    // Calculate status from response
    const status = calculateHealthStatus(healthData, response.status);

    // Update failure/success counters
    updateCounters(service.name, status);

    // Record metrics
    healthCheckDuration.observe({ service: service.name }, latency_ms / 1000);
    healthCheckSuccess.inc({ service: service.name });
    serviceHealthStatus.set({ service: service.name }, healthStatusToMetric(status));

    // Detect status changes
    const previousStatus = lastKnownStatus.get(service.name);
    if (previousStatus && previousStatus !== status) {
      logger.info(
        {
          service: service.name,
          previous_status: previousStatus,
          new_status: status,
        },
        'Service health status changed'
      );
    }
    lastKnownStatus.set(service.name, status);

    span.end();

    return {
      service_name: service.name,
      status,
      checks: healthData.checks || {},
      uptime_seconds: healthData.uptime_seconds,
      version: healthData.version,
      timestamp_ms: Date.now(),
      latency_ms,
    };
  } catch (error) {
    const latency_ms = Date.now() - startTime;

    // Determine failure reason
    let reason = 'unknown';
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError;
      if (axiosError.code === 'ECONNREFUSED') {
        reason = 'connection_refused';
      } else if (axiosError.code === 'ETIMEDOUT') {
        reason = 'timeout';
      } else if (axiosError.code === 'ENOTFOUND') {
        reason = 'dns_failure';
      } else {
        reason = 'http_error';
      }
    }

    // Update failure counters
    updateCounters(service.name, HealthStatus.UNHEALTHY);

    // Record metrics
    healthCheckFailures.inc({ service: service.name, reason });
    serviceHealthStatus.set({ service: service.name }, 0); // UNHEALTHY

    // Detect status changes
    const previousStatus = lastKnownStatus.get(service.name);
    if (previousStatus !== HealthStatus.UNHEALTHY) {
      logger.warn(
        {
          service: service.name,
          previous_status: previousStatus,
          new_status: HealthStatus.UNHEALTHY,
          reason,
          error: (error as Error).message,
        },
        'Service became unhealthy'
      );
    }
    lastKnownStatus.set(service.name, HealthStatus.UNHEALTHY);

    setSpanError(span, error as Error);
    span.end();

    return {
      service_name: service.name,
      status: HealthStatus.UNHEALTHY,
      checks: {},
      timestamp_ms: Date.now(),
      latency_ms,
      error: (error as Error).message,
    };
  }
}

/**
 * Calculate health status from service response
 * @param healthData - Parsed health response
 * @param httpStatus - HTTP status code
 * @returns HealthStatus
 */
function calculateHealthStatus(healthData: any, httpStatus: number): HealthStatus {
  // HTTP 503 or 500 → UNHEALTHY
  if (httpStatus >= 500) {
    return HealthStatus.UNHEALTHY;
  }

  // HTTP 429 → DEGRADED (rate limited)
  if (httpStatus === 429) {
    return HealthStatus.DEGRADED;
  }

  // Parse status from response body
  if (healthData.status) {
    const status = healthData.status.toLowerCase();
    if (status === 'healthy') return HealthStatus.HEALTHY;
    if (status === 'degraded') return HealthStatus.DEGRADED;
    if (status === 'unhealthy') return HealthStatus.UNHEALTHY;
  }

  // Check critical dependencies
  const checks = healthData.checks || {};

  // Database unhealthy → UNHEALTHY
  if (checks.database?.status === 'unhealthy') {
    return HealthStatus.UNHEALTHY;
  }

  // Message queue unhealthy → UNHEALTHY
  if (checks.message_queue?.status === 'unhealthy') {
    return HealthStatus.UNHEALTHY;
  }

  // Circuit breaker open → DEGRADED
  if (checks.circuit_breaker?.status === 'open') {
    return HealthStatus.DEGRADED;
  }

  // Default to HEALTHY if HTTP 2xx
  return httpStatus >= 200 && httpStatus < 300 ? HealthStatus.HEALTHY : HealthStatus.DEGRADED;
}

/**
 * Update failure/success counters and apply retry logic
 * @param serviceName - Service name
 * @param status - Current health status
 */
function updateCounters(serviceName: string, status: HealthStatus): void {
  if (status === HealthStatus.UNHEALTHY) {
    // Increment failure counter
    const failures = (failureCounters.get(serviceName) || 0) + 1;
    failureCounters.set(serviceName, failures);
    successCounters.set(serviceName, 0); // Reset success counter

    if (failures >= FAILURE_THRESHOLD) {
      logger.warn(
        {
          service: serviceName,
          consecutive_failures: failures,
          threshold: FAILURE_THRESHOLD,
        },
        'Service exceeded failure threshold'
      );
    }
  } else {
    // Increment success counter
    const successes = (successCounters.get(serviceName) || 0) + 1;
    successCounters.set(serviceName, successes);
    failureCounters.set(serviceName, 0); // Reset failure counter

    if (successes >= SUCCESS_THRESHOLD) {
      logger.debug(
        {
          service: serviceName,
          consecutive_successes: successes,
        },
        'Service recovered'
      );
    }
  }
}

/**
 * Get current failure count for a service
 * @param serviceName - Service name
 * @returns Number of consecutive failures
 */
export function getFailureCount(serviceName: string): number {
  return failureCounters.get(serviceName) || 0;
}

/**
 * Get current success count for a service
 * @param serviceName - Service name
 * @returns Number of consecutive successes
 */
export function getSuccessCount(serviceName: string): number {
  return successCounters.get(serviceName) || 0;
}

/**
 * Get last known status for a service
 * @param serviceName - Service name
 * @returns HealthStatus or undefined if never checked
 */
export function getLastKnownStatus(serviceName: string): HealthStatus | undefined {
  return lastKnownStatus.get(serviceName);
}

/**
 * Reset counters for a service (for testing)
 * @param serviceName - Service name
 */
export function resetCounters(serviceName?: string): void {
  if (serviceName) {
    failureCounters.delete(serviceName);
    successCounters.delete(serviceName);
    lastKnownStatus.delete(serviceName);
  } else {
    failureCounters.clear();
    successCounters.clear();
    lastKnownStatus.clear();
  }
}

/**
 * Check if service requires alert (exceeded failure threshold)
 * @param serviceName - Service name
 * @returns true if alert should be sent
 */
export function requiresAlert(serviceName: string): boolean {
  return getFailureCount(serviceName) >= FAILURE_THRESHOLD;
}
