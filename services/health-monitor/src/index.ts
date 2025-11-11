/**
 * Health Monitor Service - Main Entry Point
 *
 * System-wide health monitoring for eRacun platform:
 * - Polls all 40 services + external dependencies
 * - Monitors circuit breaker states
 * - Sends alerts for critical health changes
 * - Provides HTTP API for dashboard
 */

import {
  initObservability,
  logger,
  serviceUp,
} from './observability';
import {
  loadServiceRegistry,
  getAllServices,
  getExternalDependencies,
  Service,
} from './service-registry';
import {
  checkServiceHealth,
  HealthStatus,
  getLastKnownStatus,
} from './health-checker';
import {
  checkAllExternalDeps,
  closeAllConnections as closeExternalConnections,
} from './external-deps';
import {
  monitorCircuitBreakers,
  getCircuitBreakersRequiringAlerts,
} from './circuit-breaker';
import {
  publishHealthEvent,
  sendAlert,
  checkHealthAlert,
  checkCircuitBreakerAlert,
  disconnectKafka,
} from './alerting';
import {
  startApiServer,
  recordHealthHistory,
} from './api';

// =============================================
// Configuration
// =============================================

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '8084');
const CONFIG_PATH = process.env.SERVICE_REGISTRY_CONFIG;

// =============================================
// Health Checking State
// =============================================

const pollingIntervals: Map<string, NodeJS.Timeout> = new Map();
let isShuttingDown = false;

// =============================================
// Health Checking Logic
// =============================================

/**
 * Poll a single service health
 * @param service - Service to check
 */
async function pollService(service: Service): Promise<void> {
  if (isShuttingDown) return;

  try {
    // Check service health
    const healthResult = await checkServiceHealth(service);

    // Record in history
    recordHealthHistory(service.name, healthResult.status, healthResult.latency_ms);

    // Monitor circuit breakers
    monitorCircuitBreakers(healthResult);

    // Publish health event to Kafka
    await publishHealthEvent(healthResult);

    // Check if alert is needed
    const previousStatus = getLastKnownStatus(service.name);
    const alert = checkHealthAlert(service, healthResult, previousStatus);

    if (alert) {
      await sendAlert(alert);
    }
  } catch (error) {
    logger.error(
      {
        err: error,
        service: service.name,
      },
      'Error polling service health'
    );
  }
}

/**
 * Poll external dependencies health
 */
async function pollExternalDeps(): Promise<void> {
  if (isShuttingDown) return;

  try {
    const results = await checkAllExternalDeps();

    for (const result of results) {
      // Record in history
      recordHealthHistory(result.service_name, result.status, result.latency_ms);

      // Publish health event to Kafka
      await publishHealthEvent(result);
    }
  } catch (error) {
    logger.error({ err: error }, 'Error polling external dependencies');
  }
}

/**
 * Check circuit breakers for alerts
 */
async function checkCircuitBreakerAlerts(): Promise<void> {
  if (isShuttingDown) return;

  try {
    const { p0_alerts, p1_alerts } = getCircuitBreakersRequiringAlerts();

    for (const breaker of p0_alerts) {
      const alert = checkCircuitBreakerAlert(breaker);
      if (alert) {
        await sendAlert(alert);
      }
    }

    for (const breaker of p1_alerts) {
      const alert = checkCircuitBreakerAlert(breaker);
      if (alert) {
        await sendAlert(alert);
      }
    }
  } catch (error) {
    logger.error({ err: error }, 'Error checking circuit breaker alerts');
  }
}

/**
 * Start polling for a service
 * @param service - Service to poll
 */
function startServicePolling(service: Service): void {
  // Initial check
  pollService(service);

  // Schedule recurring checks
  const interval = setInterval(() => {
    pollService(service);
  }, service.poll_interval_ms);

  pollingIntervals.set(service.name, interval);

  logger.debug(
    {
      service: service.name,
      interval_ms: service.poll_interval_ms,
    },
    'Started polling service'
  );
}

/**
 * Start polling all services
 */
function startAllPolling(): void {
  // Load service registry
  loadServiceRegistry(CONFIG_PATH);

  // Start polling all services
  const services = getAllServices();
  for (const service of services) {
    startServicePolling(service);
  }

  logger.info({ services_count: services.length }, 'Started polling all services');

  // Start polling external dependencies (every 60 seconds)
  const externalDepsInterval = setInterval(() => {
    pollExternalDeps();
  }, 60000);
  pollingIntervals.set('external-deps', externalDepsInterval);

  // Start circuit breaker alert checks (every 30 seconds)
  const circuitBreakerInterval = setInterval(() => {
    checkCircuitBreakerAlerts();
  }, 30000);
  pollingIntervals.set('circuit-breaker-alerts', circuitBreakerInterval);

  logger.info('Health monitoring started');
}

/**
 * Stop all polling
 */
function stopAllPolling(): void {
  for (const [name, interval] of pollingIntervals.entries()) {
    clearInterval(interval);
    logger.debug({ service: name }, 'Stopped polling');
  }

  pollingIntervals.clear();
  logger.info('All polling stopped');
}

// =============================================
// Graceful Shutdown
// =============================================

async function shutdown(): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info('Shutdown signal received, cleaning up...');

  // Set service as down
  serviceUp.set(0);

  // Stop all polling
  stopAllPolling();

  // Disconnect Kafka
  await disconnectKafka();

  // Close external connections
  await closeExternalConnections();

  logger.info('Shutdown complete');
  process.exit(0);
}

// Register shutdown handlers
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// =============================================
// Main Entry Point
// =============================================

async function start(): Promise<void> {
  try {
    logger.info('Starting health-monitor service...');

    // Initialize observability (metrics, logs, traces)
    initObservability();

    // Start HTTP API server
    startApiServer(HTTP_PORT);

    // Start health monitoring
    startAllPolling();

    logger.info(
      {
        http_port: HTTP_PORT,
        service: 'health-monitor',
        version: '1.0.0',
      },
      'Health monitor service started successfully'
    );
  } catch (error) {
    logger.fatal({ err: error }, 'Failed to start health-monitor service');
    process.exit(1);
  }
}

// Start the service
start();
