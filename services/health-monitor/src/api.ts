/**
 * HTTP REST API Module
 *
 * Provides health dashboard data via HTTP endpoints:
 * - GET /health/dashboard - All services health status
 * - GET /health/services/:name - Specific service details
 * - GET /health/external - External dependency health
 * - GET /health/circuit-breakers - All circuit breaker states
 * - GET /health/history/:service - Historical health (last 24h)
 */

import express, { Request, Response } from 'express';
import cors from 'cors';
import { register, logger } from './observability';
import { getAllServices, getExternalDependencies, getServiceByName } from './service-registry';
import { HealthStatus, getLastKnownStatus } from './health-checker';
import { getAllCircuitBreakers, getCircuitBreaker } from './circuit-breaker';

// =============================================
// Types
// =============================================

interface DashboardResponse {
  system_health: HealthStatus;
  healthy_services: number;
  degraded_services: number;
  unhealthy_services: number;
  timestamp: string;
  services: Array<{
    name: string;
    status: HealthStatus;
    critical: boolean;
    last_check?: string;
    uptime_seconds?: number;
  }>;
}

// =============================================
// In-Memory Health History
// =============================================
// Note: For production, consider using Redis or time-series DB

interface HealthHistoryEntry {
  timestamp_ms: number;
  status: HealthStatus;
  latency_ms?: number;
}

const healthHistory: Map<string, HealthHistoryEntry[]> = new Map();
const MAX_HISTORY_ENTRIES = 288; // 24 hours at 5-minute intervals

/**
 * Record health check in history
 * @param serviceName - Service name
 * @param status - Health status
 * @param latency_ms - Check latency
 */
export function recordHealthHistory(serviceName: string, status: HealthStatus, latency_ms?: number): void {
  const history = healthHistory.get(serviceName) || [];

  history.push({
    timestamp_ms: Date.now(),
    status,
    latency_ms,
  });

  // Keep only last 24 hours
  if (history.length > MAX_HISTORY_ENTRIES) {
    history.shift();
  }

  healthHistory.set(serviceName, history);
}

// =============================================
// Express Application
// =============================================

export const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  logger.debug(
    {
      method: req.method,
      path: req.path,
      ip: req.ip,
    },
    'HTTP request received'
  );
  next();
});

// =============================================
// API Endpoints
// =============================================

/**
 * GET /health/dashboard
 * Returns overall system health and all services
 */
app.get('/health/dashboard', (req: Request, res: Response) => {
  try {
    const services = getAllServices();
    const externalDeps = getExternalDependencies();
    const allMonitoredServices = [...services, ...externalDeps];

    // Count services by status
    let healthy = 0;
    let degraded = 0;
    let unhealthy = 0;

    const servicesStatus = allMonitoredServices.map((service) => {
      const status = getLastKnownStatus(service.name) || HealthStatus.UNHEALTHY;

      if (status === HealthStatus.HEALTHY) healthy++;
      else if (status === HealthStatus.DEGRADED) degraded++;
      else unhealthy++;

      return {
        name: service.name,
        status,
        critical: service.critical,
        // last_check and uptime_seconds would come from health check result tracking
      };
    });

    // Calculate overall system health
    let systemHealth: HealthStatus;
    if (unhealthy > 0) {
      systemHealth = HealthStatus.UNHEALTHY;
    } else if (degraded > 0) {
      systemHealth = HealthStatus.DEGRADED;
    } else {
      systemHealth = HealthStatus.HEALTHY;
    }

    const response: DashboardResponse = {
      system_health: systemHealth,
      healthy_services: healthy,
      degraded_services: degraded,
      unhealthy_services: unhealthy,
      timestamp: new Date().toISOString(),
      services: servicesStatus,
    };

    res.json(response);
  } catch (error) {
    logger.error({ err: error }, 'Failed to get dashboard data');
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /health/services/:name
 * Returns specific service health details
 */
app.get('/health/services/:name', (req: Request, res: Response) => {
  try {
    const serviceName = req.params.name;

    const service = getServiceByName(serviceName);
    if (!service) {
      return res.status(404).json({ error: 'Service not found' });
    }

    const status = getLastKnownStatus(serviceName) || HealthStatus.UNHEALTHY;

    res.json({
      name: serviceName,
      status,
      critical: service.critical,
      poll_interval_ms: service.poll_interval_ms,
      layer: service.layer,
      description: service.description,
      health_url: service.health_url,
      ready_url: service.ready_url,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error({ err: error, service: req.params.name }, 'Failed to get service details');
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /health/external
 * Returns external dependency health
 */
app.get('/health/external', (req: Request, res: Response) => {
  try {
    const externalDeps = getExternalDependencies();

    const depsStatus = externalDeps.map((dep) => {
      const status = getLastKnownStatus(dep.name) || HealthStatus.UNHEALTHY;

      return {
        name: dep.name,
        status,
        health_url: dep.health_url,
      };
    });

    res.json({
      external_dependencies: depsStatus,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to get external dependencies');
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /health/circuit-breakers
 * Returns all circuit breaker states
 */
app.get('/health/circuit-breakers', (req: Request, res: Response) => {
  try {
    const breakers = getAllCircuitBreakers();

    const breakersData = breakers.map((breaker) => ({
      service: breaker.service,
      breaker_name: breaker.breaker_name,
      state: breaker.state,
      failure_rate: breaker.failure_rate,
      last_state_change: new Date(breaker.last_state_change_ms).toISOString(),
      open_duration_seconds: breaker.state === 'open'
        ? Math.floor((Date.now() - breaker.last_state_change_ms) / 1000)
        : 0,
    }));

    res.json({
      circuit_breakers: breakersData,
      total_open: breakersData.filter((b) => b.state === 'open').length,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to get circuit breakers');
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /health/history/:service
 * Returns historical health data (last 24h)
 */
app.get('/health/history/:service', (req: Request, res: Response) => {
  try {
    const serviceName = req.params.service;
    const history = healthHistory.get(serviceName) || [];

    res.json({
      service: serviceName,
      history: history.map((entry) => ({
        timestamp: new Date(entry.timestamp_ms).toISOString(),
        status: entry.status,
        latency_ms: entry.latency_ms,
      })),
      total_entries: history.length,
      time_range: '24 hours',
    });
  } catch (error) {
    logger.error({ err: error, service: req.params.service }, 'Failed to get service history');
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /health
 * Health check endpoint for health-monitor itself
 */
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'health-monitor',
    uptime_seconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /ready
 * Readiness check endpoint
 */
app.get('/ready', (req: Request, res: Response) => {
  // Check if service registry is loaded
  try {
    getAllServices();
    res.json({
      status: 'ready',
      service: 'health-monitor',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      status: 'not_ready',
      error: 'Service registry not loaded',
    });
  }
});

/**
 * GET /metrics
 * Prometheus metrics endpoint
 */
app.get('/metrics', async (req: Request, res: Response) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (error) {
    logger.error({ err: error }, 'Failed to export metrics');
    res.status(500).end('Error exporting metrics');
  }
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err: Error, req: Request, res: Response, next: any) => {
  logger.error({ err }, 'Unhandled error in API');
  res.status(500).json({ error: 'Internal server error' });
});

/**
 * Start HTTP API server
 * @param port - Port number
 * @returns Express server
 */
export function startApiServer(port: number): any {
  const server = app.listen(port, () => {
    logger.info({ port }, 'HTTP API server started');
  });

  return server;
}
