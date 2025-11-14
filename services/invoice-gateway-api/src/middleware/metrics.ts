/**
 * Metrics Middleware
 *
 * Automatically tracks HTTP request metrics (duration, count, active requests).
 */

import { Request, Response, NextFunction } from 'express';
import { httpRequestDuration, httpRequestCounter, activeRequests } from '../metrics';

/**
 * Metrics Middleware
 *
 * Instruments all HTTP requests with Prometheus metrics:
 * - Request duration histogram
 * - Request counter by status code
 * - Active requests gauge
 */
export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();

  // Increment active requests
  activeRequests.inc();

  // Hook into response finish event
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000; // Convert to seconds
    const route = getRoute(req);
    const method = req.method;
    const statusCode = res.statusCode.toString();

    // Record request duration
    httpRequestDuration.labels(method, route, statusCode).observe(duration);

    // Increment request counter
    httpRequestCounter.labels(method, route, statusCode).inc();

    // Decrement active requests
    activeRequests.dec();
  });

  next();
}

/**
 * Extract route pattern from request
 *
 * Returns the Express route pattern (e.g., "/api/v1/invoices/:id")
 * Falls back to the URL path if route is not available.
 */
function getRoute(req: Request): string {
  // Express route is available on req.route?.path
  if (req.route && req.route.path) {
    return req.baseUrl + req.route.path;
  }

  // Fallback to path (less specific)
  return req.path;
}
