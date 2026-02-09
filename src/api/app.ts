import express, { type Request, type Response, type NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../shared/logger.js';
import { healthCheck, healthCheckDb } from './routes/health.js';
import { invoiceRoutes } from './routes/invoices.js';

// Request ID middleware
export function requestIdMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const id = req.headers['x-request-id'] as string || uuidv4();
  req.id = id;
  res.setHeader('X-Request-ID', id);
  next();
}

// Error handler middleware
export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  logger.error({ error: err, requestId: req.id }, 'Request error');

  res.status(500).json({
    error: 'Internal Server Error',
    requestId: req.id,
  });
}

export function createApp() {
  const app = express();

  // Body parser with 10MB limit
  app.use(express.json({ limit: '10mb' }));

  // Request ID middleware
  app.use(requestIdMiddleware);

  // Health routes
  app.get('/health', healthCheck);
  app.get('/health/db', healthCheckDb);

  // Invoice routes
  for (const route of invoiceRoutes) {
    const middlewares = route.middleware || [];
    app[route.method](route.path, ...middlewares, route.handler);
  }

  // Error handler (must be last)
  app.use(errorHandler);

  return app;
}
