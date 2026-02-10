import express, { type Request, type Response, type NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../shared/logger.js';
import { healthCheck, healthCheckDb } from './routes/health.js';
import { invoiceRoutes } from './routes/invoices.js';
import { buildErrorResponse, NotFoundError, ValidationError, InternalError, UnauthorizedError, ForbiddenError, ConflictError, BadRequestError } from './errors.js';

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

  // Determine status code based on error type
  let statusCode = 500;
  if (err instanceof NotFoundError) {
    statusCode = 404;
  } else if (err instanceof ValidationError) {
    statusCode = 400;
  } else if (err instanceof UnauthorizedError) {
    statusCode = 401;
  } else if (err instanceof ForbiddenError) {
    statusCode = 403;
  } else if (err instanceof ConflictError) {
    statusCode = 409;
  } else if (err instanceof BadRequestError) {
    statusCode = 400;
  }
  // Default to 500 for all other errors (including plain Error and APIError)

  // Build standardized error response
  const errorResponse = buildErrorResponse(err, req.id, statusCode);

  res.status(statusCode).json(errorResponse);
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
