/**
 * Express Application Configuration
 */

import express, { Application, Request, Response, NextFunction } from 'express';
import { Container } from 'inversify';
import cors from 'cors';
import helmet from 'helmet';
import pinoHttp from 'pino-http';
import pino from 'pino';

import { errorHandler } from './middleware/error-handler';
import { rateLimiter } from './middleware/rate-limiter';
import { idempotencyMiddleware } from './middleware/idempotency';
import { requestIdMiddleware } from './middleware/request-id';

import { invoiceRoutes } from './routes/invoice.routes';
import { healthRoutes } from './routes/health.routes';

const logger = pino({ name: 'invoice-gateway-api' });

export function createApp(container: Container): Application {
  const app = express();

  // Security middleware
  app.use(helmet());
  app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  }));

  // Logging middleware
  app.use(pinoHttp({ logger }));

  // Request ID middleware (must be before other middleware)
  app.use(requestIdMiddleware);

  // Body parsing
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  app.use(express.text({ type: 'application/xml', limit: '10mb' }));

  // Rate limiting (100 req/min per client)
  app.use('/api/v1/invoices', rateLimiter);

  // Idempotency middleware for POST requests
  app.use(idempotencyMiddleware(container));

  // Routes
  app.use('/api/v1/invoices', invoiceRoutes(container));
  app.use('/api/v1/health', healthRoutes(container));

  // Root endpoint
  app.get('/', (req: Request, res: Response) => {
    res.json({
      service: 'invoice-gateway-api',
      version: '1.0.0',
      status: 'running',
      endpoints: {
        health: '/api/v1/health',
        invoices: '/api/v1/invoices',
        docs: '/api/v1/docs',
      },
    });
  });

  // 404 handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({
      error: {
        code: 'NOT_FOUND',
        message: `Route ${req.method} ${req.path} not found`,
        timestamp: new Date().toISOString(),
      },
    });
  });

  // Error handler (must be last)
  app.use(errorHandler);

  return app;
}
