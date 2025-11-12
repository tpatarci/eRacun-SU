/**
 * OIB Validator Service - Main Entry Point
 *
 * Provides HTTP REST API and RabbitMQ consumer for OIB validation
 */

import express, { Request, Response } from 'express';
import { createServer } from 'http';
import pino from 'pino';
import { register as metricsRegister } from 'prom-client';
import {
  validateOIB,
  validateOIBBatch,
  type OIBValidationResult,
} from './oib-validator.js';
import { setupMetrics } from './observability/metrics.js';
import { setupRabbitMQ } from './messaging/rabbitmq-consumer.js';

// Configuration
const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';
const ENABLE_RABBITMQ = process.env.ENABLE_RABBITMQ === 'true';

// Logger
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport:
    NODE_ENV === 'development'
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname',
          },
        }
      : undefined,
});

// Express app
const app = express();
app.use(express.json({ limit: '1mb' }));

// Request logging middleware
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();
  req.headers['x-request-id'] = requestId as string;
  res.setHeader('X-Request-ID', requestId as string);

  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info({
      requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs: duration,
    });
  });

  next();
});

// Setup metrics
setupMetrics();

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'oib-validator',
    timestamp: new Date().toISOString(),
  });
});

// Readiness check endpoint
app.get('/ready', (_req: Request, res: Response) => {
  res.json({
    status: 'ready',
    service: 'oib-validator',
    timestamp: new Date().toISOString(),
  });
});

// Metrics endpoint
app.get('/metrics', async (_req: Request, res: Response) => {
  res.setHeader('Content-Type', metricsRegister.contentType);
  const metrics = await metricsRegister.metrics();
  res.send(metrics);
});

// Validate single OIB endpoint
app.post('/api/v1/validate', (req: Request, res: Response) => {
  const { oib } = req.body;

  if (!oib) {
    return res.status(400).json({
      error: 'Missing required field: oib',
      requestId: req.headers['x-request-id'],
    });
  }

  try {
    const result: OIBValidationResult = validateOIB(oib);
    return res.json(result);
  } catch (error) {
    logger.error({ error, requestId: req.headers['x-request-id'] }, 'Validation error');
    return res.status(500).json({
      error: 'Internal server error',
      requestId: req.headers['x-request-id'],
    });
  }
});

// Validate batch of OIBs endpoint
app.post('/api/v1/validate/batch', (req: Request, res: Response) => {
  const { oibs } = req.body;

  if (!oibs || !Array.isArray(oibs)) {
    return res.status(400).json({
      error: 'Missing required field: oibs (must be array)',
      requestId: req.headers['x-request-id'],
    });
  }

  if (oibs.length > 1000) {
    return res.status(400).json({
      error: 'Batch size exceeds maximum of 1000 OIBs',
      requestId: req.headers['x-request-id'],
    });
  }

  try {
    const results: OIBValidationResult[] = validateOIBBatch(oibs);
    return res.json({
      total: results.length,
      valid: results.filter((r) => r.valid).length,
      invalid: results.filter((r) => !r.valid).length,
      results,
    });
  } catch (error) {
    logger.error({ error, requestId: req.headers['x-request-id'] }, 'Batch validation error');
    return res.status(500).json({
      error: 'Internal server error',
      requestId: req.headers['x-request-id'],
    });
  }
});

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not found',
  });
});

// Error handler
app.use((err: Error, req: Request, res: Response, _next: unknown) => {
  logger.error({ error: err, requestId: req.headers['x-request-id'] }, 'Unhandled error');
  res.status(500).json({
    error: 'Internal server error',
    requestId: req.headers['x-request-id'],
  });
});

// Create HTTP server
const server = createServer(app);

// Graceful shutdown
const shutdown = async () => {
  logger.info('Shutting down gracefully...');

  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start server
server.listen(PORT, HOST, async () => {
  logger.info(`OIB Validator service listening on ${HOST}:${PORT}`);
  logger.info(`Environment: ${NODE_ENV}`);
  logger.info(`Health check: http://${HOST}:${PORT}/health`);
  logger.info(`Metrics: http://${HOST}:${PORT}/metrics`);

  // Setup RabbitMQ consumer if enabled
  if (ENABLE_RABBITMQ) {
    try {
      await setupRabbitMQ(RABBITMQ_URL, logger);
      logger.info('RabbitMQ consumer connected');
    } catch (error) {
      logger.error({ error }, 'Failed to connect to RabbitMQ');
      process.exit(1);
    }
  } else {
    logger.info('RabbitMQ consumer disabled');
  }
});
