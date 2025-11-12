import 'dotenv/config';
import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import {
  logger,
  initObservability,
  getMetrics,
  requestTrackingMiddleware,
  serviceUp,
} from './observability';
import { initializePool } from './users/repository';
import { getSessionRepository } from './users/session-repository';
import { activeSessions } from './observability';

// Import routes
import authRoutes from './auth/routes';
import usersRoutes from './users/routes';
import errorsRoutes from './errors/routes';
import invoicesRoutes from './invoices/routes';
import healthRoutes from './health/routes';
import reportsRoutes from './reports/routes';
import certificatesRoutes from './certificates/routes';

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '8089', 10);
const PROMETHEUS_PORT = parseInt(process.env.PROMETHEUS_PORT || '9094', 10);

/**
 * Initialize Express app
 */
function createApp() {
  const app = express();

  // Security headers
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
        },
      },
      xFrameOptions: { action: 'deny' },
    })
  );

  // CORS configuration
  const corsOrigin = process.env.CORS_ORIGIN || 'https://admin.eracun.hr';
  app.use(
    cors({
      origin: corsOrigin.split(','),
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    })
  );

  // Body parsing
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request tracking
  app.use(requestTrackingMiddleware);

  // Rate limiting for auth endpoints
  const authLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX || '5', 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many authentication attempts, please try again later',
  });

  // Rate limiting for API endpoints
  const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Health endpoints (no auth required)
  app.get('/health', (req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      service: 'admin-portal-api',
      uptime_seconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/ready', async (req: Request, res: Response) => {
    try {
      // Check database connectivity
      const pool = initializePool();
      await pool.query('SELECT 1');

      // Update active sessions metric
      const sessionRepo = getSessionRepository();
      const activeCount = await sessionRepo.countActiveSessions();
      activeSessions.set(activeCount);

      res.json({
        status: 'ready',
        dependencies: {
          database: 'ok',
          active_sessions: activeCount,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      const error = err as Error;
      logger.error({
        error: error.message,
        msg: 'Readiness check failed',
      });

      res.status(503).json({
        status: 'not_ready',
        error: error.message,
      });
    }
  });

  // Register routes
  app.use('/api/v1/auth', authLimiter, authRoutes);
  app.use('/api/v1/users', apiLimiter, usersRoutes);
  app.use('/api/v1/errors', apiLimiter, errorsRoutes);
  app.use('/api/v1/invoices', apiLimiter, invoicesRoutes);
  app.use('/api/v1/health', apiLimiter, healthRoutes);
  app.use('/api/v1/reports', apiLimiter, reportsRoutes);
  app.use('/api/v1/certificates', apiLimiter, certificatesRoutes);

  // 404 handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({ error: 'Not found' });
  });

  // Error handler
  app.use((err: Error, req: Request, res: Response, _next: any) => {
    logger.error({
      request_id: (req as any).requestId,
      error: err.message,
      stack: err.stack,
      msg: 'Unhandled error',
    });

    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

/**
 * Start Prometheus metrics server
 */
function startMetricsServer() {
  const metricsApp = express();

  metricsApp.get('/metrics', async (req: Request, res: Response) => {
    try {
      const metrics = await getMetrics();
      res.set('Content-Type', 'text/plain');
      res.send(metrics);
    } catch (err) {
      const error = err as Error;
      logger.error({
        error: error.message,
        msg: 'Metrics endpoint error',
      });
      res.status(500).send('Metrics collection failed');
    }
  });

  const metricsServer = metricsApp.listen(PROMETHEUS_PORT, () => {
    logger.info(`Prometheus metrics server listening on port ${PROMETHEUS_PORT}`);
  });

  return metricsServer;
}

/**
 * Main startup
 */
async function main() {
  try {
    // Initialize observability
    initObservability();

    // Initialize database connection pool
    initializePool();
    logger.info('Database connection pool initialized');

    // Create Express app
    const app = createApp();

    // Start HTTP server
    const httpServer = app.listen(HTTP_PORT, () => {
      logger.info(`Admin Portal API server listening on port ${HTTP_PORT}`);
    });

    // Start Prometheus metrics server
    const metricsServer = startMetricsServer();

    // Graceful shutdown
    const shutdown = async () => {
      logger.info('Shutting down gracefully...');

      serviceUp.set(0);

      // Close HTTP server
      httpServer.close(() => {
        logger.info('HTTP server closed');
      });

      // Close metrics server
      metricsServer.close(() => {
        logger.info('Metrics server closed');
      });

      // Close database connections
      const pool = initializePool();
      await pool.end();
      logger.info('Database pool closed');

      process.exit(0);
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);

    // Cleanup expired sessions every hour
    setInterval(async () => {
      try {
        const sessionRepo = getSessionRepository();
        const deletedCount = await sessionRepo.cleanupExpiredSessions();

        if (deletedCount > 0) {
          // Update active sessions metric
          const activeCount = await sessionRepo.countActiveSessions();
          activeSessions.set(activeCount);
        }
      } catch (err) {
        const error = err as Error;
        logger.error({
          error: error.message,
          msg: 'Session cleanup failed',
        });
      }
    }, 60 * 60 * 1000); // 1 hour

    logger.info('Admin Portal API started successfully');
  } catch (err) {
    const error = err as Error;
    logger.error({
      error: error.message,
      stack: error.stack,
      msg: 'Failed to start Admin Portal API',
    });
    process.exit(1);
  }
}

// Start the server
if (require.main === module) {
  main();
}

export { createApp };
