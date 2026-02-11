import express, { type Request, type Response, type NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import session from 'express-session';
import RedisStore from 'connect-redis';
import Redis from 'ioredis';
import { logger } from '../shared/logger.js';
import { loadConfig } from '../shared/config.js';
import { healthCheck, healthCheckDb } from './routes/health.js';
import { invoiceRoutes } from './routes/invoices.js';
import { userRoutes } from './routes/users.js';
import { configRoutes } from './routes/config.js';
import { authRoutes } from './routes/auth.js';

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

/**
 * Create and configure session middleware with Redis store
 * Session data includes user authentication state
 */
function createSessionMiddleware() {
  const config = loadConfig();

  // Initialize Redis client for session store
  const redis = new Redis(config.REDIS_URL, {
    maxRetriesPerRequest: 3,
    enableReadyCheck: false,
  });

  redis.on('error', (err) => {
    logger.error({ error: err }, 'Redis session store error');
  });

  redis.on('connect', () => {
    logger.debug('Redis session store connected');
  });

  // Create Redis store for express-session
  // connect-redis v7+ uses a factory function
  const RedisStoreClass = RedisStore as unknown as {
    new (options: { client: Redis; prefix: string }): session.Store;
  };
  const store = new RedisStoreClass({
    client: redis,
    prefix: 'sess:',
  });

  // Configure session middleware
  // Security: httpOnly prevents XSS, secure flag in production prevents MITM
  const isProduction = config.NODE_ENV === 'production';

  return session({
    store,
    name: 'eracun.sid',
    secret: process.env.SESSION_SECRET || 'change-this-in-production-use-env-var',
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset session expiration on each request
    cookie: {
      httpOnly: true, // Prevent XSS attacks
      secure: isProduction, // HTTPS-only in production
      sameSite: 'lax', // CSRF protection
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  });
}

export function createApp() {
  const app = express();

  // Body parser with 10MB limit
  app.use(express.json({ limit: '10mb' }));

  // Session middleware (must come before request ID middleware)
  app.use(createSessionMiddleware());

  // Request ID middleware
  app.use(requestIdMiddleware);

  // Health routes
  app.get('/health', healthCheck);
  app.get('/health/db', healthCheckDb);

  // Invoice routes
  for (const route of invoiceRoutes) {
    const middlewares = 'middleware' in route ? (route.middleware ?? []) : [];
    (app as any)[route.method]('/api/v1/invoices' + route.path, ...middlewares, route.handler);
  }

  // User routes
  for (const route of userRoutes) {
    const middlewares = 'middleware' in route ? (route.middleware ?? []) : [];
    (app as any)[route.method]('/api/v1/users' + route.path, ...middlewares, route.handler);
  }

  // Config routes
  for (const route of configRoutes) {
    const middlewares = 'middleware' in route ? (route.middleware ?? []) : [];
    (app as any)[route.method]('/api/v1/users' + route.path, ...middlewares, route.handler);
  }

  // Auth routes
  for (const route of authRoutes) {
    const middlewares = 'middleware' in route ? (route.middleware ?? []) : [];
    (app as any)[route.method]('/api/v1/auth' + route.path, ...middlewares, route.handler);
  }

  // Error handler (must be last)
  app.use(errorHandler);

  return app;
}
