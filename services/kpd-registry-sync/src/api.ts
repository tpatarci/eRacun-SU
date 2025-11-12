/**
 * HTTP REST API for KPD Registry Sync
 *
 * Provides HTTP endpoints for admin portal integration:
 * - List/search KPD codes
 * - Trigger manual sync
 * - Health checks
 * - Prometheus metrics
 *
 * Port: 8088
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import {
  logger,
  getMetrics,
  HealthStatus,
  kpdLookupRequests,
  kpdLookupDuration,
  traceOperation,
} from './observability';
import {
  getKPDCode,
  getKPDCodesPaginated,
  searchKPDCodes,
  getSyncStatistics,
  checkDatabaseHealth,
} from './repository';
import { triggerManualSync, getLastSyncResult, SyncResult } from './sync';

// ============================================================================
// Configuration
// ============================================================================

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '8088', 10);
const startTime = Date.now();

// ============================================================================
// Express App Setup
// ============================================================================

const app: Express = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const startTime = Date.now();

  res.on('finish', () => {
    const duration = (Date.now() - startTime) / 1000;
    logger.info(
      {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration_seconds: duration,
      },
      'HTTP request'
    );
  });

  next();
});

// ============================================================================
// Health & Metrics Endpoints
// ============================================================================

/**
 * GET /health - Basic health check
 */
app.get('/health', async (req: Request, res: Response) => {
  const uptime = (Date.now() - startTime) / 1000;

  try {
    const dbHealthy = await checkDatabaseHealth();

    if (dbHealthy) {
      res.status(200).json({
        status: 'healthy',
        uptime_seconds: uptime,
      });
    } else {
      res.status(503).json({
        status: 'unhealthy',
        uptime_seconds: uptime,
        error: 'Database connection failed',
      });
    }
  } catch (error) {
    logger.error({ err: error }, 'Health check failed');
    res.status(503).json({
      status: 'unhealthy',
      uptime_seconds: uptime,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /ready - Readiness check (includes dependency status)
 */
app.get('/ready', async (req: Request, res: Response) => {
  const uptime = (Date.now() - startTime) / 1000;

  try {
    const dbHealthy = await checkDatabaseHealth();
    const lastSync = await getLastSyncResult();

    const healthStatus: HealthStatus = {
      status: dbHealthy ? 'healthy' : 'degraded',
      uptime_seconds: uptime,
      dependencies: {
        database: dbHealthy ? 'up' : 'down',
        dz_s_api: 'unknown', // Can't check DZS without making a request
      },
    };

    if (lastSync) {
      healthStatus.last_sync = {
        timestamp: new Date(Date.now()).toISOString(),
        codes_added: lastSync.codes_added,
        codes_updated: lastSync.codes_updated,
        codes_deleted: lastSync.codes_deleted,
      };
    }

    res.status(dbHealthy ? 200 : 503).json(healthStatus);
  } catch (error) {
    logger.error({ err: error }, 'Readiness check failed');
    res.status(503).json({
      status: 'unhealthy',
      uptime_seconds: uptime,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /metrics - Prometheus metrics
 */
app.get('/metrics', async (req: Request, res: Response) => {
  try {
    const metrics = await getMetrics();
    res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(metrics);
  } catch (error) {
    logger.error({ err: error }, 'Failed to get metrics');
    res.status(500).json({ error: 'Failed to get metrics' });
  }
});

// ============================================================================
// KPD Code Endpoints
// ============================================================================

/**
 * GET /api/v1/kpd/codes - List all KPD codes (paginated)
 * Query params: page (default: 1), pageSize (default: 100, max: 1000)
 */
app.get('/api/v1/kpd/codes', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const page = parseInt(req.query.page as string) || 1;
  const pageSize = Math.min(parseInt(req.query.pageSize as string) || 100, 1000);

  try {
    const result = await traceOperation('http.list_codes', async (span) => {
      span.setAttribute('page', page);
      span.setAttribute('page_size', pageSize);
      return getKPDCodesPaginated(page, pageSize);
    });

    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'found' });

    res.status(200).json({
      codes: result.codes,
      pagination: {
        page,
        pageSize,
        total: result.total,
        totalPages: Math.ceil(result.total / pageSize),
      },
    });
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'error' });

    logger.error({ err: error, page, pageSize }, 'Failed to list KPD codes');
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to list KPD codes',
    });
  }
});

/**
 * GET /api/v1/kpd/codes/:code - Get specific KPD code details
 */
app.get('/api/v1/kpd/codes/:code', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { code } = req.params;

  try {
    const kpdCode = await traceOperation('http.get_code', async (span) => {
      span.setAttribute('kpd_code', code);
      return getKPDCode(code);
    });

    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);

    if (kpdCode) {
      kpdLookupRequests.inc({ status: 'found' });
      res.status(200).json(kpdCode);
    } else {
      kpdLookupRequests.inc({ status: 'not_found' });
      res.status(404).json({
        error: `KPD code '${code}' not found`,
      });
    }
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'error' });

    logger.error({ err: error, code }, 'Failed to get KPD code');
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to get KPD code',
    });
  }
});

/**
 * GET /api/v1/kpd/search - Search KPD codes by description
 * Query params: q (query string), limit (default: 100, max: 1000)
 */
app.get('/api/v1/kpd/search', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const query = req.query.q as string;
  const limit = Math.min(parseInt(req.query.limit as string) || 100, 1000);

  if (!query) {
    return res.status(400).json({
      error: 'Query parameter "q" is required',
    });
  }

  try {
    const codes = await traceOperation('http.search_codes', async (span) => {
      span.setAttribute('query', query);
      span.setAttribute('limit', limit);
      return searchKPDCodes(query, limit);
    });

    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'found' });

    res.status(200).json({
      codes,
      total_results: codes.length,
      query,
    });
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'error' });

    logger.error({ err: error, query }, 'Failed to search KPD codes');
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to search KPD codes',
    });
  }
});

// ============================================================================
// Sync Endpoints
// ============================================================================

/**
 * POST /api/v1/kpd/sync/trigger - Manually trigger sync
 */
app.post('/api/v1/kpd/sync/trigger', async (req: Request, res: Response) => {
  logger.info('Manual sync triggered via HTTP API');

  try {
    // Trigger sync asynchronously (don't wait for completion)
    triggerManualSync().catch((error) => {
      logger.error({ err: error }, 'Manual sync failed');
    });

    res.status(202).json({
      message: 'Sync triggered successfully',
      status: 'in_progress',
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to trigger sync');
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to trigger sync',
    });
  }
});

/**
 * GET /api/v1/kpd/sync/status - Get last sync status
 */
app.get('/api/v1/kpd/sync/status', async (req: Request, res: Response) => {
  try {
    const lastSync = await getLastSyncResult();
    const stats = await getSyncStatistics();

    if (lastSync) {
      res.status(200).json({
        last_sync: lastSync,
        current_stats: stats,
      });
    } else {
      res.status(200).json({
        last_sync: null,
        current_stats: stats,
        message: 'No sync has been performed yet',
      });
    }
  } catch (error) {
    logger.error({ err: error }, 'Failed to get sync status');
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to get sync status',
    });
  }
});

// ============================================================================
// Error Handling
// ============================================================================

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
  });
});

// Global error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error({ err, path: req.path, method: req.method }, 'Unhandled error in HTTP API');
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
  });
});

// ============================================================================
// Server Lifecycle
// ============================================================================

let server: any = null;

/**
 * Start HTTP server
 */
export function startHTTPServer(): Promise<void> {
  return new Promise((resolve) => {
    server = app.listen(HTTP_PORT, () => {
      logger.info({ port: HTTP_PORT }, 'HTTP API server started');
      resolve();
    });
  });
}

/**
 * Stop HTTP server (graceful shutdown)
 */
export function stopHTTPServer(): Promise<void> {
  return new Promise((resolve) => {
    if (server) {
      server.close(() => {
        logger.info('HTTP API server shut down');
        server = null;
        resolve();
      });
    } else {
      resolve();
    }
  });
}

export { app };
