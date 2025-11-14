/**
 * HTTP REST API for Admin Portal
 *
 * Provides endpoints for manual error review and resolution:
 * - GET /api/v1/errors - List all errors
 * - GET /api/v1/errors/:id - Get error details
 * - POST /api/v1/errors/:id/resolve - Mark error as resolved
 * - POST /api/v1/errors/:id/resubmit - Resubmit to original queue
 * - GET /api/v1/errors/stats - Error statistics
 *
 * See: README.md §2.4 for API specification
 */

import express, { Request, Response, NextFunction } from 'express';
import { Channel } from 'amqplib';
import { ManualReviewRepository } from './repository';
import { createLogger } from './utils/logger';
import { httpRequestsTotal, httpRequestDuration } from './observability';

const logger = createLogger('api');

export interface APIDependencies {
  repository: ManualReviewRepository;
  retryChannel: Channel;
}

/**
 * Create Express HTTP API server
 *
 * @param deps - API dependencies
 * @param port - HTTP port to listen on
 * @returns Express app instance
 */
export function createAPI(deps: APIDependencies, port: number): express.Application {
  const app = express();

  app.use(express.json({ limit: '1mb' }));

  // Request ID middleware
  app.use((req, _res, next) => {
    req.headers['x-request-id'] = req.headers['x-request-id'] ?? generateRequestId();
    next();
  });

  // Request timing middleware
  app.use((req, res, next) => {
    const startTime = Date.now();

    res.on('finish', () => {
      const duration = (Date.now() - startTime) / 1000;
      const route = req.route?.path || req.path;

      httpRequestDuration.observe({ method: req.method, route }, duration);
      httpRequestsTotal.inc({
        method: req.method,
        route,
        status: res.statusCode.toString(),
      });
    });

    next();
  });

  // Health checks
  app.get('/health/live', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.get('/health/ready', async (_req, res) => {
    try {
      // Check database connectivity
      await deps.repository.getStats();
      res.status(200).json({ status: 'ready' });
    } catch (error) {
      logger.error('Readiness check failed', { error });
      res.status(503).json({ status: 'not ready', error: 'Database unavailable' });
    }
  });

  /**
   * GET /api/v1/errors
   * List all errors with pagination
   */
  app.get('/api/v1/errors', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { status, limit = '100', offset = '0' } = req.query;

      logger.info('Listing errors', {
        status,
        limit,
        offset,
        requestId: req.headers['x-request-id'],
      });

      const limitNum = parseInt(limit as string, 10);
      const offsetNum = parseInt(offset as string, 10);

      let errors;
      if (status) {
        errors = await deps.repository.listByStatus(
          status as 'pending' | 'in_review' | 'resolved',
          limitNum,
          offsetNum
        );
      } else {
        errors = await deps.repository.listErrors(limitNum, offsetNum);
      }

      // Sanitize - don't send full message payload in list view
      const sanitized = errors.map((error) => ({
        error_id: error.error_id,
        invoice_id: error.invoice_id,
        service_name: error.service_name,
        error_classification: error.error_classification,
        error_reason: error.error_reason,
        retry_count: error.retry_count,
        status: error.status,
        created_at: error.created_at,
        resolved_at: error.resolved_at,
        resolved_by: error.resolved_by,
      }));

      return res.status(200).json({
        errors: sanitized,
        pagination: {
          limit: limitNum,
          offset: offsetNum,
          total: errors.length,
        },
      });
    } catch (error) {
      next(error);
    }
  });

  /**
   * GET /api/v1/errors/:id
   * Get error details (including full message payload)
   */
  app.get('/api/v1/errors/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id: errorId } = req.params;

      logger.info('Getting error details', { errorId, requestId: req.headers['x-request-id'] });

      const error = await deps.repository.getError(errorId);

      if (!error) {
        return res.status(404).json({ error: 'Error not found', errorId });
      }

      // Include full details for single error view
      return res.status(200).json({
        error_id: error.error_id,
        invoice_id: error.invoice_id,
        service_name: error.service_name,
        error_classification: error.error_classification,
        original_queue: error.original_queue,
        error_reason: error.error_reason,
        error_stack: error.error_stack,
        retry_count: error.retry_count,
        status: error.status,
        created_at: error.created_at,
        resolved_at: error.resolved_at,
        resolved_by: error.resolved_by,
        // Decode message payload for display
        original_message: error.original_message.toString('utf-8'),
      });
    } catch (error) {
      next(error);
    }
  });

  /**
   * POST /api/v1/errors/:id/resolve
   * Mark error as resolved
   */
  app.post(
    '/api/v1/errors/:id/resolve',
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id: errorId } = req.params;
        const { resolved_by } = req.body;

        if (!resolved_by) {
          return res.status(400).json({ error: 'resolved_by is required' });
        }

        logger.info('Resolving error', {
          errorId,
          resolvedBy: resolved_by,
          requestId: req.headers['x-request-id'],
        });

        await deps.repository.resolveError(errorId, resolved_by);

        return res.status(200).json({
          message: 'Error resolved successfully',
          error_id: errorId,
          resolved_by,
          resolved_at: new Date().toISOString(),
        });
      } catch (error) {
        next(error);
      }
    }
  );

  /**
   * POST /api/v1/errors/:id/resubmit
   * Resubmit error to original queue
   */
  app.post(
    '/api/v1/errors/:id/resubmit',
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id: errorId } = req.params;
        const { resubmitted_by } = req.body;

        if (!resubmitted_by) {
          return res.status(400).json({ error: 'resubmitted_by is required' });
        }

        logger.info('Resubmitting error', {
          errorId,
          resubmittedBy: resubmitted_by,
          requestId: req.headers['x-request-id'],
        });

        const error = await deps.repository.getError(errorId);

        if (!error) {
          return res.status(404).json({ error: 'Error not found', errorId });
        }

        // Resubmit to original queue
        await deps.retryChannel.sendToQueue(error.original_queue, error.original_message, {
          persistent: true,
          headers: {
            'x-resubmitted-from-dlq': true,
            'x-resubmitted-by': resubmitted_by,
            'x-resubmitted-at': new Date().toISOString(),
          },
        });

        // Mark as resolved
        await deps.repository.resolveError(errorId, resubmitted_by);

        logger.info('Error resubmitted successfully', {
          errorId,
          originalQueue: error.original_queue,
        });

        return res.status(200).json({
          message: 'Error resubmitted successfully',
          error_id: errorId,
          original_queue: error.original_queue,
          resubmitted_by,
          resubmitted_at: new Date().toISOString(),
        });
      } catch (error) {
        next(error);
      }
    }
  );

  /**
   * GET /api/v1/errors/stats
   * Get error statistics
   */
  app.get('/api/v1/errors/stats', async (req: Request, res: Response, next: NextFunction) => {
    try {
      logger.info('Getting error statistics', { requestId: req.headers['x-request-id'] });

      const stats = await deps.repository.getStats();

      return res.status(200).json(stats);
    } catch (error) {
      next(error);
    }
  });

  // Error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled error', {
      error: err,
      stack: err.stack,
      requestId: _req.headers['x-request-id'],
    });

    res.status(500).json({
      error: 'Internal server error',
      message: err.message,
      requestId: _req.headers['x-request-id'],
    });
  });

  // Start server
  app.listen(port, () => {
    logger.info('HTTP API listening', { port });
  });

  return app;
}

/**
 * Generate unique request ID
 */
function generateRequestId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}
