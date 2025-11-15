import { Router, Request, Response } from 'express';
import { authenticateJWT } from '../auth/middleware';
import { operatorOrAdmin } from '../auth/rbac';
import { AuthenticatedRequest } from '../auth/types';
import { logger } from '../observability';
import { getAdminCommandGateway } from '../messaging';
import { createRequestContext } from '../messaging/request-context';
import { buildDeadLetterFilters } from '../messaging/dead-letter-filters';

const messagingGateway = getAdminCommandGateway();

const router = Router();

/**
 * GET /api/v1/errors
 *
 * List errors in manual review (operator+)
 */
router.get('/', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);

  try {
    const filters = buildDeadLetterFilters(req.query as Record<string, unknown>);
    const response = await messagingGateway.listDeadLetterErrors(context, filters);

    logger.info({
      request_id: context.requestId,
      user_id: authReq.user?.userId,
      msg: 'Retrieved errors list via messaging',
    });

    res.json(response);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'List errors failed',
    });
    res.status(502).json({ error: 'Failed to retrieve errors' });
  }
});

/**
 * GET /api/v1/errors/:id
 *
 * Get error details (operator+)
 */
router.get('/:id', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);
  const errorId = req.params.id;

  try {
    const response = await messagingGateway.getDeadLetterError(context, errorId);
    res.json(response.error ?? null);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error_id: errorId,
      error: error.message,
      msg: 'Get error details failed',
    });
    res.status(502).json({ error: 'Failed to retrieve error details' });
  }
});

/**
 * POST /api/v1/errors/:id/resolve
 *
 * Mark error as resolved (operator+)
 */
router.post('/:id/resolve', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);
  const errorId = req.params.id;

  try {
    const result = await messagingGateway.resolveDeadLetter(context, errorId);

    logger.info({
      request_id: context.requestId,
      user_id: authReq.user?.userId,
      error_id: errorId,
      msg: 'Error resolved',
    });

    res.json(result);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error_id: errorId,
      error: error.message,
      msg: 'Resolve error failed',
    });
    res.status(502).json({ error: 'Failed to resolve error' });
  }
});

/**
 * POST /api/v1/errors/:id/resubmit
 *
 * Resubmit error to original queue (operator+)
 */
router.post('/:id/resubmit', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);
  const errorId = req.params.id;

  try {
    const result = await messagingGateway.resubmitDeadLetter(context, errorId);

    logger.info({
      request_id: context.requestId,
      user_id: authReq.user?.userId,
      error_id: errorId,
      msg: 'Error resubmitted',
    });

    return res.json(result);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error_id: errorId,
      error: error.message,
      msg: 'Resubmit error failed',
    });
    return res.status(502).json({ error: 'Failed to resubmit error' });
  }
});

/**
 * POST /api/v1/errors/bulk-resolve
 *
 * Bulk resolve multiple errors (operator+)
 */
router.post('/bulk-resolve', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);
  const { error_ids: errorIds } = req.body;

  if (!Array.isArray(errorIds) || errorIds.length === 0) {
    return res.status(400).json({ error: 'error_ids array required' });
  }

  try {
    const result = await messagingGateway.bulkResolveDeadLetters(context, errorIds);

    logger.info({
      request_id: context.requestId,
      user_id: authReq.user?.userId,
      error_count: errorIds.length,
      msg: 'Errors bulk resolved',
    });

    return res.json(result);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'Bulk resolve failed',
    });
    return res.status(502).json({ error: 'Failed to bulk resolve errors' });
  }
});

export default router;
