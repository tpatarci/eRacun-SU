import { Router, Request, Response } from 'express';
import { authenticateJWT } from '../auth/middleware';
import { operatorOrAdmin } from '../auth/rbac';
import { AuthenticatedRequest } from '../auth/types';
import { getDeadLetterHandlerClient } from '../clients/dead-letter-handler';
import { logger } from '../observability';

const router = Router();

/**
 * GET /api/v1/errors
 *
 * List errors in manual review (operator+)
 */
router.get('/', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const dlhClient = getDeadLetterHandlerClient();
    const errors = await dlhClient.listErrors(authReq.requestId, req.query);

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      msg: 'Retrieved errors list',
    });

    res.json(errors);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'List errors failed',
    });
    res.status(500).json({ error: 'Failed to retrieve errors' });
  }
});

/**
 * GET /api/v1/errors/:id
 *
 * Get error details (operator+)
 */
router.get('/:id', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const errorId = req.params.id;

  try {
    const dlhClient = getDeadLetterHandlerClient();
    const errorDetails = await dlhClient.getError(errorId, authReq.requestId);

    res.json(errorDetails);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error_id: errorId,
      error: error.message,
      msg: 'Get error details failed',
    });
    res.status(500).json({ error: 'Failed to retrieve error details' });
  }
});

/**
 * POST /api/v1/errors/:id/resolve
 *
 * Mark error as resolved (operator+)
 */
router.post('/:id/resolve', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const errorId = req.params.id;

  try {
    const dlhClient = getDeadLetterHandlerClient();
    const result = await dlhClient.resolveError(errorId, authReq.requestId);

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      error_id: errorId,
      msg: 'Error resolved',
    });

    res.json(result);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error_id: errorId,
      error: error.message,
      msg: 'Resolve error failed',
    });
    res.status(500).json({ error: 'Failed to resolve error' });
  }
});

/**
 * POST /api/v1/errors/:id/resubmit
 *
 * Resubmit error to original queue (operator+)
 */
router.post('/:id/resubmit', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const errorId = req.params.id;

  try {
    const dlhClient = getDeadLetterHandlerClient();
    const result = await dlhClient.resubmitError(errorId, authReq.requestId);

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      error_id: errorId,
      msg: 'Error resubmitted',
    });

    res.json(result);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error_id: errorId,
      error: error.message,
      msg: 'Resubmit error failed',
    });
    res.status(500).json({ error: 'Failed to resubmit error' });
  }
});

/**
 * POST /api/v1/errors/bulk-resolve
 *
 * Bulk resolve multiple errors (operator+)
 */
router.post('/bulk-resolve', authenticateJWT, operatorOrAdmin, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { error_ids } = req.body;

  if (!Array.isArray(error_ids) || error_ids.length === 0) {
    return res.status(400).json({ error: 'error_ids array required' });
  }

  try {
    const dlhClient = getDeadLetterHandlerClient();
    const result = await dlhClient.bulkResolve(error_ids, authReq.requestId);

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      error_count: error_ids.length,
      msg: 'Errors bulk resolved',
    });

    res.json(result);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Bulk resolve failed',
    });
    res.status(500).json({ error: 'Failed to bulk resolve errors' });
  }
});

export default router;
