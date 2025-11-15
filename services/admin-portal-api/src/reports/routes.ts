import { Router, Request, Response } from 'express';
import { authenticateJWT } from '../auth/middleware';
import { anyAuthenticated } from '../auth/rbac';
import { AuthenticatedRequest } from '../auth/types';
import { logger } from '../observability';
import { getAdminCommandGateway } from '../messaging';
import { createRequestContext } from '../messaging/request-context';

const messagingGateway = getAdminCommandGateway();

const router = Router();

/**
 * GET /api/v1/reports/monthly
 *
 * Monthly invoice summary (viewer+)
 */
router.get('/monthly', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    // TODO: Aggregate invoice data from audit-logger
    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      msg: 'Monthly report requested (placeholder)',
    });

    res.json({
      month: new Date().toISOString().substring(0, 7),
      total_invoices: 0,
      b2c_invoices: 0,
      b2b_invoices: 0,
      b2g_invoices: 0,
      note: 'Audit-logger integration pending',
    });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Monthly report failed',
    });
    res.status(500).json({ error: 'Failed to generate monthly report' });
  }
});

/**
 * GET /api/v1/reports/errors
 *
 * Error statistics (viewer+)
 */
router.get('/errors', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);

  try {
    const stats = await messagingGateway.deadLetterStats(context);
    res.json(stats ?? {});
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'Error report failed',
    });
    res.status(502).json({ error: 'Failed to generate error report' });
  }
});

/**
 * GET /api/v1/reports/submissions
 *
 * Submission rates (viewer+)
 */
router.get('/submissions', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    // TODO: Aggregate submission data
    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      msg: 'Submissions report requested (placeholder)',
    });

    res.json({
      period: 'last_30_days',
      total_submissions: 0,
      successful_submissions: 0,
      failed_submissions: 0,
      note: 'Audit-logger integration pending',
    });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Submissions report failed',
    });
    res.status(500).json({ error: 'Failed to generate submissions report' });
  }
});

export default router;
