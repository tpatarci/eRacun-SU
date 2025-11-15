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
 * GET /api/v1/health/dashboard
 *
 * System-wide health dashboard (viewer+)
 */
router.get('/dashboard', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);

  try {
    const snapshot = await messagingGateway.fetchHealthDashboard(context);

    const dashboard = {
      system_health: snapshot.services ?? [],
      error_stats: snapshot.deadLetterStats,
      expiring_certificates: snapshot.expiringCertificates ?? [],
      dependencies: snapshot.dependencies ?? [],
      circuit_breakers: snapshot.circuitBreakers ?? [],
      timestamp: new Date().toISOString(),
    };

    logger.info({
      request_id: context.requestId,
      user_id: authReq.user?.userId,
      msg: 'Dashboard data aggregated via messaging',
    });

    res.json(dashboard);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'Dashboard aggregation failed',
    });
    res.status(502).json({ error: 'Failed to aggregate dashboard data' });
  }
});

/**
 * GET /api/v1/health/services
 *
 * All services status (viewer+)
 */
router.get('/services', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);

  try {
    const snapshot = await messagingGateway.fetchServiceStatuses(context);
    res.json(snapshot.services ?? []);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'Services status retrieval failed',
    });
    res.status(502).json({ error: 'Failed to retrieve services status' });
  }
});

/**
 * GET /api/v1/health/external
 *
 * External dependencies status (viewer+)
 */
router.get('/external', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);

  try {
    const snapshot = await messagingGateway.fetchExternalStatuses(context);
    res.json(snapshot.dependencies ?? []);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'External status retrieval failed',
    });
    res.status(502).json({ error: 'Failed to retrieve external status' });
  }
});

/**
 * GET /api/v1/health/circuit-breakers
 *
 * Circuit breaker states (viewer+)
 */
router.get('/circuit-breakers', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);

  try {
    const snapshot = await messagingGateway.fetchCircuitBreakers(context);
    res.json(snapshot.circuitBreakers ?? []);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'Circuit breakers retrieval failed',
    });
    res.status(502).json({ error: 'Failed to retrieve circuit breakers' });
  }
});

export default router;
