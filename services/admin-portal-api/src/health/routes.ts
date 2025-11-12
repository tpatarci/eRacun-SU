import { Router, Request, Response } from 'express';
import { authenticateJWT } from '../auth/middleware';
import { anyAuthenticated } from '../auth/rbac';
import { AuthenticatedRequest } from '../auth/types';
import { getHealthMonitorClient } from '../clients/health-monitor';
import { getDeadLetterHandlerClient } from '../clients/dead-letter-handler';
import { getCertLifecycleManagerClient } from '../clients/cert-lifecycle-manager';
import { logger } from '../observability';

const router = Router();

/**
 * GET /api/v1/health/dashboard
 *
 * System-wide health dashboard (viewer+)
 */
router.get('/dashboard', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const healthClient = getHealthMonitorClient();
    const dlhClient = getDeadLetterHandlerClient();
    const certClient = getCertLifecycleManagerClient();

    // Aggregate data from multiple services
    const [systemHealth, errorStats, certificates] = await Promise.all([
      healthClient.getDashboard(authReq.requestId).catch(() => null),
      dlhClient.getErrorStats(authReq.requestId).catch(() => null),
      certClient.getExpiringCertificates(30, authReq.requestId).catch(() => null),
    ]);

    const dashboard = {
      system_health: systemHealth,
      error_stats: errorStats,
      expiring_certificates: certificates,
      timestamp: new Date().toISOString(),
    };

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      msg: 'Dashboard data aggregated',
    });

    res.json(dashboard);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Dashboard aggregation failed',
    });
    res.status(500).json({ error: 'Failed to aggregate dashboard data' });
  }
});

/**
 * GET /api/v1/health/services
 *
 * All services status (viewer+)
 */
router.get('/services', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const healthClient = getHealthMonitorClient();
    const services = await healthClient.getServicesStatus(authReq.requestId);

    res.json(services);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Services status retrieval failed',
    });
    res.status(500).json({ error: 'Failed to retrieve services status' });
  }
});

/**
 * GET /api/v1/health/external
 *
 * External dependencies status (viewer+)
 */
router.get('/external', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const healthClient = getHealthMonitorClient();
    const external = await healthClient.getExternalStatus(authReq.requestId);

    res.json(external);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'External status retrieval failed',
    });
    res.status(500).json({ error: 'Failed to retrieve external status' });
  }
});

/**
 * GET /api/v1/health/circuit-breakers
 *
 * Circuit breaker states (viewer+)
 */
router.get('/circuit-breakers', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const healthClient = getHealthMonitorClient();
    const circuitBreakers = await healthClient.getCircuitBreakers(authReq.requestId);

    res.json(circuitBreakers);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Circuit breakers retrieval failed',
    });
    res.status(500).json({ error: 'Failed to retrieve circuit breakers' });
  }
});

export default router;
