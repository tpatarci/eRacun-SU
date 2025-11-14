/**
 * Health Check Routes
 * Provides health, readiness, and liveness endpoints
 */

import { Router, Request, Response } from 'express';
import { Container } from 'inversify';
import { HealthController } from '../controllers/health.controller';

export function healthRoutes(container: Container): Router {
  const router = Router();
  const controller = new HealthController(container);

  /**
   * GET /api/v1/health
   * Full health check with dependency status
   */
  router.get('/', async (req: Request, res: Response) => {
    await controller.healthCheck(req, res);
  });

  /**
   * GET /api/v1/health/ready
   * Readiness check (can accept traffic)
   */
  router.get('/ready', async (req: Request, res: Response) => {
    await controller.readinessCheck(req, res);
  });

  /**
   * GET /api/v1/health/live
   * Liveness check (is alive)
   */
  router.get('/live', (req: Request, res: Response) => {
    controller.livenessCheck(req, res);
  });

  return router;
}
