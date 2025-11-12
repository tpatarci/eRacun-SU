import { Router, Request, Response } from 'express';
import { authenticateJWT } from '../auth/middleware';
import { adminOnly, anyAuthenticated } from '../auth/rbac';
import { AuthenticatedRequest } from '../auth/types';
import { getCertLifecycleManagerClient } from '../clients/cert-lifecycle-manager';
import { logger } from '../observability';

const router = Router();

/**
 * GET /api/v1/certificates
 *
 * List certificates (viewer+)
 */
router.get('/', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const certClient = getCertLifecycleManagerClient();
    const certificates = await certClient.listCertificates(authReq.requestId);

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      msg: 'Certificates list retrieved',
    });

    res.json(certificates);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'List certificates failed',
    });
    res.status(500).json({ error: 'Failed to retrieve certificates' });
  }
});

/**
 * POST /api/v1/certificates/upload
 *
 * Upload new certificate (admin only)
 */
router.post('/upload', authenticateJWT, adminOnly, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;

  try {
    const certClient = getCertLifecycleManagerClient();

    // Pass form data to cert-lifecycle-manager
    // NOTE: Express needs multer middleware for multipart/form-data
    // This is a simplified implementation
    const result = await certClient.uploadCertificate(req.body as any, authReq.requestId);

    logger.info({
      request_id: authReq.requestId,
      user_id: authReq.user?.userId,
      msg: 'Certificate uploaded',
    });

    res.json(result);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Certificate upload failed',
    });
    res.status(500).json({ error: 'Failed to upload certificate' });
  }
});

/**
 * GET /api/v1/certificates/expiring
 *
 * Certificates expiring soon (viewer+)
 */
router.get('/expiring', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const days = parseInt(req.query.days as string, 10) || 30;

  try {
    const certClient = getCertLifecycleManagerClient();
    const expiring = await certClient.getExpiringCertificates(days, authReq.requestId);

    res.json(expiring);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: authReq.requestId,
      error: error.message,
      msg: 'Get expiring certificates failed',
    });
    res.status(500).json({ error: 'Failed to retrieve expiring certificates' });
  }
});

export default router;
