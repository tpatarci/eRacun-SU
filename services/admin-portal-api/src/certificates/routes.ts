import { Router, Request, Response } from 'express';
import { authenticateJWT } from '../auth/middleware';
import { adminOnly, anyAuthenticated } from '../auth/rbac';
import { AuthenticatedRequest } from '../auth/types';
import { logger } from '../observability';
import { getAdminCommandGateway } from '../messaging';
import { createRequestContext } from '../messaging/request-context';

const messagingGateway = getAdminCommandGateway();

const router = Router();

/**
 * GET /api/v1/certificates
 *
 * List certificates (viewer+)
 */
router.get('/', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);

  try {
    const certificates = await messagingGateway.listCertificates(context);

    logger.info({
      request_id: context.requestId,
      user_id: authReq.user?.userId,
      msg: 'Certificates list retrieved via messaging',
    });

    return res.json({ certificates });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'List certificates failed',
    });
    return res.status(502).json({ error: 'Failed to retrieve certificates' });
  }
});

/**
 * POST /api/v1/certificates/upload
 *
 * Upload new certificate (admin only)
 */
router.post('/upload', authenticateJWT, adminOnly, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);
  const { filename, certificate_bundle: certificateBundle, password, label } = req.body || {};

  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'filename is required' });
  }

  if (!certificateBundle || typeof certificateBundle !== 'string') {
    return res.status(400).json({ error: 'certificate_bundle (base64 string) is required' });
  }

  try {
    const pkcs12Bundle = certificateBundle.trim();
    const response = await messagingGateway.uploadCertificate(context, {
      filename,
      pkcs12Bundle,
      password,
      label,
    });

    logger.info({
      request_id: context.requestId,
      user_id: authReq.user?.userId,
      msg: 'Certificate upload command published',
    });

    return res.json(response);
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'Certificate upload failed',
    });
    return res.status(502).json({ error: 'Failed to upload certificate' });
  }
});

/**
 * GET /api/v1/certificates/expiring
 *
 * Certificates expiring soon (viewer+)
 */
router.get('/expiring', authenticateJWT, anyAuthenticated, async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const context = createRequestContext(authReq);
  const days = parseInt(req.query.days as string, 10) || 30;

  try {
    const expiring = await messagingGateway.getExpiringCertificates(context, days);

    return res.json({ certificates: expiring, days });
  } catch (err) {
    const error = err as Error;
    logger.error({
      request_id: context.requestId,
      error: error.message,
      msg: 'Get expiring certificates failed',
    });
    return res.status(502).json({ error: 'Failed to retrieve expiring certificates' });
  }
});

export default router;
