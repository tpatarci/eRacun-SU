import type { Response } from 'express';
import { getConfigs, updateConfig, deleteConfig } from '../../repositories/user-config-repository.js';
import { finaConfigSchema, imapConfigSchema } from '../schemas.js';
import { logger } from '../../shared/logger.js';
import { authMiddleware, type AuthenticatedRequest } from '../../shared/auth.js';

// GET /api/v1/users/me/config
export async function getConfigsHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  // userId is guaranteed to exist because authMiddleware is used
  const userId = req.user!.id;

  try {
    const configs = await getConfigs(userId);

    // Transform array into object keyed by service name
    const configMap: Record<string, Record<string, unknown>> = {};
    for (const config of configs) {
      configMap[config.serviceName] = config.config as Record<string, unknown>;
    }

    res.json({
      configs: configMap,
    });
  } catch (error) {
    logger.error({
      error: error instanceof Error ? error.message : String(error),
      userId,
    }, 'Failed to get configurations');

    res.status(500).json({
      error: 'Failed to get configurations',
      requestId: req.id,
    });
  }
}

// PUT /api/v1/users/me/config/:service
export async function updateConfigHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  // userId is guaranteed to exist because authMiddleware is used
  const userId = req.user!.id;
  const { service } = req.params;

  // Validate service name
  if (service !== 'fina' && service !== 'imap') {
    res.status(400).json({
      error: 'Invalid service name',
      message: 'Service must be either "fina" or "imap"',
      requestId: req.id,
    });
    return;
  }

  // Validate request body using appropriate schema
  const schema = service === 'fina' ? finaConfigSchema : imapConfigSchema;
  const validationResult = schema.safeParse(req.body);

  if (!validationResult.success) {
    const errors = validationResult.error.errors.map((e) => ({
      field: e.path.join('.'),
      message: e.message,
    }));

    res.status(400).json({
      error: 'Validation failed',
      errors,
      requestId: req.id,
    });
    return;
  }

  const configData = validationResult.data;

  try {
    // Update configuration
    const config = await updateConfig(userId, service, configData);

    logger.info({
      userId,
      service,
    }, 'Configuration updated');

    res.json({
      serviceName: service,
      config: config.config as Record<string, unknown>,
      updatedAt: config.updatedAt,
    });
  } catch (error) {
    logger.error({
      error: error instanceof Error ? error.message : String(error),
      userId,
      service,
    }, 'Failed to update configuration');

    res.status(500).json({
      error: 'Failed to update configuration',
      requestId: req.id,
    });
  }
}

// DELETE /api/v1/users/me/config/:service
export async function deleteConfigHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  // userId is guaranteed to exist because authMiddleware is used
  const userId = req.user!.id;
  const { service } = req.params;

  // Validate service name
  if (service !== 'fina' && service !== 'imap') {
    res.status(400).json({
      error: 'Invalid service name',
      message: 'Service must be either "fina" or "imap"',
      requestId: req.id,
    });
    return;
  }

  try {
    await deleteConfig(userId, service);

    logger.info({
      userId,
      service,
    }, 'Configuration deleted');

    res.status(204).send();
  } catch (error) {
    logger.error({
      error: error instanceof Error ? error.message : String(error),
      userId,
      service,
    }, 'Failed to delete configuration');

    res.status(500).json({
      error: 'Failed to delete configuration',
      requestId: req.id,
    });
  }
}

// Route handlers - paths are relative to /api/v1/users/me/config
export const configRoutes = [
  {
    path: '/me/config',
    method: 'get',
    handler: getConfigsHandler,
    middleware: [authMiddleware],
  },
  {
    path: '/me/config/:service',
    method: 'put',
    handler: updateConfigHandler,
    middleware: [authMiddleware],
  },
  {
    path: '/me/config/:service',
    method: 'delete',
    handler: deleteConfigHandler,
    middleware: [authMiddleware],
  },
];
