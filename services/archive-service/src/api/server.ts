/**
 * REST API Server
 *
 * Exposes endpoints for invoice retrieval, validation, and audit queries.
 * See: docs/adr/004-archive-compliance-layer.md §85-90
 */

import express from 'express';
import { createLogger } from '../utils/logger';

const logger = createLogger('api-server');

export async function startApiServer(port: number): Promise<void> {
  const app = express();

  app.use(express.json({ limit: '1mb' }));

  // Health checks
  app.get('/health/live', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.get('/health/ready', (_req, res) => {
    // TODO: Check database, RabbitMQ, S3 connectivity
    res.status(200).json({ status: 'ready' });
  });

  // API routes (to be implemented)
  app.get('/v1/archive/invoices/:id', (_req, res) => {
    res.status(501).json({ error: 'Not implemented' });
  });

  app.get('/v1/archive/invoices', (_req, res) => {
    res.status(501).json({ error: 'Not implemented' });
  });

  app.get('/v1/archive/invoices/:id/audit', (_req, res) => {
    res.status(501).json({ error: 'Not implemented' });
  });

  app.post('/v1/archive/invoices/:id/validate', (_req, res) => {
    res.status(501).json({ error: 'Not implemented' });
  });

  // Error handler
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    logger.error('Unhandled error', { error: err });
    res.status(500).json({ error: 'Internal server error' });
  });

  app.listen(port, () => {
    logger.info('API server listening', { port });
  });
}
