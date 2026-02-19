import { type Request, type Response } from 'express';
import { getPool } from '../../shared/db.js';
import { logger } from '../../shared/logger.js';
import { InternalError, buildErrorResponse } from '../errors.js';

export async function healthCheck(req: Request, res: Response): Promise<void> {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
}

export async function healthCheckDb(req: Request, res: Response): Promise<void> {
  try {
    const pool = getPool();
    const result = await pool.query('SELECT 1');

    if (result.rows[0] && result.rows[0]['?column?'] === 1) {
      res.json({
        status: 'ok',
      });
    } else {
      const error = new InternalError('Unexpected query result');
      res.status(500).json(buildErrorResponse(error, req.id, 500));
    }
  } catch (error) {
    logger.error({ error }, 'Database health check failed');
    const internalError = new InternalError('Database connection failed', error instanceof Error ? error : undefined);
    res.status(500).json(buildErrorResponse(internalError, req.id, 500));
  }
}
