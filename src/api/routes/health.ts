import type { Request, type Response } from 'express';
import { getPool } from '../../shared/db.js';
import { logger } from '../../shared/logger.js';

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
      res.status(500).json({
        status: 'error',
        message: 'Unexpected query result',
      });
    }
  } catch (error) {
    logger.error({ error }, 'Database health check failed');
    res.status(500).json({
      status: 'error',
      message: 'Database connection failed',
    });
  }
}
