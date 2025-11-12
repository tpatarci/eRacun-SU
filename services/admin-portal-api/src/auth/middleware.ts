import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { JWTPayload, AuthenticatedRequest } from './types';
import { logger, maskToken, authAttempts } from '../observability';

/**
 * JWT authentication middleware
 *
 * Validates JWT token from Authorization header and attaches user to request
 */
export function authenticateJWT(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    logger.warn({
      request_id: (req as any).requestId,
      msg: 'Missing Authorization header',
    });
    authAttempts.inc({ status: 'failed' });
    return res.status(401).json({ error: 'Unauthorized - Missing token' });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    logger.warn({
      request_id: (req as any).requestId,
      msg: 'Invalid Authorization header format',
    });
    authAttempts.inc({ status: 'failed' });
    return res.status(401).json({ error: 'Unauthorized - Invalid token format' });
  }

  const token = parts[1];
  const jwtSecret = process.env.JWT_SECRET;

  if (!jwtSecret) {
    logger.error({
      request_id: (req as any).requestId,
      msg: 'JWT_SECRET not configured',
    });
    return res.status(500).json({ error: 'Internal server error' });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret) as JWTPayload;

    // Attach user to request
    (req as AuthenticatedRequest).user = decoded;

    logger.debug({
      request_id: (req as any).requestId,
      user_id: decoded.userId,
      role: decoded.role,
      token: maskToken(token),
      msg: 'JWT authentication successful',
    });

    authAttempts.inc({ status: 'success' });
    next();
  } catch (err) {
    const error = err as Error;

    logger.warn({
      request_id: (req as any).requestId,
      token: maskToken(token),
      error: error.message,
      msg: 'JWT verification failed',
    });

    authAttempts.inc({ status: 'invalid_token' });

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Invalid token' });
    }

    return res.status(500).json({ error: 'Token verification error' });
  }
}

/**
 * Optional authentication middleware
 *
 * Attaches user to request if token is present, but doesn't require it
 */
export function optionalAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return next();
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return next();
  }

  const token = parts[1];
  const jwtSecret = process.env.JWT_SECRET;

  if (!jwtSecret) {
    return next();
  }

  try {
    const decoded = jwt.verify(token, jwtSecret) as JWTPayload;
    (req as AuthenticatedRequest).user = decoded;
  } catch (err) {
    // Silently fail for optional auth
    logger.debug({
      request_id: (req as any).requestId,
      msg: 'Optional auth failed, continuing without user',
    });
  }

  next();
}
