import type { Request, Response, NextFunction } from 'express';
import { randomBytes } from 'crypto';
import { logger } from './logger.js';

/**
 * Extended Express Request with user context
 */
export interface AuthenticatedRequest extends Request {
  /** Authenticated user */
  user?: {
    id: string;
    email: string;
  };
  /** Request ID (added by requestIdMiddleware) */
  id?: string;
}

/**
 * Hash a password using bcrypt
 * @param password - Plain text password
 * @returns Hashed password
 */
export async function hashPassword(password: string): Promise<string> {
  const bcrypt = await import('bcrypt');
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
}

/**
 * Verify a password against a hash using bcrypt
 * @param password - Plain text password to verify
 * @param hash - Stored password hash
 * @returns True if password matches
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  const bcrypt = await import('bcrypt');
  return bcrypt.compare(password, hash);
}

/**
 * Generate a secure random session token
 * @returns 64-character hex string
 */
export function generateSessionToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Authentication middleware for Express routes
 * Validates session and attaches user context to request
 *
 * Session is managed by express-session with Redis store
 * On success: attaches req.user with { id, email }
 * On failure: returns 401 Unauthorized
 */
export function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  // Check if session exists and has user data
  const session = req.session;

  if (!session || !session.userId || !session.email) {
    logger.warn({
      requestId: req.id,
      ip: req.ip,
      path: req.path,
      hasSession: !!session,
    }, 'Authentication failed: No valid session');

    res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required',
      requestId: req.id,
    });
    return;
  }

  // Attach user context to request
  req.user = {
    id: session.userId,
    email: session.email,
  };

  logger.debug({
    requestId: req.id,
    userId: req.user.id,
    path: req.path,
  }, 'Request authenticated');

  next();
}

/**
 * Optional authentication middleware
 * Attaches user context if session is present, but doesn't require it
 * Useful for routes that work for both authenticated and anonymous users
 */
export function optionalAuthMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const session = req.session;

  if (session && session.userId && session.email) {
    req.user = {
      id: session.userId,
      email: session.email,
    };
  }

  next();
}

/**
 * Require specific user role or permission
 * @param requiredRole - Role required to access the route
 */
export function requireRole(requiredRole: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        requestId: req.id,
      });
      return;
    }

    // TODO: Implement role-based access control
    // For now, just pass through - basic user isolation is sufficient for MVP
    // as specified in the requirements

    logger.warn({
      requestId: req.id,
      userId: req.user.id,
      requiredRole,
    }, 'Role checking not yet implemented - allowing access');

    next();
  };
}

