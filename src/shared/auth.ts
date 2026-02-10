import type { Request, Response, NextFunction } from 'express';
import { randomBytes } from 'crypto';
import { logger } from './logger.js';

// Type imports - bcrypt will be installed as part of this task
// import bcrypt from 'bcrypt';

/**
 * Session data structure
 */
export interface Session {
  /** User ID */
  userId: string;
  /** User email */
  email: string;
  /** Session token */
  token: string;
  /** Timestamp when session was created */
  createdAt: Date;
}

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
 * Validates session token and attaches user context to request
 *
 * Expected session format:
 * - Header: Authorization: Bearer <token>
 * - Query: ?token=<token>
 *
 * On success: attaches req.user with { id, email }
 * On failure: returns 401 Unauthorized
 */
export function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  // Get token from Authorization header or query parameter
  const authHeader = req.headers.authorization;
  const queryToken = req.query.token as string | undefined;

  let token: string | undefined;

  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (queryToken) {
    token = queryToken;
  }

  if (!token) {
    logger.warn({
      requestId: req.id,
      ip: req.ip,
      path: req.path,
    }, 'Authentication failed: No token provided');

    res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication token required',
      requestId: req.id,
    });
    return;
  }

  // TODO: Validate token against sessions storage (database or Redis)
  // For now, this is a placeholder that will be enhanced in subtask-2-3
  // when session middleware is added to app.ts
  //
  // Future implementation:
  // const session = await getSession(token);
  // if (!session || session.expiresAt < new Date()) {
  //   res.status(401).json({ error: 'Invalid or expired token' });
  //   return;
  // }
  // req.user = { id: session.userId, email: session.email };

  logger.warn({
    requestId: req.id,
    token: token.substring(0, 8) + '...', // Log partial token for security
  }, 'Auth middleware: Session validation not yet implemented');

  // Temporary: For development, allow requests with valid token format
  // This will be replaced with proper session validation
  res.status(501).json({
    error: 'Not Implemented',
    message: 'Session validation will be implemented in subtask-2-3',
    requestId: req.id,
  });
}

/**
 * Optional authentication middleware
 * Attaches user context if token is present, but doesn't require it
 * Useful for routes that work for both authenticated and anonymous users
 */
export function optionalAuthMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;
  const queryToken = req.query.token as string | undefined;

  let token: string | undefined;

  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (queryToken) {
    token = queryToken;
  }

  if (token) {
    // TODO: Validate token and attach user
    // For now, skip since session storage isn't ready
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
