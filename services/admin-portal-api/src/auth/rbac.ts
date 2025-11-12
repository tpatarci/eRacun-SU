import { Request, Response, NextFunction } from 'express';
import { UserRole, AuthenticatedRequest } from './types';
import { logger } from '../observability';

/**
 * Role-Based Access Control (RBAC) middleware
 *
 * Ensures authenticated user has one of the required roles
 *
 * @param roles - List of allowed roles
 */
export function requireRole(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;

    if (!authReq.user) {
      logger.warn({
        request_id: authReq.requestId,
        msg: 'RBAC check failed - no user attached to request',
      });
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!roles.includes(authReq.user.role)) {
      logger.warn({
        request_id: authReq.requestId,
        user_id: authReq.user.userId,
        user_role: authReq.user.role,
        required_roles: roles,
        msg: 'RBAC check failed - insufficient permissions',
      });
      return res.status(403).json({
        error: 'Forbidden - Insufficient permissions',
        required_roles: roles,
        user_role: authReq.user.role,
      });
    }

    logger.debug({
      request_id: authReq.requestId,
      user_id: authReq.user.userId,
      user_role: authReq.user.role,
      msg: 'RBAC check passed',
    });

    next();
  };
}

/**
 * Check if user is admin
 */
export function isAdmin(req: Request): boolean {
  const authReq = req as AuthenticatedRequest;
  return authReq.user?.role === UserRole.ADMIN;
}

/**
 * Check if user is operator or higher
 */
export function isOperatorOrHigher(req: Request): boolean {
  const authReq = req as AuthenticatedRequest;
  return (
    authReq.user?.role === UserRole.ADMIN || authReq.user?.role === UserRole.OPERATOR
  );
}

/**
 * Check if user is viewer or higher (all authenticated users)
 */
export function isViewerOrHigher(req: Request): boolean {
  const authReq = req as AuthenticatedRequest;
  return authReq.user !== undefined;
}

/**
 * Convenience middleware: Admin only
 */
export const adminOnly = requireRole(UserRole.ADMIN);

/**
 * Convenience middleware: Operator or Admin
 */
export const operatorOrAdmin = requireRole(UserRole.OPERATOR, UserRole.ADMIN);

/**
 * Convenience middleware: Any authenticated user
 */
export const anyAuthenticated = requireRole(
  UserRole.VIEWER,
  UserRole.OPERATOR,
  UserRole.ADMIN
);
