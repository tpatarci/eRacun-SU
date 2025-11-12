/**
 * User roles for RBAC
 */
export enum UserRole {
  ADMIN = 'admin',
  OPERATOR = 'operator',
  VIEWER = 'viewer',
}

/**
 * JWT payload structure
 */
export interface JWTPayload {
  userId: number;
  email: string;
  role: UserRole;
  iat?: number;
  exp?: number;
}

/**
 * Session data
 */
export interface Session {
  id: string;
  userId: number;
  token: string;
  expiresAt: Date;
  createdAt: Date;
}

/**
 * Extended Express Request with user info
 */
export interface AuthenticatedRequest extends Express.Request {
  user?: JWTPayload;
  requestId?: string;
}
