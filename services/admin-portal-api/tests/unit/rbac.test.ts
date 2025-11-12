import { Request, Response } from 'express';
import { requireRole } from '../../src/auth/rbac';
import { UserRole, AuthenticatedRequest } from '../../src/auth/types';

describe('RBAC - Role-Based Access Control', () => {
  let mockReq: Partial<AuthenticatedRequest>;
  let mockRes: Partial<Response>;
  let nextFn: jest.Mock;

  beforeEach(() => {
    mockReq = {
      requestId: 'test-request-123',
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    nextFn = jest.fn();
  });

  describe('requireRole', () => {
    it('should allow access for matching role', () => {
      mockReq.user = {
        userId: 1,
        email: 'admin@example.com',
        role: UserRole.ADMIN,
      };

      const middleware = requireRole(UserRole.ADMIN);
      middleware(mockReq as Request, mockRes as Response, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should allow access for any of multiple roles', () => {
      mockReq.user = {
        userId: 2,
        email: 'operator@example.com',
        role: UserRole.OPERATOR,
      };

      const middleware = requireRole(UserRole.ADMIN, UserRole.OPERATOR);
      middleware(mockReq as Request, mockRes as Response, nextFn);

      expect(nextFn).toHaveBeenCalled();
    });

    it('should deny access for mismatched role', () => {
      mockReq.user = {
        userId: 3,
        email: 'viewer@example.com',
        role: UserRole.VIEWER,
      };

      const middleware = requireRole(UserRole.ADMIN);
      middleware(mockReq as Request, mockRes as Response, nextFn);

      expect(nextFn).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Forbidden - Insufficient permissions',
        })
      );
    });

    it('should deny access when no user attached', () => {
      mockReq.user = undefined;

      const middleware = requireRole(UserRole.ADMIN);
      middleware(mockReq as Request, mockRes as Response, nextFn);

      expect(nextFn).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(401);
    });
  });
});
