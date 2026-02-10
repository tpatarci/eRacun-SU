import { requestIdMiddleware, errorHandler } from '../../../src/api/app';
import {
  NotFoundError,
  ValidationError,
  InternalError,
  UnauthorizedError,
  ForbiddenError,
  ConflictError,
  BadRequestError,
} from '../../../src/api/errors';

// Mock uuid
jest.mock('uuid', () => ({
  v4: () => 'test-request-id-123',
}));

describe('Express App', () => {
  describe('requestIdMiddleware', () => {
    it('should generate UUID if header not present', () => {
      const req = {
        headers: {},
        id: undefined,
      } as unknown as Request;
      const res = {
        getHeader: jest.fn(),
        setHeader: jest.fn(),
      } as unknown as Response;
      const next = jest.fn();

      requestIdMiddleware(req, res as Response, next);

      expect(req.id).toBe('test-request-id-123');
      expect(res.setHeader).toHaveBeenCalledWith('X-Request-ID', 'test-request-id-123');
      expect(next).toHaveBeenCalled();
    });

    it('should use existing header if present', () => {
      const req = {
        headers: { 'x-request-id': 'custom-id' },
        id: undefined,
      } as unknown as Request;
      const res = {
        getHeader: jest.fn(),
        setHeader: jest.fn(),
      } as unknown as Response;
      const next = jest.fn();

      requestIdMiddleware(req, res as Response, next);

      expect(req.id).toBe('custom-id');
      expect(res.setHeader).toHaveBeenCalledWith('X-Request-ID', 'custom-id');
    });
  });

  describe('errorHandler', () => {
    it('should return 500 with error message for plain Error', () => {
      const err = new Error('Test error');
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        code: 'INTERNAL_ERROR',
        message: 'Internal Server Error',
        requestId: 'test-request-id',
      });
    });

    it('should return 404 for NotFoundError', () => {
      const err = new NotFoundError('Resource not found');
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({
        code: 'NOT_FOUND',
        message: 'Resource not found',
        requestId: 'test-request-id',
      });
    });

    it('should return 400 for ValidationError with errors array', () => {
      const fieldErrors = [
        { field: 'email', message: 'Invalid email format' },
        { field: 'password', message: 'Password too short' },
      ];
      const err = new ValidationError('Validation failed', fieldErrors);
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: 'test-request-id',
        errors: fieldErrors,
      });
    });

    it('should return 400 for ValidationError without errors array', () => {
      const err = new ValidationError('Validation failed');
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: 'test-request-id',
      });
    });

    it('should return 401 for UnauthorizedError', () => {
      const err = new UnauthorizedError('Authentication required');
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
        requestId: 'test-request-id',
      });
    });

    it('should return 403 for ForbiddenError', () => {
      const err = new ForbiddenError('Access denied');
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        code: 'FORBIDDEN',
        message: 'Access denied',
        requestId: 'test-request-id',
      });
    });

    it('should return 409 for ConflictError', () => {
      const err = new ConflictError('Resource already exists');
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(409);
      expect(res.json).toHaveBeenCalledWith({
        code: 'CONFLICT',
        message: 'Resource already exists',
        requestId: 'test-request-id',
      });
    });

    it('should return 400 for BadRequestError', () => {
      const err = new BadRequestError('Invalid request format');
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        code: 'BAD_REQUEST',
        message: 'Invalid request format',
        requestId: 'test-request-id',
      });
    });

    it('should return 500 for InternalError', () => {
      const err = new InternalError('Server error occurred');
      const req = {
        id: 'test-request-id',
      } as unknown as Request;
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;
      const next = jest.fn();

      errorHandler(err, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        code: 'INTERNAL_ERROR',
        message: 'Server error occurred',
        requestId: 'test-request-id',
      });
    });
  });
});
