import { requestIdMiddleware, errorHandler } from '../../../src/api/app';

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
    it('should return 500 with error message', () => {
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
  });
});
