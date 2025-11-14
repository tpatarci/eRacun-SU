/**
 * Idempotency Middleware Tests
 */

import { Request, Response, NextFunction } from 'express';
import { Container } from 'inversify';
import { idempotencyMiddleware } from '../../../src/middleware/idempotency';

describe('Idempotency Middleware', () => {
  let container: Container;
  let middleware: ReturnType<typeof idempotencyMiddleware>;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: jest.Mock;
  let jsonSpy: jest.Mock;
  let statusSpy: jest.Mock;

  beforeEach(() => {
    container = new Container();
    middleware = idempotencyMiddleware(container);

    jsonSpy = jest.fn();
    statusSpy = jest.fn().mockReturnThis();

    mockRequest = {
      method: 'POST',
      headers: {},
      requestId: 'test-request-id',
    };

    mockResponse = {
      status: statusSpy,
      json: jsonSpy,
      statusCode: 200,
    };

    mockNext = jest.fn();
  });

  describe('POST requests', () => {
    it('should require idempotency key header', () => {
      middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(statusSpy).toHaveBeenCalledWith(400);
      expect(jsonSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'MISSING_IDEMPOTENCY_KEY',
            message: 'X-Idempotency-Key header is required for POST requests',
          }),
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject invalid UUID format', () => {
      mockRequest.headers = { 'x-idempotency-key': 'invalid-uuid' };

      middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(statusSpy).toHaveBeenCalledWith(400);
      expect(jsonSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'INVALID_IDEMPOTENCY_KEY',
            message: 'X-Idempotency-Key must be a valid UUID',
          }),
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should accept valid UUID idempotency key', () => {
      mockRequest.headers = { 'x-idempotency-key': '123e4567-e89b-12d3-a456-426614174000' };

      middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockRequest.idempotencyKey).toBe('123e4567-e89b-12d3-a456-426614174000');
      expect(mockNext).toHaveBeenCalled();
      expect(statusSpy).not.toHaveBeenCalled();
    });

    it('should return cached response for duplicate idempotency key', () => {
      const idempotencyKey = '123e4567-e89b-12d3-a456-426614174000';
      mockRequest.headers = { 'x-idempotency-key': idempotencyKey };

      // First request
      const originalJson = mockResponse.json!;
      mockResponse.json = jest.fn((body) => {
        originalJson.call(mockResponse, body);
        return mockResponse as Response;
      });

      middleware(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();

      // Simulate response
      (mockResponse.json as jest.Mock)({ invoiceId: 'test-123', status: 'QUEUED' });

      // Reset for second request
      mockNext.mockClear();
      jsonSpy.mockClear();
      statusSpy.mockClear();

      // Second request with same idempotency key
      middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(jsonSpy).toHaveBeenCalledWith({ invoiceId: 'test-123', status: 'QUEUED' });
    });
  });

  describe('Non-POST requests', () => {
    it('should skip idempotency check for GET requests', () => {
      mockRequest.method = 'GET';

      middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(statusSpy).not.toHaveBeenCalled();
    });

    it('should skip idempotency check for DELETE requests', () => {
      mockRequest.method = 'DELETE';

      middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(statusSpy).not.toHaveBeenCalled();
    });
  });
});
