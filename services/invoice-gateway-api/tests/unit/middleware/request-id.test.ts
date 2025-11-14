/**
 * Request ID Middleware Tests
 */

import { Request, Response, NextFunction } from 'express';
import { requestIdMiddleware } from '../../../src/middleware/request-id';

describe('Request ID Middleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockRequest = {
      headers: {},
    };
    mockResponse = {
      setHeader: jest.fn(),
    };
    mockNext = jest.fn();
  });

  it('should generate new request ID if not provided', () => {
    requestIdMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

    expect(mockRequest.requestId).toBeDefined();
    expect(mockRequest.requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    expect(mockResponse.setHeader).toHaveBeenCalledWith('X-Request-ID', mockRequest.requestId);
    expect(mockNext).toHaveBeenCalled();
  });

  it('should use existing X-Request-ID header if provided', () => {
    const existingId = '123e4567-e89b-12d3-a456-426614174000';
    mockRequest.headers = { 'x-request-id': existingId };

    requestIdMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

    expect(mockRequest.requestId).toBe(existingId);
    expect(mockResponse.setHeader).toHaveBeenCalledWith('X-Request-ID', existingId);
    expect(mockNext).toHaveBeenCalled();
  });
});
