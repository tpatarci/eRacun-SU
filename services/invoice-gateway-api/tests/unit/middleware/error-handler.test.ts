/**
 * Error Handler Tests
 */

import { Request, Response, NextFunction } from 'express';
import { errorHandler, createError } from '../../../src/middleware/error-handler';
import { ErrorCode } from '@eracun/contracts';

describe('Error Handler Middleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let jsonSpy: jest.Mock;
  let statusSpy: jest.Mock;

  beforeEach(() => {
    jsonSpy = jest.fn();
    statusSpy = jest.fn().mockReturnThis();

    mockRequest = {
      requestId: 'test-request-id',
      path: '/api/v1/test',
      method: 'POST',
    };

    mockResponse = {
      status: statusSpy,
      json: jsonSpy,
    };

    mockNext = jest.fn();
  });

  it('should handle errors with status code', () => {
    const error = createError('Test error', 400, ErrorCode.INVALID_OIB);

    errorHandler(error, mockRequest as Request, mockResponse as Response, mockNext);

    expect(statusSpy).toHaveBeenCalledWith(400);
    expect(jsonSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.objectContaining({
          code: ErrorCode.INVALID_OIB,
          message: 'Test error',
          correlationId: 'test-request-id',
        }),
      })
    );
  });

  it('should default to 500 for errors without status code', () => {
    const error = new Error('Unexpected error');

    errorHandler(error, mockRequest as Request, mockResponse as Response, mockNext);

    expect(statusSpy).toHaveBeenCalledWith(500);
    expect(jsonSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.objectContaining({
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Unexpected error',
        }),
      })
    );
  });

  it('should include error details if provided', () => {
    const error = createError(
      'Validation failed',
      400,
      ErrorCode.SCHEMA_VALIDATION_FAILED,
      { fields: ['supplier.name', 'buyer.vatNumber'] }
    );

    errorHandler(error, mockRequest as Request, mockResponse as Response, mockNext);

    expect(jsonSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.objectContaining({
          details: { fields: ['supplier.name', 'buyer.vatNumber'] },
        }),
      })
    );
  });

  it('should include timestamp in error response', () => {
    const error = createError('Test error', 400);

    errorHandler(error, mockRequest as Request, mockResponse as Response, mockNext);

    const callArg = jsonSpy.mock.calls[0][0];
    expect(callArg.error.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });
});

describe('createError', () => {
  it('should create error with all properties', () => {
    const error = createError(
      'Test message',
      404,
      'TEST_CODE',
      { extra: 'data' }
    );

    expect(error.message).toBe('Test message');
    expect(error.statusCode).toBe(404);
    expect(error.code).toBe('TEST_CODE');
    expect(error.details).toEqual({ extra: 'data' });
  });

  it('should default status code to 500', () => {
    const error = createError('Test message');

    expect(error.statusCode).toBe(500);
  });
});
